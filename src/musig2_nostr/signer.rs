use super::nostr_utils::initialize_nostr;
use super::keystore::KeyStore;
use nostr::{Event, Filter, Kind, Keys as NostrKeys, Tag};
use nostr_sdk::Client;
use musig2::{KeyAggContext, FirstRound, SecondRound, PubNonce, PartialSignature, secp256k1::{SecretKey, PublicKey}};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;
use serde_json;

pub struct Signer {
    secret_key: SecretKey,
    public_key: PublicKey,
    nostr_keys: NostrKeys,
    client: Arc<Mutex<Client>>,
    coordinator_nostr_pubkey: PublicKey,
    key_agg_ctx: Option<KeyAggContext>,
    session_id: String,
}

impl Signer {
    pub fn new(secret_key: SecretKey, nostr_keys: NostrKeys, coordinator_nostr_pubkey: PublicKey, session_id: String) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let client = Arc::new(Mutex::new(Client::new(nostr_keys.clone())));
        Signer {
            secret_key,
            public_key,
            nostr_keys,
            client,
            coordinator_nostr_pubkey,
            key_agg_ctx: None,
            session_id,
        }
    }

    pub async fn register_with_coordinator(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.client.lock().await;
        let registration_msg = format!(
            "register: session_id={}, musig2_pk={}, nostr_pk={}",
            self.session_id,
            self.public_key.to_string(),
            self.nostr_keys.public_key().to_string()
        );
        let event = Event::new(
            Kind::EncryptedDirectMessage,
            vec![Tag::PublicKey(self.coordinator_nostr_pubkey)],
            registration_msg,
            &self.nostr_keys,
        );
        client.send_event(&event).await?;
        println!("Signer registered for session: {}", self.session_id);
        Ok(())
    }

    pub async fn start_first_round(&mut self) -> Result<PubNonce, Box<dyn std::error::Error>> {
        let mut client = self.client.lock().await;
        let sec_nonce = musig2::SecNonce::new(&self.secret_key);
        let pub_nonce = PubNonce::from_sec_nonce(&sec_nonce);
        let event = Event::new(
            Kind::EncryptedDirectMessage,
            vec![Tag::PublicKey(self.coordinator_nostr_pubkey)],
            format!("pub_nonce: session_id={}, nonce={}", self.session_id, serde_json::to_string(&pub_nonce)?),
            &self.nostr_keys,
        )?;
        client.send_event(event).await?;
        Ok(pub_nonce)
    }

    pub async fn wait_for_nonces_and_signal(&mut self) -> Result<Vec<PubNonce>, Box<dyn std::error::Error>> {
        let mut client = self.client.lock().await;
        let filter = Filter::new()
            .kind(Kind::EncryptedDirectMessage)
            .pubkey(self.nostr_keys.public_key());
        client.subscribe(vec![filter]).await?;

        let timeout = tokio::time::sleep(Duration::from_secs(300));
        tokio::pin!(timeout);

        let mut all_nonces = None;
        loop {
            tokio::select! {
                _ = &mut timeout => return Err("Timed out waiting for coordinator nonces or signal".into()),
                Some(event) = client.next_event() => {
                    if event.kind == Kind::EncryptedDirectMessage {
                        if let Some(sender_pk) = event.pubkey {
                            if sender_pk != self.coordinator_nostr_pubkey {
                                println!("Ignoring event from unknown sender: {:?}", sender_pk);
                                continue;
                            }
                        }
                        if let Ok(content) = std::str::from_utf8(&event.content) {
                            if content.starts_with("nonce_broadcast: ") && content.contains(&self.session_id) {
                                let parts: Vec<&str> = content.split("nonce_broadcast: ").collect();
                                if parts.len() > 1 {
                                    let data: Vec<&str> = parts[1].split(',').collect();
                                    if data.len() >= 3 && data[0].split('=').nth(1).unwrap_or("") == self.session_id {
                                        let expected_signers: usize = data[1].split('=').nth(1).unwrap_or("0").parse()?;
                                        let nonces_str = data[2].split('=').nth(1).unwrap_or("");
                                        let nonces: Vec<PubNonce> = serde_json::from_str(nonces_str)?;

                                        // Validate nonces
                                        if nonces.len() != expected_signers {
                                            return Err(format!("Invalid nonce count: expected {}, got {}", expected_signers, nonces.len()).into());
                                        }
                                        if nonces.is_empty() {
                                            return Err("Received empty nonce list".into());
                                        }
                                        for nonce in &nonces {
                                            if nonce.to_bytes().iter().all(|&b| b == 0) {
                                                return Err("Received invalid (all-zero) nonce".into());
                                            }
                                        }

                                        all_nonces = Some(nonces);
                                        println!("Received and validated broadcasted nonces for session {}: {:?}", self.session_id, all_nonces);
                                    }
                                }
                            } else if content.contains(&format!("proceed to second round: session_id={}", self.session_id)) {
                                if let Some(nonces) = all_nonces.take() {
                                    return Ok(nonces);
                                } else {
                                    return Err("Received proceed signal before valid nonces".into());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub async fn handle_second_round(&mut self, all_nonces: Vec<PubNonce>) -> Result<PartialSignature, Box<dyn std::error::Error>> {
        if self.key_agg_ctx.is_none() {
            self.key_agg_ctx = Some(KeyAggContext::new(vec![self.public_key])); // Should include all signers
        }
        let first_round = FirstRound::new(&self.key_agg_ctx.as_ref().unwrap(), all_nonces);
        let partial_sig = first_round.sign(&self.secret_key, b"message_to_sign").unwrap();
        let mut client = self.client.lock().await;
        let event = Event::new(
            Kind::EncryptedDirectMessage,
            vec![Tag::PublicKey(self.coordinator_nostr_pubkey)],
            format!("partial_sig: session_id={}, sig={}", self.session_id, serde_json::to_string(&partial_sig)?),
            &self.nostr_keys,
        )?;
        client.send_event(event).await?;
        Ok(partial_sig)
    }

    pub fn save_keys(&self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        let key_store = KeyStore::new(self.secret_key, &self.nostr_keys)?;
        key_store.save(password)?;
        Ok(())
    }

    pub fn load_keys(password: &str, coordinator_nostr_pubkey: PublicKey, session_id: String) -> Result<Self, Box<dyn std::error::Error>> {
        let (secret_key, nostr_keys) = KeyStore::load(password)?;
        Ok(Signer::new(secret_key, nostr_keys, coordinator_nostr_pubkey, session_id))
    }

    pub fn generate_and_store_keys(password: &str, coordinator_nostr_pubkey: PublicKey, session_id: String) -> Result<Self, Box<dyn std::error::Error>> {
        let (secret_key, nostr_keys) = KeyStore::generate_and_store(password)?;
        Ok(Signer::new(secret_key, nostr_keys, coordinator_nostr_pubkey, session_id))
    }
}