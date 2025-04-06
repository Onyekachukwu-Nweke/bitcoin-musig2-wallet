use super::nostr_utils::initialize_nostr;
use super::session::SessionState;
use musig2::{
    KeyAggContext, PartialSignature, PubNonce, secp256k1::PublicKey,
};
use nostr::{Event, Filter, Keys as NostrKeys, PublicKey as NostrPublicKey, Kind, Tag};
use nostr_sdk::Client;
use serde_json;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub struct Coordinator {
    aggregated_pubkey: Option<PublicKey>,
    pub(crate) signers: HashMap<NostrPublicKey, PublicKey>,
    nostr_keys: NostrKeys,
    pub(crate) client: Arc<Mutex<Client>>,
    first_round_nonces: HashMap<PublicKey, PubNonce>,
    partial_sigs: HashMap<PublicKey, PartialSignature>,
    expected_signers: usize,
    faulty_signers: Vec<PublicKey>,
    session_id: String,
}

impl Coordinator {
    pub fn new(nostr_keys: NostrKeys, expected_signers: usize, session_id: String) -> Self {
        let client = Arc::new(Mutex::new(Client::new(nostr_keys.clone())));
        Coordinator {
            aggregated_pubkey: None,
            signers: HashMap::new(),
            nostr_keys,
            client,
            first_round_nonces: HashMap::new(),
            partial_sigs: HashMap::new(),
            expected_signers,
            faulty_signers: Vec::new(),
            session_id,
        }
    }

    pub async fn collect_signer_registrations(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.client.lock().await;
        let filter = Filter::new()
            .kind(Kind::EncryptedDirectMessage)
            .pubkey(self.nostr_keys.public_key());
        client.subscribe(filter, None).await?;

        println!("Waiting for {} signers to register for session {}", self.expected_signers, self.session_id);

        let timeout = Duration::from_secs(300);
        let deadline = std::time::Instant::now() + timeout;

        while self.signers.len() < self.expected_signers {
            if std::time::Instant::now() >= deadline {
                return Err(format!("Timed out waiting for {} signers; only {} registered", self.expected_signers, self.signers.len()).into());
            }

            let remaining_time = deadline - std::time::Instant::now();
            let events = client.fetch_events(filter.clone(), remaining_time).await?;

            for event in events {
                if event.kind == Kind::EncryptedDirectMessage {
                    if let Ok(content) = std::str::from_utf8((&event.content).as_ref()) {
                        if content.starts_with("register: ") && content.contains(&self.session_id) {
                            let parts: Vec<&str> = content.split("register: ").collect();
                            if parts.len() > 1 {
                                let data: Vec<&str> = parts[1].split(',').collect();
                                if data.len() >= 3 {
                                    let session_id = data[0].split('=').nth(1).unwrap_or("");
                                    if session_id != self.session_id { continue; }
                                    let musig2_pk_str = data[1].split('=').nth(1).unwrap_or("");
                                    let nostr_pk_str = data[2].split('=').nth(1).unwrap_or("");
                                    match (PublicKey::from_str(musig2_pk_str), NostrPublicKey::from_str(nostr_pk_str)) {
                                        (Ok(musig2_pk), Ok(nostr_pk)) => {
                                            self.signers.insert(nostr_pk, musig2_pk);
                                            println!("Registered signer for session {}: Nostr PK: {:?}", self.session_id, nostr_pk);
                                        }
                                        _ => {
                                            if let Some(sender_pk) = event.pubkey {
                                                self.faulty_signers.push(sender_pk);
                                                eprintln!("Invalid registration for session {}: {:?}", self.session_id, sender_pk);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if self.signers.len() < self.expected_signers {
                tokio::time::sleep(Duration::from_secs(1)).await; // Avoid tight loop
            }
        }

        let musig2_pks: Vec<PublicKey> = self.signers.values().cloned().collect();
        let sorted_agg_pubkey = KeyAggContext::new(musig2_pks).unwrap();
        self.aggregated_pubkey = Some(sorted_agg_pubkey.aggregated_pubkey());
        self.save_session_state()?;
        Ok(())
    }

    fn save_session_state(&self) -> Result<(), Box<dyn std::error::Error>> {
        let state = SessionState {
            session_id: self.session_id.clone(),
            signers: self.signers.clone(),
            first_round_nonces: self.first_round_nonces.clone(),
            partial_sigs: self.partial_sigs.clone(),
        };
        state.save()?;
        Ok(())
    }
}
