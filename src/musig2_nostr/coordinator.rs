use super::nostr_utils::initialize_nostr;
use super::session::SessionState;
use musig2::{
    CompactSignature, FirstRound, KeyAggContext, PartialSignature, PubNonce, PublicKey, SecondRound,
};
use nostr::{Event, Filter, Keys as NostrKeys, Kind, Tag};
use nostr_sdk::Client;
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub struct Coordinator {
    aggregated_pubkey: Option<PublicKey>,
    signers: HashMap<PublicKey, PublicKey>,
    nostr_keys: NostrKeys,
    client: Arc<Mutex<Client>>,
    first_round_nonces: HashMap<PublicKey, PubNonce>,
    partial_sigs: HashMap<PublicKey, PartialSignature>,
    expected_signers: usize,
    faulty_signers: Vec<PublicKey>,
    session_id: String,
}

impl Coordinator {
    pub fn new(nostr_keys: NostrKeys, expected_signers: usize, session_id: String) -> Self {
        Coordinator {
            aggregated_pubkey: None,
            signers: HashMap::new(),
            nostr_keys,
            client: Arc::new(Mutex::new(Client::new(nostr_keys.clone()))),
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

        println!(
            "Waiting for {} signers to register for session {}",
            self.expected_signers, self.session_id
        );

        let timeout = tokio::time::sleep(Duration::from_secs(300));
        tokio::pin!(timeout);

        while self.signers.len() < self.expected_signers {
            tokio::select! {
                _ = &mut timeout => return Err(format!("Timed out waiting for {} signers; only {} registered", self.expected_signers, self.signers.len()).into()),
                Some(event) = client.next_event() => {
                    if event.kind == Kind::EncryptedDirectMessage {
                        if let Ok(content) = std::str::from_utf8(&event.content) {
                            if content.starts_with("register: ") && content.contains(&self.session_id) {
                                let parts: Vec<&str> = content.split("register: ").collect();
                                if parts.len() > 1 {
                                    let data: Vec<&str> = parts[1].split(',').collect();
                                    if data.len() >= 3 {
                                        let session_id = data[0].split('=').nth(1).unwrap_or("");
                                        if session_id != self.session_id { continue; }
                                        let musig2_pk_str = data[1].split('=').nth(1).unwrap_or("");
                                        let nostr_pk_str = data[2].split('=').nth(1).unwrap_or("");
                                        match (PublicKey::from_str(musig2_pk_str), PublicKey::from_str(nostr_pk_str)) {
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
            }
        }

        if self.signers.len() < self.expected_signers {
            return Err(format!(
                "Only {} signers registered for session {}, expected {}",
                self.signers.len(),
                self.session_id,
                self.expected_signers
            )
            .into());
        }

        let musig2_pks: Vec<PublicKey> = self.signers.values().cloned().collect();
        self.aggregated_pubkey = Some(KeyAggContext::new(musig2_pks).aggregated_pubkey());
        self.save_session_state()?;
        Ok(())
    }

    pub async fn start_signing_process(
        &mut self,
    ) -> Result<CompactSignature, Box<dyn std::error::Error>> {
        let mut client = self.client.lock().await;
        let filter = Filter::new()
            .kind(Kind::EncryptedDirectMessage)
            .pubkey(self.nostr_keys.public_key());
        client.subscribe(vec![filter]).await?;

        // First round: Collect nonces
        let timeout = tokio::time::sleep(Duration::from_secs(300));
        tokio::pin!(timeout);

        while self.first_round_nonces.len() < self.signers.len() {
            tokio::select! {
                _ = &mut timeout => return Err(format!("Timed out waiting for nonces for session {}; {} signers failed", self.session_id, self.signers.len() - self.first_round_nonces.len()).into()),
                Some(event) = client.next_event() => {
                    if event.kind == Kind::EncryptedDirectMessage {
                        if let Ok(content) = std::str::from_utf8(&event.content) {
                            if content.starts_with("pub_nonce: ") && content.contains(&self.session_id) {
                                let parts: Vec<&str> = content.split("pub_nonce: ").collect();
                                if parts.len() > 1 {
                                    let data: Vec<&str> = parts[1].split(',').collect();
                                    if data.len() >= 2 && data[0].split('=').nth(1).unwrap_or("") == self.session_id {
                                        match serde_json::from_str::<PubNonce>(data[1].split('=').nth(1).unwrap_or("")) {
                                            Ok(nonce) => {
                                                if let Some(sender_nostr_pk) = event.pubkey {
                                                    if self.signers.contains_key(&sender_nostr_pk) {
                                                        self.first_round_nonces.insert(sender_nostr_pk, nonce);
                                                        println!("Received nonce for session {}: {:?}", self.session_id, sender_nostr_pk);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                if let Some(sender_pk) = event.pubkey {
                                                    self.faulty_signers.push(sender_pk);
                                                    return Err(format!("Invalid nonce for session {}: {}", self.session_id, e).into());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if self.first_round_nonces.len() < self.signers.len() {
            return Err(format!(
                "Not all signers provided nonces for session {}. Faulty: {:?}",
                self.session_id, self.faulty_signers
            )
            .into());
        }

        // Broadcast all nonces to signers
        let all_nonces: Vec<PubNonce> = self.first_round_nonces.values().cloned().collect();
        let nonce_broadcast_msg = format!(
            "nonce_broadcast: session_id={}, nonces={}",
            self.session_id,
            serde_json::to_string(&all_nonces)?
        );
        for nostr_pk in self.signers.keys() {
            let event = Event::new(
                Kind::EncryptedDirectMessage,
                vec![Tag::public_key(*nostr_pk)],
                nonce_broadcast_msg.clone(),
                &self.nostr_keys,
            )?;
            client.send_event(event).await?;
            println!(
                "Broadcasted nonces to signer {:?} for session {}",
                nostr_pk, self.session_id
            );
        }

        // Signal signers to proceed to second round
        for nostr_pk in self.signers.keys() {
            let event = Event::new(
                Kind::EncryptedDirectMessage,
                vec![Tag::public_key(*nostr_pk)],
                format!("proceed to second round: session_id={}", self.session_id),
                &self.nostr_keys,
            )?;
            client.send_event(event).await?;
        }

        // Second round: Collect partial signatures
        while self.partial_sigs.len() < self.signers.len() {
            tokio::select! {
                _ = &mut timeout => return Err(format!("Timed out waiting for signatures for session {}; {} signers failed", self.session_id, self.signers.len() - self.partial_sigs.len()).into()),
                Some(event) = client.next_event() => {
                    if event.kind == Kind::EncryptedDirectMessage {
                        if let Ok(content) = std::str::from_utf8(&event.content) {
                            if content.starts_with("partial_sig: ") && content.contains(&self.session_id) {
                                let parts: Vec<&str> = content.split("partial_sig: ").collect();
                                if parts.len() > 1 {
                                    let data: Vec<&str> = parts[1].split(',').collect();
                                    if data.len() >= 2 && data[0].split('=').nth(1).unwrap_or("") == self.session_id {
                                        match serde_json::from_str::<PartialSignature>(data[1].split('=').nth(1).unwrap_or("")) {
                                            Ok(partial_sig) => {
                                                if let Some(sender_nostr_pk) = event.pubkey {
                                                    if self.signers.contains_key(&sender_nostr_pk) {
                                                        self.partial_sigs.insert(sender_nostr_pk, partial_sig);
                                                        println!("Received partial signature for session {}: {:?}", self.session_id, sender_nostr_pk);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                if let Some(sender_pk) = event.pubkey {
                                                    self.faulty_signers.push(sender_pk);
                                                    return Err(format!("Invalid partial signature for session {}: {}", self.session_id, e).into());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if self.partial_sigs.len() < self.signers.len() {
            return Err(format!(
                "Not all signers provided signatures for session {}. Faulty: {:?}",
                self.session_id, self.faulty_signers
            )
            .into());
        }

        let all_sigs: Vec<PartialSignature> = self.partial_sigs.values().cloned().collect();
        let second_round = SecondRound::new(&all_nonces, all_sigs);
        let final_signature = second_round.finalize().map_err(|e| {
            format!(
                "Failed to finalize signature for session {}: {}",
                self.session_id, e
            )
        })?;

        self.save_session_state()?;
        Ok(final_signature)
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
