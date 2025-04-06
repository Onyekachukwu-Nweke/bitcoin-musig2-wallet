use musig2::{
    secp256k1::{PublicKey, SecretKey},
    FirstRound, KeyAggContext, PartialSignature, PubNonce, SecondRound,
};
use nostr::{Filter, Keys as NostrKeys, Keys, Kind, Tag, PublicKey as NostrPublicKey, Timestamp, EventId, EventBuilder};
use nostr_sdk::{Client, Event};
use serde_json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use crate::musig2_nostr::keystore::KeyStore;

pub struct Signer {
    secret_key: SecretKey,
    pub(crate) public_key: PublicKey,
    pub(crate) nostr_keys: NostrKeys,
    pub(crate) client: Arc<Mutex<Client>>,
    coordinator_nostr_pubkey: NostrPublicKey,
    key_agg_ctx: Option<KeyAggContext>,
    session_id: String,
}

impl Signer {
    pub fn new(
        secret_key: SecretKey,
        nostr_keys: NostrKeys,
        coordinator_nostr_pubkey: NostrPublicKey,
        session_id: String,
    ) -> Self {
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
        let event = EventBuilder::new(
            Kind::EncryptedDirectMessage,
            registration_msg,
        ).tag(Tag::public_key(self.coordinator_nostr_pubkey))
            .sign_with_keys(&self.nostr_keys).unwrap();
        client.send_event(&event).await?;
        println!("Signer registered for session: {}", self.session_id);
        Ok(())
    }

    pub fn save_keys(&self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        let key_store = KeyStore::new(self.secret_key, &self.nostr_keys)?;
        key_store.save(password)?;
        Ok(())
    }

    pub fn load_keys(password: &str, coordinator_nostr_pubkey: NostrPublicKey, session_id: String) -> Result<Self, Box<dyn std::error::Error>> {
        let (secret_key, nostr_keys) = KeyStore::load(password)?;
        Ok(Signer::new(secret_key, nostr_keys, coordinator_nostr_pubkey, session_id))
    }

    pub fn generate_and_store_keys(password: &str, coordinator_nostr_pubkey: NostrPublicKey, session_id: String) -> Result<Self, Box<dyn std::error::Error>> {
        let (secret_key, nostr_keys) = KeyStore::generate_and_store(password)?;
        Ok(Signer::new(secret_key, nostr_keys, coordinator_nostr_pubkey, session_id))
    }
}
