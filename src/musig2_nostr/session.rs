use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use musig2::{PubNonce, PartialSignature, secp256k1::PublicKey};
use std::fs;
use nostr_sdk::PublicKey as NostrPublicKey;

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionState {
    pub session_id: String,
    pub signers: HashMap<NostrPublicKey, PublicKey>, // Nostr PK -> MuSig2 PK
    pub first_round_nonces: HashMap<PublicKey, PubNonce>,
    pub partial_sigs: HashMap<PublicKey, PartialSignature>,
}

impl SessionState {
    pub fn new(session_id: String) -> Self {
        SessionState {
            session_id,
            signers: HashMap::new(),
            first_round_nonces: HashMap::new(),
            partial_sigs: HashMap::new(),
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(self)?;
        fs::write(format!("session_{}.json", self.session_id), json)?;
        println!("Session state saved to session_{}.json", self.session_id);
        Ok(())
    }

    pub fn load(session_id: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let json = fs::read_to_string(format!("session_{}.json", session_id))?;
        let state: SessionState = serde_json::from_str(&json)?;
        Ok(state)
    }
}