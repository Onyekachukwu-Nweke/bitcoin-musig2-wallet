use crate::signing::{SessionId, ParticipantId};
use bitcoin::Transaction;
use secp256k1_zkp::;
use secp256k1_zkp::schnorr;
use std::collections::HashMap;
use anyhow::Result;
use serde::{Serialize, Deserialize};

/// Represents the state of a signer in the MuSig2 protocol
#[derive(Debug, Clone)]
pub struct SignerState {
    /// The participant identifier
    pub participant_id: ParticipantId,
    /// The participant's public nonce
    pub pub_nonce: Option<MusigPubNonce>,
    /// The participant's partial signature
    pub partial_signature: Option<schnorr::Signature>,
    /// Has the participant approved the transaction
    pub approved: bool,
    /// Timestamp of the last update from this participant
    pub last_update: u64,
}

impl SignerState {
    pub fn new(participant_id: &str) -> Self {
        SignerState {
            participant_id: participant_id.to_string(),
            pub_nonce: None,
            partial_signature: None,
            approved: false,
            last_update: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn set_nonce(&mut self, nonce: MusigPubNonce) -> &mut Self {
        self.pub_nonce = Some(nonce);
        self.update_timestamp();
        self
    }

    pub fn set_signature(&mut self, signature: schnorr::Signature) -> &mut Self {
        self.partial_signature = Some(signature);
        self.approved = true;
        self.update_timestamp();
        self
    }

    pub fn set_approved(&mut self, approved: bool) -> &mut Self {
        self.approved = approved;
        self.update_timestamp();
        self
    }

    fn update_timestamp(&mut self) {
        self.last_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

/// The current state of the signing process for a session
#[derive(Debug)]
pub struct SigningState {
    /// Session identifier
    pub session_id: SessionId,
    /// Transaction to be signed
    pub transaction: Option<Transaction>,
    /// Transaction hex string
    pub transaction_hex: String,
    /// Map of participant states
    pub signers: HashMap<ParticipantId, SignerState>,
    /// Secret nonce for this participant
    pub secret_nonce: Option<MusigSecNonce>,
    /// Public nonce for this participant
    pub pub_nonce: Option<MusigPubNonce>,
    /// MuSig2 session object for this signing session
    pub musig_session: Option<MusigSession>,
    /// Combined final signature
    pub final_signature: Option<schnorr::Signature>,
    /// Sighash message to be signed (transaction hash)
    pub sighash: Option<Vec<u8>>,
    /// Creator of the session
    pub creator: ParticipantId,
    /// This participant's ID
    pub my_participant_id: ParticipantId,
    /// Required participants for this session
    pub required_participants: Vec<ParticipantId>,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiry timestamp
    pub expiry: u64,
}

impl SigningState {
    pub fn new(
        session_id: &str,
        transaction_hex: &str,
        creator: &str,
        my_participant_id: &str,
        required_participants: Vec<String>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Default expiry: 1 hour from now
        let expiry = now + 3600;

        let mut signers = HashMap::new();
        for participant_id in &required_participants {
            signers.insert(
                participant_id.clone(),
                SignerState::new(participant_id),
            );
        }

        SigningState {
            session_id: session_id.to_string(),
            transaction: None,
            transaction_hex: transaction_hex.to_string(),
            signers,
            secret_nonce: None,
            pub_nonce: None,
            musig_session: None,
            final_signature: None,
            sighash: None,
            creator: creator.to_string(),
            my_participant_id: my_participant_id.to_string(),
            required_participants,
            created_at: now,
            expiry,
        }
    }

    /// Check if all required nonces have been received
    pub fn has_all_nonces(&self) -> bool {
        self.signers.values().all(|s| s.pub_nonce.is_some())
    }

    /// Check if all required signatures have been received
    pub fn has_all_signatures(&self) -> bool {
        self.signers.values().all(|s| s.partial_signature.is_some())
    }

    /// Check if all participants have approved the transaction
    pub fn is_approved_by_all(&self) -> bool {
        self.signers.values().all(|s| s.approved)
    }

    /// Get all public nonces
    pub fn get_all_nonces(&self) -> Vec<MusigPubNonce> {
        self.signers.values()
            .filter_map(|s| s.pub_nonce.clone())
            .collect()
    }

    /// Get all partial signatures
    pub fn get_all_signatures(&self) -> Vec<schnorr::Signature> {
        self.signers.values()
            .filter_map(|s| s.partial_signature)
            .collect()
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now > self.expiry
    }

    /// Parse the transaction hex into a Transaction object
    pub fn parse_transaction(&mut self) -> Result<&Transaction> {
        if self.transaction.is_none() {
            let tx_bytes = hex::decode(&self.transaction_hex)?;
            self.transaction = Some(bitcoin::consensus::deserialize(&tx_bytes)?);
        }

        Ok(self.transaction.as_ref().unwrap())
    }

    /// Set my nonce
    pub fn set_my_nonce(&mut self, secret_nonce: MusigSecNonce, pub_nonce: MusigPubNonce) -> &mut Self {
        self.secret_nonce = Some(secret_nonce);
        self.pub_nonce = Some(pub_nonce.clone());

        // Add my nonce to my signer state
        if let Some(signer) = self.signers.get_mut(&self.my_participant_id) {
            signer.set_nonce(pub_nonce);
        }

        self
    }

    /// Set nonce for a participant
    pub fn set_participant_nonce(&mut self, participant_id: &str, nonce: MusigPubNonce) -> &mut Self {
        if let Some(signer) = self.signers.get_mut(participant_id) {
            signer.set_nonce(nonce);
        }

        self
    }

    /// Set signature for a participant
    pub fn set_participant_signature(&mut self, participant_id: &str, signature: schnorr::Signature) -> &mut Self {
        if let Some(signer) = self.signers.get_mut(participant_id) {
            signer.set_signature(signature);
        }

        self
    }
}