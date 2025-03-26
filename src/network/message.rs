use serde::{Serialize, Deserialize};
use std::fmt;
use uuid::Uuid;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::Result;
use rand::thread_rng;
use secp256k1_zkp::{Keypair, Message as Secp256k1Message, XOnlyPublicKey, Secp256k1};
use secp256k1_zkp::schnorr::Signature;
use bitcoin::hashes::{Hash, sha256, HashEngine};

/// The types of messages that can be sent over the network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Ping message to check if a peer is alive
    Ping,
    /// Pong response to a ping
    Pong,
    /// Transaction proposal for a signing session
    TransactionProposal,
    /// Public nonce for a signing session
    PublicNonce,
    /// Partial signature for a signing session
    PartialSignature,
    /// Completed transaction with final signature
    TransactionComplete,
    /// General purpose error message
    Error,
    /// Peer discovery message
    Discovery,
    /// Peer announcement message
    PeerAnnouncement,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageType::Ping => write!(f, "Ping"),
            MessageType::Pong => write!(f, "Pong"),
            MessageType::TransactionProposal => write!(f, "TransactionProposal"),
            MessageType::PublicNonce => write!(f, "PublicNonce"),
            MessageType::PartialSignature => write!(f, "PartialSignature"),
            MessageType::TransactionComplete => write!(f, "TransactionComplete"),
            MessageType::Error => write!(f, "Error"),
            MessageType::Discovery => write!(f, "Discovery"),
            MessageType::PeerAnnouncement => write!(f, "PeerAnnouncement"),
        }
    }
}

/// A network message with authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Unique identifier for this message
    pub message_id: String,
    /// The type of message
    pub message_type: MessageType,
    /// The sender's participant ID
    pub sender_id: String,
    /// Timestamp when the message was created
    pub timestamp: u64,
    /// Message payload (serialized data specific to the message type)
    pub payload: Vec<u8>,
    /// Signature of the message for authentication
    pub signature: Vec<u8>,
}

impl Message {
    /// Create a new message with the given type, sender ID, and payload
    pub fn new(message_type: MessageType, sender_id: &str, payload: Vec<u8>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Message {
            message_id: Uuid::new_v4().to_string(),
            message_type,
            sender_id: sender_id.to_string(),
            timestamp,
            payload,
            signature: Vec::new(),
        }
    }

    /// Create a ping message
    pub fn ping(sender_id: &str) -> Self {
        Message::new(MessageType::Ping, sender_id, Vec::new())
    }

    /// Create a pong message in response to a ping
    pub fn pong(sender_id: &str, ping_id: &str) -> Self {
        Message::new(MessageType::Pong, sender_id, ping_id.as_bytes().to_vec())
    }

    /// Sign the message using the given keypair
    pub fn sign(&mut self, keypair: &Keypair) -> Result<()> {
        // Create a message hash
        let hash = self.compute_message_hash();
        let secp_msg = Secp256k1Message::from_digest_slice(&hash.as_ref())?;

        // Sign the message hash
        let secp = Secp256k1::new();
        let sig = secp.sign_schnorr(&secp_msg, &keypair);

        // Store the signature
        self.signature = sig.as_ref().to_vec();

        Ok(())
    }

    /// Verify the message signature using the given public key
    pub fn verify(&self, pubkey: &XOnlyPublicKey) -> Result<bool> {
        // If there's no signature, it can't be verified
        if self.signature.is_empty() {
            return Ok(false);
        }

        // Create a message hash
        let hash = self.compute_message_hash();
        let secp_msg =Secp256k1Message::from_digest_slice(&hash.as_ref())?;

        // Parse the signature
        let sig = Signature::from_slice(&self.signature)?;

        // Verify the signature
        let secp = Secp256k1::new();
        match secp.verify_schnorr(&sig, &secp_msg, pubkey) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Compute a hash of the message data for signing/verification
    fn compute_message_hash(&self) -> sha256::Hash {
        let mut engine = sha256::Hash::engine();
        engine.input(self.message_id.as_bytes());
        engine.input(&[self.message_type as u8]);
        engine.input(self.sender_id.as_bytes());
        engine.input(&self.timestamp.to_be_bytes());
        engine.input(&self.payload);
        sha256::Hash::from_engine(engine)
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Message {{ id: {}, type: {}, sender: {}, timestamp: {} }}",
               self.message_id, self.message_type, self.sender_id, self.timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1_zkp::Keypair;

    #[test]
    fn test_message_signing_and_verification() {

        // Create a keypair
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut thread_rng());
        let (pubkey, _) = keypair.x_only_public_key();

        // Create a message
        let mut message = Message::new(
            MessageType::Ping,
            "test_sender",
            Vec::from("test payload"),
        );

        // Sign the message
        message.sign(&keypair).unwrap();

        // Verify the signature
        assert!(message.verify(&pubkey).unwrap());

        // Modify the message
        message.payload = Vec::from("modified payload");

        // Signature should no longer be valid
        assert!(!message.verify(&pubkey).unwrap());
    }
}
