use nostr::prelude::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MusigError {
    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    #[error("Musig2 error: {0}")]
    Musig2(String),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Nostr error: {0}")]
    Nostr(#[from] Error),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Session not found")]
    SessionNotFound,

    #[error("Invalid state transition")]
    InvalidStateTransition,
}

pub type Result<T> = std::result::Result<T, MusigError>;