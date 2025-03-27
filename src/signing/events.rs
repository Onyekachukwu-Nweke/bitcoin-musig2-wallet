use crate::signing::{SessionId, ParticipantId};
use crate::network::message::Message;
use anyhow::Result;
use std::fmt;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Events that can occur during the signing process
#[derive(Debug, Clone)]
pub enum SigningEvent {
    /// A new signing session has been created
    SessionCreated {
        session_id: SessionId,
    },
    /// A session has been received from another participant
    SessionReceived {
        session_id: SessionId,
        from_participant: ParticipantId,
    },
    /// A nonce has been received from a participant
    NonceReceived {
        session_id: SessionId,
        from_participant: ParticipantId,
    },
    /// All required nonces have been received for a session
    AllNoncesReceived {
        session_id: SessionId,
    },
    /// A partial signature has been received from a participant
    SignatureReceived {
        session_id: SessionId,
        from_participant: ParticipantId,
    },
    /// All required signatures have been received for a session
    AllSignaturesReceived {
        session_id: SessionId,
    },
    /// A session has been completed with a final transaction
    SessionCompleted {
        session_id: SessionId,
        final_tx_hex: String,
    },
    /// A session has failed
    SessionFailed {
        session_id: SessionId,
        reason: String,
    },
    /// A session has been aborted by a participant
    SessionAborted {
        session_id: SessionId,
        by_participant: ParticipantId,
        reason: String,
    },
    /// A message has been received that cannot be processed
    MessageError {
        message_id: String,
        from_participant: ParticipantId,
        error: String,
    },
}

impl fmt::Display for SigningEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningEvent::SessionCreated { session_id } => {
                write!(f, "Session created: {}", session_id)
            }
            SigningEvent::SessionReceived { session_id, from_participant } => {
                write!(f, "Session received from {}: {}", from_participant, session_id)
            }
            SigningEvent::NonceReceived { session_id, from_participant } => {
                write!(f, "Nonce received from {}: {}", from_participant, session_id)
            }
            SigningEvent::AllNoncesReceived { session_id } => {
                write!(f, "All nonces received: {}", session_id)
            }
            SigningEvent::SignatureReceived { session_id, from_participant } => {
                write!(f, "Signature received from {}: {}", from_participant, session_id)
            }
            SigningEvent::AllSignaturesReceived { session_id } => {
                write!(f, "All signatures received: {}", session_id)
            }
            SigningEvent::SessionCompleted { session_id, final_tx_hex } => {
                write!(f, "Session completed: {}", session_id)
            }
            SigningEvent::SessionFailed { session_id, reason } => {
                write!(f, "Session failed: {} - {}", session_id, reason)
            }
            SigningEvent::SessionAborted { session_id, by_participant, reason } => {
                write!(f, "Session aborted by {}: {} - {}", by_participant, session_id, reason)
            }
            SigningEvent::MessageError { message_id, from_participant, error } => {
                write!(f, "Message error from {}: {} - {}", from_participant, message_id, error)
            }
        }
    }
}

/// Trait for handling signing events
pub trait SigningEventHandler: Send + Sync {
    /// Handle a signing event
    async fn handle_event(&self, event: SigningEvent) -> Result<()>;
}

/// Default implementation of SigningEventHandler that logs events
pub struct DefaultSigningEventHandler {
    pub event_tx: mpsc::Sender<SigningEvent>,
}

impl DefaultSigningEventHandler {
    pub fn new(event_tx: mpsc::Sender<SigningEvent>) -> Self {
        DefaultSigningEventHandler { event_tx }
    }
}

impl SigningEventHandler for DefaultSigningEventHandler {
    async fn handle_event(&self, event: SigningEvent) -> Result<()> {
        log::info!("Signing event: {}", event);

        // Forward event to channel
        self.event_tx.send(event.clone()).await?;

        Ok(())
    }
}