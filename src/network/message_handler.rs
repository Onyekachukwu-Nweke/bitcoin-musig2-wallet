use crate::network::message::Message;
use crate::network::MessageType;
// use crate::signing::coordinator::{
//     SigningCoordinator, TransactionProposal, PublicNonceData,
//     PartialSignatureData, SessionCompletionData, SessionAbortData
// };
use anyhow::{anyhow, Result};
use log::{info, error, warn, debug};
use std::sync::Arc;

/// Handler for network messages
pub struct MessageHandler {
    /// Signing coordinator
    signing_coordinator: Arc<SigningCoordinator>,
}

impl MessageHandler {
    /// Create a new message handler
    pub fn new(signing_coordinator: Arc<SigningCoordinator>) -> Self {
        MessageHandler {
            signing_coordinator,
        }
    }

    /// Handle an incoming message
    pub async fn handle_message(&self, message: Message) -> Result<()> {
        match message.message_type {
            MessageType::TransactionProposal => {
                // Deserialize the transaction proposal
                let proposal: TransactionProposal = serde_json::from_slice(&message.payload)?;

                // Handle the proposal
                self.signing_coordinator.handle_transaction_proposal(proposal).await?;
            },
            MessageType::PublicNonce => {
                // Deserialize the nonce data
                let nonce_data: PublicNonceData = serde_json::from_slice(&message.payload)?;

                // Handle the nonce
                self.signing_coordinator.handle_public_nonce(nonce_data).await?;
            },
            MessageType::PartialSignature => {
                // Deserialize the signature data
                let sig_data: PartialSignatureData = serde_json::from_slice(&message.payload)?;

                // Handle the signature
                self.signing_coordinator.handle_partial_signature(sig_data).await?;
            },
            MessageType::TransactionComplete => {
                // Deserialize the completion data
                let completion_data: SessionCompletionData = serde_json::from_slice(&message.payload)?;

                // Handle the completion
                self.signing_coordinator.handle_session_completion(completion_data).await?;
            },
            MessageType::Error => {
                // Deserialize the abort data
                let abort_data: SessionAbortData = serde_json::from_slice(&message.payload)?;

                // Handle the abort
                self.signing_coordinator.handle_session_abort(abort_data).await?;
            },
            MessageType::Ping => {
                // Respond with a pong
                // This would be handled by the network service directly
            },
            MessageType::Pong => {
                // Update connection status
                // This would be handled by the network service directly
            },
            _ => {
                warn!("Received unknown message type: {:?}", message.message_type);
            }
        }

        Ok(())
    }
}