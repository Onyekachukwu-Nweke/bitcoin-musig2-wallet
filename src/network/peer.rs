use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use bitcoin::hex::FromHex;
use secp256k1_zkp::XOnlyPublicKey;
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;
use crate::network::message::Message;
use crate::network::error::NetworkError;

/// Connection state of a peer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerState {
    /// Disconnected
    Disconnected,
    /// Connecting
    Connecting,
    /// Connected
    Connected,
    /// Connection failed
    Failed,
}

impl fmt::Display for PeerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerState::Disconnected => write!(f, "Disconnected"),
            PeerState::Connecting => write!(f, "Connecting"),
            PeerState::Connected => write!(f, "Connected"),
            PeerState::Failed => write!(f, "Failed"),
        }
    }
}

/// Information about a network peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Unique identifier for this peer
    pub id: String,
    /// Human-readable name for this peer
    pub name: String,
    /// Host address (IP or hostname)
    pub host: String,
    /// Port number
    pub port: u16,
    /// Public key for verifying messages
    pub pubkey_hex: String,
}

impl PeerInfo {
    /// Create a new peer info
    pub fn new(id: &str, name: &str, host: &str, port: u16, pubkey: &XOnlyPublicKey) -> Self {
        PeerInfo {
            id: id.to_string(),
            name: name.to_string(),
            host: host.to_string(),
            port,
            pubkey_hex: hex::encode(pubkey.serialize()),
        }
    }

    /// Get the socket address for this peer
    pub fn socket_addr(&self) -> Result<SocketAddr, NetworkError> {
        let addr_str = format!("{}:{}", self.host, self.port);
        addr_str.parse::<SocketAddr>()
            .map_err(|e| NetworkError::ConnectionError(format!("Invalid peer address: {}", e)))
    }

    /// Get the public key for this peer
    pub fn pubkey(&self) -> Result<XOnlyPublicKey, NetworkError> {
        let pubkey_bytes = hex::decode(&self.pubkey_hex)
            .map_err(|e| NetworkError::Other(format!("Invalid pubkey hex: {}", e)))?;

        XOnlyPublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| NetworkError::Other(format!("Invalid pubkey: {}", e)))
    }
}

impl fmt::Display for PeerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}) @ {}:{}", self.name, self.id, self.host, self.port)
    }
}

/// A connection to a remote peer
pub struct Peer {
    /// Information about this peer
    pub info: PeerInfo,
    /// Current connection state
    state: AtomicBool,
    /// Last time a message was received from this peer
    last_seen: AtomicU64,
    /// Channel for sending messages to this peer
    send_tx: mpsc::Sender<Vec<u8>>,
}

impl Peer {
    /// Create a new peer
    pub fn new(info: PeerInfo, send_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Peer {
            info,
            state: AtomicBool::new(false), // Disconnected
            last_seen: AtomicU64::new(0),
            send_tx,
        }
    }

    /// Check if the peer is connected
    pub fn is_connected(&self) -> bool {
        self.state.load(Ordering::Relaxed)
    }

    /// Set the peer's connection state
    pub fn set_connected(&self, connected: bool) {
        self.state.store(connected, Ordering::Relaxed);
    }

    /// Update the last seen timestamp
    pub fn update_last_seen(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_seen.store(now, Ordering::Relaxed);
    }

    /// Get the last seen timestamp
    pub fn last_seen(&self) -> u64 {
        self.last_seen.load(Ordering::Relaxed)
    }

    /// Send a message to this peer
    pub async fn send_message(&self, message: Vec<u8>) -> Result<(), NetworkError> {
        if !self.is_connected() {
            return Err(NetworkError::ConnectionError(format!(
                "Peer {} is not connected", self.info.id
            )));
        }

        self.send_tx.send(message).await
            .map_err(|e| NetworkError::SendError(format!("Failed to send message: {}", e)))?;

        Ok(())
    }

    /// Returns true if the peer has been seen in the last n seconds
    pub fn is_recently_seen(&self, seconds: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last = self.last_seen();
        now - last <= seconds
    }
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("info", &self.info)
            .field("connected", &self.is_connected())
            .field("last_seen", &self.last_seen())
            .finish()
    }
}