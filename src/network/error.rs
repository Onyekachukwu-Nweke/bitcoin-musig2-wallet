use std::fmt;
use std::error::Error;
use std::io;

/// Network-related errors
#[derive(Debug)]
pub enum NetworkError {
    /// Error during IO operations
    IoError(io::Error),
    /// Failed to serialize or deserialize data
    SerializationError(String),
    /// Failed to connect to a peer
    ConnectionError(String),
    /// Failed to send a message
    SendError(String),
    /// Failed to receive a message
    ReceiveError(String),
    /// Invalid message format
    InvalidMessage(String),
    /// Authentication failure
    AuthenticationError(String),
    /// Peer not found
    PeerNotFound(String),
    /// Transport error
    TransportError(String),
    /// Timeout waiting for a response
    Timeout(String),
    /// General network error
    Other(String),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::IoError(e) => write!(f, "IO error: {}", e),
            NetworkError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            NetworkError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            NetworkError::SendError(msg) => write!(f, "Send error: {}", msg),
            NetworkError::ReceiveError(msg) => write!(f, "Receive error: {}", msg),
            NetworkError::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            NetworkError::AuthenticationError(msg) => write!(f, "Authentication error: {}", msg),
            NetworkError::PeerNotFound(msg) => write!(f, "Peer not found: {}", msg),
            NetworkError::TransportError(msg) => write!(f, "Transport error: {}", msg),
            NetworkError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            NetworkError::Other(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl Error for NetworkError {}

impl From<io::Error> for NetworkError {
    fn from(error: io::Error) -> Self {
        NetworkError::IoError(error)
    }
}

impl From<serde_json::Error> for NetworkError {
    fn from(error: serde_json::Error) -> Self {
        NetworkError::SerializationError(error.to_string())
    }
}

impl From<tokio::sync::mpsc::error::SendError<Vec<u8>>> for NetworkError {
    fn from(error: tokio::sync::mpsc::error::SendError<Vec<u8>>) -> Self {
        NetworkError::SendError(error.to_string())
    }
}

// impl From<bincode::error> for NetworkError {
//     fn from(error: bincode::error) -> Self {
//         NetworkError::SerializationError(error.to_string())
//     }
// }

impl From<&str> for NetworkError {
    fn from(msg: &str) -> Self {
        NetworkError::Other(msg.to_string())
    }
}

impl From<String> for NetworkError {
    fn from(msg: String) -> Self {
        NetworkError::Other(msg)
    }
}