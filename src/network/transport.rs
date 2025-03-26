use std::net::SocketAddr;
use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::collections::HashMap;
use log::{info, error, debug, warn};
use crate::network::error::NetworkError;
use crate::network::peer::{Peer, PeerInfo};

/// Maximum message size in bytes
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Transport layer for sending and receiving messages
#[async_trait]
pub trait Transport: Send + Sync {
    /// Start the transport layer
    async fn start(&self) -> Result<(), NetworkError>;

    /// Connect to a peer
    async fn connect(&self, peer_info: &PeerInfo) -> Result<(), NetworkError>;

    /// Disconnect from a peer
    async fn disconnect(&self, peer_id: &str) -> Result<(), NetworkError>;

    /// Send a message to a peer
    async fn send(&self, peer_id: &str, message: Vec<u8>) -> Result<(), NetworkError>;

    /// Send a message to all connected peers
    async fn broadcast(&self, message: Vec<u8>) -> Result<(), NetworkError>;

    /// Check if connected to a peer
    async fn is_connected(&self, peer_id: &str) -> bool;

    /// Get all connected peers
    async fn connected_peers(&self) -> Vec<PeerInfo>;
}

/// TCP-based transport implementation
pub struct TcpTransport {
    /// Local socket address to bind to
    local_addr: SocketAddr,

    /// Callback for received messages
    message_handler: Arc<dyn Fn(Vec<u8>, String) -> Result<(), NetworkError> + Send + Sync>,

    /// Connected peers
    peers: Arc<Mutex<HashMap<String, Arc<Peer>>>>,
}

impl TcpTransport {
    /// Create a new TCP transport
    pub fn new<F>(addr: SocketAddr, message_handler: F) -> Self
    where
        F: Fn(Vec<u8>, String) -> Result<(), NetworkError> + Send + Sync + 'static,
    {
        TcpTransport {
            local_addr: addr,
            message_handler: Arc::new(message_handler),
            peers: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn start(&self) -> Result<(), NetworkError> {
        let listener = TcpListener::bind(self.local_addr).await
            .map_err(|e| NetworkError::IoError(e))?;

        info!("TCP transport listening on {}", self.local_addr);

        let peers = self.peers.clone();
        let message_handler = self.message_handler.clone();

        // Spawn a task to accept incoming connections
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("Accepted connection from {}", addr);

                        // Clone the handler and peers for the connection task
                        let message_handler = message_handler.clone();
                        let peers = peers.clone();

                        // Handle the connection
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, addr, message_handler, peers).await {
                                error!("Error handling connection from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Error accepting connection: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    async fn connect(&self, peer_info: &PeerInfo) -> Result<(), NetworkError> {
        let addr = peer_info.socket_addr()?;

        // Check if already connected
        {
            let peers = self.peers.lock().await;
            if peers.contains_key(&peer_info.id) {
                return Ok(());
            }
        }

        // Connect to the peer
        debug!("Connecting to peer {} at {}", peer_info.id, addr);
        let stream = TcpStream::connect(addr).await
            .map_err(|e| NetworkError::ConnectionError(format!("Failed to connect to {}: {}", addr, e)))?;

        // Set up channels for sending messages to this peer
        let (send_tx, mut send_rx) = mpsc::channel(100);

        // Create peer
        let peer = Arc::new(Peer::new(peer_info.clone(), send_tx));
        peer.set_connected(true);
        peer.update_last_seen();

        // Add to peers map
        {
            let mut peers = self.peers.lock().await;
            peers.insert(peer_info.id.clone(), peer.clone());
        }

        // Split the TCP stream
        let (mut reader, mut writer) = stream.into_split();

        // Clone for the reader task
        let message_handler = self.message_handler.clone();
        let peer_id = peer_info.id.clone();
        let peers_reader = self.peers.clone();

        // Spawn reader task
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4]; // Length prefix buffer

            loop {
                // Read message length
                match reader.read_exact(&mut buffer).await {
                    Ok(0) => {
                        // Connection closed
                        debug!("Connection closed by peer {}", peer_id);
                        break;
                    }
                    Ok(_) => {
                        // Parse message length
                        let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

                        // Sanity check message size
                        if len > MAX_MESSAGE_SIZE {
                            error!("Message too large from peer {}: {} bytes", peer_id, len);
                            break;
                        }

                        // Read message data
                        let mut message = vec![0u8; len];
                        match reader.read_exact(&mut message).await {
                            Ok(_) => {
                                // Update last seen
                                {
                                    let peers = peers_reader.lock().await;
                                    if let Some(p) = peers.get(&peer_id) {
                                        p.update_last_seen();
                                    }
                                }

                                // Process message
                                if let Err(e) = message_handler(message, peer_id.clone()) {
                                    error!("Error handling message from peer {}: {}", peer_id, e);
                                }
                            }
                            Err(e) => {
                                error!("Error reading message from peer {}: {}", peer_id, e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error reading message length from peer {}: {}", peer_id, e);
                        break;
                    }
                }
            }

            // Remove peer on disconnect
            {
                let mut peers = peers_reader.lock().await;
                if let Some(p) = peers.remove(&peer_id) {
                    p.set_connected(false);
                }
            }

            debug!("Reader task for peer {} terminated", peer_id);
        });

        // Clone for the writer task
        let peer_id = peer_info.id.clone();
        let peers_writer = self.peers.clone();

        // Spawn writer task
        tokio::spawn(async move {
            while let Some(message) = send_rx.recv().await {
                // Write message length
                let len = message.len() as u32;
                let len_bytes = len.to_be_bytes();

                if let Err(e) = writer.write_all(&len_bytes).await {
                    error!("Error writing message length to peer {}: {}", peer_id, e);
                    break;
                }

                // Write message data
                if let Err(e) = writer.write_all(&message).await {
                    error!("Error writing message to peer {}: {}", peer_id, e);
                    break;
                }

                // Flush to ensure message is sent immediately
                if let Err(e) = writer.flush().await {
                    error!("Error flushing message to peer {}: {}", peer_id, e);
                    break;
                }
            }

            // Remove peer on disconnect
            {
                let mut peers = peers_writer.lock().await;
                if let Some(p) = peers.remove(&peer_id) {
                    p.set_connected(false);
                }
            }

            debug!("Writer task for peer {} terminated", peer_id);
        });

        info!("Connected to peer {}", peer_info);
        Ok(())
    }

    async fn disconnect(&self, peer_id: &str) -> Result<(), NetworkError> {
        let mut peers = self.peers.lock().await;

        if let Some(peer) = peers.remove(peer_id) {
            peer.set_connected(false);
            info!("Disconnected from peer {}", peer_id);
            Ok(())
        } else {
            Err(NetworkError::PeerNotFound(format!("Peer {} not found", peer_id)))
        }
    }

    async fn send(&self, peer_id: &str, message: Vec<u8>) -> Result<(), NetworkError> {
        let peers = self.peers.lock().await;

        if let Some(peer) = peers.get(peer_id) {
            peer.send_message(message).await
        } else {
            Err(NetworkError::PeerNotFound(format!("Peer {} not found", peer_id)))
        }
    }

    async fn broadcast(&self, message: Vec<u8>) -> Result<(), NetworkError> {
        let peers = self.peers.lock().await;

        let mut send_errors = Vec::new();

        for (peer_id, peer) in peers.iter() {
            if let Err(e) = peer.send_message(message.clone()).await {
                send_errors.push((peer_id.clone(), e));
            }
        }

        if send_errors.is_empty() {
            Ok(())
        } else {
            let error_str = send_errors
                .iter()
                .map(|(id, e)| format!("{}:{}", id, e))
                .collect::<Vec<_>>()
                .join(", ");

            Err(NetworkError::SendError(format!(
                "Failed to send to some peers: {}", error_str
            )))
        }
    }

    async fn is_connected(&self, peer_id: &str) -> bool {
        let peers = self.peers.lock().await;
        peers.get(peer_id).map_or(false, |p| p.is_connected())
    }

    async fn connected_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.lock().await;
        peers.values()
            .filter(|p| p.is_connected())
            .map(|p| p.info.clone())
            .collect()
    }
}

/// Handle an incoming connection
/// Handle an incoming connection
async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    message_handler: Arc<dyn Fn(Vec<u8>, String) -> Result<(), NetworkError> + Send + Sync>,
    peers: Arc<Mutex<HashMap<String, Arc<Peer>>>>,
) -> Result<(), NetworkError> {
    // For incoming connections, we don't know the peer ID yet
    // We'll use the socket address as a temporary ID
    let temp_peer_id = format!("unknown:{}", addr);

    let (mut reader, _) = stream.into_split();

    // Read initial message to identify peer
    let mut len_buffer = vec![0u8; 4];
    match reader.read_exact(&mut len_buffer).await {
        Ok(_) => {
            // Parse message length
            let len = u32::from_be_bytes([len_buffer[0], len_buffer[1], len_buffer[2], len_buffer[3]]) as usize;

            // Sanity check message size
            if len > MAX_MESSAGE_SIZE {
                return Err(NetworkError::InvalidMessage(format!(
                    "Initial message too large from {}: {} bytes", addr, len
                )));
            }

            // Read initial message data
            let mut message_data = vec![0u8; len];
            match reader.read_exact(&mut message_data).await {
                Ok(_) => {
                    // Process the initial message to identify the peer
                    // This should be a peer announcement message with peer info
                    match message_handler(message_data, temp_peer_id.clone()) {
                        Ok(_) => {
                            // The message handler will validate the peer and add it to the peers map
                            // For now, just return ok
                            Ok(())
                        }
                        Err(e) => {
                            error!("Error handling initial message from {}: {}", addr, e);
                            Err(e)
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading initial message from {}: {}", addr, e);
                    Err(NetworkError::ReceiveError(format!(
                        "Failed to read initial message: {}", e
                    )))
                }
            }
        }
        Err(e) => {
            error!("Error reading message length from {}: {}", addr, e);
            Err(NetworkError::ReceiveError(format!(
                "Failed to read message length: {}", e
            )))
        }
    }
}

/// UDP-based transport implementation for discovery
pub struct UdpTransport {
    /// Local socket address to bind to
    local_addr: SocketAddr,

    /// Callback for received discovery messages
    discovery_handler: Arc<dyn Fn(Vec<u8>, SocketAddr) -> Result<(), NetworkError> + Send + Sync>,
}

impl UdpTransport {
    /// Create a new UDP transport for discovery
    pub fn new<F>(addr: SocketAddr, discovery_handler: F) -> Self
    where
        F: Fn(Vec<u8>, SocketAddr) -> Result<(), NetworkError> + Send + Sync + 'static,
    {
        UdpTransport {
            local_addr: addr,
            discovery_handler: Arc::new(discovery_handler),
        }
    }

    /// Start the UDP transport for discovery
    pub async fn start(&self) -> Result<(), NetworkError> {
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind(self.local_addr).await
            .map_err(|e| NetworkError::IoError(e))?;

        info!("UDP discovery transport listening on {}", self.local_addr);

        // Allow broadcasting
        socket.set_broadcast(true)
            .map_err(|e| NetworkError::IoError(e))?;

        let discovery_handler = self.discovery_handler.clone();

        // Spawn a task to handle incoming discovery messages
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096]; // Fixed buffer for UDP

            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        if len > 0 {
                            // Process discovery message
                            let message = buf[..len].to_vec();
                            if let Err(e) = discovery_handler(message, addr) {
                                error!("Error handling discovery message from {}: {}", addr, e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error receiving discovery message: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Send a discovery message to a specific address
    pub async fn send_to(&self, message: Vec<u8>, addr: SocketAddr) -> Result<(), NetworkError> {
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| NetworkError::IoError(e))?;

        socket.set_broadcast(true)
            .map_err(|e| NetworkError::IoError(e))?;

        socket.send_to(&message, addr).await
            .map_err(|e| NetworkError::SendError(format!("Failed to send discovery message: {}", e)))?;

        Ok(())
    }

    /// Broadcast a discovery message on the local network
    pub async fn broadcast(&self, message: Vec<u8>, port: u16) -> Result<(), NetworkError> {
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| NetworkError::IoError(e))?;

        socket.set_broadcast(true)
            .map_err(|e| NetworkError::IoError(e))?;

        // Broadcast to the local network
        let broadcast_addr = SocketAddr::new("255.255.255.255".parse().unwrap(), port);

        socket.send_to(&message, broadcast_addr).await
            .map_err(|e| NetworkError::SendError(format!("Failed to broadcast discovery message: {}", e)))?;

        Ok(())
    }
}