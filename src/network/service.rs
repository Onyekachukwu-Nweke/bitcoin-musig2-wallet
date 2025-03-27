use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::Mutex;
use async_trait::async_trait;
use bincode::{decode_from_slice, encode_to_vec};
use bincode::config::standard;
use log::{info, debug, error, warn};
use secp256k1_zkp::{Keypair, XOnlyPublicKey, Secp256k1};
use futures::future::join_all;

use crate::network::error::NetworkError;
use crate::network::peer::{Peer, PeerInfo, PeerState};
use crate::network::transport::{Transport, TcpTransport};
use crate::network::discovery::{PeerDiscovery, DiscoveryMessage};
use crate::network::message::{Message, MessageType};
use crate::network::message_handler::MessageHandler;

/// The default network service implementation
pub struct NetworkService {
    /// Local peer ID
    pub local_id: String,
    /// Local peer name
    pub local_name: String,
    /// Local host (IP or hostname)
    pub local_host: String,
    /// Local port
    pub local_port: u16,
    /// Discovery port
    pub discovery_port: u16,
    /// Local keypair for authentication
    keypair: Arc<Mutex<Keypair>>,
    /// Transport layer
    transport: Arc<dyn Transport>,
    /// Peer discovery service
    discovery: Option<Arc<PeerDiscovery>>,
    /// Known peers
    peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    /// Message handler
    message_handler: Option<Arc<dyn Fn(Message) -> Result<(), NetworkError> + Send + Sync>>,
}

impl NetworkService {
    /// Create a new network service
    pub fn new(
        local_id: String,
        local_name: String,
        local_host: String,
        local_port: u16,
    ) -> Self {
        // Create a keypair
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());
        let local_host_clone = local_host.clone();

        NetworkService {
            local_id,
            local_name,
            local_host,
            local_port,
            discovery_port: local_port + 1, // Default discovery port is TCP port + 1
            keypair: Arc::new(Mutex::new(keypair)),
            transport: Arc::new(TcpTransport::new(
                SocketAddr::new(
                    local_host_clone.parse().unwrap_or_else(|_| "0.0.0.0".parse().unwrap()),
                    local_port,
                ),
                |data, from_peer| {
                    // This is just a placeholder, will be replaced in start()
                    Ok(())
                },
            )),
            discovery: None,
            peers: Arc::new(Mutex::new(HashMap::new())),
            message_handler: None,
        }
    }

    /// Start the network service
    pub async fn start<F>(&self, message_handler: F) -> Result<(), NetworkError>
    where
        F: Fn(Message) -> Result<(), NetworkError> + Send + Sync + 'static,
    {
        let message_handler = Arc::new(message_handler);
        let keypair = self.keypair.clone();
        let handler_clone = message_handler.clone();

        // Get the local peer's public key
        let pubkey = {
            let kp = keypair.lock().await;
            let (pubkey, _) = kp.x_only_public_key();
            pubkey
        };

        // Create local peer info
        let local_peer = PeerInfo::new(
            &self.local_id,
            &self.local_name,
            &self.local_host,
            self.local_port,
            &pubkey,
        );

        // Initialize the TCP transport with message handling
        let transport = Arc::new(TcpTransport::new(
            SocketAddr::new(
                self.local_host.parse().unwrap_or_else(|_| "0.0.0.0".parse().unwrap()),
                self.local_port,
            ),
            move |data, from_peer| {
                // Try to deserialize the message
                match decode_from_slice::<Message, _>(&data, standard()) {
                    Ok((mut message, _)) => {
                        // Verify the message signature
                        let sender_id = message.sender_id.clone();
                        let message_id = message.message_id.clone();

                        // Special handling for peer announcements to handle new peers
                        if message.message_type == MessageType::PeerAnnouncement {
                            // Handle peer announcement - this will be implemented in handle_peer_announcement
                            // For now, just pass it to the message handler
                            handler_clone(message)
                        } else {
                            // For regular messages, pass to the handler
                            handler_clone(message)
                        }
                    },
                    Err(e) => {
                        error!("Failed to deserialize message from {}: {}", from_peer, e);
                        Err(NetworkError::SerializationError(format!(
                            "Failed to deserialize message: {}", e
                        )))
                    }
                }
            },
        )) as Arc<dyn Transport>;

        // Start the transport
        transport.start().await?;

        // Initialize peer discovery if enabled
        let peers = self.peers.clone();
        let discovery = PeerDiscovery::new(
            local_peer,
            self.discovery_port,
            move |discovered_peer| {
                // Don't connect to ourselves
                if discovered_peer.id == self.local_id {
                    return Ok(());
                }

                // Add to known peers
                let mut peers_lock = futures::executor::block_on(async {
                    peers.lock().await
                });

                if !peers_lock.contains_key(&discovered_peer.id) {
                    debug!("Discovered new peer: {}", discovered_peer);
                    peers_lock.insert(discovered_peer.id.clone(), discovered_peer.clone());

                    // Attempt to connect to the peer
                    // This will be done asynchronously to avoid blocking
                    let transport_clone = transport.clone();
                    tokio::spawn(async move {
                        if let Err(e) = transport_clone.connect(&discovered_peer).await {
                            error!("Failed to connect to discovered peer {}: {}", discovered_peer.id, e);
                        }
                    });
                }

                Ok(())
            },
        );

        // Start peer discovery
        discovery.start().await?;

        // Start periodic peer discovery broadcasts
        discovery.start_periodic_broadcast(Duration::from_secs(60)).await?;

        info!("Network service started on {}:{}", self.local_host, self.local_port);
        info!("Discovery service started on port {}", self.discovery_port);

        Ok(())
    }

    /// Send a message to a specific peer
    pub async fn send_message_to(&self, peer_id: &str, mut message: Message) -> Result<(), NetworkError> {
        // Sign the message
        {
            let keypair = self.keypair.lock().await;
            message.sign(&keypair);
        }

        // Serialize the message
        let data = encode_to_vec(&message, standard())
            .map_err(|e| NetworkError::SerializationError(format!(
                "Failed to serialize message: {}", e
            )))?;

        // Send the message
        self.transport.send(peer_id, data).await
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast_message(&self, mut message: Message) -> Result<(), NetworkError> {
        // Sign the message
        {
            let keypair = self.keypair.lock().await;
            message.sign(&keypair);
        }

        // Serialize the message
        let data = encode_to_vec(&message, standard())
            .map_err(|e| NetworkError::SerializationError(format!(
                "Failed to serialize message: {}", e
            )))?;

        // Broadcast the message
        self.transport.broadcast(data).await
    }

    /// Connect to a peer
    pub async fn connect_to_peer(&self, peer_info: &PeerInfo) -> Result<(), NetworkError> {
        // Add to known peers
        {
            let mut peers = self.peers.lock().await;
            peers.insert(peer_info.id.clone(), peer_info.clone());
        }

        // Connect to the peer
        self.transport.connect(peer_info).await
    }

    /// Connect to multiple peers
    pub async fn connect_to_peers(&self, peer_infos: Vec<PeerInfo>) -> Result<(), NetworkError> {
        let mut results = Vec::new();

        for peer_info in peer_infos {
            results.push(self.connect_to_peer(&peer_info));
        }

        // Wait for all connections to complete
        let results = join_all(results).await;

        // Check for errors
        let errors: Vec<NetworkError> = results.into_iter()
            .filter_map(|r| r.err())
            .collect();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(NetworkError::ConnectionError(format!(
                "Failed to connect to some peers: {:?}", errors
            )))
        }
    }

    /// Disconnect from a peer
    pub async fn disconnect_from_peer(&self, peer_id: &str) -> Result<(), NetworkError> {
        // Remove from known peers
        {
            let mut peers = self.peers.lock().await;
            peers.remove(peer_id);
        }

        // Disconnect from the peer
        self.transport.disconnect(peer_id).await
    }

    /// Get all connected peers
    pub async fn get_connected_peers(&self) -> Vec<PeerInfo> {
        self.transport.connected_peers().await
    }

    /// Get all known peers (connected or not)
    pub async fn get_known_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.lock().await;
        peers.values().cloned().collect()
    }

    /// Check if connected to a peer
    pub async fn is_connected_to(&self, peer_id: &str) -> bool {
        self.transport.is_connected(peer_id).await
    }
}