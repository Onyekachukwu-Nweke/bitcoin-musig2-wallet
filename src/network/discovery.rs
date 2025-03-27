use bincode::{config::standard, decode_from_slice, encode_to_vec, Decode, Encode};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time;

use crate::network::error::NetworkError;
use crate::network::peer::PeerInfo;
use crate::network::transport::UdpTransport;

#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub enum DiscoveryMessage {
    Ping { sender: PeerInfo },
    Pong { sender: PeerInfo },
}

pub struct PeerDiscovery {
    transport: Arc<UdpTransport>,
    local_peer: PeerInfo,
    discovery_port: u16,
    on_peer_discovered: Arc<dyn Fn(PeerInfo) -> Result<(), NetworkError> + Send + Sync>,
}

impl PeerDiscovery {
    pub fn new<F>(local_peer: PeerInfo, discovery_port: u16, on_peer_discovered: F) -> Self
    where
        F: Fn(PeerInfo) -> Result<(), NetworkError> + Send + Sync + 'static,
    {
        let addr = SocketAddr::new("0.0.0.0".parse().unwrap(), discovery_port);
        let on_peer_discovered = Arc::new(on_peer_discovered);
        let local_peer_clone = local_peer.clone();

        // Clone on_peer_discovered for the closure
        let on_peer_discovered_clone = on_peer_discovered.clone();

        let message_handler = move |data: Vec<u8>, from_addr: SocketAddr| {
            let local_peer = local_peer_clone.clone();
            let discovery_cb = on_peer_discovered_clone.clone();
            let peer_addr = SocketAddr::new(from_addr.ip(), discovery_port);

            match decode_from_slice::<DiscoveryMessage, _>(&data, standard()) {
                Ok((message, _)) => match message {
                    DiscoveryMessage::Ping { sender } => {
                        debug!("Received discovery ping from {}", sender.id);

                        let transport = UdpTransport::new(
                            SocketAddr::new("0.0.0.0".parse().unwrap(), 0),
                            |_, _| Ok(()),
                        );

                        let local_peer_response = local_peer.clone();
                        tokio::spawn(async move {
                            let pong = DiscoveryMessage::Pong {
                                sender: local_peer_response,
                            };

                            let pong_data = encode_to_vec(&pong, standard()).map_err(|e| {
                                NetworkError::SerializationError(format!(
                                    "Failed to serialize discovery pong: {}",
                                    e
                                ))
                            })?;

                            transport.send_to(pong_data, peer_addr).await?;
                            Ok::<_, NetworkError>(())
                        });

                        discovery_cb(sender)
                    }
                    DiscoveryMessage::Pong { sender } => {
                        debug!("Received discovery pong from {}", sender.id);
                        discovery_cb(sender)
                    }
                },
                Err(e) => {
                    error!("Failed to deserialize discovery message: {}", e);
                    Err(NetworkError::SerializationError(format!(
                        "Failed to deserialize discovery message: {}",
                        e
                    )))
                }
            }
        };

        let transport = Arc::new(UdpTransport::new(addr, message_handler));

        PeerDiscovery {
            transport,
            local_peer,
            discovery_port,
            on_peer_discovered, // Use the original Arc here
        }
    }

    pub async fn start(&self) -> Result<(), NetworkError> {
        self.transport.start().await?;
        info!(
            "Peer discovery service started on port {}",
            self.discovery_port
        );
        Ok(())
    }

    pub async fn broadcast_discovery(&self) -> Result<(), NetworkError> {
        debug!("Broadcasting discovery ping");

        let ping = DiscoveryMessage::Ping {
            sender: self.local_peer.clone(),
        };

        let ping_data = encode_to_vec(&ping, standard()).map_err(|e| {
            NetworkError::SerializationError(format!("Failed to serialize discovery ping: {}", e))
        })?;

        self.transport
            .broadcast(ping_data, self.discovery_port)
            .await?;

        Ok(())
    }

    pub async fn start_periodic_broadcast(&self, interval: Duration) -> Result<(), NetworkError> {
        let discovery = self.clone();

        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);

            loop {
                interval_timer.tick().await;

                if let Err(e) = discovery.broadcast_discovery().await {
                    error!("Error broadcasting discovery: {}", e);
                }
            }
        });

        Ok(())
    }
}

impl Clone for PeerDiscovery {
    fn clone(&self) -> Self {
        PeerDiscovery {
            transport: self.transport.clone(),
            local_peer: self.local_peer.clone(),
            discovery_port: self.discovery_port,
            on_peer_discovered: self.on_peer_discovered.clone(),
        }
    }
}