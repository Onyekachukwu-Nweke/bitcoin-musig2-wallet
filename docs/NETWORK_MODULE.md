# MuSig2 Wallet Network Module

The network module provides communication capabilities between distributed wallet nodes running on different devices. It handles secure message exchange, peer discovery, and connection management for the MuSig2 wallet implementation.

## Architecture Overview

The network module consists of several components that work together to enable communication between wallet nodes:

1. **NetworkService**: The main entry point for the network functionality.
2. **Transport**: Handles low-level communication between peers.
3. **Message**: Defines the structure and types of messages exchanged.
4. **Peer**: Represents and manages connections to other wallet nodes.
5. **Discovery**: Provides peer discovery on local networks.
6. **MessageHandler**: Processes incoming messages and routes them to appropriate handlers.

## Key Components

### NetworkService

The `NetworkService` is the main entry point for the network module. It manages connections to peers and provides high-level methods for sending and receiving messages.

```rust
// Create a network service
let network = NetworkService::new(
    "alice".to_string(),       // Local peer ID
    "Alice's Node".to_string(), // Local peer name
    "127.0.0.1".to_string(),   // Local host
    8001,                      // Local port
);

// Start the network service
network.start(|message| {
    // Handle incoming messages
    println!("Received message: {:?}", message);
    Ok(())
}).await?;
```

### Message

The `Message` struct defines the structure of messages exchanged between peers. Each message includes authentication information and is signed to ensure integrity and authenticity.

```rust
// Message types
pub enum MessageType {
    Ping,
    Pong,
    TransactionProposal,
    PublicNonce,
    PartialSignature,
    TransactionComplete,
    Error,
    Discovery,
    PeerAnnouncement,
}

// Create a message
let mut message = Message::new(
    MessageType::TransactionProposal,
    "alice",
    payload_bytes,
);

// Sign the message
message.sign(&keypair)?;

// Send the message
network.broadcast_message(message).await?;
```

### Transport

The `Transport` trait defines methods for sending and receiving data between peers. The module includes a TCP-based implementation and a UDP-based implementation for discovery.

```rust
// Transport trait
#[async_trait]
pub trait Transport: Send + Sync {
    async fn start(&self) -> Result<(), NetworkError>;
    async fn connect(&self, peer_info: &PeerInfo) -> Result<(), NetworkError>;
    async fn disconnect(&self, peer_id: &str) -> Result<(), NetworkError>;
    async fn send(&self, peer_id: &str, message: Vec<u8>) -> Result<(), NetworkError>;
    async fn broadcast(&self, message: Vec<u8>) -> Result<(), NetworkError>;
    async fn is_connected(&self, peer_id: &str) -> bool;
    async fn connected_peers(&self) -> Vec<PeerInfo>;
}
```

### Peer

The `Peer` struct represents a connection to another wallet node. It includes information about the peer and methods for sending messages.

```rust
// Peer information
pub struct PeerInfo {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub pubkey_hex: String,
}

// Peer connection state
pub enum PeerState {
    Disconnected,
    Connecting,
    Connected,
    Failed,
}
```

### Discovery

The `PeerDiscovery` service provides automatic discovery of peers on local networks using UDP broadcasts.

```rust
// Create a peer discovery service
let discovery = PeerDiscovery::new(
    local_peer_info,
    8002, // Discovery port
    |discovered_peer| {
        println!("Discovered peer: {}", discovered_peer);
        Ok(())
    },
);

// Start the discovery service
discovery.start().await?;

// Broadcast a discovery message
discovery.broadcast_discovery().await?;

// Start periodic discovery broadcasts
discovery.start_periodic_broadcast(Duration::from_secs(60)).await?;
```

## Network Communication Flow

The network module uses the following communication flow:

1. **Initialization**: Each node creates a `NetworkService` with a unique ID and keypair.
2. **Discovery**: Nodes discover each other using UDP broadcasts on the local network.
3. **Connection**: Once discovered, nodes establish TCP connections to each other.
4. **Authentication**: Nodes verify each other's identities using public key cryptography.
5. **Message Exchange**: Nodes exchange signed messages for the MuSig2 signing process.
6. **Disconnection**: Nodes can disconnect gracefully when communication is complete.

## Security Considerations

The network module includes several security features:

1. **Message Authentication**: All messages are signed using Schnorr signatures to ensure authenticity and integrity.
2. **Peer Verification**: Peers are verified using their public keys to prevent impersonation.
3. **Transport Security**: The transport layer ensures that messages are delivered securely.
4. **Error Handling**: Comprehensive error handling prevents security vulnerabilities.

## Example Usage

Here's a complete example of using the network module to create a simple chat application:

```rust
// Create a network service
let network = NetworkService::new(
    "alice".to_string(),
    "Alice's Node".to_string(),
    "127.0.0.1".to_string(),
    8001,
);

// Start the network service
network.start(|message| {
    // Handle incoming chat messages
    if message.message_type == MessageType::Error { // Using Error type for chat
        let chat_msg: ChatMessage = bincode::deserialize(&message.payload)?;
        println!("{}: {}", chat_msg.from, chat_msg.content);
    }
    Ok(())
}).await?;

// Connect to a known peer
let peer_info = PeerInfo {
    id: "bob".to_string(),
    name: "Bob's Node".to_string(),
    host: "127.0.0.1".to_string(),
    port: 8002,
    pubkey_hex: "..." // Bob's public key
};
network.connect_to_peer(&peer_info).await?;

// Send a chat message
let chat_msg = ChatMessage {
    from: "alice".to_string(),
    content: "Hello, Bob!".to_string(),
};
let payload = bincode::serialize(&chat_msg)?;
let message = Message::new(MessageType::Error, "alice", payload);
network.send_message_to("bob", message).await?;
```

## Integration with Signing Module

The network module integrates with the signing module to enable distributed MuSig2 signing:

1. **Transaction Proposal**: One node creates a transaction proposal and sends it to all participants.
2. **Public Nonces**: Each participant generates a nonce and broadcasts the public part.
3. **Partial Signatures**: After receiving all nonces, each participant creates a partial signature and broadcasts it.
4. **Transaction Completion**: One node collects all partial signatures, combines them, and broadcasts the finalized transaction.

```rust
// Message handler for signing-related messages
network.start(|message| {
    match message.message_type {
        MessageType::TransactionProposal => {
            // Handle transaction proposal
            let proposal: TransactionProposal = bincode::deserialize(&message.payload)?;
            signing_coordinator.handle_transaction_proposal(proposal).await?;
        },
        MessageType::PublicNonce => {
            // Handle public nonce
            let nonce_data: PublicNonceData = bincode::deserialize(&message.payload)?;
            signing_coordinator.handle_public_nonce(nonce_data).await?;
        },
        MessageType::PartialSignature => {
            // Handle partial signature
            let sig_data: PartialSignatureData = bincode::deserialize(&message.payload)?;
            signing_coordinator.handle_partial_signature(sig_data).await?;
        },
        MessageType::TransactionComplete => {
            // Handle completed transaction
            let completion: SessionCompletionData = bincode::deserialize(&message.payload)?;
            signing_coordinator.handle_session_completion(completion).await?;
        },
        _ => {
            // Handle other message types
        }
    }
    Ok(())
}).await?;
```

## Error Handling

The network module includes comprehensive error handling through the `NetworkError` enum:

```rust
pub enum NetworkError {
    IoError(io::Error),
    SerializationError(String),
    ConnectionError(String),
    SendError(String),
    ReceiveError(String),
    InvalidMessage(String),
    AuthenticationError(String),
    PeerNotFound(String),
    TransportError(String),
    Timeout(String),
    Other(String),
}
```

## Future Improvements

Potential future improvements to the network module include:

1. **TLS Support**: Add TLS encryption for all communications.
2. **NAT Traversal**: Implement techniques for connecting peers across NATs and firewalls.
3. **Relay Servers**: Add support for relay servers to facilitate communication when direct connections are not possible.
4. **Bandwidth Management**: Implement bandwidth throttling and prioritization for better performance.
5. **Connection Pooling**: Improve connection management for better scalability.
6. **Peer Reputation**: Add a reputation system for peers to improve reliability.

## Conclusion

The network module provides a robust foundation for distributed communication between MuSig2 wallet nodes. It ensures secure, reliable message exchange for collaborative transaction signing while maintaining the security principles essential for cryptocurrency wallets.