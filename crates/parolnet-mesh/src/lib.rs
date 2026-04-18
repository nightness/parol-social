//! # parolnet-mesh
//!
//! Mesh networking and gossip protocol for ParolNet (PNP-005).
//!
//! Provides:
//! - Peer discovery (mDNS, future: BLE)
//! - Gossip protocol for epidemic message propagation
//! - Store-and-forward for delay-tolerant networking
//! - Set reconciliation for reconnection sync
//! - Peer scoring and anti-spam

pub mod connection_pool;
pub mod discovery;
pub mod error;
pub mod gossip;
pub mod peer_manager;
pub mod peer_table;
pub mod store_forward;
pub mod sync;

pub use error::MeshError;

use async_trait::async_trait;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::envelope::Envelope;
use std::time::Duration;

/// Discovers nearby peers on local networks or via proximity.
#[async_trait]
pub trait PeerDiscovery: Send + Sync {
    async fn discover(&self) -> Result<Vec<DiscoveredPeer>, MeshError>;
    async fn announce(&self, identity: &PeerId) -> Result<(), MeshError>;
}

/// A peer discovered via mDNS or other local mechanism.
#[derive(Clone, Debug)]
pub struct DiscoveredPeer {
    pub peer_id: PeerId,
    pub addr: std::net::SocketAddr,
}

/// Store-and-forward message buffer for delay-tolerant networking.
#[async_trait]
pub trait MessageStore: Send + Sync {
    async fn store(&self, envelope: &Envelope, ttl: Duration) -> Result<(), MeshError>;
    async fn retrieve(&self, recipient: &PeerId) -> Result<Vec<Envelope>, MeshError>;
    async fn expire(&self) -> Result<usize, MeshError>;
}

/// Gossip protocol for propagating messages through the mesh (PNP-005).
#[async_trait]
pub trait GossipProtocol: Send + Sync {
    async fn broadcast(&self, envelope: Envelope) -> Result<(), MeshError>;
    async fn on_receive(&self, envelope: Envelope) -> Result<GossipAction, MeshError>;
}

/// Action to take after receiving a gossip message.
#[derive(Debug)]
pub enum GossipAction {
    /// Relay to these specific peers after applying the specified jitter delay.
    Forward { peers: Vec<PeerId>, jitter_ms: u64 },
    /// Message is for us — deliver to application layer.
    Deliver,
    /// Already seen or expired — drop silently.
    Drop,
    /// Source peer exceeded the per-peer rate limit.
    RateLimited,
}
