//! PeerManager — orchestrates connections, gossip, and store-and-forward.

use crate::connection_pool::ConnectionPool;
use crate::gossip::StandardGossip;
use crate::store_forward::InMemoryStore;
use crate::{MeshError, MessageStore};
use parolnet_protocol::address::PeerId;
use parolnet_protocol::gossip::GossipEnvelope;
use parolnet_transport::Connection;
use std::sync::Arc;
use tracing::{info, warn};

/// Orchestrates mesh networking: connections, gossip, and store-and-forward.
pub struct PeerManager {
    our_peer_id: PeerId,
    pool: Arc<ConnectionPool>,
    gossip: StandardGossip,
    store: InMemoryStore,
}

impl PeerManager {
    /// Create a new PeerManager.
    pub fn new(our_peer_id: PeerId, signing_key: ed25519_dalek::SigningKey) -> Self {
        let pool = Arc::new(ConnectionPool::new());
        let gossip = StandardGossip::new(our_peer_id, signing_key, pool.clone());
        let store = InMemoryStore::new();
        Self {
            our_peer_id,
            pool,
            gossip,
            store,
        }
    }

    /// Add a peer connection. Delivers any stored messages for that peer.
    pub async fn add_peer(
        &self,
        peer_id: PeerId,
        conn: Arc<dyn Connection>,
    ) -> Result<(), MeshError> {
        self.pool.add_peer(peer_id, conn.clone()).await;
        info!(peer = %peer_id, "peer connected");

        // Deliver any stored messages for this peer
        let stored = self.store.retrieve(&peer_id).await?;
        for envelope in &stored {
            // Re-serialize header + payload + mac for delivery
            let mut buf = Vec::new();
            ciborium::into_writer(&envelope.header, &mut buf)
                .map_err(|e| MeshError::StorageError(format!("CBOR encode: {e}")))?;
            buf.extend_from_slice(&envelope.encrypted_payload);
            buf.extend_from_slice(&envelope.mac);

            if let Err(e) = conn.send(&buf).await {
                warn!(
                    peer = %peer_id,
                    error = %e,
                    "failed to deliver stored message"
                );
            }
        }

        if !stored.is_empty() {
            info!(
                peer = %peer_id,
                count = stored.len(),
                "delivered stored messages"
            );
        }

        Ok(())
    }

    /// Remove a peer from the pool.
    pub async fn remove_peer(&self, peer_id: &PeerId) {
        self.pool.remove_peer(peer_id).await;
        info!(peer = %peer_id, "peer disconnected");
    }

    /// Broadcast a gossip envelope to the mesh.
    pub async fn send_gossip(&self, gossip_env: GossipEnvelope) -> Result<(), MeshError> {
        let serialized = gossip_env
            .to_cbor()
            .map_err(|e| MeshError::ValidationFailed(format!("CBOR encode: {e}")))?;

        let excluded = vec![self.our_peer_id];
        let fanout = self
            .pool
            .select_fanout_peers(&excluded, crate::gossip::DEFAULT_FANOUT)
            .await;

        for (pid, conn) in &fanout {
            if let Err(e) = conn.send(&serialized).await {
                warn!(peer = %pid, error = %e, "failed to send gossip");
            }
        }

        Ok(())
    }

    /// Handle incoming gossip data. Returns the payload bytes if the message is for us.
    pub async fn handle_incoming(&self, data: &[u8]) -> Result<Option<Vec<u8>>, MeshError> {
        match self.gossip.process_gossip(data).await {
            Ok(crate::GossipAction::Deliver) => {
                // Decode the GossipEnvelope to get the inner payload
                let gossip_env = GossipEnvelope::from_cbor(data)
                    .map_err(|e| MeshError::ValidationFailed(format!("CBOR decode: {e}")))?;
                Ok(Some(gossip_env.payload))
            }
            Ok(crate::GossipAction::Forward(_)) => Ok(None),
            Ok(crate::GossipAction::Drop) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get a reference to the connection pool.
    pub fn pool(&self) -> &Arc<ConnectionPool> {
        &self.pool
    }

    /// Number of connected peers.
    pub async fn peer_count(&self) -> usize {
        self.pool.peer_count().await
    }

    /// Run periodic maintenance: expire stored messages, rotate dedup filter.
    pub async fn run_maintenance(&self) -> Result<(), MeshError> {
        let expired = self.store.expire().await?;
        if expired > 0 {
            info!(count = expired, "expired stored messages");
        }

        self.gossip.dedup.rotate();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use parolnet_transport::TransportError;
    use std::net::SocketAddr;
    use tokio::sync::Mutex;

    struct MockConnection {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockConnection {
        fn new() -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (Self { sent: sent.clone() }, sent)
        }
    }

    #[async_trait]
    impl Connection for MockConnection {
        async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
            self.sent.lock().await.push(data.to_vec());
            Ok(())
        }
        async fn recv(&self) -> Result<Vec<u8>, TransportError> {
            Err(TransportError::ConnectionClosed)
        }
        async fn close(&self) -> Result<(), TransportError> {
            Ok(())
        }
        fn peer_addr(&self) -> Option<SocketAddr> {
            None
        }
    }

    #[tokio::test]
    async fn test_add_remove_peer() {
        let mgr = PeerManager::new(
            PeerId([0xAA; 32]),
            ed25519_dalek::SigningKey::from_bytes(&[0xAA; 32]),
        );
        let peer_id = PeerId([0xBB; 32]);
        let (conn, _sent) = MockConnection::new();

        mgr.add_peer(peer_id, Arc::new(conn)).await.unwrap();
        assert_eq!(mgr.peer_count().await, 1);

        mgr.remove_peer(&peer_id).await;
        assert_eq!(mgr.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_run_maintenance() {
        let mgr = PeerManager::new(
            PeerId([0xAA; 32]),
            ed25519_dalek::SigningKey::from_bytes(&[0xAA; 32]),
        );
        // Should not panic with empty state
        mgr.run_maintenance().await.unwrap();
    }
}
