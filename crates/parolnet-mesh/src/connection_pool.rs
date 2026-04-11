//! Connection pool for managing active peer connections and scores.

use crate::peer_table::PeerScore;
use parolnet_protocol::address::PeerId;
use parolnet_transport::Connection;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Manages active peer connections and their reputation scores.
pub struct ConnectionPool {
    connections: RwLock<HashMap<PeerId, Arc<dyn Connection>>>,
    scores: RwLock<HashMap<PeerId, PeerScore>>,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            scores: RwLock::new(HashMap::new()),
        }
    }

    /// Add a peer connection and initialize its score.
    pub async fn add_peer(&self, peer_id: PeerId, conn: Arc<dyn Connection>) {
        self.connections.write().await.insert(peer_id, conn);
        self.scores
            .write()
            .await
            .entry(peer_id)
            .or_insert_with(|| PeerScore::new(peer_id));
    }

    /// Remove a peer's connection and score.
    pub async fn remove_peer(&self, peer_id: &PeerId) {
        self.connections.write().await.remove(peer_id);
        self.scores.write().await.remove(peer_id);
    }

    /// Get a connection to a specific peer.
    pub async fn get_connection(&self, peer_id: &PeerId) -> Option<Arc<dyn Connection>> {
        self.connections.read().await.get(peer_id).cloned()
    }

    /// Get the current score for a peer.
    pub async fn get_score(&self, peer_id: &PeerId) -> Option<PeerScore> {
        self.scores.read().await.get(peer_id).cloned()
    }

    /// Update a peer's score using the provided closure.
    pub async fn update_score<F: FnOnce(&mut PeerScore)>(&self, peer_id: &PeerId, f: F) {
        if let Some(score) = self.scores.write().await.get_mut(peer_id) {
            f(score);
        }
    }

    /// Randomly select up to `count` peers, excluding the given list and banned peers.
    pub async fn select_fanout_peers(
        &self,
        exclude: &[PeerId],
        count: usize,
    ) -> Vec<(PeerId, Arc<dyn Connection>)> {
        let connections = self.connections.read().await;
        let scores = self.scores.read().await;

        let mut candidates: Vec<(PeerId, Arc<dyn Connection>)> = connections
            .iter()
            .filter(|(pid, _)| {
                !exclude.contains(pid) && scores.get(pid).map(|s| !s.is_banned()).unwrap_or(true)
            })
            .map(|(pid, conn)| (*pid, conn.clone()))
            .collect();

        let mut rng = rand::thread_rng();
        candidates.shuffle(&mut rng);
        candidates.truncate(count);
        candidates
    }

    /// Number of currently connected peers.
    pub async fn peer_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// List all connected peer IDs.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.connections.read().await.keys().copied().collect()
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
        _sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockConnection {
        fn new() -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    _sent: sent.clone(),
                },
                sent,
            )
        }
    }

    #[async_trait]
    impl Connection for MockConnection {
        async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
            self._sent.lock().await.push(data.to_vec());
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
        let pool = ConnectionPool::new();
        let peer_id = PeerId([1u8; 32]);
        let (conn, _sent) = MockConnection::new();

        pool.add_peer(peer_id, Arc::new(conn)).await;
        assert_eq!(pool.peer_count().await, 1);
        assert!(pool.get_connection(&peer_id).await.is_some());
        assert!(pool.get_score(&peer_id).await.is_some());

        pool.remove_peer(&peer_id).await;
        assert_eq!(pool.peer_count().await, 0);
        assert!(pool.get_connection(&peer_id).await.is_none());
    }

    #[tokio::test]
    async fn test_select_fanout_excludes_banned() {
        let pool = ConnectionPool::new();

        let good_peer = PeerId([1u8; 32]);
        let banned_peer = PeerId([2u8; 32]);
        let excluded_peer = PeerId([3u8; 32]);

        let (conn1, _) = MockConnection::new();
        let (conn2, _) = MockConnection::new();
        let (conn3, _) = MockConnection::new();

        pool.add_peer(good_peer, Arc::new(conn1)).await;
        pool.add_peer(banned_peer, Arc::new(conn2)).await;
        pool.add_peer(excluded_peer, Arc::new(conn3)).await;

        // Ban the second peer by reducing score below 0
        pool.update_score(&banned_peer, |s| {
            for _ in 0..20 {
                s.penalize_invalid();
            }
        })
        .await;

        let selected = pool.select_fanout_peers(&[excluded_peer], 10).await;

        let selected_ids: Vec<PeerId> = selected.iter().map(|(pid, _)| *pid).collect();
        assert!(selected_ids.contains(&good_peer));
        assert!(!selected_ids.contains(&banned_peer));
        assert!(!selected_ids.contains(&excluded_peer));
    }

    #[tokio::test]
    async fn test_connected_peers() {
        let pool = ConnectionPool::new();
        let p1 = PeerId([1u8; 32]);
        let p2 = PeerId([2u8; 32]);

        let (c1, _) = MockConnection::new();
        let (c2, _) = MockConnection::new();

        pool.add_peer(p1, Arc::new(c1)).await;
        pool.add_peer(p2, Arc::new(c2)).await;

        let peers = pool.connected_peers().await;
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&p1));
        assert!(peers.contains(&p2));
    }

    #[tokio::test]
    async fn test_update_score() {
        let pool = ConnectionPool::new();
        let peer_id = PeerId([1u8; 32]);
        let (conn, _) = MockConnection::new();

        pool.add_peer(peer_id, Arc::new(conn)).await;

        pool.update_score(&peer_id, |s| s.reward()).await;
        let score = pool.get_score(&peer_id).await.unwrap();
        assert_eq!(score.score, 101);
    }
}
