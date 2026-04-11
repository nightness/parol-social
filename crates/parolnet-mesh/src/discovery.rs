//! Peer discovery via local network (PNP-005 Section 5.9).
//!
//! Implements simple UDP broadcast discovery on the local network.
//! Service: _parolnet._tcp.local with PeerId in TXT record.

use crate::{DiscoveredPeer, MeshError, PeerDiscovery};
use async_trait::async_trait;
use parolnet_protocol::address::PeerId;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Discovery port for ParolNet LAN discovery.
const DISCOVERY_PORT: u16 = 19532;

/// Magic bytes for discovery packets.
const MAGIC: &[u8; 8] = b"PAROLNET";

pub struct UdpDiscovery {
    our_peer_id: PeerId,
    listen_port: u16,
}

impl UdpDiscovery {
    pub fn new(our_peer_id: PeerId, listen_port: u16) -> Self {
        Self {
            our_peer_id,
            listen_port,
        }
    }
}

#[async_trait]
impl PeerDiscovery for UdpDiscovery {
    async fn discover(&self) -> Result<Vec<DiscoveredPeer>, MeshError> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| MeshError::DiscoveryFailed(format!("bind: {e}")))?;
        socket
            .set_broadcast(true)
            .map_err(|e| MeshError::DiscoveryFailed(format!("broadcast: {e}")))?;

        // Send discovery request
        let mut request = Vec::with_capacity(40);
        request.extend_from_slice(MAGIC);
        request.extend_from_slice(&self.our_peer_id.0);

        socket
            .send_to(&request, format!("255.255.255.255:{DISCOVERY_PORT}"))
            .await
            .map_err(|e| MeshError::DiscoveryFailed(format!("send: {e}")))?;

        // Collect responses with timeout
        let mut peers = Vec::new();
        let mut buf = [0u8; 128];

        let deadline = tokio::time::sleep(std::time::Duration::from_secs(2));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) if len >= 42 && &buf[..8] == MAGIC => {
                            let mut peer_id = [0u8; 32];
                            peer_id.copy_from_slice(&buf[8..40]);
                            let peer = PeerId(peer_id);
                            // Don't include ourselves
                            if peer != self.our_peer_id {
                                let service_port = u16::from_be_bytes([buf[40], buf[41]]);
                                let peer_addr = SocketAddr::new(addr.ip(), service_port);
                                peers.push(DiscoveredPeer { peer_id: peer, addr: peer_addr });
                            }
                        }
                        _ => {}
                    }
                }
                _ = &mut deadline => break,
            }
        }

        Ok(peers)
    }

    async fn announce(&self, _identity: &PeerId) -> Result<(), MeshError> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{DISCOVERY_PORT}"))
            .await
            .map_err(|e| MeshError::DiscoveryFailed(format!("bind announce: {e}")))?;
        socket
            .set_broadcast(true)
            .map_err(|e| MeshError::DiscoveryFailed(format!("broadcast: {e}")))?;

        // Listen for discovery requests and respond
        let mut buf = [0u8; 128];
        let timeout = tokio::time::sleep(std::time::Duration::from_secs(30));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) if len >= 40 && &buf[..8] == MAGIC => {
                            // Respond with our peer ID + listen port
                            let mut response = Vec::with_capacity(42);
                            response.extend_from_slice(MAGIC);
                            response.extend_from_slice(&self.our_peer_id.0);
                            response.extend_from_slice(&self.listen_port.to_be_bytes());
                            let _ = socket.send_to(&response, addr).await;
                        }
                        _ => {}
                    }
                }
                _ = &mut timeout => break,
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore] // UDP broadcast may be flaky in CI environments
    #[tokio::test]
    async fn test_discovery_round_trip() {
        // Create two peers with different IDs
        let peer_a_id = PeerId([1u8; 32]);
        let peer_b_id = PeerId([2u8; 32]);

        let announcer = UdpDiscovery::new(peer_b_id, 9999);

        // Start announcer in background
        let announce_handle = tokio::spawn(async move { announcer.announce(&peer_b_id).await });

        // Give the announcer a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Discover peers
        let discoverer = UdpDiscovery::new(peer_a_id, 8888);
        let peers = discoverer
            .discover()
            .await
            .expect("discovery should succeed");

        // We should find peer B
        assert!(
            peers.iter().any(|p| p.peer_id == peer_b_id),
            "Should discover peer B, found: {:?}",
            peers.iter().map(|p| p.peer_id).collect::<Vec<_>>()
        );

        // Check the service port is correct
        let found = peers.iter().find(|p| p.peer_id == peer_b_id).unwrap();
        assert_eq!(found.addr.port(), 9999);

        announce_handle.abort();
    }
}
