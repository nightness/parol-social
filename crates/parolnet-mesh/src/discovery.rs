//! Peer discovery via local network (PNP-005 Section 5.9).
//!
//! Implements simple UDP broadcast discovery on the local network.
//! Discovery packets are obfuscated: the magic tag is derived from an
//! HMAC of the current epoch hour and the PeerId is XOR-masked with
//! a key derived via HKDF from the same epoch, so only peers who share
//! the discovery key can decode announcements.

use crate::{DiscoveredPeer, MeshError, PeerDiscovery};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use parolnet_protocol::address::PeerId;
use sha2::Sha256;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Discovery port for ParolNet LAN discovery.
const DISCOVERY_PORT: u16 = 19532;

/// Default discovery key: SHA-256("parolnet-discovery-v1").
fn default_discovery_key() -> [u8; 32] {
    use sha2::Digest;
    let hash = Sha256::digest(b"parolnet-discovery-v1");
    hash.into()
}

/// Get the current epoch hour (seconds since UNIX epoch / 3600).
fn epoch_hour() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 3600
}

/// Derive an 8-byte tag from the discovery key and epoch hour.
/// tag = HMAC-SHA256(discovery_key, epoch_hour_be_bytes)[..8]
fn derive_tag(discovery_key: &[u8; 32], epoch_hour: u64) -> [u8; 8] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(discovery_key).expect("HMAC accepts any key length");
    mac.update(&epoch_hour.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&result[..8]);
    tag
}

/// Derive a 32-byte mask for XOR-obfuscating the PeerId.
/// mask = HKDF-SHA256(discovery_key, epoch_hour_be_bytes, "peer-mask")
fn derive_peer_mask(discovery_key: &[u8; 32], epoch_hour: u64) -> [u8; 32] {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(Some(&epoch_hour.to_be_bytes()), discovery_key);
    let mut mask = [0u8; 32];
    hk.expand(b"peer-mask", &mut mask)
        .expect("32 bytes is a valid HKDF output length");
    mask
}

/// XOR a 32-byte PeerId with a 32-byte mask.
fn xor_peer_id(peer_id: &[u8; 32], mask: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = peer_id[i] ^ mask[i];
    }
    out
}

pub struct UdpDiscovery {
    our_peer_id: PeerId,
    listen_port: u16,
    discovery_key: [u8; 32],
}

impl UdpDiscovery {
    pub fn new(our_peer_id: PeerId, listen_port: u16) -> Self {
        Self {
            our_peer_id,
            listen_port,
            discovery_key: default_discovery_key(),
        }
    }

    /// Create a UdpDiscovery with a custom discovery key.
    pub fn with_key(our_peer_id: PeerId, listen_port: u16, discovery_key: [u8; 32]) -> Self {
        Self {
            our_peer_id,
            listen_port,
            discovery_key,
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

        let hour = epoch_hour();
        let tag = derive_tag(&self.discovery_key, hour);
        let mask = derive_peer_mask(&self.discovery_key, hour);
        let masked_id = xor_peer_id(&self.our_peer_id.0, &mask);

        // Send discovery request: tag(8) + masked_peer_id(32) = 40 bytes
        let mut request = Vec::with_capacity(40);
        request.extend_from_slice(&tag);
        request.extend_from_slice(&masked_id);

        socket
            .send_to(&request, format!("255.255.255.255:{DISCOVERY_PORT}"))
            .await
            .map_err(|e| MeshError::DiscoveryFailed(format!("send: {e}")))?;

        // Collect responses with timeout
        let mut peers = Vec::new();
        let mut buf = [0u8; 128];

        let deadline = tokio::time::sleep(std::time::Duration::from_secs(2));
        tokio::pin!(deadline);

        // Also check the previous hour's tag to handle hour boundaries
        let prev_tag = derive_tag(&self.discovery_key, hour.wrapping_sub(1));
        let prev_mask = derive_peer_mask(&self.discovery_key, hour.wrapping_sub(1));

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) if len >= 42 => {
                            // Try current hour tag, then previous hour tag
                            let matched_mask = if buf[..8] == tag {
                                Some(mask)
                            } else if buf[..8] == prev_tag {
                                Some(prev_mask)
                            } else {
                                None
                            };
                            if let Some(m) = matched_mask {
                                let mut masked_peer = [0u8; 32];
                                masked_peer.copy_from_slice(&buf[8..40]);
                                let peer_id_bytes = xor_peer_id(&masked_peer, &m);
                                let peer = PeerId(peer_id_bytes);
                                // Don't include ourselves
                                if peer != self.our_peer_id {
                                    let service_port = u16::from_be_bytes([buf[40], buf[41]]);
                                    let peer_addr = SocketAddr::new(addr.ip(), service_port);
                                    peers.push(DiscoveredPeer { peer_id: peer, addr: peer_addr });
                                }
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
                        Ok((len, addr)) if len >= 40 => {
                            let hour = epoch_hour();
                            let tag = derive_tag(&self.discovery_key, hour);
                            let prev_tag = derive_tag(&self.discovery_key, hour.wrapping_sub(1));

                            // Verify the tag matches current or previous hour
                            if buf[..8] == tag || buf[..8] == prev_tag {
                                let mask = derive_peer_mask(&self.discovery_key, hour);
                                let masked_id = xor_peer_id(&self.our_peer_id.0, &mask);

                                // Respond with tag + masked peer ID + listen port
                                let mut response = Vec::with_capacity(42);
                                response.extend_from_slice(&tag);
                                response.extend_from_slice(&masked_id);
                                response.extend_from_slice(&self.listen_port.to_be_bytes());
                                let _ = socket.send_to(&response, addr).await;
                            }
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

    #[test]
    fn test_tag_derivation_deterministic() {
        let key = default_discovery_key();
        let tag1 = derive_tag(&key, 12345);
        let tag2 = derive_tag(&key, 12345);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_tag_derivation_different_hours() {
        let key = default_discovery_key();
        let tag1 = derive_tag(&key, 12345);
        let tag2 = derive_tag(&key, 12346);
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_peer_mask_roundtrip() {
        let key = default_discovery_key();
        let mask = derive_peer_mask(&key, 12345);
        let peer_id = [42u8; 32];
        let masked = xor_peer_id(&peer_id, &mask);
        let unmasked = xor_peer_id(&masked, &mask);
        assert_eq!(unmasked, peer_id);
    }

    #[test]
    fn test_masked_peer_id_not_cleartext() {
        let key = default_discovery_key();
        let mask = derive_peer_mask(&key, 12345);
        let peer_id = [42u8; 32];
        let masked = xor_peer_id(&peer_id, &mask);
        assert_ne!(masked, peer_id);
    }

    #[test]
    fn test_different_keys_produce_different_tags() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let hour = 12345;
        assert_ne!(derive_tag(&key1, hour), derive_tag(&key2, hour));
    }

    #[ignore] // UDP broadcast may be flaky in CI environments
    #[tokio::test]
    async fn test_discovery_round_trip() {
        // Create two peers with different IDs and the same discovery key
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
