//! Relay directory — gossip-based discovery (PNP-004 Section 5.6).

use crate::RelayInfo;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parolnet_protocol::address::PeerId;
use std::collections::HashMap;

/// Minimum relay descriptors to maintain locally.
pub const MIN_DESCRIPTORS: usize = 100;
/// Maximum descriptor age before considered stale (24 hours).
pub const MAX_DESCRIPTOR_AGE_SECS: u64 = 86400;
/// Descriptor refresh interval (6 hours).
pub const DESCRIPTOR_REFRESH_SECS: u64 = 21600;

/// A signed relay descriptor (PNP-004 Section 5.6).
#[derive(Clone, Debug)]
pub struct RelayDescriptor {
    pub peer_id: PeerId,
    pub identity_key: [u8; 32],
    pub x25519_key: [u8; 32],
    pub addr: std::net::SocketAddr,
    pub bandwidth_class: u8,
    pub uptime_secs: u64,
    pub timestamp: u64,
    pub signature: [u8; 64],
    /// Estimated bandwidth in bytes/sec for weighted relay selection.
    pub bandwidth_estimate: u64,
}

/// Extract the /16 subnet prefix from a SocketAddr.
///
/// For IPv4, returns the first two octets. For IPv6-mapped IPv4, extracts
/// the embedded IPv4 address. For native IPv6, returns the first two bytes
/// of the address.
fn subnet_prefix(addr: &std::net::SocketAddr) -> [u8; 2] {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            [octets[0], octets[1]]
        }
        std::net::IpAddr::V6(ip) => {
            // Check for IPv4-mapped IPv6 (::ffff:a.b.c.d)
            if let Some(v4) = ip.to_ipv4_mapped() {
                let octets = v4.octets();
                [octets[0], octets[1]]
            } else {
                let octets = ip.octets();
                [octets[0], octets[1]]
            }
        }
    }
}

impl RelayDescriptor {
    /// Produce the bytes to sign (all fields except signature).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&self.peer_id.0);
        buf.extend_from_slice(&self.identity_key);
        buf.extend_from_slice(&self.x25519_key);
        match self.addr {
            std::net::SocketAddr::V4(a) => {
                buf.push(4);
                buf.extend_from_slice(&a.ip().octets());
            }
            std::net::SocketAddr::V6(a) => {
                buf.push(6);
                buf.extend_from_slice(&a.ip().octets());
            }
        }
        buf.extend_from_slice(&self.addr.port().to_be_bytes());
        buf.push(self.bandwidth_class);
        buf.extend_from_slice(&self.uptime_secs.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.bandwidth_estimate.to_be_bytes());
        buf
    }

    /// Convert to a RelayInfo for circuit building.
    pub fn to_relay_info(&self) -> RelayInfo {
        RelayInfo {
            peer_id: self.peer_id,
            identity_key: self.identity_key,
            x25519_key: self.x25519_key,
            addr: self.addr,
            bandwidth_class: self.bandwidth_class,
        }
    }
}

/// Local cache of relay descriptors.
pub struct RelayDirectory {
    descriptors: HashMap<PeerId, RelayDescriptor>,
    /// Guard set: 2-3 stable relays reused across circuits.
    guards: Vec<PeerId>,
}

impl Default for RelayDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayDirectory {
    pub fn new() -> Self {
        Self {
            descriptors: HashMap::new(),
            guards: Vec::new(),
        }
    }

    /// Add or update a relay descriptor.
    pub fn insert(&mut self, descriptor: RelayDescriptor) {
        self.descriptors.insert(descriptor.peer_id, descriptor);
    }

    /// Get the number of known relays.
    pub fn len(&self) -> usize {
        self.descriptors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }

    /// Look up a relay's SocketAddr by PeerId.
    pub fn lookup_addr(&self, peer_id: &PeerId) -> Option<std::net::SocketAddr> {
        self.descriptors.get(peer_id).map(|d| d.addr)
    }

    /// Remove stale descriptors older than `max_age_secs`.
    pub fn prune_stale(&mut self, now: u64) {
        self.descriptors
            .retain(|_, d| now.saturating_sub(d.timestamp) < MAX_DESCRIPTOR_AGE_SECS);
    }

    /// Select guard nodes (PNP-004 Section 5.7).
    ///
    /// Guards are selected from relays with uptime > 7 days using
    /// bandwidth-weighted random selection. The guard set is stable for 30+ days.
    pub fn select_guards(&mut self, count: usize) -> Vec<RelayInfo> {
        // If we already have enough guards, return them
        if self.guards.len() >= count {
            return self
                .guards
                .iter()
                .take(count)
                .filter_map(|id| self.descriptors.get(id))
                .map(|d| d.to_relay_info())
                .collect();
        }

        // Select new guards: prefer high-uptime relays with bandwidth weighting
        let seven_days = 7 * 24 * 3600;
        let candidates: Vec<_> = self
            .descriptors
            .values()
            .filter(|d| d.uptime_secs >= seven_days)
            .collect();

        if candidates.is_empty() {
            return Vec::new();
        }

        // Bandwidth-weighted random selection
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut selected = Vec::new();
        let mut selected_ids: Vec<PeerId> = Vec::new();

        for _ in 0..count {
            let remaining: Vec<_> = candidates
                .iter()
                .filter(|d| !selected_ids.contains(&d.peer_id))
                .collect();
            if remaining.is_empty() {
                break;
            }

            let total_weight: u64 = remaining.iter().map(|d| d.bandwidth_estimate.max(1)).sum();
            let mut pick = rng.gen_range(0..total_weight);

            for desc in &remaining {
                let weight = desc.bandwidth_estimate.max(1);
                if pick < weight {
                    selected_ids.push(desc.peer_id);
                    selected.push(desc.peer_id);
                    break;
                }
                pick -= weight;
            }
        }

        self.guards = selected;

        self.guards
            .iter()
            .filter_map(|id| self.descriptors.get(id))
            .map(|d| d.to_relay_info())
            .collect()
    }

    /// Select a random relay excluding the given PeerIds (PNP-004 Section 5.7).
    ///
    /// Enforces /16 IPv4 subnet diversity: candidates that share a /16
    /// prefix with any excluded peer are deprioritized. If no diverse
    /// candidates exist, falls back to random selection.
    pub fn select_random(&self, exclude: &[PeerId]) -> Option<RelayInfo> {
        use rand::seq::SliceRandom;

        // Collect /16 prefixes of excluded peers
        let excluded_subnets: Vec<[u8; 2]> = exclude
            .iter()
            .filter_map(|pid| self.descriptors.get(pid))
            .map(|d| subnet_prefix(&d.addr))
            .collect();

        let candidates: Vec<_> = self
            .descriptors
            .values()
            .filter(|d| !exclude.contains(&d.peer_id))
            .collect();

        if candidates.is_empty() {
            return None;
        }

        // Prefer candidates from diverse /16 subnets
        let diverse: Vec<_> = candidates
            .iter()
            .filter(|d| !excluded_subnets.contains(&subnet_prefix(&d.addr)))
            .collect();

        let mut rng = rand::thread_rng();
        if !diverse.is_empty() {
            diverse.choose(&mut rng).map(|d| d.to_relay_info())
        } else {
            // Fall back to any candidate if no diverse ones exist
            candidates.choose(&mut rng).map(|d| d.to_relay_info())
        }
    }

    /// Create a signed relay descriptor for this node.
    ///
    /// Signs the descriptor with the provided Ed25519 key.
    #[allow(clippy::too_many_arguments)]
    pub fn create_descriptor(
        peer_id: PeerId,
        identity_key: [u8; 32],
        x25519_key: [u8; 32],
        addr: std::net::SocketAddr,
        bandwidth_class: u8,
        uptime_secs: u64,
        now: u64,
        signing_key: &SigningKey,
    ) -> RelayDescriptor {
        let mut desc = RelayDescriptor {
            peer_id,
            identity_key,
            x25519_key,
            addr,
            bandwidth_class,
            uptime_secs,
            timestamp: now,
            signature: [0u8; 64],
            bandwidth_estimate: 1000,
        };
        let sig = signing_key.sign(&desc.signable_bytes());
        desc.signature = sig.to_bytes();
        desc
    }

    /// Process a received relay descriptor from gossip.
    ///
    /// Validates the timestamp is not stale (within 24 hours of `now`),
    /// inserts it if valid, and returns `true` if the descriptor was new
    /// or updated an existing entry.
    pub fn handle_gossip_descriptor(&mut self, desc: RelayDescriptor, now: u64) -> bool {
        // Reject stale descriptors
        if now.saturating_sub(desc.timestamp) >= MAX_DESCRIPTOR_AGE_SECS {
            return false;
        }

        // Verify Ed25519 signature
        let verifying_key = match VerifyingKey::from_bytes(&desc.identity_key) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&desc.signature);
        if verifying_key
            .verify(&desc.signable_bytes(), &signature)
            .is_err()
        {
            return false;
        }

        // Only accept if newer than what we have
        if let Some(existing) = self.descriptors.get(&desc.peer_id)
            && existing.timestamp >= desc.timestamp
        {
            return false;
        }

        self.insert(desc);
        true
    }

    /// Select a relay path: 1 guard + 2 random relays, with subnet diversity.
    pub fn select_path(&mut self) -> Option<[RelayInfo; 3]> {
        let guards = self.select_guards(1);
        let guard = guards.first()?;

        let exclude = vec![guard.peer_id];
        let middle = self.select_random(&exclude)?;

        let exclude = vec![guard.peer_id, middle.peer_id];
        let exit = self.select_random(&exclude)?;

        Some([guard.clone(), middle, exit])
    }
}
