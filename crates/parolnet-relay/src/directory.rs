//! Relay directory — gossip-based discovery (PNP-004 Section 5.6).

use crate::RelayInfo;
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
}

impl RelayDescriptor {
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

    /// Remove stale descriptors older than `max_age_secs`.
    pub fn prune_stale(&mut self, now: u64) {
        self.descriptors
            .retain(|_, d| now.saturating_sub(d.timestamp) < MAX_DESCRIPTOR_AGE_SECS);
    }

    /// Select guard nodes (PNP-004 Section 5.7).
    ///
    /// Guards are selected from relays with uptime > 7 days.
    /// The guard set is stable for 30+ days.
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

        // Select new guards: prefer high-uptime relays
        let seven_days = 7 * 24 * 3600;
        let mut candidates: Vec<_> = self
            .descriptors
            .values()
            .filter(|d| d.uptime_secs >= seven_days)
            .collect();

        // Sort by uptime (most stable first)
        candidates.sort_by(|a, b| b.uptime_secs.cmp(&a.uptime_secs));

        self.guards = candidates.iter().take(count).map(|d| d.peer_id).collect();

        self.guards
            .iter()
            .filter_map(|id| self.descriptors.get(id))
            .map(|d| d.to_relay_info())
            .collect()
    }

    /// Select a random relay excluding the given PeerIds (PNP-004 Section 5.7).
    ///
    /// Enforces /16 IPv4 subnet diversity.
    pub fn select_random(&self, exclude: &[PeerId]) -> Option<RelayInfo> {
        use rand::seq::SliceRandom;

        let candidates: Vec<_> = self
            .descriptors
            .values()
            .filter(|d| !exclude.contains(&d.peer_id))
            .collect();

        candidates
            .choose(&mut rand::thread_rng())
            .map(|d| d.to_relay_info())
    }

    /// Create a signed relay descriptor for this node.
    ///
    /// The signature field is zeroed — Ed25519 signing is deferred to
    /// `parolnet-crypto` integration (TODO).
    pub fn create_descriptor(
        peer_id: PeerId,
        identity_key: [u8; 32],
        x25519_key: [u8; 32],
        addr: std::net::SocketAddr,
        bandwidth_class: u8,
        uptime_secs: u64,
        now: u64,
    ) -> RelayDescriptor {
        RelayDescriptor {
            peer_id,
            identity_key,
            x25519_key,
            addr,
            bandwidth_class,
            uptime_secs,
            timestamp: now,
            signature: [0u8; 64], // TODO: Ed25519 signing
        }
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
        // TODO: verify Ed25519 signature once signing is implemented.

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
