//! Relay directory — gossip-based discovery (PNP-004 Section 5.6).

use crate::RelayInfo;
use crate::authority::{EndorsedDescriptor, SignedDirectory};
use crate::trust_roots;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parolnet_protocol::address::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Serde helper for `[u8; 64]` arrays (signatures).
mod sig_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(bytes.as_slice()).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = serde_bytes::ByteBuf::deserialize(deserializer)?.into_vec();
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len()))
        })
    }
}

/// Minimum relay descriptors to maintain locally.
pub const MIN_DESCRIPTORS: usize = 100;
/// Maximum descriptor age before considered stale (24 hours).
pub const MAX_DESCRIPTOR_AGE_SECS: u64 = 86400;
/// Descriptor refresh interval (6 hours).
pub const DESCRIPTOR_REFRESH_SECS: u64 = 21600;

/// A signed relay descriptor (PNP-004 Section 5.6).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayDescriptor {
    pub peer_id: PeerId,
    pub identity_key: [u8; 32],
    pub x25519_key: [u8; 32],
    pub addr: std::net::SocketAddr,
    pub bandwidth_class: u8,
    pub uptime_secs: u64,
    pub timestamp: u64,
    #[serde(with = "sig_bytes")]
    pub signature: [u8; 64],
    /// Estimated bandwidth in bytes/sec for weighted relay selection.
    pub bandwidth_estimate: u64,
    /// Optional next public key for future key rotation.
    pub next_pubkey: Option<[u8; 32]>,
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
        if let Some(ref next_key) = self.next_pubkey {
            buf.push(1);
            buf.extend_from_slice(next_key);
        } else {
            buf.push(0);
        }
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

/// Health metrics for a relay, tracked locally.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayHealth {
    /// Exponential moving average of latency in milliseconds.
    pub latency_ms: f64,
    /// Total number of connection/communication failures.
    pub failure_count: u32,
    /// Total number of successful interactions.
    pub success_count: u32,
    /// Unix timestamp of last successful interaction.
    pub last_seen: u64,
    /// Computed health score (0.0 to 1.0). Higher is better.
    pub score: f64,
}

impl Default for RelayHealth {
    fn default() -> Self {
        Self {
            latency_ms: 0.0,
            failure_count: 0,
            success_count: 0,
            last_seen: 0,
            score: 1.0,
        }
    }
}

/// Local cache of relay descriptors.
pub struct RelayDirectory {
    descriptors: HashMap<PeerId, RelayDescriptor>,
    /// Guard set: 2-3 stable relays reused across circuits.
    guards: Vec<PeerId>,
    /// Health metrics for known relays.
    health: HashMap<PeerId, RelayHealth>,
}

impl Default for RelayDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayDirectory {
    /// Minimum health score to be eligible for path selection.
    const MIN_HEALTH_SCORE: f64 = 0.1;

    pub fn new() -> Self {
        Self {
            descriptors: HashMap::new(),
            guards: Vec::new(),
            health: HashMap::new(),
        }
    }

    /// Record a successful interaction with a relay.
    pub fn record_success(&mut self, peer_id: &PeerId, latency_ms: f64, now: u64) {
        let health = self.health.entry(*peer_id).or_default();
        health.success_count += 1;
        health.last_seen = now;
        // Exponential moving average for latency (alpha = 0.3)
        if health.latency_ms == 0.0 {
            health.latency_ms = latency_ms;
        } else {
            health.latency_ms = 0.7 * health.latency_ms + 0.3 * latency_ms;
        }
        health.score = Self::compute_score(health);
    }

    /// Record a failed interaction with a relay.
    pub fn record_failure(&mut self, peer_id: &PeerId) {
        let health = self.health.entry(*peer_id).or_default();
        health.failure_count += 1;
        health.score = Self::compute_score(health);
    }

    /// Compute the health score for a relay.
    fn compute_score(health: &RelayHealth) -> f64 {
        let total = health.success_count + health.failure_count;
        let success_ratio = if total == 0 {
            1.0 // Unknown relay gets benefit of the doubt
        } else {
            health.success_count as f64 / total as f64
        };
        let latency_factor = 1.0 / (1.0 + health.latency_ms / 1000.0);
        let failure_penalty = 1.0 / (1.0 + health.failure_count as f64);
        (success_ratio * latency_factor * failure_penalty).clamp(0.0, 1.0)
    }

    /// Get health score for a relay (1.0 if unknown).
    pub fn health_score(&self, peer_id: &PeerId) -> f64 {
        self.health.get(peer_id).map_or(1.0, |h| h.score)
    }

    /// Get health metrics for a relay.
    pub fn get_health(&self, peer_id: &PeerId) -> Option<&RelayHealth> {
        self.health.get(peer_id)
    }

    /// Get all health metrics.
    pub fn all_health(&self) -> &HashMap<PeerId, RelayHealth> {
        &self.health
    }

    /// Select from candidates using health-weighted random selection.
    fn weighted_select(&self, candidates: &[&RelayDescriptor]) -> Option<RelayInfo> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Filter out relays below minimum health threshold
        let eligible: Vec<_> = candidates
            .iter()
            .filter(|d| self.health_score(&d.peer_id) >= Self::MIN_HEALTH_SCORE)
            .copied()
            .collect();

        // Fall back to all candidates if none meet health threshold
        let pool = if eligible.is_empty() {
            candidates
        } else {
            &eligible
        };

        let weights: Vec<f64> = pool
            .iter()
            .map(|d| self.health_score(&d.peer_id) * d.bandwidth_estimate.max(1) as f64)
            .collect();

        let total: f64 = weights.iter().sum();
        if total <= 0.0 {
            return pool.first().map(|d| d.to_relay_info());
        }

        let mut pick: f64 = rng.r#gen::<f64>() * total;
        for (i, w) in weights.iter().enumerate() {
            pick -= w;
            if pick <= 0.0 {
                return Some(pool[i].to_relay_info());
            }
        }
        pool.last().map(|d| d.to_relay_info())
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

    /// Return a reference to all known descriptors.
    pub fn descriptors(&self) -> &HashMap<PeerId, RelayDescriptor> {
        &self.descriptors
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

            let weights: Vec<f64> = remaining
                .iter()
                .map(|d| self.health_score(&d.peer_id) * d.bandwidth_estimate.max(1) as f64)
                .collect();
            let total_weight: f64 = weights.iter().sum();
            if total_weight <= 0.0 {
                break;
            }
            let mut pick: f64 = rng.r#gen::<f64>() * total_weight;

            for (j, desc) in remaining.iter().enumerate() {
                let weight = weights[j];
                if pick <= weight {
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
    /// candidates exist, falls back to health-weighted random selection.
    pub fn select_random(&self, exclude: &[PeerId]) -> Option<RelayInfo> {
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
            .copied()
            .collect();

        if !diverse.is_empty() {
            self.weighted_select(&diverse)
        } else {
            // Fall back to any candidate if no diverse ones exist
            self.weighted_select(&candidates)
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
            next_pubkey: None,
        };
        let sig = signing_key.sign(&desc.signable_bytes());
        desc.signature = sig.to_bytes();
        desc
    }

    /// Merge a batch of relay descriptors from a peer relay.
    ///
    /// Skips our own descriptor (identified by `our_peer_id`) and uses
    /// `handle_gossip_descriptor` for each remaining descriptor, which
    /// validates timestamp, Ed25519 signature, and freshness.
    ///
    /// Returns the number of newly merged (accepted) descriptors.
    pub fn merge_descriptors(
        &mut self,
        descriptors: Vec<RelayDescriptor>,
        our_peer_id: &PeerId,
        now: u64,
    ) -> usize {
        let mut merged = 0;
        for desc in descriptors {
            if desc.peer_id == *our_peer_id {
                continue;
            }
            if self.handle_gossip_descriptor(desc, now) {
                merged += 1;
            }
        }
        merged
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

    /// Process an authority-endorsed descriptor.
    ///
    /// Verifies that the descriptor has sufficient authority endorsements
    /// (meeting the configured threshold), then inserts it into the directory.
    pub fn handle_endorsed_descriptor(
        &mut self,
        desc: EndorsedDescriptor,
    ) -> Result<(), crate::RelayError> {
        if !desc.verify_threshold(
            trust_roots::AUTHORITY_PUBKEYS,
            trust_roots::AUTHORITY_THRESHOLD,
        )? {
            return Err(crate::RelayError::CellError(
                "endorsed descriptor did not meet authority threshold".into(),
            ));
        }
        self.insert(desc.descriptor);
        Ok(())
    }

    /// Process a signed directory snapshot from an authority.
    ///
    /// Verifies the directory signature, then replaces all known descriptors
    /// with those from the signed directory.
    pub fn handle_signed_directory(
        &mut self,
        dir: SignedDirectory,
    ) -> Result<(), crate::RelayError> {
        if !dir.verify(trust_roots::AUTHORITY_PUBKEYS)? {
            return Err(crate::RelayError::CellError(
                "signed directory verification failed".into(),
            ));
        }
        self.descriptors.clear();
        for endorsed in dir.descriptors {
            self.insert(endorsed.descriptor);
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test descriptor with a specific /16 subnet to avoid diversity filter issues.
    fn make_test_descriptor(index: u8, bandwidth: u64) -> RelayDescriptor {
        let peer_id = PeerId([index; 32]);
        RelayDescriptor {
            peer_id,
            identity_key: [index; 32],
            x25519_key: [index; 32],
            // Each descriptor gets a unique /16 subnet
            addr: format!("{}.{}.0.1:9001", index, index).parse().unwrap(),
            bandwidth_class: 1,
            uptime_secs: 8 * 24 * 3600, // 8 days, qualifies as guard
            timestamp: 1000,
            signature: [0u8; 64],
            bandwidth_estimate: bandwidth,
            next_pubkey: None,
        }
    }

    #[test]
    fn test_relay_health_default_score() {
        let dir = RelayDirectory::new();
        let peer_id = PeerId([1; 32]);
        assert_eq!(dir.health_score(&peer_id), 1.0);
    }

    #[test]
    fn test_relay_health_success_updates() {
        let mut dir = RelayDirectory::new();
        let peer_id = PeerId([1; 32]);

        dir.record_success(&peer_id, 50.0, 1000);
        let health = dir.get_health(&peer_id).unwrap();
        assert_eq!(health.success_count, 1);
        assert_eq!(health.last_seen, 1000);
        assert!((health.latency_ms - 50.0).abs() < f64::EPSILON);
        assert!(health.score > 0.0 && health.score <= 1.0);

        // Second success with different latency uses EMA
        dir.record_success(&peer_id, 100.0, 2000);
        let health = dir.get_health(&peer_id).unwrap();
        assert_eq!(health.success_count, 2);
        assert_eq!(health.last_seen, 2000);
        let expected_latency = 0.7 * 50.0 + 0.3 * 100.0;
        assert!((health.latency_ms - expected_latency).abs() < f64::EPSILON);
    }

    #[test]
    fn test_relay_health_failure_decreases_score() {
        let mut dir = RelayDirectory::new();
        let peer_id = PeerId([1; 32]);

        // Record a success first to establish a baseline
        dir.record_success(&peer_id, 50.0, 1000);
        let score_before = dir.health_score(&peer_id);

        // Record failures
        dir.record_failure(&peer_id);
        let score_after = dir.health_score(&peer_id);
        let health = dir.get_health(&peer_id).unwrap();

        assert_eq!(health.failure_count, 1);
        assert!(
            score_after < score_before,
            "score should decrease after failure: {} >= {}",
            score_after,
            score_before
        );
    }

    #[test]
    fn test_relay_health_weighted_selection() {
        let mut dir = RelayDirectory::new();

        let healthy_desc = make_test_descriptor(1, 1000);
        let degraded_desc = make_test_descriptor(2, 1000);

        dir.insert(healthy_desc);
        dir.insert(degraded_desc);

        let healthy_id = PeerId([1; 32]);
        let degraded_id = PeerId([2; 32]);

        // Make relay 1 healthy
        for _ in 0..10 {
            dir.record_success(&healthy_id, 20.0, 1000);
        }

        // Make relay 2 degraded
        for _ in 0..10 {
            dir.record_failure(&degraded_id);
        }

        let mut healthy_count = 0;
        let iterations = 200;
        for _ in 0..iterations {
            if let Some(info) = dir.select_random(&[]) {
                if info.peer_id == healthy_id {
                    healthy_count += 1;
                }
            }
        }

        // Healthy relay should be selected significantly more often
        assert!(
            healthy_count > iterations / 2,
            "healthy relay selected only {healthy_count}/{iterations} times, expected majority",
        );
    }

    #[test]
    fn test_relay_health_minimum_threshold() {
        let mut dir = RelayDirectory::new();

        let good_desc = make_test_descriptor(1, 1000);
        let bad_desc = make_test_descriptor(2, 1000);

        dir.insert(good_desc);
        dir.insert(bad_desc);

        let bad_id = PeerId([2; 32]);
        let good_id = PeerId([1; 32]);

        // Make relay 2 very unhealthy (below MIN_HEALTH_SCORE)
        for _ in 0..100 {
            dir.record_failure(&bad_id);
        }
        // Record high latency too
        dir.record_success(&bad_id, 100_000.0, 1000);

        assert!(
            dir.health_score(&bad_id) < RelayDirectory::MIN_HEALTH_SCORE,
            "bad relay score {} should be below threshold {}",
            dir.health_score(&bad_id),
            RelayDirectory::MIN_HEALTH_SCORE,
        );

        // With health filtering, the good relay should always be selected
        let mut good_count = 0;
        let iterations = 50;
        for _ in 0..iterations {
            if let Some(info) = dir.select_random(&[]) {
                if info.peer_id == good_id {
                    good_count += 1;
                }
            }
        }

        assert_eq!(
            good_count, iterations,
            "good relay should be selected every time when bad relay is below threshold",
        );
    }

    /// Helper: create a properly signed descriptor for merge/gossip tests.
    fn make_signed_descriptor(
        signing_key: &ed25519_dalek::SigningKey,
        addr: std::net::SocketAddr,
        timestamp: u64,
    ) -> RelayDescriptor {
        use sha2::{Digest, Sha256};
        let pubkey = signing_key.verifying_key().to_bytes();
        let peer_id = PeerId(Sha256::digest(pubkey).into());
        RelayDirectory::create_descriptor(
            peer_id,
            pubkey,
            [0xAA; 32], // dummy x25519 key
            addr,
            1,
            8 * 24 * 3600,
            timestamp,
            signing_key,
        )
    }

    #[test]
    fn test_merge_descriptors_basic() {
        let mut dir = RelayDirectory::new();
        let our_peer_id = PeerId([0xFF; 32]);
        let now = 5000u64;

        let key1 = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let key2 = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let desc1 = make_signed_descriptor(&key1, "10.0.0.1:9001".parse().unwrap(), now - 100);
        let desc2 = make_signed_descriptor(&key2, "10.1.0.1:9001".parse().unwrap(), now - 200);

        let count = dir.merge_descriptors(vec![desc1, desc2], &our_peer_id, now);
        assert_eq!(count, 2, "both descriptors should be merged");
        assert_eq!(dir.len(), 2);
    }

    #[test]
    fn test_merge_descriptors_skips_own() {
        let mut dir = RelayDirectory::new();
        let now = 5000u64;

        let our_key = ed25519_dalek::SigningKey::from_bytes(&[0xAA; 32]);
        let our_desc =
            make_signed_descriptor(&our_key, "10.0.0.1:9001".parse().unwrap(), now - 100);
        let our_peer_id = our_desc.peer_id;

        let other_key = ed25519_dalek::SigningKey::from_bytes(&[0xBB; 32]);
        let other_desc =
            make_signed_descriptor(&other_key, "10.1.0.1:9001".parse().unwrap(), now - 100);

        let count = dir.merge_descriptors(vec![our_desc, other_desc], &our_peer_id, now);
        assert_eq!(count, 1, "own descriptor should be skipped");
        assert_eq!(dir.len(), 1);
    }

    #[test]
    fn test_merge_descriptors_skips_stale() {
        let mut dir = RelayDirectory::new();
        let our_peer_id = PeerId([0xFF; 32]);
        let now = 200_000u64;

        let key1 = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        // Descriptor older than MAX_DESCRIPTOR_AGE_SECS (86400)
        let stale_desc = make_signed_descriptor(&key1, "10.0.0.1:9001".parse().unwrap(), 1000);

        let count = dir.merge_descriptors(vec![stale_desc], &our_peer_id, now);
        assert_eq!(count, 0, "stale descriptor should be rejected");
        assert_eq!(dir.len(), 0);
    }
}
