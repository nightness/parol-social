//! Gossip protocol implementation (PNP-005).

use crate::connection_pool::ConnectionPool;
use crate::{GossipAction, GossipProtocol, MeshError};
use async_trait::async_trait;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::envelope::Envelope;
use parolnet_protocol::gossip::{GossipEnvelope, GossipPayloadType};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::warn;

/// Default gossip fanout (number of peers to forward to).
pub const DEFAULT_FANOUT: usize = 3;
/// Default TTL for gossip messages.
pub const DEFAULT_TTL: u8 = 7;
/// Default expiry duration in seconds.
pub const DEFAULT_EXPIRY_SECS: u64 = 86400;
/// Maximum messages per source peer per rate-limit window (PNP-005 Section 6.4).
pub const RATE_LIMIT_MAX_MESSAGES: u32 = 10;
/// Rate-limit window duration in seconds.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;
/// Maximum allowed clock skew for future timestamps (seconds).
pub const MAX_FUTURE_SKEW_SECS: u64 = 300;

/// 1024-bit bloom filter for seen-peer deduplication (PNP-005 Section 3.3).
#[derive(Clone)]
pub struct SeenBloomFilter {
    bits: [u8; 128], // 1024 bits
}

impl Default for SeenBloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl SeenBloomFilter {
    pub fn new() -> Self {
        Self { bits: [0u8; 128] }
    }

    /// Insert a PeerId into the bloom filter using 3 hash functions.
    pub fn insert(&mut self, peer_id: &PeerId) {
        for k in 0u8..3 {
            let idx = self.hash(k, peer_id);
            self.bits[idx / 8] |= 1 << (idx % 8);
        }
    }

    /// Check if a PeerId is probably in the bloom filter.
    pub fn probably_contains(&self, peer_id: &PeerId) -> bool {
        for k in 0u8..3 {
            let idx = self.hash(k, peer_id);
            if self.bits[idx / 8] & (1 << (idx % 8)) == 0 {
                return false;
            }
        }
        true
    }

    /// h_k(PeerId) = SHA-256(k || PeerId) mod 1024
    fn hash(&self, k: u8, peer_id: &PeerId) -> usize {
        let mut hasher = Sha256::new();
        hasher.update([k]);
        hasher.update(peer_id.as_bytes());
        let result = hasher.finalize();
        let val = u16::from_be_bytes([result[0], result[1]]);
        (val as usize) % 1024
    }
}

/// Local deduplication filter for recently seen message IDs.
///
/// Uses a double-buffer approach: current + previous, rotated every 12 hours.
pub struct DedupFilter {
    current: Mutex<HashSet<[u8; 32]>>,
    previous: Mutex<HashSet<[u8; 32]>>,
}

impl Default for DedupFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl DedupFilter {
    pub fn new() -> Self {
        Self {
            current: Mutex::new(HashSet::new()),
            previous: Mutex::new(HashSet::new()),
        }
    }

    /// Check if a message ID has been seen recently.
    pub fn is_seen(&self, message_id: &[u8; 32]) -> bool {
        self.current.lock().unwrap().contains(message_id)
            || self.previous.lock().unwrap().contains(message_id)
    }

    /// Mark a message ID as seen.
    pub fn mark_seen(&self, message_id: [u8; 32]) {
        self.current.lock().unwrap().insert(message_id);
    }

    /// Rotate the double buffer: discard previous, promote current.
    pub fn rotate(&self) {
        let current = std::mem::take(&mut *self.current.lock().unwrap());
        *self.previous.lock().unwrap() = current;
    }

    /// Total number of entries across both buffers.
    pub fn len(&self) -> usize {
        self.current.lock().unwrap().len() + self.previous.lock().unwrap().len()
    }

    /// Whether both buffers are empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Proof-of-Work computation (PNP-005 Section 3.4).
pub struct ProofOfWork;

impl ProofOfWork {
    /// Compute a PoW nonce that produces `difficulty` leading zero bits.
    ///
    /// challenge = SHA-256("pgmp-pow-v1" || message_id || sender || timestamp)
    pub fn compute(
        message_id: &[u8; 32],
        sender: &PeerId,
        timestamp: u64,
        difficulty: u8,
    ) -> [u8; 8] {
        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(b"pgmp-pow-v1");
        challenge_hasher.update(message_id);
        challenge_hasher.update(sender.as_bytes());
        challenge_hasher.update(timestamp.to_be_bytes());
        let challenge = challenge_hasher.finalize();

        let mut nonce = [0u8; 8];
        loop {
            let mut h = Sha256::new();
            h.update(challenge);
            h.update(nonce);
            let result = h.finalize();

            if Self::has_leading_zeros(&result, difficulty) {
                return nonce;
            }

            // Increment nonce
            for byte in nonce.iter_mut().rev() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
        }
    }

    /// Verify a PoW nonce.
    pub fn verify(
        message_id: &[u8; 32],
        sender: &PeerId,
        timestamp: u64,
        nonce: &[u8; 8],
        difficulty: u8,
    ) -> bool {
        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(b"pgmp-pow-v1");
        challenge_hasher.update(message_id);
        challenge_hasher.update(sender.as_bytes());
        challenge_hasher.update(timestamp.to_be_bytes());
        let challenge = challenge_hasher.finalize();

        let mut h = Sha256::new();
        h.update(challenge);
        h.update(nonce);
        let result = h.finalize();

        Self::has_leading_zeros(&result, difficulty)
    }

    /// Check if a hash has at least `n` leading zero bits.
    fn has_leading_zeros(hash: &[u8], n: u8) -> bool {
        let full_bytes = n / 8;
        let remaining_bits = n % 8;

        for byte in hash.iter().take(full_bytes as usize) {
            if *byte != 0 {
                return false;
            }
        }

        if remaining_bits > 0 {
            let mask = 0xFF << (8 - remaining_bits);
            if hash[full_bytes as usize] & mask != 0 {
                return false;
            }
        }

        true
    }
}

pub struct StandardGossip {
    pub our_peer_id: PeerId,
    pub signing_key: ed25519_dalek::SigningKey,
    pub dedup: DedupFilter,
    pub default_difficulty: u8,
    pub pool: Arc<ConnectionPool>,
    /// Per-PeerId rate limiting: (window_start, message_count).
    rate_limits: Mutex<HashMap<PeerId, (Instant, u32)>>,
}

impl StandardGossip {
    pub fn new(
        our_peer_id: PeerId,
        signing_key: ed25519_dalek::SigningKey,
        pool: Arc<ConnectionPool>,
    ) -> Self {
        Self {
            our_peer_id,
            signing_key,
            dedup: DedupFilter::new(),
            default_difficulty: 16,
            pool,
            rate_limits: Mutex::new(HashMap::new()),
        }
    }

    /// Check and update the per-source rate limit.
    /// Returns true if the source has exceeded the rate limit.
    fn is_rate_limited(&self, source: &PeerId) -> bool {
        let mut limits = self.rate_limits.lock().unwrap();
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        let entry = limits.entry(*source).or_insert((now, 0));

        // Reset window if expired
        if now.duration_since(entry.0) >= window {
            *entry = (now, 1);
            return false;
        }

        entry.1 += 1;
        entry.1 > RATE_LIMIT_MAX_MESSAGES
    }

    /// Get the current unix timestamp in seconds.
    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Build a GossipEnvelope from an Envelope for broadcasting.
    fn build_gossip_envelope(&self, envelope: &Envelope) -> Result<GossipEnvelope, MeshError> {
        // Serialize the inner Envelope header + payload as the gossip payload.
        // Since Envelope doesn't implement Serialize, we pack header CBOR + encrypted_payload + mac.
        let mut payload_buf = Vec::new();
        ciborium::into_writer(&envelope.header, &mut payload_buf)
            .map_err(|e| MeshError::ValidationFailed(format!("CBOR encode header: {e}")))?;
        payload_buf.extend_from_slice(&envelope.encrypted_payload);
        payload_buf.extend_from_slice(&envelope.mac);

        // Generate message_id = SHA-256(encrypted_payload || our_peer_id || random_nonce)
        let random_nonce: [u8; 16] = rand::random();
        let mut id_hasher = Sha256::new();
        id_hasher.update(&envelope.encrypted_payload);
        id_hasher.update(self.our_peer_id.as_bytes());
        id_hasher.update(random_nonce);
        let message_id: [u8; 32] = id_hasher.finalize().into();

        let ts = Self::now_secs();
        let exp = ts + DEFAULT_EXPIRY_SECS;

        // Initialize bloom filter with our peer ID
        let mut bloom = SeenBloomFilter::new();
        bloom.insert(&self.our_peer_id);

        // Compute PoW
        let pow_nonce =
            ProofOfWork::compute(&message_id, &self.our_peer_id, ts, self.default_difficulty);

        // Build envelope with placeholder signature, then sign
        let mut gossip_env = GossipEnvelope {
            v: 1,
            id: message_id.to_vec(),
            src: self.our_peer_id,
            src_pubkey: self.signing_key.verifying_key().to_bytes().to_vec(),
            ts,
            exp,
            ttl: DEFAULT_TTL,
            hops: 0,
            seen: bloom.bits.to_vec(),
            pow: pow_nonce.to_vec(),
            sig: vec![0u8; 64],
            payload_type: GossipPayloadType::UserMessage as u8,
            payload: payload_buf,
        };

        // Compute signable bytes and produce real Ed25519 signature
        let signable = gossip_env.signable_bytes();
        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(&signable);
        gossip_env.sig = signature.to_bytes().to_vec();

        Ok(gossip_env)
    }

    /// Extract peer IDs from a bloom filter for exclusion during fanout.
    fn bloom_excluded_peers(seen: &[u8], all_peers: &[PeerId]) -> Vec<PeerId> {
        if seen.len() != 128 {
            return Vec::new();
        }
        let bloom = SeenBloomFilter {
            bits: {
                let mut bits = [0u8; 128];
                bits.copy_from_slice(seen);
                bits
            },
        };
        all_peers
            .iter()
            .filter(|pid| bloom.probably_contains(pid))
            .copied()
            .collect()
    }

    /// Process a received gossip envelope (the primary entry point for gossip messages).
    pub async fn process_gossip(&self, data: &[u8]) -> Result<GossipAction, MeshError> {
        // 1. Deserialize GossipEnvelope from CBOR
        let mut gossip_env = GossipEnvelope::from_cbor(data)
            .map_err(|e| MeshError::ValidationFailed(format!("gossip CBOR decode: {e}")))?;

        // 2. Check structural validity
        if !gossip_env.is_valid_structure() {
            return Err(MeshError::ValidationFailed(
                "invalid gossip envelope structure".into(),
            ));
        }

        let message_id = gossip_env
            .message_id()
            .ok_or_else(|| MeshError::ValidationFailed("invalid message_id length".into()))?;

        // 3. Per-source rate limiting (PNP-005 Section 6.4)
        if self.is_rate_limited(&gossip_env.src) {
            warn!(peer = %gossip_env.src, "rate limited: too many gossip messages");
            return Ok(GossipAction::RateLimited);
        }

        // 4. Check expiry
        let now = Self::now_secs();
        if gossip_env.is_expired(now) {
            // Penalize sender for expired message
            self.pool
                .update_score(&gossip_env.src, |s| s.penalize_expired())
                .await;
            return Err(MeshError::MessageExpired);
        }

        // 4b. Reject future timestamps (beyond MAX_FUTURE_SKEW_SECS)
        if gossip_env.ts > now + MAX_FUTURE_SKEW_SECS {
            warn!(
                peer = %gossip_env.src,
                ts = gossip_env.ts,
                now = now,
                "gossip message has future timestamp"
            );
            return Ok(GossipAction::Drop);
        }

        // 5. Check dedup
        if self.dedup.is_seen(&message_id) {
            self.pool
                .update_score(&gossip_env.src, |s| s.penalize_duplicate())
                .await;
            return Ok(GossipAction::Drop);
        }

        // 5. Verify PoW
        let pow_nonce = gossip_env
            .pow_nonce()
            .ok_or_else(|| MeshError::ValidationFailed("invalid pow nonce length".into()))?;

        let required_difficulty = GossipPayloadType::from_u8(gossip_env.payload_type)
            .map(|pt| pt.pow_difficulty())
            .unwrap_or(self.default_difficulty);

        if !ProofOfWork::verify(
            &message_id,
            &gossip_env.src,
            gossip_env.ts,
            &pow_nonce,
            required_difficulty,
        ) {
            self.pool
                .update_score(&gossip_env.src, |s| s.penalize_invalid())
                .await;
            return Err(MeshError::InsufficientPoW);
        }

        // 6. Verify Ed25519 signature
        {
            // Verify src_pubkey matches the claimed src PeerId
            let pubkey_hash: [u8; 32] = Sha256::digest(&gossip_env.src_pubkey).into();
            if pubkey_hash != gossip_env.src.0 {
                self.pool
                    .update_score(&gossip_env.src, |s| s.penalize_invalid())
                    .await;
                return Err(MeshError::ValidationFailed(
                    "src_pubkey does not match src PeerId".into(),
                ));
            }

            // Verify the Ed25519 signature
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let verifying_key =
                VerifyingKey::from_bytes(gossip_env.src_pubkey.as_slice().try_into().map_err(
                    |_| MeshError::ValidationFailed("invalid src_pubkey length".into()),
                )?)
                .map_err(|_| MeshError::ValidationFailed("invalid Ed25519 public key".into()))?;

            let sig_bytes: [u8; 64] = gossip_env
                .sig
                .as_slice()
                .try_into()
                .map_err(|_| MeshError::ValidationFailed("invalid signature length".into()))?;
            let signature = Signature::from_bytes(&sig_bytes);

            let signable = gossip_env.signable_bytes();
            verifying_key
                .verify(&signable, &signature)
                .map_err(|_| MeshError::ValidationFailed("invalid Ed25519 signature".into()))?;
        }

        // 7. Mark as seen in dedup
        self.dedup.mark_seen(message_id);

        // Reward the sender for a valid message
        self.pool
            .update_score(&gossip_env.src, |s| s.reward())
            .await;

        // 8. If ttl == 0, deliver without forwarding
        if gossip_env.ttl == 0 {
            return Ok(GossipAction::Deliver);
        }

        // 9. Decrement ttl, increment hops, insert our_peer_id in bloom
        gossip_env.ttl -= 1;
        gossip_env.hops = gossip_env.hops.saturating_add(1);
        if gossip_env.seen.len() == 128 {
            let mut bloom = SeenBloomFilter {
                bits: {
                    let mut bits = [0u8; 128];
                    bits.copy_from_slice(&gossip_env.seen);
                    bits
                },
            };
            bloom.insert(&self.our_peer_id);
            gossip_env.seen = bloom.bits.to_vec();
        }

        // 10. Select fanout peers (exclude bloom filter matches)
        let all_peers = self.pool.connected_peers().await;
        let excluded = Self::bloom_excluded_peers(&gossip_env.seen, &all_peers);
        let fanout = self
            .pool
            .select_fanout_peers(&excluded, DEFAULT_FANOUT)
            .await;

        // 11. Send modified envelope to fanout peers
        let serialized = gossip_env
            .to_cbor()
            .map_err(|e| MeshError::ValidationFailed(format!("gossip CBOR encode: {e}")))?;

        let mut forwarded_to = Vec::new();
        for (pid, conn) in &fanout {
            if let Err(e) = conn.send(&serialized).await {
                warn!(peer = %pid, error = %e, "failed to forward gossip");
            } else {
                forwarded_to.push(*pid);
            }
        }

        // 12. Determine if message is for us
        // Check if dest_peer_id in the envelope header matches our peer_id
        // The payload contains the inner envelope header + encrypted payload + mac
        // We try to decode the header to check the destination
        if self.is_payload_for_us(&gossip_env.payload) {
            Ok(GossipAction::Deliver)
        } else if forwarded_to.is_empty() {
            // No peers to forward to, but message is not for us
            Ok(GossipAction::Drop)
        } else {
            // Apply 0-200ms random jitter before forwarding (PNP-005 Section 5.2 step 4)
            let jitter_ms = rand::rngs::OsRng.gen_range(0..200);
            Ok(GossipAction::Forward {
                peers: forwarded_to,
                jitter_ms,
            })
        }
    }

    /// Check if the gossip payload's inner envelope is addressed to us.
    fn is_payload_for_us(&self, payload: &[u8]) -> bool {
        // Try to decode the CleartextHeader from the start of the payload.
        // The payload is: CBOR(header) || encrypted_payload || mac
        use parolnet_protocol::envelope::CleartextHeader;
        if let Ok(header) = ciborium::from_reader::<CleartextHeader, _>(payload) {
            header.dest_peer_id == self.our_peer_id
        } else {
            false
        }
    }
}

#[async_trait]
impl GossipProtocol for StandardGossip {
    async fn broadcast(&self, envelope: Envelope) -> Result<(), MeshError> {
        let gossip_env = self.build_gossip_envelope(&envelope)?;
        let message_id = gossip_env.message_id().unwrap();

        // Mark as seen in dedup
        self.dedup.mark_seen(message_id);

        // Serialize
        let serialized = gossip_env
            .to_cbor()
            .map_err(|e| MeshError::ValidationFailed(format!("CBOR encode: {e}")))?;

        // Select fanout peers (exclude ourselves via bloom)
        let excluded = vec![self.our_peer_id];
        let fanout = self
            .pool
            .select_fanout_peers(&excluded, DEFAULT_FANOUT)
            .await;

        // Send to each peer
        for (pid, conn) in &fanout {
            if let Err(e) = conn.send(&serialized).await {
                warn!(peer = %pid, error = %e, "failed to send gossip broadcast");
            }
        }

        Ok(())
    }

    async fn on_receive(&self, envelope: Envelope) -> Result<GossipAction, MeshError> {
        // The envelope's encrypted_payload carries the CBOR-encoded GossipEnvelope
        self.process_gossip(&envelope.encrypted_payload).await
    }
}
