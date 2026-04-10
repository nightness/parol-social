//! Gossip protocol implementation (PNP-005).

use crate::{GossipAction, GossipProtocol, MeshError};
use async_trait::async_trait;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::envelope::Envelope;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Mutex;

/// Default gossip fanout (number of peers to forward to).
pub const DEFAULT_FANOUT: usize = 3;
/// Default TTL for gossip messages.
pub const DEFAULT_TTL: u8 = 7;
/// Default expiry duration in seconds.
pub const DEFAULT_EXPIRY_SECS: u64 = 86400;

/// 1024-bit bloom filter for seen-peer deduplication (PNP-005 Section 3.3).
#[derive(Clone)]
pub struct SeenBloomFilter {
    bits: [u8; 128], // 1024 bits
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
        challenge_hasher.update(&timestamp.to_be_bytes());
        let challenge = challenge_hasher.finalize();

        let mut nonce = [0u8; 8];
        loop {
            let mut h = Sha256::new();
            h.update(&challenge);
            h.update(&nonce);
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
        challenge_hasher.update(&timestamp.to_be_bytes());
        let challenge = challenge_hasher.finalize();

        let mut h = Sha256::new();
        h.update(&challenge);
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
    pub dedup: DedupFilter,
    pub default_difficulty: u8,
}

impl StandardGossip {
    pub fn new(our_peer_id: PeerId) -> Self {
        Self {
            our_peer_id,
            dedup: DedupFilter::new(),
            default_difficulty: 16,
        }
    }
}

#[async_trait]
impl GossipProtocol for StandardGossip {
    async fn broadcast(&self, _envelope: Envelope) -> Result<(), MeshError> {
        // In production: sign, compute PoW, insert self in bloom, forward to fanout peers
        // This requires transport integration
        Ok(())
    }

    async fn on_receive(&self, _envelope: Envelope) -> Result<GossipAction, MeshError> {
        // In production: validate signature, PoW, TTL, expiry, check dedup
        // Return Forward/Deliver/Drop
        Ok(GossipAction::Drop)
    }
}
