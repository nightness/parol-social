//! Store-and-forward buffer (PNP-005 Section 5.4).

use crate::{MeshError, MessageStore};
use async_trait::async_trait;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::envelope::Envelope;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Max messages per peer in the store-and-forward buffer.
pub const MAX_MESSAGES_PER_PEER: usize = 256;
/// Max buffer size per peer in bytes.
pub const MAX_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MB

/// A buffered message with metadata for eviction.
#[derive(Clone)]
struct BufferedMessage {
    envelope: Envelope,
    stored_at: Instant,
    expires_at: Instant,
    ttl: u8,
    size: usize,
}

/// In-memory store-and-forward buffer.
pub struct InMemoryStore {
    buffers: Mutex<HashMap<PeerId, Vec<BufferedMessage>>>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            buffers: Mutex::new(HashMap::new()),
        }
    }

    /// Get the number of buffered messages for a peer.
    pub fn count_for_peer(&self, peer: &PeerId) -> usize {
        self.buffers
            .lock()
            .unwrap()
            .get(peer)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Get total buffered message count across all peers.
    pub fn total_count(&self) -> usize {
        self.buffers.lock().unwrap().values().map(|v| v.len()).sum()
    }

    /// Evict messages to make room, following PNP-005 Section 5.4 priority:
    /// 1. Nearest expiry first
    /// 2. Lowest TTL first
    /// 3. Oldest first
    fn evict_one(buffer: &mut Vec<BufferedMessage>) {
        if buffer.is_empty() {
            return;
        }

        let mut worst_idx = 0;
        for (i, msg) in buffer.iter().enumerate().skip(1) {
            let worst = &buffer[worst_idx];
            if msg.expires_at < worst.expires_at
                || (msg.expires_at == worst.expires_at && msg.ttl < worst.ttl)
                || (msg.expires_at == worst.expires_at
                    && msg.ttl == worst.ttl
                    && msg.stored_at < worst.stored_at)
            {
                worst_idx = i;
            }
        }

        buffer.swap_remove(worst_idx);
    }
}

#[async_trait]
impl MessageStore for InMemoryStore {
    async fn store(&self, envelope: &Envelope, ttl: Duration) -> Result<(), MeshError> {
        let now = Instant::now();
        let size = envelope.encrypted_payload.len() + 16; // rough size estimate

        // Use dest_peer_id as the recipient
        let recipient = envelope.header.dest_peer_id;

        let mut buffers = self.buffers.lock().unwrap();
        let buffer = buffers.entry(recipient).or_default();

        // Check limits and evict if necessary
        while buffer.len() >= MAX_MESSAGES_PER_PEER {
            Self::evict_one(buffer);
        }

        let total_size: usize = buffer.iter().map(|m| m.size).sum();
        if total_size + size > MAX_BUFFER_SIZE {
            Self::evict_one(buffer);
        }

        buffer.push(BufferedMessage {
            envelope: envelope.clone(),
            stored_at: now,
            expires_at: now + ttl,
            ttl: envelope.header.ttl(),
            size,
        });

        Ok(())
    }

    async fn retrieve(&self, recipient: &PeerId) -> Result<Vec<Envelope>, MeshError> {
        let mut buffers = self.buffers.lock().unwrap();
        let messages = buffers
            .remove(recipient)
            .unwrap_or_default()
            .into_iter()
            .map(|m| m.envelope)
            .collect();
        Ok(messages)
    }

    async fn expire(&self) -> Result<usize, MeshError> {
        let now = Instant::now();
        let mut buffers = self.buffers.lock().unwrap();
        let mut expired = 0;

        for buffer in buffers.values_mut() {
            let before = buffer.len();
            buffer.retain(|m| m.expires_at > now);
            expired += before - buffer.len();
        }

        // Remove empty peer entries
        buffers.retain(|_, v| !v.is_empty());

        Ok(expired)
    }
}
