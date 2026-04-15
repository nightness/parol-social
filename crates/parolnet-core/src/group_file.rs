//! Group file transfer manager (PNP-009 Section 5).
//!
//! Manages chunked file transfers within groups. Files are split into chunks
//! and reassembled on the receiving side with SHA-256 integrity verification.
//! Encryption is handled at the group layer via sender keys -- this module
//! deals with raw (plaintext) chunks only.

use parolnet_protocol::file::DEFAULT_CHUNK_SIZE;
use parolnet_protocol::group::{GroupFileOffer, GroupId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::CoreError;

/// A chunk of file data for group file transfer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupFileChunk {
    pub file_id: [u8; 16],
    pub chunk_index: u32,
    pub data: Vec<u8>,
}

/// Tracks an outgoing file transfer to a group.
pub struct GroupFileSender {
    pub group_id: GroupId,
    pub file_id: [u8; 16],
    pub file_name: String,
    pub file_size: u64,
    pub chunk_size: u32,
    pub sha256_hash: [u8; 32],
    pub chunks_sent: u32,
    pub total_chunks: u32,
    pub cancelled: bool,
    data: Vec<u8>,
}

impl GroupFileSender {
    /// Create a new group file sender.
    ///
    /// Computes the SHA-256 hash and total chunk count from the file data.
    pub fn new(group_id: GroupId, file_name: String, file_data: Vec<u8>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&file_data);
        let sha256_hash: [u8; 32] = hasher.finalize().into();

        let mut file_id = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut file_id);

        let file_size = file_data.len() as u64;
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let total_chunks = if file_size == 0 {
            1
        } else {
            file_size.div_ceil(chunk_size as u64) as u32
        };

        let file_name = crate::file_transfer::sanitize_filename(&file_name);

        Self {
            group_id,
            file_id,
            file_name,
            file_size,
            chunk_size,
            sha256_hash,
            chunks_sent: 0,
            total_chunks,
            cancelled: false,
            data: file_data,
        }
    }

    /// Build a GroupFileOffer to send to the group before transferring chunks.
    pub fn offer(&self) -> GroupFileOffer {
        use parolnet_protocol::file::FileOffer;
        GroupFileOffer {
            group_id: self.group_id,
            offer: FileOffer {
                file_id: self.file_id,
                file_name: self.file_name.clone(),
                file_size: self.file_size,
                chunk_size: self.chunk_size,
                sha256: self.sha256_hash,
                mime_type: None,
            },
        }
    }

    /// Return the next chunk of raw data, or None if the transfer is
    /// complete or cancelled.
    pub fn next_chunk(&mut self) -> Option<GroupFileChunk> {
        if self.cancelled || self.chunks_sent >= self.total_chunks {
            return None;
        }

        let chunk_size = self.chunk_size as usize;
        let start = self.chunks_sent as usize * chunk_size;
        let end = (start + chunk_size).min(self.data.len());
        let data = self.data[start..end].to_vec();

        let chunk = GroupFileChunk {
            file_id: self.file_id,
            chunk_index: self.chunks_sent,
            data,
        };

        self.chunks_sent += 1;
        Some(chunk)
    }

    /// Get transfer progress as a fraction in [0.0, 1.0].
    pub fn progress(&self) -> f32 {
        if self.total_chunks == 0 {
            return 1.0;
        }
        self.chunks_sent as f32 / self.total_chunks as f32
    }

    /// Check if all chunks have been sent.
    pub fn is_complete(&self) -> bool {
        self.chunks_sent >= self.total_chunks
    }

    /// Cancel this transfer.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }
}

/// Tracks an incoming file transfer from a group member.
pub struct GroupFileReceiver {
    pub group_id: GroupId,
    pub file_id: [u8; 16],
    pub file_name: String,
    pub file_size: u64,
    pub expected_hash: [u8; 32],
    pub total_chunks: u32,
    pub chunk_size: u32,
    chunks: HashMap<u32, Vec<u8>>,
}

impl GroupFileReceiver {
    /// Create a receiver from a GroupFileOffer.
    pub fn from_offer(offer: &GroupFileOffer) -> Self {
        let total_chunks = offer.offer.total_chunks();
        Self {
            group_id: offer.group_id,
            file_id: offer.offer.file_id,
            file_name: crate::file_transfer::sanitize_filename(&offer.offer.file_name),
            file_size: offer.offer.file_size,
            expected_hash: offer.offer.sha256,
            total_chunks,
            chunk_size: offer.offer.chunk_size,
            chunks: HashMap::new(),
        }
    }

    /// Receive a chunk of file data. Duplicate chunks overwrite silently.
    pub fn receive_chunk(&mut self, index: u32, data: Vec<u8>) -> Result<(), CoreError> {
        if index >= self.total_chunks {
            return Err(CoreError::GroupError(format!(
                "chunk index {} out of range (total {})",
                index, self.total_chunks
            )));
        }
        self.chunks.insert(index, data);
        Ok(())
    }

    /// Check if all chunks have been received.
    pub fn is_complete(&self) -> bool {
        self.chunks.len() as u32 >= self.total_chunks
    }

    /// Get transfer progress as a fraction in [0.0, 1.0].
    pub fn progress(&self) -> f32 {
        if self.total_chunks == 0 {
            return 1.0;
        }
        self.chunks.len() as f32 / self.total_chunks as f32
    }

    /// Reassemble the file from received chunks and verify SHA-256 integrity.
    pub fn assemble(&self) -> Result<Vec<u8>, CoreError> {
        let mut data = Vec::with_capacity(self.file_size as usize);

        for i in 0..self.total_chunks {
            let chunk = self
                .chunks
                .get(&i)
                .ok_or_else(|| CoreError::GroupError(format!("missing chunk {}", i)))?;
            data.extend_from_slice(chunk);
        }

        // Verify SHA-256 integrity
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let computed: [u8; 32] = hasher.finalize().into();

        if computed != self.expected_hash {
            return Err(CoreError::GroupError(
                "SHA-256 integrity check failed".into(),
            ));
        }

        Ok(data)
    }
}

/// Manages all active group file transfers (both sending and receiving).
pub struct GroupFileManager {
    senders: Mutex<HashMap<[u8; 16], GroupFileSender>>,
    receivers: Mutex<HashMap<[u8; 16], GroupFileReceiver>>,
}

impl Default for GroupFileManager {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupFileManager {
    /// Create a new empty group file manager.
    pub fn new() -> Self {
        Self {
            senders: Mutex::new(HashMap::new()),
            receivers: Mutex::new(HashMap::new()),
        }
    }

    /// Start a new outgoing file transfer and return the file_id and offer.
    pub fn create_send(
        &self,
        group_id: GroupId,
        file_name: String,
        file_data: Vec<u8>,
    ) -> ([u8; 16], GroupFileOffer) {
        let sender = GroupFileSender::new(group_id, file_name, file_data);
        let file_id = sender.file_id;
        let offer = sender.offer();
        self.senders
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(file_id, sender);
        (file_id, offer)
    }

    /// Get the next chunk for an outgoing transfer.
    pub fn get_next_chunk(&self, file_id: &[u8; 16]) -> Option<GroupFileChunk> {
        self.senders
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(file_id)?
            .next_chunk()
    }

    /// Register an incoming file transfer from a received offer.
    pub fn receive_offer(&self, offer: &GroupFileOffer) {
        let receiver = GroupFileReceiver::from_offer(offer);
        self.receivers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(offer.offer.file_id, receiver);
    }

    /// Feed a received chunk into an incoming transfer.
    pub fn receive_chunk(
        &self,
        file_id: &[u8; 16],
        index: u32,
        data: Vec<u8>,
    ) -> Result<(), CoreError> {
        let mut receivers = self.receivers.lock().unwrap_or_else(|e| e.into_inner());
        let receiver = receivers
            .get_mut(file_id)
            .ok_or_else(|| CoreError::GroupError("unknown file transfer".into()))?;
        receiver.receive_chunk(index, data)
    }

    /// Check if an outgoing transfer is complete.
    pub fn is_send_complete(&self, file_id: &[u8; 16]) -> bool {
        self.senders
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(file_id)
            .is_some_and(|s| s.is_complete())
    }

    /// Check if an incoming transfer is complete.
    pub fn is_recv_complete(&self, file_id: &[u8; 16]) -> bool {
        self.receivers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(file_id)
            .is_some_and(|r| r.is_complete())
    }

    /// Assemble a completed incoming transfer.
    pub fn assemble_file(&self, file_id: &[u8; 16]) -> Result<Vec<u8>, CoreError> {
        let receivers = self.receivers.lock().unwrap_or_else(|e| e.into_inner());
        let receiver = receivers
            .get(file_id)
            .ok_or_else(|| CoreError::GroupError("unknown file transfer".into()))?;
        receiver.assemble()
    }

    /// Cancel an outgoing transfer.
    pub fn cancel_send(&self, file_id: &[u8; 16]) -> Result<(), CoreError> {
        let mut senders = self.senders.lock().unwrap_or_else(|e| e.into_inner());
        let sender = senders
            .get_mut(file_id)
            .ok_or_else(|| CoreError::GroupError("unknown file transfer".into()))?;
        sender.cancel();
        Ok(())
    }

    /// Securely wipe all file transfer state (for panic_wipe).
    pub fn wipe_all(&self) {
        self.senders
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.receivers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Get the number of active outgoing transfers.
    pub fn active_send_count(&self) -> usize {
        self.senders.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Get the number of active incoming transfers.
    pub fn active_recv_count(&self) -> usize {
        self.receivers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_group_id(byte: u8) -> GroupId {
        GroupId([byte; 32])
    }

    #[test]
    fn test_group_file_send_receive() {
        let group_id = make_group_id(0xAA);
        let data = b"Hello, group file transfer!".to_vec();

        let mut sender = GroupFileSender::new(group_id, "test.txt".into(), data.clone());
        let offer = sender.offer();

        let mut receiver = GroupFileReceiver::from_offer(&offer);

        while let Some(chunk) = sender.next_chunk() {
            receiver
                .receive_chunk(chunk.chunk_index, chunk.data)
                .unwrap();
        }

        assert!(sender.is_complete());
        assert!(receiver.is_complete());

        let assembled = receiver.assemble().unwrap();
        assert_eq!(assembled, data);
    }

    #[test]
    fn test_group_file_integrity_check() {
        let group_id = make_group_id(0xBB);
        let data = b"Integrity test data".to_vec();

        let mut sender = GroupFileSender::new(group_id, "integrity.bin".into(), data);
        let offer = sender.offer();

        let mut receiver = GroupFileReceiver::from_offer(&offer);

        while let Some(mut chunk) = sender.next_chunk() {
            if chunk.chunk_index == 0 {
                if let Some(byte) = chunk.data.first_mut() {
                    *byte ^= 0xFF;
                }
            }
            receiver
                .receive_chunk(chunk.chunk_index, chunk.data)
                .unwrap();
        }

        assert!(receiver.is_complete());

        let result = receiver.assemble();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{}", err).contains("SHA-256"),
            "expected SHA-256 error, got: {}",
            err
        );
    }

    #[test]
    fn test_group_file_progress() {
        let group_id = make_group_id(0xCC);
        let data = vec![0x42u8; (DEFAULT_CHUNK_SIZE as usize) * 3 + 100];

        let mut sender = GroupFileSender::new(group_id, "large.bin".into(), data);
        let offer = sender.offer();

        assert_eq!(sender.total_chunks, 4);
        assert_eq!(sender.progress(), 0.0);

        let mut receiver = GroupFileReceiver::from_offer(&offer);
        assert_eq!(receiver.progress(), 0.0);

        let chunk = sender.next_chunk().unwrap();
        receiver
            .receive_chunk(chunk.chunk_index, chunk.data)
            .unwrap();

        assert_eq!(sender.progress(), 0.25);
        assert_eq!(receiver.progress(), 0.25);

        while let Some(chunk) = sender.next_chunk() {
            receiver
                .receive_chunk(chunk.chunk_index, chunk.data)
                .unwrap();
        }

        assert_eq!(sender.progress(), 1.0);
        assert_eq!(receiver.progress(), 1.0);
    }

    #[test]
    fn test_group_file_out_of_order_chunks() {
        let group_id = make_group_id(0xDD);
        let data = vec![0xABu8; (DEFAULT_CHUNK_SIZE as usize) * 4];

        let mut sender = GroupFileSender::new(group_id, "ooo.bin".into(), data.clone());
        let offer = sender.offer();

        let mut chunks = Vec::new();
        while let Some(chunk) = sender.next_chunk() {
            chunks.push(chunk);
        }

        let mut receiver = GroupFileReceiver::from_offer(&offer);
        for chunk in chunks.into_iter().rev() {
            receiver
                .receive_chunk(chunk.chunk_index, chunk.data)
                .unwrap();
        }

        assert!(receiver.is_complete());
        let assembled = receiver.assemble().unwrap();
        assert_eq!(assembled, data);
    }

    #[test]
    fn test_group_file_cancel() {
        let group_id = make_group_id(0xEE);
        let data = vec![0u8; (DEFAULT_CHUNK_SIZE as usize) * 5];

        let mut sender = GroupFileSender::new(group_id, "cancel.bin".into(), data);

        sender.next_chunk().unwrap();
        sender.next_chunk().unwrap();
        assert!(!sender.is_complete());
        assert!(!sender.cancelled);

        sender.cancel();
        assert!(sender.cancelled);

        assert!(sender.next_chunk().is_none());
    }

    #[test]
    fn test_group_file_manager_wipe() {
        let mgr = GroupFileManager::new();
        let group_id = make_group_id(0xFF);

        let (file_id1, offer1) = mgr.create_send(group_id, "a.txt".into(), b"aaa".to_vec());
        let (file_id2, _offer2) = mgr.create_send(group_id, "b.txt".into(), b"bbb".to_vec());

        mgr.receive_offer(&offer1);

        assert_eq!(mgr.active_send_count(), 2);
        assert_eq!(mgr.active_recv_count(), 1);

        mgr.wipe_all();

        assert_eq!(mgr.active_send_count(), 0);
        assert_eq!(mgr.active_recv_count(), 0);

        assert!(!mgr.is_send_complete(&file_id1));
        assert!(!mgr.is_send_complete(&file_id2));
    }

    #[test]
    fn test_group_file_duplicate_chunk() {
        let group_id = make_group_id(0x11);
        let data = b"duplicate chunk test".to_vec();

        let mut sender = GroupFileSender::new(group_id, "dup.txt".into(), data.clone());
        let offer = sender.offer();

        let mut receiver = GroupFileReceiver::from_offer(&offer);

        let chunk = sender.next_chunk().unwrap();
        let chunk_data = chunk.data.clone();

        receiver
            .receive_chunk(chunk.chunk_index, chunk_data.clone())
            .unwrap();
        receiver
            .receive_chunk(chunk.chunk_index, chunk_data)
            .unwrap();

        assert!(receiver.is_complete());
        let assembled = receiver.assemble().unwrap();
        assert_eq!(assembled, data);
    }

    #[test]
    fn test_group_file_empty_file() {
        let group_id = make_group_id(0x22);
        let data: Vec<u8> = Vec::new();

        let mut sender = GroupFileSender::new(group_id, "empty.bin".into(), data.clone());
        let offer = sender.offer();

        assert_eq!(sender.total_chunks, 1);
        assert_eq!(sender.file_size, 0);

        let mut receiver = GroupFileReceiver::from_offer(&offer);

        let chunk = sender.next_chunk().unwrap();
        assert!(chunk.data.is_empty());

        receiver
            .receive_chunk(chunk.chunk_index, chunk.data)
            .unwrap();

        assert!(sender.is_complete());
        assert!(receiver.is_complete());

        let assembled = receiver.assemble().unwrap();
        assert_eq!(assembled, data);
    }
}
