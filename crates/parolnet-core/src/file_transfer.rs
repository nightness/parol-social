//! File transfer engine (PNP-007 Section 7).
//!
//! Chunked file transfer with SHA-256 integrity verification,
//! per-chunk encryption via Double Ratchet, and resume support.

use parolnet_protocol::file::{FileOffer, FileChunkHeader, DEFAULT_CHUNK_SIZE};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

/// Tracks an outgoing file transfer.
pub struct FileTransferSender {
    pub offer: FileOffer,
    pub data: Vec<u8>,
    pub next_chunk: u32,
}

impl FileTransferSender {
    /// Create a new file transfer from raw data.
    pub fn new(data: Vec<u8>, file_name: String, mime_type: Option<String>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha256: [u8; 32] = hasher.finalize().into();

        let mut file_id = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut file_id);

        let offer = FileOffer {
            file_id,
            file_name,
            file_size: data.len() as u64,
            chunk_size: DEFAULT_CHUNK_SIZE,
            sha256,
            mime_type,
        };

        Self {
            offer,
            data,
            next_chunk: 0,
        }
    }

    /// Get the total number of chunks.
    pub fn total_chunks(&self) -> u32 {
        self.offer.total_chunks()
    }

    /// Get the next chunk to send. Returns None when all chunks are sent.
    pub fn next(&mut self) -> Option<(FileChunkHeader, Vec<u8>)> {
        let total = self.total_chunks();
        if self.next_chunk >= total {
            return None;
        }

        let chunk_size = self.offer.chunk_size as usize;
        let start = self.next_chunk as usize * chunk_size;
        let end = (start + chunk_size).min(self.data.len());
        let chunk_data = self.data[start..end].to_vec();
        let is_last = self.next_chunk == total - 1;

        let header = FileChunkHeader {
            file_id: self.offer.file_id,
            chunk_index: self.next_chunk,
            chunk_size: chunk_data.len() as u16,
            is_last,
        };

        self.next_chunk += 1;
        Some((header, chunk_data))
    }

    /// Resume from a specific chunk index.
    pub fn resume_from(&mut self, chunk_index: u32) {
        self.next_chunk = chunk_index;
    }

    /// Check if transfer is complete (all chunks sent).
    pub fn is_complete(&self) -> bool {
        self.next_chunk >= self.total_chunks()
    }

    /// Get progress as (chunks_sent, total_chunks).
    pub fn progress(&self) -> (u32, u32) {
        (self.next_chunk, self.total_chunks())
    }
}

/// Tracks an incoming file transfer being reassembled.
pub struct FileTransferReceiver {
    pub offer: FileOffer,
    chunks: HashMap<u32, Vec<u8>>,
    pub completed: bool,
}

impl FileTransferReceiver {
    /// Create a receiver from a file offer.
    pub fn new(offer: FileOffer) -> Self {
        Self {
            offer,
            chunks: HashMap::new(),
            completed: false,
        }
    }

    /// Receive a chunk. Returns true if this was the last chunk.
    pub fn receive_chunk(&mut self, header: &FileChunkHeader, data: Vec<u8>) -> Result<bool, crate::CoreError> {
        if header.file_id != self.offer.file_id {
            return Err(crate::CoreError::SessionError("file_id mismatch".into()));
        }

        self.chunks.insert(header.chunk_index, data);

        if header.is_last {
            self.completed = true;
        }

        Ok(header.is_last)
    }

    /// Check if all chunks have been received.
    pub fn is_complete(&self) -> bool {
        if !self.completed {
            return false;
        }
        let total = self.offer.total_chunks();
        self.chunks.len() as u32 >= total
    }

    /// Get the last received chunk index (for resume).
    pub fn last_chunk_index(&self) -> Option<u32> {
        self.chunks.keys().max().copied()
    }

    /// Reassemble the file from chunks and verify SHA-256 integrity.
    pub fn assemble(&self) -> Result<Vec<u8>, crate::CoreError> {
        let total = self.offer.total_chunks();
        let mut data = Vec::with_capacity(self.offer.file_size as usize);

        for i in 0..total {
            let chunk = self.chunks.get(&i).ok_or_else(|| {
                crate::CoreError::SessionError(format!("missing chunk {i}"))
            })?;
            data.extend_from_slice(chunk);
        }

        // Verify SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let computed: [u8; 32] = hasher.finalize().into();

        if computed != self.offer.sha256 {
            return Err(crate::CoreError::SessionError(
                "SHA-256 integrity check failed".into(),
            ));
        }

        Ok(data)
    }

    /// Get progress as (chunks_received, total_chunks).
    pub fn progress(&self) -> (u32, u32) {
        (self.chunks.len() as u32, self.offer.total_chunks())
    }
}
