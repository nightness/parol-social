//! File transfer protocol types (PNP-007).

use serde::{Deserialize, Serialize};

/// File transfer offer — sent by the sender to propose a file transfer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileOffer {
    pub file_id: [u8; 16],
    pub file_name: String,
    pub file_size: u64,
    pub chunk_size: u32,
    pub sha256: [u8; 32],
    pub mime_type: Option<String>,
}

/// Header for each file chunk.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileChunkHeader {
    pub file_id: [u8; 16],
    pub chunk_index: u32,
    pub chunk_size: u16,
    pub is_last: bool,
}

/// File transfer control actions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FileAction {
    Accept,
    Reject,
    Cancel,
    Pause,
    Resume,
}

/// File transfer control message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileControl {
    pub file_id: [u8; 16],
    pub action: FileAction,
    pub resume_from: Option<u32>,
}

/// Default chunk size (fits in 4096-byte envelope bucket).
pub const DEFAULT_CHUNK_SIZE: u32 = 4096;

impl FileOffer {
    /// Calculate the total number of chunks for this file.
    pub fn total_chunks(&self) -> u32 {
        if self.file_size == 0 {
            return 1; // empty file is 1 chunk
        }
        self.file_size.div_ceil(self.chunk_size as u64) as u32
    }
}
