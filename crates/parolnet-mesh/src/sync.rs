//! Set reconciliation using Invertible Bloom Lookup Tables (IBLTs).
//!
//! Used to efficiently sync message histories between peers that reconnect
//! after being offline. Each peer encodes their message IDs into an IBLT,
//! exchanges them, and decodes the symmetric difference to find missing messages.
//!
//! Reference: Eppstein et al., "What's the Difference? Efficient Set Reconciliation
//! without Prior Context" (2011).

use crate::MeshError;
use sha2::{Digest, Sha256};

/// Number of cells in the IBLT.
const NUM_CELLS: usize = 80;

/// Number of hash functions (cells per entry).
const NUM_HASHES: usize = 3;

/// A single cell in the IBLT.
#[derive(Clone, Debug)]
struct IbltCell {
    /// XOR of all key hashes mapped to this cell.
    key_sum: [u8; 32],
    /// XOR of all value hashes mapped to this cell.
    hash_sum: [u8; 32],
    /// Count of entries mapped to this cell.
    count: i32,
}

impl Default for IbltCell {
    fn default() -> Self {
        Self {
            key_sum: [0; 32],
            hash_sum: [0; 32],
            count: 0,
        }
    }
}

/// Invertible Bloom Lookup Table for set reconciliation.
#[derive(Clone, Debug)]
pub struct Iblt {
    cells: Vec<IbltCell>,
}

impl Iblt {
    /// Create a new empty IBLT.
    pub fn new() -> Self {
        Self {
            cells: vec![IbltCell::default(); NUM_CELLS],
        }
    }

    /// Compute the hash indices for a key.
    fn indices(key: &[u8; 32]) -> [usize; NUM_HASHES] {
        let mut indices = [0usize; NUM_HASHES];
        for (i, idx) in indices.iter_mut().enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(&[i as u8]);
            hasher.update(key);
            let hash = hasher.finalize();
            *idx = u64::from_be_bytes(hash[..8].try_into().unwrap()) as usize % NUM_CELLS;
        }
        indices
    }

    /// Compute a check hash for a key.
    fn check_hash(key: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"iblt-check");
        hasher.update(key);
        hasher.finalize().into()
    }

    /// XOR two 32-byte arrays.
    fn xor_32(a: &mut [u8; 32], b: &[u8; 32]) {
        for (x, y) in a.iter_mut().zip(b.iter()) {
            *x ^= y;
        }
    }

    /// Insert a message ID into the IBLT.
    pub fn insert(&mut self, key: &[u8; 32]) {
        let check = Self::check_hash(key);
        for &idx in Self::indices(key).iter() {
            Self::xor_32(&mut self.cells[idx].key_sum, key);
            Self::xor_32(&mut self.cells[idx].hash_sum, &check);
            self.cells[idx].count += 1;
        }
    }

    /// Remove a message ID from the IBLT.
    pub fn remove(&mut self, key: &[u8; 32]) {
        let check = Self::check_hash(key);
        for &idx in Self::indices(key).iter() {
            Self::xor_32(&mut self.cells[idx].key_sum, key);
            Self::xor_32(&mut self.cells[idx].hash_sum, &check);
            self.cells[idx].count -= 1;
        }
    }

    /// Subtract another IBLT from this one (compute the difference).
    /// After subtraction, decoding yields the symmetric difference.
    pub fn subtract(&mut self, other: &Iblt) {
        for i in 0..NUM_CELLS {
            Self::xor_32(&mut self.cells[i].key_sum, &other.cells[i].key_sum);
            Self::xor_32(&mut self.cells[i].hash_sum, &other.cells[i].hash_sum);
            self.cells[i].count -= other.cells[i].count;
        }
    }

    /// Decode the IBLT, extracting entries.
    /// Returns (positive_keys, negative_keys) where:
    /// - positive_keys are entries in self but not other (after subtract)
    /// - negative_keys are entries in other but not self
    /// Returns Err if decoding fails (too many differences for this IBLT size).
    pub fn decode(&self) -> Result<(Vec<[u8; 32]>, Vec<[u8; 32]>), MeshError> {
        let mut iblt = self.clone();
        let mut positive = Vec::new();
        let mut negative = Vec::new();

        let mut progress = true;
        while progress {
            progress = false;
            for i in 0..NUM_CELLS {
                if iblt.cells[i].count == 1 || iblt.cells[i].count == -1 {
                    let key = iblt.cells[i].key_sum;
                    let expected_check = Self::check_hash(&key);
                    if expected_check == iblt.cells[i].hash_sum {
                        if iblt.cells[i].count == 1 {
                            positive.push(key);
                        } else {
                            negative.push(key);
                        }
                        // Remove this entry from the IBLT ("peel")
                        let indices = Self::indices(&key);
                        let check = Self::check_hash(&key);
                        let sign = iblt.cells[i].count; // +1 or -1
                        for &idx in indices.iter() {
                            Self::xor_32(&mut iblt.cells[idx].key_sum, &key);
                            Self::xor_32(&mut iblt.cells[idx].hash_sum, &check);
                            iblt.cells[idx].count -= sign;
                        }
                        progress = true;
                    }
                }
            }
        }

        // Check if fully decoded
        let all_empty = iblt.cells.iter().all(|c| c.count == 0);
        if !all_empty {
            return Err(MeshError::SyncError(
                "IBLT decode failed — too many differences for table size".into(),
            ));
        }

        Ok((positive, negative))
    }

    /// Serialize the IBLT to bytes for network transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(NUM_CELLS * 68); // 32 + 32 + 4 per cell
        for cell in &self.cells {
            buf.extend_from_slice(&cell.key_sum);
            buf.extend_from_slice(&cell.hash_sum);
            buf.extend_from_slice(&cell.count.to_be_bytes());
        }
        buf
    }

    /// Deserialize an IBLT from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, MeshError> {
        let cell_size = 32 + 32 + 4;
        if data.len() != NUM_CELLS * cell_size {
            return Err(MeshError::SyncError(format!(
                "invalid IBLT size: expected {}, got {}",
                NUM_CELLS * cell_size,
                data.len()
            )));
        }
        let mut cells = Vec::with_capacity(NUM_CELLS);
        for i in 0..NUM_CELLS {
            let offset = i * cell_size;
            let mut key_sum = [0u8; 32];
            let mut hash_sum = [0u8; 32];
            key_sum.copy_from_slice(&data[offset..offset + 32]);
            hash_sum.copy_from_slice(&data[offset + 32..offset + 64]);
            let count = i32::from_be_bytes(data[offset + 64..offset + 68].try_into().unwrap());
            cells.push(IbltCell {
                key_sum,
                hash_sum,
                count,
            });
        }
        Ok(Self { cells })
    }
}

impl Default for Iblt {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform set reconciliation between local and remote message ID sets.
///
/// Given our local message IDs and the remote peer's IBLT (as bytes),
/// returns the message IDs that the remote peer is missing (that we have).
pub async fn reconcile(
    local_message_ids: &[[u8; 32]],
    remote_iblt_bytes: &[u8],
) -> Result<Vec<[u8; 32]>, MeshError> {
    let remote_iblt = Iblt::from_bytes(remote_iblt_bytes)?;

    // Build our local IBLT
    let mut local_iblt = Iblt::new();
    for id in local_message_ids {
        local_iblt.insert(id);
    }

    // Subtract remote from local
    local_iblt.subtract(&remote_iblt);

    // Decode the difference
    let (we_have, _they_have) = local_iblt.decode()?;

    // Return IDs that we have but they don't — these need to be sent to them
    Ok(we_have)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a deterministic test key from a byte value.
    fn test_key(n: u8) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&[n]);
        hasher.finalize().into()
    }

    #[test]
    fn test_empty_iblt_decodes_to_empty() {
        let iblt = Iblt::new();
        let (pos, neg) = iblt.decode().unwrap();
        assert!(pos.is_empty());
        assert!(neg.is_empty());
    }

    #[test]
    fn test_insert_and_decode_single() {
        let mut iblt = Iblt::new();
        let key = test_key(1);
        iblt.insert(&key);

        let (pos, neg) = iblt.decode().unwrap();
        assert_eq!(pos.len(), 1);
        assert_eq!(pos[0], key);
        assert!(neg.is_empty());
    }

    #[test]
    fn test_insert_and_decode_multiple() {
        let mut iblt = Iblt::new();
        let keys: Vec<[u8; 32]> = (0..5).map(test_key).collect();
        for key in &keys {
            iblt.insert(key);
        }

        let (pos, neg) = iblt.decode().unwrap();
        assert_eq!(pos.len(), 5);
        assert!(neg.is_empty());
        for key in &keys {
            assert!(pos.contains(key));
        }
    }

    #[test]
    fn test_insert_remove_cancels() {
        let mut iblt = Iblt::new();
        let key = test_key(42);
        iblt.insert(&key);
        iblt.remove(&key);

        let (pos, neg) = iblt.decode().unwrap();
        assert!(pos.is_empty());
        assert!(neg.is_empty());
    }

    #[test]
    fn test_subtract_symmetric_difference() {
        let shared_keys: Vec<[u8; 32]> = (0..5).map(test_key).collect();
        let only_a: Vec<[u8; 32]> = (10..13).map(test_key).collect();
        let only_b: Vec<[u8; 32]> = (20..22).map(test_key).collect();

        let mut iblt_a = Iblt::new();
        let mut iblt_b = Iblt::new();

        for key in &shared_keys {
            iblt_a.insert(key);
            iblt_b.insert(key);
        }
        for key in &only_a {
            iblt_a.insert(key);
        }
        for key in &only_b {
            iblt_b.insert(key);
        }

        // Subtract B from A: positive = only_a, negative = only_b
        iblt_a.subtract(&iblt_b);
        let (pos, neg) = iblt_a.decode().unwrap();

        assert_eq!(pos.len(), only_a.len());
        assert_eq!(neg.len(), only_b.len());
        for key in &only_a {
            assert!(pos.contains(key));
        }
        for key in &only_b {
            assert!(neg.contains(key));
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut iblt = Iblt::new();
        for i in 0..10 {
            iblt.insert(&test_key(i));
        }

        let bytes = iblt.to_bytes();
        assert_eq!(bytes.len(), NUM_CELLS * 68);

        let restored = Iblt::from_bytes(&bytes).unwrap();
        // Verify they produce the same decode result
        let (pos1, neg1) = iblt.decode().unwrap();
        let (pos2, neg2) = restored.decode().unwrap();
        assert_eq!(pos1.len(), pos2.len());
        assert_eq!(neg1.len(), neg2.len());
        for key in &pos1 {
            assert!(pos2.contains(key));
        }
    }

    #[test]
    fn test_from_bytes_invalid_size() {
        let result = Iblt::from_bytes(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_fails_too_many_differences() {
        // Insert many entries into one IBLT to exceed decode capacity
        let mut iblt_a = Iblt::new();
        let mut iblt_b = Iblt::new();

        // With NUM_CELLS=80, having 50+ differences will likely fail
        for i in 0..60u8 {
            iblt_a.insert(&test_key(i));
        }
        for i in 60..120u8 {
            iblt_b.insert(&test_key(i));
        }

        iblt_a.subtract(&iblt_b);
        let result = iblt_a.decode();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reconcile_end_to_end() {
        let shared: Vec<[u8; 32]> = (0..5).map(test_key).collect();
        let only_local: Vec<[u8; 32]> = (10..13).map(test_key).collect();
        let only_remote: Vec<[u8; 32]> = (20..22).map(test_key).collect();

        // Build local set
        let mut local_ids: Vec<[u8; 32]> = shared.clone();
        local_ids.extend_from_slice(&only_local);

        // Build remote IBLT
        let mut remote_iblt = Iblt::new();
        for key in &shared {
            remote_iblt.insert(key);
        }
        for key in &only_remote {
            remote_iblt.insert(key);
        }
        let remote_bytes = remote_iblt.to_bytes();

        // Reconcile
        let missing = reconcile(&local_ids, &remote_bytes).await.unwrap();

        // Remote is missing the only_local keys
        assert_eq!(missing.len(), only_local.len());
        for key in &only_local {
            assert!(missing.contains(key));
        }
    }

    #[test]
    fn test_serialization_empty() {
        let iblt = Iblt::new();
        let bytes = iblt.to_bytes();
        let restored = Iblt::from_bytes(&bytes).unwrap();
        let (pos, neg) = restored.decode().unwrap();
        assert!(pos.is_empty());
        assert!(neg.is_empty());
    }
}
