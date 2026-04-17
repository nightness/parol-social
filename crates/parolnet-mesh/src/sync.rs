//! Set reconciliation using Invertible Bloom Lookup Tables (IBLTs).
//!
//! Used to efficiently sync message histories between peers that reconnect
//! after being offline. Each peer encodes their message IDs into an IBLT,
//! exchanges them, and decodes the symmetric difference to find missing messages.
//!
//! Reference: Eppstein et al., "What's the Difference? Efficient Set Reconciliation
//! without Prior Context" (2011).
//!
//! ## Tiered sizing (PNP-008 §6.2)
//!
//! Federation directory sync uses tiered IBLT capacities so the wire cost scales
//! with the expected set difference. See [`IbltTier`]. Tier L carries one extra
//! hash function per the spec table.

use crate::MeshError;
use sha2::{Digest, Sha256};

/// Tier S (80 cells, 3 hashes) — default for ≤ 20 differences.
pub const TIER_S_CELLS: usize = 80;
/// Tier M (400 cells, 3 hashes) — for ≤ 100 differences.
pub const TIER_M_CELLS: usize = 400;
/// Tier L (2000 cells, 4 hashes) — for ≤ 500 differences.
pub const TIER_L_CELLS: usize = 2000;

/// Spec-mandated upper bound on IBLT cell count (PNP-008-MUST-025).
pub const MAX_IBLT_CELLS: usize = TIER_L_CELLS;

/// IBLT sizing tier per PNP-008 §6.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IbltTier {
    /// Small — 80 cells, 3 hashes, intended |Δ| ≤ 20.
    S,
    /// Medium — 400 cells, 3 hashes, intended |Δ| ≤ 100.
    M,
    /// Large — 2000 cells, 4 hashes, intended |Δ| ≤ 500.
    L,
}

impl IbltTier {
    pub const fn cells(self) -> usize {
        match self {
            Self::S => TIER_S_CELLS,
            Self::M => TIER_M_CELLS,
            Self::L => TIER_L_CELLS,
        }
    }

    pub const fn hashes(self) -> usize {
        match self {
            Self::S | Self::M => 3,
            Self::L => 4,
        }
    }

    /// Smallest tier whose expected decode probability exceeds 0.99 for the
    /// given estimated symmetric-difference count (PNP-008-MUST-024).
    ///
    /// Uses the empirical upper bounds from the PNP-008 §6.2 table. Callers
    /// estimate |Δ| from directory size; if a decode fails at the selected
    /// tier, they re-issue at the next tier per the spec.
    pub fn select_for_delta(estimated_delta: usize) -> Self {
        if estimated_delta <= 20 {
            Self::S
        } else if estimated_delta <= 100 {
            Self::M
        } else {
            Self::L
        }
    }
}

/// A single cell in the IBLT.
#[derive(Clone, Debug, Default)]
struct IbltCell {
    /// XOR of all key hashes mapped to this cell.
    key_sum: [u8; 32],
    /// XOR of all value hashes mapped to this cell.
    hash_sum: [u8; 32],
    /// Count of entries mapped to this cell.
    count: i32,
}

/// Invertible Bloom Lookup Table for set reconciliation.
#[derive(Clone, Debug)]
pub struct Iblt {
    cells: Vec<IbltCell>,
    num_hashes: usize,
}

impl Iblt {
    /// Create a new empty IBLT at tier S (80 cells, 3 hashes).
    ///
    /// For federation directory sync, prefer [`Iblt::with_tier`] to match the
    /// expected set difference.
    pub fn new() -> Self {
        Self::with_tier(IbltTier::S)
    }

    /// Create a new empty IBLT at the given tier.
    pub fn with_tier(tier: IbltTier) -> Self {
        Self::with_capacity(tier.cells(), tier.hashes())
    }

    /// Create a new empty IBLT with explicit cell count and hash count.
    ///
    /// # Panics
    /// Panics if `cells == 0`, `num_hashes == 0`, or `cells > MAX_IBLT_CELLS`.
    pub fn with_capacity(cells: usize, num_hashes: usize) -> Self {
        assert!(cells > 0, "IBLT cells must be > 0");
        assert!(num_hashes > 0, "IBLT num_hashes must be > 0");
        assert!(
            cells <= MAX_IBLT_CELLS,
            "IBLT cells {} exceeds PNP-008-MUST-025 cap of {}",
            cells,
            MAX_IBLT_CELLS
        );
        Self {
            cells: vec![IbltCell::default(); cells],
            num_hashes,
        }
    }

    /// Number of cells in this IBLT.
    pub fn num_cells(&self) -> usize {
        self.cells.len()
    }

    /// Number of hash functions used by this IBLT.
    pub fn num_hashes(&self) -> usize {
        self.num_hashes
    }

    /// Compute the hash indices for a key.
    fn indices(&self, key: &[u8; 32]) -> Vec<usize> {
        let cells = self.cells.len();
        let mut out = Vec::with_capacity(self.num_hashes);
        for i in 0..self.num_hashes {
            let mut hasher = Sha256::new();
            hasher.update([i as u8]);
            hasher.update(key);
            let hash = hasher.finalize();
            let idx = u64::from_be_bytes(hash[..8].try_into().unwrap()) as usize % cells;
            out.push(idx);
        }
        out
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
        for idx in self.indices(key) {
            Self::xor_32(&mut self.cells[idx].key_sum, key);
            Self::xor_32(&mut self.cells[idx].hash_sum, &check);
            self.cells[idx].count += 1;
        }
    }

    /// Remove a message ID from the IBLT.
    pub fn remove(&mut self, key: &[u8; 32]) {
        let check = Self::check_hash(key);
        for idx in self.indices(key) {
            Self::xor_32(&mut self.cells[idx].key_sum, key);
            Self::xor_32(&mut self.cells[idx].hash_sum, &check);
            self.cells[idx].count -= 1;
        }
    }

    /// Subtract another IBLT from this one (compute the difference).
    /// After subtraction, decoding yields the symmetric difference.
    ///
    /// Returns `Err` if the two IBLTs have mismatched dimensions — callers
    /// must ensure both sides agreed on a tier before subtracting.
    pub fn subtract(&mut self, other: &Iblt) -> Result<(), MeshError> {
        if self.cells.len() != other.cells.len() || self.num_hashes != other.num_hashes {
            return Err(MeshError::SyncError(format!(
                "IBLT dimension mismatch: self=({},{}) other=({},{})",
                self.cells.len(),
                self.num_hashes,
                other.cells.len(),
                other.num_hashes,
            )));
        }
        for i in 0..self.cells.len() {
            Self::xor_32(&mut self.cells[i].key_sum, &other.cells[i].key_sum);
            Self::xor_32(&mut self.cells[i].hash_sum, &other.cells[i].hash_sum);
            self.cells[i].count -= other.cells[i].count;
        }
        Ok(())
    }

    /// Decode the IBLT, extracting entries.
    /// Returns (positive_keys, negative_keys) where:
    /// - positive_keys are entries in self but not other (after subtract)
    /// - negative_keys are entries in other but not self
    ///   Returns Err if decoding fails (too many differences for this IBLT size).
    #[allow(clippy::type_complexity)]
    pub fn decode(&self) -> Result<(Vec<[u8; 32]>, Vec<[u8; 32]>), MeshError> {
        let mut iblt = self.clone();
        let num_cells = iblt.cells.len();
        let mut positive = Vec::new();
        let mut negative = Vec::new();

        let mut progress = true;
        while progress {
            progress = false;
            for i in 0..num_cells {
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
                        let indices = iblt.indices(&key);
                        let check = Self::check_hash(&key);
                        let sign = iblt.cells[i].count; // +1 or -1
                        for idx in indices {
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
    ///
    /// Wire format: `[u16 num_cells | u8 num_hashes | cell_0 .. cell_n]` where
    /// each cell is `32 + 32 + 4 = 68` bytes. The 3-byte prefix lets receivers
    /// decode tiered IBLTs without an out-of-band sizing agreement.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(3 + self.cells.len() * 68);
        buf.extend_from_slice(&(self.cells.len() as u16).to_be_bytes());
        buf.push(self.num_hashes as u8);
        for cell in &self.cells {
            buf.extend_from_slice(&cell.key_sum);
            buf.extend_from_slice(&cell.hash_sum);
            buf.extend_from_slice(&cell.count.to_be_bytes());
        }
        buf
    }

    /// Deserialize an IBLT from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, MeshError> {
        const CELL_SIZE: usize = 32 + 32 + 4;
        if data.len() < 3 {
            return Err(MeshError::SyncError(format!(
                "IBLT too short: {} bytes",
                data.len()
            )));
        }
        let num_cells = u16::from_be_bytes([data[0], data[1]]) as usize;
        let num_hashes = data[2] as usize;
        if num_cells == 0 || num_hashes == 0 {
            return Err(MeshError::SyncError(
                "IBLT header: num_cells / num_hashes MUST be > 0".into(),
            ));
        }
        if num_cells > MAX_IBLT_CELLS {
            // PNP-008-MUST-025
            return Err(MeshError::SyncError(format!(
                "IBLT cell count {} exceeds PNP-008-MUST-025 cap of {}",
                num_cells, MAX_IBLT_CELLS
            )));
        }
        let expected = 3 + num_cells * CELL_SIZE;
        if data.len() != expected {
            return Err(MeshError::SyncError(format!(
                "invalid IBLT size: expected {} (num_cells={}), got {}",
                expected,
                num_cells,
                data.len()
            )));
        }
        let mut cells = Vec::with_capacity(num_cells);
        for i in 0..num_cells {
            let offset = 3 + i * CELL_SIZE;
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
        Ok(Self { cells, num_hashes })
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
///
/// The local IBLT is built at the same tier as the remote to satisfy the
/// dimension check in [`Iblt::subtract`].
pub async fn reconcile(
    local_message_ids: &[[u8; 32]],
    remote_iblt_bytes: &[u8],
) -> Result<Vec<[u8; 32]>, MeshError> {
    let remote_iblt = Iblt::from_bytes(remote_iblt_bytes)?;

    // Build our local IBLT at the remote's dimensions
    let mut local_iblt =
        Iblt::with_capacity(remote_iblt.num_cells(), remote_iblt.num_hashes());
    for id in local_message_ids {
        local_iblt.insert(id);
    }

    // Subtract remote from local
    local_iblt.subtract(&remote_iblt)?;

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
        hasher.update([n]);
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
        iblt_a.subtract(&iblt_b).unwrap();
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
        assert_eq!(bytes.len(), 3 + TIER_S_CELLS * 68);

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

        // With tier S (80 cells), having 50+ differences will likely fail
        for i in 0..60u8 {
            iblt_a.insert(&test_key(i));
        }
        for i in 60..120u8 {
            iblt_b.insert(&test_key(i));
        }

        iblt_a.subtract(&iblt_b).unwrap();
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

    // -- Tiered sizing (PNP-008 §6.2) ---------------------------------------

    #[test]
    fn tier_dimensions_match_spec_table() {
        // PNP-008 §6.2 table: S=80/3, M=400/3, L=2000/4.
        assert_eq!(IbltTier::S.cells(), 80);
        assert_eq!(IbltTier::S.hashes(), 3);
        assert_eq!(IbltTier::M.cells(), 400);
        assert_eq!(IbltTier::M.hashes(), 3);
        assert_eq!(IbltTier::L.cells(), 2000);
        assert_eq!(IbltTier::L.hashes(), 4);
    }

    #[test]
    fn tier_select_picks_smallest_fit() {
        // Exercising MUST-024's "smallest tier" rule against the bound table.
        assert_eq!(IbltTier::select_for_delta(0), IbltTier::S);
        assert_eq!(IbltTier::select_for_delta(20), IbltTier::S);
        assert_eq!(IbltTier::select_for_delta(21), IbltTier::M);
        assert_eq!(IbltTier::select_for_delta(100), IbltTier::M);
        assert_eq!(IbltTier::select_for_delta(101), IbltTier::L);
        assert_eq!(IbltTier::select_for_delta(10_000), IbltTier::L);
    }

    #[test]
    fn tier_m_reconciles_beyond_tier_s_capacity() {
        // Tier S can't decode ~60 differences; tier M handles it.
        let mut a = Iblt::with_tier(IbltTier::M);
        let mut b = Iblt::with_tier(IbltTier::M);
        for i in 0..50u8 {
            a.insert(&test_key(i));
        }
        for i in 50..110u8 {
            b.insert(&test_key(i));
        }
        a.subtract(&b).unwrap();
        let (pos, neg) = a.decode().unwrap();
        assert_eq!(pos.len(), 50);
        assert_eq!(neg.len(), 60);
    }

    #[test]
    fn subtract_rejects_dimension_mismatch() {
        let mut s = Iblt::with_tier(IbltTier::S);
        let m = Iblt::with_tier(IbltTier::M);
        assert!(s.subtract(&m).is_err());
    }

    #[test]
    fn from_bytes_rejects_over_cap() {
        // Fabricate a header claiming 2001 cells — MUST-025 says reject.
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_IBLT_CELLS + 1) as u16).to_be_bytes());
        buf.push(3);
        buf.extend(std::iter::repeat(0u8).take((MAX_IBLT_CELLS + 1) * 68));
        assert!(Iblt::from_bytes(&buf).is_err());
    }

    #[test]
    #[should_panic]
    fn with_capacity_panics_over_cap() {
        let _ = Iblt::with_capacity(MAX_IBLT_CELLS + 1, 3);
    }
}
