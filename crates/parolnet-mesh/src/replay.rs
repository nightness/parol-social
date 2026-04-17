//! `sync_id` replay protection for federation syncs (PNP-008-MUST-006).
//!
//! Any `FederationSync` (PNP-008 §4.1) carries a 128-bit random `sync_id`.
//! The receiver MUST drop duplicates seen within the last 5 minutes. This
//! module implements that rule with a bounded LRU-by-time cache — entries
//! older than the window are pruned on every touch so memory stays
//! proportional to recent traffic, not cumulative history.
//!
//! The cache is intentionally *per federation peer*: two peers sharing a
//! sync_id by random chance is astronomically unlikely (birthday-bound
//! ≈ 2^{-64} per collision), but keeping state keyed per peer also prevents
//! a malicious peer from evicting a legitimate peer's entries.

use crate::MeshError;
use std::collections::HashMap;

use parolnet_protocol::federation::SYNC_ID_REPLAY_WINDOW_SECS;

/// Bounded replay-protection cache keyed by 128-bit `sync_id`.
#[derive(Clone, Debug, Default)]
pub struct SyncIdReplayCache {
    seen: HashMap<[u8; 16], u64>,
    /// Hard cap on entries — defends against flooding a peer who then replays
    /// old IDs after the window slides. `0` disables the cap.
    max_entries: usize,
}

impl SyncIdReplayCache {
    /// New cache with the default cap of 4096 entries.
    pub fn new() -> Self {
        Self::with_capacity(4096)
    }

    /// New cache with an explicit entry cap.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            seen: HashMap::with_capacity(max_entries.min(4096)),
            max_entries,
        }
    }

    /// Observe a `sync_id` arriving at `now`. Returns `Err` on replay.
    ///
    /// A replay is any `sync_id` already observed within the last
    /// [`SYNC_ID_REPLAY_WINDOW_SECS`] seconds. After the window has slid past,
    /// the same `sync_id` becomes acceptable again — the cache evicts it on
    /// the next call and the insert succeeds.
    pub fn observe(&mut self, sync_id: &[u8; 16], now: u64) -> Result<(), MeshError> {
        self.prune(now);
        if let Some(&prev) = self.seen.get(sync_id) {
            if now.saturating_sub(prev) < SYNC_ID_REPLAY_WINDOW_SECS {
                return Err(MeshError::SyncError(format!(
                    "PNP-008-MUST-006: sync_id replayed within {} s",
                    SYNC_ID_REPLAY_WINDOW_SECS
                )));
            }
        }
        // Enforce the entry cap before insert.
        if self.max_entries > 0 && self.seen.len() >= self.max_entries {
            // Evict the oldest entry (scan is O(n) but n <= max_entries).
            if let Some((oldest_key, _)) = self.seen.iter().min_by_key(|(_, ts)| **ts) {
                let k = *oldest_key;
                self.seen.remove(&k);
            }
        }
        self.seen.insert(*sync_id, now);
        Ok(())
    }

    /// Drop entries older than the replay window.
    pub fn prune(&mut self, now: u64) {
        let cutoff = now.saturating_sub(SYNC_ID_REPLAY_WINDOW_SECS);
        self.seen.retain(|_, ts| *ts >= cutoff);
    }

    /// Count currently tracked entries (after any lazy pruning the caller
    /// chose to perform).
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_id_is_accepted() {
        let mut c = SyncIdReplayCache::new();
        assert!(c.observe(&[1u8; 16], 1000).is_ok());
    }

    #[test]
    fn replay_within_window_is_rejected() {
        let mut c = SyncIdReplayCache::new();
        c.observe(&[1u8; 16], 1000).unwrap();
        assert!(c.observe(&[1u8; 16], 1000 + 100).is_err());
        assert!(c
            .observe(&[1u8; 16], 1000 + SYNC_ID_REPLAY_WINDOW_SECS - 1)
            .is_err());
    }

    #[test]
    fn replay_past_window_is_accepted_again() {
        let mut c = SyncIdReplayCache::new();
        c.observe(&[1u8; 16], 1000).unwrap();
        // Exactly at the window boundary: window is exclusive.
        assert!(c
            .observe(&[1u8; 16], 1000 + SYNC_ID_REPLAY_WINDOW_SECS)
            .is_ok());
    }

    #[test]
    fn distinct_ids_do_not_collide() {
        let mut c = SyncIdReplayCache::new();
        for i in 0u8..100 {
            assert!(c.observe(&[i; 16], 1000 + i as u64).is_ok());
        }
    }

    #[test]
    fn prune_drops_old_entries() {
        let mut c = SyncIdReplayCache::new();
        c.observe(&[1u8; 16], 1000).unwrap();
        c.observe(&[2u8; 16], 1000).unwrap();
        assert_eq!(c.len(), 2);
        c.prune(1000 + SYNC_ID_REPLAY_WINDOW_SECS + 1);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn entry_cap_is_enforced() {
        let mut c = SyncIdReplayCache::with_capacity(4);
        for i in 0u8..4 {
            c.observe(&[i; 16], 1000 + i as u64).unwrap();
        }
        assert_eq!(c.len(), 4);
        // The 5th insert evicts the oldest rather than erroring.
        c.observe(&[4u8; 16], 1005).unwrap();
        assert_eq!(c.len(), 4);
        // The oldest (key [0; 16], ts 1000) should be gone; replay acceptable.
        assert!(c.observe(&[0u8; 16], 1006).is_ok());
    }

    #[test]
    fn window_matches_spec() {
        assert_eq!(SYNC_ID_REPLAY_WINDOW_SECS, 300);
    }
}
