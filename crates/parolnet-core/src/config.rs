//! Configuration for a ParolNet node.

use std::path::PathBuf;

/// Top-level configuration for a ParolNet node.
#[derive(Clone, Debug)]
pub struct ParolNetConfig {
    /// Path for persistent storage (None = ephemeral only).
    pub storage_path: Option<PathBuf>,
    /// Whether to start in decoy mode.
    pub decoy_mode: bool,
    /// Maximum number of relay circuits to pre-build.
    pub circuit_pool_size: usize,
    /// Federation peering configuration. `None` disables federation peering —
    /// the node still accepts presence/lookup HTTP traffic from other relays
    /// but does not open persistent federation links itself.
    pub federation: Option<FederationConfig>,
}

impl Default for ParolNetConfig {
    fn default() -> Self {
        Self {
            storage_path: None,
            decoy_mode: false,
            circuit_pool_size: 3,
            federation: None,
        }
    }
}

/// Federation peering configuration (PNP-008 §5).
///
/// Defaults are taken directly from the PNP-008 spec:
/// - `max_active_peers = 8` (PNP-008-MUST-015)
/// - `heartbeat_interval = 60 s` (PNP-008-MUST-011)
/// - `unreachable_threshold = 180 s` (PNP-008-MUST-011)
/// - `resync_interval = 300 s ± 30 s jitter` (PNP-008-SHOULD-003)
/// - `descriptor_rate_per_min = 100`, `sync_inits_per_hour = 10`
///   (PNP-008-MUST-022)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationConfig {
    /// Maximum concurrent ACTIVE federation peers (PNP-008-MUST-015).
    pub max_active_peers: usize,
    /// Heartbeat emit cadence in seconds (PNP-008-MUST-011).
    pub heartbeat_interval_secs: u64,
    /// Silence threshold before a peer is considered unreachable
    /// (PNP-008-MUST-011).
    pub unreachable_threshold_secs: u64,
    /// Incremental re-sync interval while ACTIVE (PNP-008-SHOULD-003).
    pub resync_interval_secs: u64,
    /// Jitter window applied to the resync interval (PNP-008-SHOULD-003).
    pub resync_jitter_secs: u64,
    /// Rate-limit cap on inbound descriptor deliveries per peer per minute
    /// (PNP-008-MUST-022).
    pub descriptor_rate_per_min: u32,
    /// Rate-limit cap on FederationSync initiations per peer per hour
    /// (PNP-008-MUST-022).
    pub sync_inits_per_hour: u32,
    /// Upper bound on the reconnect-backoff delay (PNP-008-MUST-020).
    pub reconnect_backoff_max_secs: u64,
    /// Base reconnect-backoff delay; the full formula is
    /// `min(max, base * 2^failures) ± 25%` (PNP-008-MUST-020).
    pub reconnect_backoff_base_secs: u64,
    /// Static list of federation peer HTTP URLs to keep persistent links to.
    /// Typically supplied via `PEER_RELAY_URLS`-style operator config; left
    /// empty a node still accepts inbound federation links.
    pub peer_urls: Vec<String>,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            max_active_peers: 8,
            heartbeat_interval_secs: 60,
            unreachable_threshold_secs: 180,
            resync_interval_secs: 300,
            resync_jitter_secs: 30,
            descriptor_rate_per_min: 100,
            sync_inits_per_hour: 10,
            reconnect_backoff_max_secs: 3600,
            reconnect_backoff_base_secs: 30,
            peer_urls: Vec::new(),
        }
    }
}

impl FederationConfig {
    /// Compute the PNP-008-MUST-020 reconnect delay (base only — callers add
    /// the ±25 % jitter).
    pub fn reconnect_delay_base(&self, failures: u32) -> u64 {
        let shift = failures.min(63);
        let raw = self
            .reconnect_backoff_base_secs
            .saturating_mul(1u64 << shift);
        raw.min(self.reconnect_backoff_max_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_parolnet_config_has_no_federation() {
        // Federation is opt-in; Default must leave it disabled so existing
        // callers are unaffected.
        assert!(ParolNetConfig::default().federation.is_none());
    }

    #[test]
    fn federation_config_defaults_match_pnp_008() {
        let c = FederationConfig::default();
        assert_eq!(c.max_active_peers, 8);
        assert_eq!(c.heartbeat_interval_secs, 60);
        assert_eq!(c.unreachable_threshold_secs, 180);
        assert_eq!(c.resync_interval_secs, 300);
        assert_eq!(c.descriptor_rate_per_min, 100);
        assert_eq!(c.sync_inits_per_hour, 10);
        assert_eq!(c.reconnect_backoff_max_secs, 3600);
    }

    #[test]
    fn reconnect_delay_saturates_at_cap() {
        let c = FederationConfig::default();
        assert_eq!(c.reconnect_delay_base(0), 30);
        assert_eq!(c.reconnect_delay_base(1), 60);
        assert_eq!(c.reconnect_delay_base(6), 1920);
        // 30 * 128 = 3840 → capped at 3600.
        assert_eq!(c.reconnect_delay_base(7), 3600);
        assert_eq!(c.reconnect_delay_base(100), 3600);
    }
}
