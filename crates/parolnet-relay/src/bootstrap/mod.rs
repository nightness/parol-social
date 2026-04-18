//! Bootstrap channels (PNP-008 §8).
//!
//! A node with no prior state MUST obtain at least one valid relay descriptor
//! before it can participate. This module implements the §8 fallback chain
//! (seed → DNS TXT → HTTPS → DHT → manual/LAN) and the `BootstrapBundle`
//! verification pipeline that every channel funnels its output through.
//!
//! DHT (§8.5) is added in a follow-up commit — this module exposes the three
//! network-free or TLS-backed channels and the verifier that all channels share.
//!
//! ## Spec mapping
//! - §8.1 MUST-038 / MUST-039 — every channel feeds the same verifier; no channel is trusted
//! - §8.2 MUST-040 / SHOULD-007 — [`seed`]
//! - §8.3 MUST-041..044 — [`dns`]
//! - §8.4 MUST-045 / MUST-046 / MUST-076 — [`https`]
//! - §8.6 MUST-050 — [`ChannelError::BootstrapExhausted`]
//! - §8.7 MUST-071..076 — [`bundle`] enforces version, freshness, content-type

pub mod bundle;
pub mod dns;
pub mod https;
pub mod seed;

pub use bundle::{BootstrapBundle, BundleError, BUNDLE_VERSION, BUNDLE_MAX_AGE_SECS};

/// Per-attempt timeout on any bootstrap channel (PNP-008-MUST-074).
pub const CHANNEL_ATTEMPT_TIMEOUT_SECS: u64 = 10;

/// Cooldown before retrying a timed-out endpoint (PNP-008-MUST-074).
pub const CHANNEL_RETRY_COOLDOWN_SECS: u64 = 60;

/// Overall failure window before emitting the "no bootstrap" error
/// (PNP-008-MUST-050).
pub const BOOTSTRAP_FAILURE_WINDOW_SECS: u64 = 600;

/// Channel identity for the §8.1 priority registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelKind {
    /// Priority 1 — compiled-in seeds (§8.2).
    Seed,
    /// Priority 2 — DNS TXT (§8.3).
    DnsTxt,
    /// Priority 3 — HTTPS directory (§8.4).
    Https,
    /// Priority 4 — mainline DHT BEP-44 (§8.5). Added in follow-up.
    Dht,
    /// Priority 5 — manual / LAN (PNP-003).
    Manual,
}

impl ChannelKind {
    /// PNP-008 §8.1 priority (1 = highest).
    pub fn priority(self) -> u8 {
        match self {
            Self::Seed => 1,
            Self::DnsTxt => 2,
            Self::Https => 3,
            Self::Dht => 4,
            Self::Manual => 5,
        }
    }

    /// Stable string identifier used in logs and conformance fixtures.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::DnsTxt => "dns_txt",
            Self::Https => "https",
            Self::Dht => "dht",
            Self::Manual => "lan",
        }
    }
}

/// Result of a single channel attempt.
#[derive(Debug)]
pub enum ChannelOutcome {
    /// Channel returned a verified bundle.
    Bundle(BootstrapBundle),
    /// Channel failed in a recoverable way (timeout, no record, bad sig).
    /// Fallback chain proceeds.
    Failed(ChannelError),
}

/// Errors emitted by bootstrap channels.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    #[error("per-attempt timeout exceeded ({0} s)")]
    Timeout(u64),
    #[error("endpoint in retry cooldown for {0} more seconds")]
    Cooldown(u64),
    #[error("no record")]
    NotFound,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("bundle invalid: {0}")]
    Bundle(#[from] BundleError),
    #[error("wrong content-type: {0}")]
    ContentType(String),
    #[error("all channels failed within the {0} s window")]
    BootstrapExhausted(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_priority_order_matches_spec() {
        assert_eq!(ChannelKind::Seed.priority(), 1);
        assert_eq!(ChannelKind::DnsTxt.priority(), 2);
        assert_eq!(ChannelKind::Https.priority(), 3);
        assert_eq!(ChannelKind::Dht.priority(), 4);
        assert_eq!(ChannelKind::Manual.priority(), 5);
    }

    #[test]
    fn channel_identifiers_match_vector_fixture() {
        // vectors/PNP-008/bootstrap_channel_timeout.json pins these identifiers.
        assert_eq!(ChannelKind::Seed.as_str(), "seed");
        assert_eq!(ChannelKind::DnsTxt.as_str(), "dns_txt");
        assert_eq!(ChannelKind::Https.as_str(), "https");
        assert_eq!(ChannelKind::Dht.as_str(), "dht");
        assert_eq!(ChannelKind::Manual.as_str(), "lan");
    }

    #[test]
    fn channel_timeout_constants_match_spec() {
        assert_eq!(CHANNEL_ATTEMPT_TIMEOUT_SECS, 10);
        assert_eq!(CHANNEL_RETRY_COOLDOWN_SECS, 60);
        assert_eq!(BOOTSTRAP_FAILURE_WINDOW_SECS, 600);
    }
}
