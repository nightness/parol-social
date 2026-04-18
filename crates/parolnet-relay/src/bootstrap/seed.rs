//! Seed-relay channel (PNP-008 §8.2).
//!
//! Seed relays are a compiled-in list of `BootstrapBundle` payloads shipped in
//! the release binary. They MUST be verifiable without any network access
//! (PNP-008-MUST-075) so a first-run node can produce candidate descriptors
//! before any DNS/HTTPS/DHT attempt.
//!
//! The actual seed bundle will be minted by `parolnet-authority-cli` and
//! embedded via `include_bytes!` in this module for release builds. During
//! development and conformance testing an empty seed list is used — the
//! invariant we care about is that whatever ships MUST satisfy MUST-071 and
//! MUST-072 at startup, enforced by [`SeedChannel::load`].

use super::bundle::BootstrapBundle;
use super::{ChannelError, ChannelKind};

/// Placeholder for the compiled-in seed bundle. A release build overrides
/// this with `include_bytes!("../../../seeds/current.cbor")` (or similar)
/// once `parolnet-authority-cli` mints the payload.
pub const EMBEDDED_SEED_CBOR: &[u8] = &[];

/// Seed-list loader.
pub struct SeedChannel;

impl SeedChannel {
    pub fn kind() -> ChannelKind {
        ChannelKind::Seed
    }

    /// Load the compiled-in seed bundle and run the §8.7 gates.
    ///
    /// PNP-008-MUST-075: this method MUST NOT touch the network. It is pure
    /// CBOR decode + `verify_and_validate`.
    pub fn load(
        authority_pubkeys: &[[u8; 32]],
        now_secs: u64,
    ) -> Result<BootstrapBundle, ChannelError> {
        if EMBEDDED_SEED_CBOR.is_empty() {
            return Err(ChannelError::NotFound);
        }
        let bundle = BootstrapBundle::from_cbor(EMBEDDED_SEED_CBOR)
            .map_err(ChannelError::from)?;
        bundle
            .verify_and_validate(authority_pubkeys, now_secs)
            .map_err(ChannelError::from)?;
        Ok(bundle)
    }

    /// Whether this channel requires network access — always false, used by
    /// the fallback chain to prioritize seeds at startup.
    pub const fn requires_network() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_channel_does_not_require_network() {
        // PNP-008-MUST-075.
        assert!(!SeedChannel::requires_network());
    }

    #[test]
    fn seed_kind_is_highest_priority() {
        assert_eq!(SeedChannel::kind().priority(), 1);
    }

    #[test]
    fn empty_embedded_seed_returns_not_found() {
        // With no compiled-in bundle the loader yields NotFound; it MUST NOT
        // silently succeed or attempt a network fallback on its own.
        let err = SeedChannel::load(&[], 1_000).unwrap_err();
        assert_eq!(err, ChannelError::NotFound);
    }
}
