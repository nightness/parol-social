//! Federation wire-type registry (PNP-008 §4).
//!
//! Codes `0x06 FederationSync`, `0x07 FederationHeartbeat`, and
//! `0x08 BridgeAnnouncement` are confined to federation links (§5) or
//! out-of-band bridge channels (§9). Per **PNP-008-MUST-004** they MUST NOT
//! be emitted on the public gossip mesh defined in PNP-005 — for that reason
//! these codes live in a distinct enum from [`crate::gossip::GossipPayloadType`].
//!
//! The full wire struct definitions (`FederationSync`, `FederationHeartbeat`,
//! `BridgeAnnouncement`) are introduced alongside the federation manager in a
//! later commit. This module pins the type-code assignment so the `message` and
//! `gossip` registries stay honest.
//!
//! All values here are spec-normative constants, not implementation choices.

use serde::{Deserialize, Serialize};

/// Federation payload types (PNP-008 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FederationPayloadType {
    /// IBLT-encoded descriptor-set summary + delta request (PNP-008 §4.1).
    FederationSync = 0x06,
    /// Liveness probe with monotonic counter (PNP-008 §4.2).
    FederationHeartbeat = 0x07,
    /// Out-of-band bridge descriptor delivery; never gossiped (PNP-008 §4.3).
    BridgeAnnouncement = 0x08,
}

impl FederationPayloadType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x06 => Some(Self::FederationSync),
            0x07 => Some(Self::FederationHeartbeat),
            0x08 => Some(Self::BridgeAnnouncement),
            _ => None,
        }
    }

    /// Whether this payload type is permitted on a standalone federation link
    /// (PNP-008 §5) vs. an out-of-band bridge channel (§9).
    pub fn is_federation_link_ok(self) -> bool {
        matches!(self, Self::FederationSync | Self::FederationHeartbeat)
    }
}

/// Heartbeat minimum emit cadence (PNP-008-MUST-011).
pub const HEARTBEAT_MIN_INTERVAL_SECS: u64 = 60;

/// Receiver silence threshold before peer is considered unreachable
/// (PNP-008-MUST-011).
pub const HEARTBEAT_UNREACHABLE_SECS: u64 = 180;

/// Per-peer cap on descriptor deliveries per minute (PNP-008-MUST-022).
pub const RATE_LIMIT_DESCRIPTORS_PER_MIN: u32 = 100;

/// Per-peer cap on FederationSync initiations per hour (PNP-008-MUST-022).
pub const RATE_LIMIT_SYNC_INITS_PER_HOUR: u32 = 10;

/// Replay-protection window on sync_id (PNP-008-MUST-006).
pub const SYNC_ID_REPLAY_WINDOW_SECS: u64 = 300;

/// Max clock skew accepted on federation messages (PNP-008-MUST-008).
pub const FEDERATION_MAX_CLOCK_SKEW_SECS: i64 = 300;

/// BridgeAnnouncement maximum validity window (PNP-008-MUST-013).
pub const BRIDGE_ANNOUNCEMENT_MAX_VALIDITY_SECS: u64 = 7 * 86400;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_spec_table() {
        // PNP-008 §4 table — these codes are on-the-wire normative.
        assert_eq!(FederationPayloadType::FederationSync as u8, 0x06);
        assert_eq!(FederationPayloadType::FederationHeartbeat as u8, 0x07);
        assert_eq!(FederationPayloadType::BridgeAnnouncement as u8, 0x08);
    }

    #[test]
    fn roundtrip_from_u8() {
        for t in [
            FederationPayloadType::FederationSync,
            FederationPayloadType::FederationHeartbeat,
            FederationPayloadType::BridgeAnnouncement,
        ] {
            assert_eq!(FederationPayloadType::from_u8(t as u8), Some(t));
        }
        // Gossip codes from PNP-005 must not round-trip as federation codes.
        assert_eq!(FederationPayloadType::from_u8(0x01), None);
        assert_eq!(FederationPayloadType::from_u8(0x05), None);
        assert_eq!(FederationPayloadType::from_u8(0x09), None);
    }

    #[test]
    fn federation_codes_disjoint_from_gossip() {
        // PNP-008-MUST-004: 0x06..=0x08 must not be emitted on the PNP-005
        // gossip mesh. Ensure the gossip registry does not overlap.
        for code in [0x06u8, 0x07, 0x08] {
            assert!(
                crate::gossip::GossipPayloadType::from_u8(code).is_none(),
                "gossip registry must not accept federation code 0x{:02x}",
                code
            );
        }
    }

    #[test]
    fn bridge_announcement_not_allowed_on_federation_link() {
        // BridgeAnnouncement is distributed out-of-band per §9 — not inside a
        // FederationSync/Heartbeat session.
        assert!(FederationPayloadType::FederationSync.is_federation_link_ok());
        assert!(FederationPayloadType::FederationHeartbeat.is_federation_link_ok());
        assert!(!FederationPayloadType::BridgeAnnouncement.is_federation_link_ok());
    }
}
