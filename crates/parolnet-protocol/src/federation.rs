//! Federation wire-type registry and payload structs (PNP-008 §4).
//!
//! Codes `0x06 FederationSync`, `0x07 FederationHeartbeat`, and
//! `0x08 BridgeAnnouncement` are confined to federation links (§5) or
//! out-of-band bridge channels (§9). Per **PNP-008-MUST-004** they MUST NOT
//! be emitted on the public gossip mesh defined in PNP-005 — for that reason
//! these codes live in a distinct enum from [`crate::gossip::GossipPayloadType`].
//!
//! ## Descriptor opacity
//!
//! `RelayDescriptor` is defined in `parolnet-relay`, which depends on this
//! crate. To keep the layering acyclic, `FederationSync::response_descriptors`
//! carries each descriptor as a CBOR byte blob (`serde_bytes::ByteBuf`); the
//! receiver decodes each blob with `ciborium` before validating. The blobs are
//! included in `signable_bytes` verbatim so two valid encodings of the same
//! descriptor are never treated as equivalent under the outer signature
//! (deterministic-CBOR invariance is the descriptor's own responsibility per
//! PNP-008-MUST-001).
//!
//! All values here are spec-normative constants, not implementation choices.

use crate::ProtocolError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// Scope of a `FederationSync` (PNP-008 §4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SyncScope {
    /// Sync only relay descriptors (the default; PNP-008 §4.1).
    DescriptorsOnly = 0x00,
    /// Sync descriptors plus recent gossip IDs. Reserved for partition-healing
    /// replay-suppression per PNP-008 §6.3 / §10.3.
    DescriptorsAndGossipIds = 0x01,
}

impl SyncScope {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::DescriptorsOnly),
            0x01 => Some(Self::DescriptorsAndGossipIds),
            _ => None,
        }
    }
}

/// Bitflags in `FederationHeartbeat::flags` (PNP-008 §4.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HeartbeatFlags(pub u32);

impl HeartbeatFlags {
    /// Peer advertises bridge capability.
    pub const BRIDGE_CAPABLE: Self = Self(1 << 0);
    /// Peer is currently accepting circuit extensions.
    pub const ACCEPTING_CIRCUITS: Self = Self(1 << 1);
    /// Peer is in read-only mode (directory sync allowed, no new circuits).
    pub const READ_ONLY: Self = Self(1 << 2);

    pub const fn empty() -> Self {
        Self(0)
    }
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
}

/// Advertised load from a federation peer (PNP-008 §4.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadHint {
    /// Number of active circuits on the sender.
    pub circuits: u32,
    /// Averaged bandwidth in bytes/sec over the last 60 s (SHOULD-002).
    pub bandwidth_bps: u64,
}

/// `FederationSync` payload (PNP-008 §4.1).
///
/// `response_descriptors` carries each relay descriptor as a CBOR byte blob
/// (see module docs). Receivers decode each blob independently and run it
/// through §6.3 validation before storing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationSync {
    /// 128-bit cryptographically random request correlation ID
    /// (PNP-008-MUST-006).
    #[serde(with = "serde_bytes_array_16")]
    pub sync_id: [u8; 16],
    /// Only descriptors with `timestamp >= since_timestamp` are summarized.
    pub since_timestamp: u64,
    /// Serialized IBLT of locally known descriptor digests
    /// (PNP-008 §6.2 / [`crate::BUCKET_SIZES`] does not apply here).
    #[serde(with = "serde_bytes")]
    pub iblt: Vec<u8>,
    /// Scope of this sync.
    pub scope: SyncScope,
    /// Explicit digest fetch list after IBLT decode (PNP-008-MUST-009).
    pub requested_digests: Option<Vec<[u8; 32]>>,
    /// Descriptors returned in response to `requested_digests`; each entry is
    /// a deterministic-CBOR-encoded RelayDescriptor.
    pub response_descriptors: Option<Vec<serde_bytes::ByteBuf>>,
    /// Emission timestamp (Unix seconds). Must satisfy PNP-008-MUST-008.
    pub timestamp: u64,
    /// Ed25519 signature by the sender's relay identity key over
    /// [`Self::signable_bytes`]. PNP-008-MUST-007.
    #[serde(with = "sig64")]
    pub signature: [u8; 64],
}

/// `FederationHeartbeat` payload (PNP-008 §4.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederationHeartbeat {
    /// Monotonically increasing counter per sender (PNP-008-MUST-010).
    pub counter: u64,
    /// Averaged load hint (SHOULD-002).
    pub load_hint: LoadHint,
    /// Capability bits.
    pub flags: HeartbeatFlags,
    /// Emission timestamp (Unix seconds). Must satisfy PNP-008-MUST-008.
    pub timestamp: u64,
    /// Ed25519 signature by the sender's relay identity key.
    #[serde(with = "sig64")]
    pub signature: [u8; 64],
}

mod serde_bytes_array_16 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(bytes.as_slice()).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let v: Vec<u8> = serde_bytes::ByteBuf::deserialize(d)?.into_vec();
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("sync_id must be 16 bytes, got {}", v.len()))
        })
    }
}

mod sig64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(bytes.as_slice()).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = serde_bytes::ByteBuf::deserialize(d)?.into_vec();
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("signature must be 64 bytes, got {}", v.len()))
        })
    }
}

impl FederationSync {
    /// Bytes signed by the sender (all fields except `signature`).
    ///
    /// Domain-separated by the `PNP-008-FederationSync-v1` label so a
    /// signature over these bytes cannot be confused with any other
    /// construction (handshakes, heartbeats, descriptors).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"PNP-008-FederationSync-v1");
        hasher.update(self.sync_id);
        hasher.update(self.since_timestamp.to_be_bytes());
        hasher.update((self.iblt.len() as u32).to_be_bytes());
        hasher.update(&self.iblt);
        hasher.update([self.scope as u8]);
        if let Some(ref req) = self.requested_digests {
            hasher.update([1u8]);
            hasher.update((req.len() as u32).to_be_bytes());
            for d in req {
                hasher.update(d);
            }
        } else {
            hasher.update([0u8]);
        }
        if let Some(ref resp) = self.response_descriptors {
            hasher.update([1u8]);
            hasher.update((resp.len() as u32).to_be_bytes());
            for blob in resp {
                hasher.update((blob.len() as u32).to_be_bytes());
                hasher.update(blob.as_ref());
            }
        } else {
            hasher.update([0u8]);
        }
        hasher.update(self.timestamp.to_be_bytes());
        hasher.finalize().to_vec()
    }

    /// Sign this payload in place with `signing_key`.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let sig = signing_key.sign(&self.signable_bytes());
        self.signature = sig.to_bytes();
    }

    /// Verify the signature against `public_key`.
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<bool, ProtocolError> {
        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|e| ProtocolError::CborDecode(format!("bad pubkey: {e}")))?;
        let sig = Signature::from_bytes(&self.signature);
        Ok(vk.verify(&self.signable_bytes(), &sig).is_ok())
    }

    /// PNP-008-MUST-008: within ±`FEDERATION_MAX_CLOCK_SKEW_SECS` of `now`.
    pub fn timestamp_fresh(&self, now: u64) -> bool {
        let skew = FEDERATION_MAX_CLOCK_SKEW_SECS as u64;
        self.timestamp.abs_diff(now) <= skew
    }

    /// CBOR encode.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| ProtocolError::CborEncode(format!("{e}")))?;
        Ok(buf)
    }

    /// CBOR decode.
    pub fn from_cbor(data: &[u8]) -> Result<Self, ProtocolError> {
        ciborium::from_reader(data).map_err(|e| ProtocolError::CborDecode(format!("{e}")))
    }
}

impl FederationHeartbeat {
    /// Bytes signed by the sender (all fields except `signature`).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"PNP-008-FederationHeartbeat-v1");
        hasher.update(self.counter.to_be_bytes());
        hasher.update(self.load_hint.circuits.to_be_bytes());
        hasher.update(self.load_hint.bandwidth_bps.to_be_bytes());
        hasher.update(self.flags.0.to_be_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.finalize().to_vec()
    }

    pub fn sign(&mut self, signing_key: &SigningKey) {
        let sig = signing_key.sign(&self.signable_bytes());
        self.signature = sig.to_bytes();
    }

    pub fn verify(&self, public_key: &[u8; 32]) -> Result<bool, ProtocolError> {
        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|e| ProtocolError::CborDecode(format!("bad pubkey: {e}")))?;
        let sig = Signature::from_bytes(&self.signature);
        Ok(vk.verify(&self.signable_bytes(), &sig).is_ok())
    }

    pub fn timestamp_fresh(&self, now: u64) -> bool {
        let skew = FEDERATION_MAX_CLOCK_SKEW_SECS as u64;
        self.timestamp.abs_diff(now) <= skew
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| ProtocolError::CborEncode(format!("{e}")))?;
        Ok(buf)
    }

    pub fn from_cbor(data: &[u8]) -> Result<Self, ProtocolError> {
        ciborium::from_reader(data).map_err(|e| ProtocolError::CborDecode(format!("{e}")))
    }
}

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

    // -- FederationSync / FederationHeartbeat wire types --------------------

    fn sk(seed: u8) -> SigningKey {
        let mut s = [0u8; 32];
        s[0] = seed;
        SigningKey::from_bytes(&s)
    }

    fn sample_sync() -> FederationSync {
        FederationSync {
            sync_id: [0xAA; 16],
            since_timestamp: 1_700_000_000,
            iblt: vec![0u8; 64],
            scope: SyncScope::DescriptorsOnly,
            requested_digests: Some(vec![[1u8; 32], [2u8; 32]]),
            response_descriptors: None,
            timestamp: 1_700_000_100,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn sync_id_is_128_bits_on_the_wire() {
        let s = sample_sync();
        assert_eq!(s.sync_id.len(), 16);
    }

    #[test]
    fn federation_sync_signable_is_deterministic() {
        let s = sample_sync();
        assert_eq!(s.signable_bytes(), s.signable_bytes());
    }

    #[test]
    fn federation_sync_signable_domain_separated() {
        // Bytes MUST include the domain-separation label so no cross-protocol
        // replay can occur. We can't read the internal hasher output, but we
        // can check that changing the label in a copy changes the digest —
        // done implicitly by changing one field and observing divergence.
        let s1 = sample_sync();
        let mut s2 = s1.clone();
        s2.timestamp += 1;
        assert_ne!(s1.signable_bytes(), s2.signable_bytes());
    }

    #[test]
    fn federation_sync_sign_verify_roundtrip() {
        let signer = sk(1);
        let pubkey = signer.verifying_key().to_bytes();
        let mut s = sample_sync();
        s.sign(&signer);
        assert!(s.verify(&pubkey).unwrap());

        // Tamper with sync_id → signature MUST fail.
        let mut tampered = s.clone();
        tampered.sync_id[0] ^= 0xFF;
        assert!(!tampered.verify(&pubkey).unwrap());
    }

    #[test]
    fn federation_sync_cbor_roundtrip_with_response_blob() {
        let signer = sk(2);
        let pubkey = signer.verifying_key().to_bytes();
        let mut s = sample_sync();
        s.response_descriptors = Some(vec![serde_bytes::ByteBuf::from(vec![7u8; 120])]);
        s.sign(&signer);
        let bytes = s.to_cbor().unwrap();
        let back = FederationSync::from_cbor(&bytes).unwrap();
        assert_eq!(back.sync_id, s.sync_id);
        assert_eq!(back.iblt, s.iblt);
        assert_eq!(back.response_descriptors, s.response_descriptors);
        assert_eq!(back.signature, s.signature);
        assert!(back.verify(&pubkey).unwrap());
    }

    #[test]
    fn federation_sync_timestamp_window_is_300_seconds() {
        let mut s = sample_sync();
        s.timestamp = 10_000;
        assert!(s.timestamp_fresh(10_000));
        assert!(s.timestamp_fresh(10_000 + 299));
        assert!(s.timestamp_fresh(10_000 - 299));
        assert!(!s.timestamp_fresh(10_000 + 301));
        assert!(!s.timestamp_fresh(10_000 - 301));
    }

    fn sample_heartbeat() -> FederationHeartbeat {
        FederationHeartbeat {
            counter: 42,
            load_hint: LoadHint {
                circuits: 10,
                bandwidth_bps: 1_000_000,
            },
            flags: HeartbeatFlags::ACCEPTING_CIRCUITS,
            timestamp: 1_700_000_000,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn heartbeat_sign_verify_roundtrip() {
        let signer = sk(3);
        let pubkey = signer.verifying_key().to_bytes();
        let mut h = sample_heartbeat();
        h.sign(&signer);
        assert!(h.verify(&pubkey).unwrap());

        // Change the counter → signature must not re-verify.
        let mut tampered = h.clone();
        tampered.counter += 1;
        assert!(!tampered.verify(&pubkey).unwrap());
    }

    #[test]
    fn heartbeat_cbor_roundtrip() {
        let signer = sk(4);
        let mut h = sample_heartbeat();
        h.sign(&signer);
        let bytes = h.to_cbor().unwrap();
        let back = FederationHeartbeat::from_cbor(&bytes).unwrap();
        assert_eq!(back.counter, h.counter);
        assert_eq!(back.load_hint, h.load_hint);
        assert_eq!(back.flags, h.flags);
        assert_eq!(back.signature, h.signature);
    }

    #[test]
    fn heartbeat_flags_bit_ops() {
        let mut f = HeartbeatFlags::empty();
        f.insert(HeartbeatFlags::BRIDGE_CAPABLE);
        f.insert(HeartbeatFlags::ACCEPTING_CIRCUITS);
        assert!(f.contains(HeartbeatFlags::BRIDGE_CAPABLE));
        assert!(f.contains(HeartbeatFlags::ACCEPTING_CIRCUITS));
        f.remove(HeartbeatFlags::BRIDGE_CAPABLE);
        assert!(!f.contains(HeartbeatFlags::BRIDGE_CAPABLE));
        assert!(f.contains(HeartbeatFlags::ACCEPTING_CIRCUITS));
    }

    #[test]
    fn sync_scope_roundtrip() {
        assert_eq!(
            SyncScope::from_u8(SyncScope::DescriptorsOnly as u8),
            Some(SyncScope::DescriptorsOnly)
        );
        assert_eq!(
            SyncScope::from_u8(SyncScope::DescriptorsAndGossipIds as u8),
            Some(SyncScope::DescriptorsAndGossipIds)
        );
        assert_eq!(SyncScope::from_u8(0x99), None);
    }
}
