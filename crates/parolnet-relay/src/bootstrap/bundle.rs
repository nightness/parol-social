//! `BootstrapBundle` — the signed descriptor delivery format shared by every
//! §8 channel.
//!
//! ## Verification order (normative)
//!
//! PNP-008-MUST-071 and MUST-072 together pin an exact ordering of
//! validation steps:
//!
//! 1. **Version gate** (MUST-071): reject if `version != 0x01` **before**
//!    any signature work happens.
//! 2. **Signature verification** (MUST-043, MUST-046, MUST-049): verify the
//!    Ed25519 signature against a compiled-in authority key.
//! 3. **Freshness check** (MUST-072): reject if `now − issued_at > 7 × 86400`.
//!    This follows the signature check — a stale-but-signed bundle must not
//!    leak its freshness window to unauthenticated callers.
//! 4. **Descriptor enumeration** — only after the three gates above.
//!
//! This order is exercised by [`BootstrapBundle::verify_and_validate`].

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parolnet_protocol::address::PeerId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::directory::RelayDescriptor;

/// Wire version for `BootstrapBundle` — PNP-008-MUST-071.
pub const BUNDLE_VERSION: u8 = 0x01;

/// Maximum bundle age in seconds — PNP-008-MUST-072 (7 days).
pub const BUNDLE_MAX_AGE_SECS: u64 = 7 * 86_400;

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

/// PNP-008 §8.3 / §8.4 / §8.5 bootstrap bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapBundle {
    /// PNP-008-MUST-071 — MUST be [`BUNDLE_VERSION`] == 0x01.
    pub version: u8,
    /// Descriptors carried by this bundle — each must pass §6.3 before use.
    pub descriptors: Vec<RelayDescriptor>,
    /// Seconds since UNIX epoch at issuance. Drives MUST-072 freshness.
    pub issued_at: u64,
    /// Ed25519 signature by an authority over [`Self::signable_bytes`].
    #[serde(with = "sig64")]
    pub signature: [u8; 64],
}

/// Errors from `BootstrapBundle` verification. Ordering of returning these
/// variants is normative — callers relying on the error kind for policy
/// (e.g. rate limiting a channel after repeated bad signatures) need the
/// spec-mandated priority preserved.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    #[error("MUST-071: BootstrapBundle version {0:#x} != 0x01")]
    WrongVersion(u8),
    #[error("MUST-043/046/049: signature verification failed")]
    SignatureInvalid,
    #[error("MUST-072: bundle stale — {age} s > {max} s")]
    Stale { age: u64, max: u64 },
    #[error("CBOR decode failed: {0}")]
    CborDecode(String),
    #[error("CBOR encode failed: {0}")]
    CborEncode(String),
    #[error("no trusted authority accepted the bundle signature")]
    NoTrustedAuthority,
}

impl BootstrapBundle {
    /// Build a new bundle and sign it. Used by tooling and tests; production
    /// seed-list generation lives in `parolnet-authority-cli`.
    pub fn signed(
        descriptors: Vec<RelayDescriptor>,
        issued_at: u64,
        signing_key: &SigningKey,
    ) -> Self {
        let mut b = Self {
            version: BUNDLE_VERSION,
            descriptors,
            issued_at,
            signature: [0u8; 64],
        };
        let sig = signing_key.sign(&b.signable_bytes());
        b.signature = sig.to_bytes();
        b
    }

    /// Bytes signed by the authority.
    ///
    /// Domain-separated with the label `PNP-008-BootstrapBundle-v1` so no
    /// cross-protocol replay is possible. Descriptors are folded by their
    /// individual `signable_bytes` — if any descriptor body changes the
    /// outer signature invalidates too.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"PNP-008-BootstrapBundle-v1");
        hasher.update([self.version]);
        hasher.update(self.issued_at.to_be_bytes());
        hasher.update((self.descriptors.len() as u32).to_be_bytes());
        for d in &self.descriptors {
            let body = d.signable_bytes();
            hasher.update((body.len() as u32).to_be_bytes());
            hasher.update(&body);
            hasher.update(d.signature);
        }
        hasher.finalize().to_vec()
    }

    /// Perform the full §8 verification chain in spec order:
    /// version → signature → freshness → return descriptors.
    ///
    /// `authority_pubkeys` is the list of compiled-in authority keys
    /// (typically [`crate::trust_roots::AUTHORITY_PUBKEYS`]). Any one of them
    /// verifying the signature is sufficient.
    pub fn verify_and_validate(
        &self,
        authority_pubkeys: &[[u8; 32]],
        now_secs: u64,
    ) -> Result<&[RelayDescriptor], BundleError> {
        // MUST-071 — version gate BEFORE any signature math.
        if self.version != BUNDLE_VERSION {
            return Err(BundleError::WrongVersion(self.version));
        }
        // MUST-043 / MUST-046 / MUST-049 — signature.
        let signable = self.signable_bytes();
        let sig = Signature::from_bytes(&self.signature);
        let mut any_verified = false;
        for key_bytes in authority_pubkeys {
            if let Ok(vk) = VerifyingKey::from_bytes(key_bytes)
                && vk.verify(&signable, &sig).is_ok()
            {
                any_verified = true;
                break;
            }
        }
        if !any_verified {
            // Distinguish "no trusted authority known" from "sig invalid"
            // for clearer error reporting.
            if authority_pubkeys.is_empty() {
                return Err(BundleError::NoTrustedAuthority);
            }
            return Err(BundleError::SignatureInvalid);
        }
        // MUST-072 — freshness.
        let age = now_secs.saturating_sub(self.issued_at);
        if age > BUNDLE_MAX_AGE_SECS {
            return Err(BundleError::Stale {
                age,
                max: BUNDLE_MAX_AGE_SECS,
            });
        }
        Ok(&self.descriptors)
    }

    /// Deterministic CBOR encode (per PNP-008 §6.3).
    pub fn to_cbor(&self) -> Result<Vec<u8>, BundleError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| BundleError::CborEncode(format!("{e}")))?;
        Ok(buf)
    }

    /// Deterministic CBOR decode — caller still needs to run
    /// [`Self::verify_and_validate`].
    pub fn from_cbor(data: &[u8]) -> Result<Self, BundleError> {
        ciborium::from_reader(data).map_err(|e| BundleError::CborDecode(format!("{e}")))
    }

    /// All distinct `PeerId` values carried by this bundle.
    pub fn peer_ids(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.descriptors.iter().map(|d| d.peer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(seed: u8) -> SigningKey {
        let mut s = [0u8; 32];
        s[0] = seed;
        SigningKey::from_bytes(&s)
    }

    fn test_descriptor(seed: u8, ts: u64) -> RelayDescriptor {
        RelayDescriptor {
            peer_id: PeerId([seed; 32]),
            identity_key: [seed; 32],
            x25519_key: [seed; 32],
            addr: format!("{seed}.{seed}.0.1:9001").parse().unwrap(),
            bandwidth_class: 1,
            uptime_secs: 0,
            timestamp: ts,
            signature: [0u8; 64],
            bandwidth_estimate: 1000,
            next_pubkey: None,
        }
    }

    #[test]
    fn new_bundle_has_version_one() {
        let b = BootstrapBundle::signed(vec![], 1_000, &sk(1));
        assert_eq!(b.version, BUNDLE_VERSION);
        assert_eq!(b.version, 0x01);
    }

    #[test]
    fn signed_bundle_verifies() {
        let signer = sk(1);
        let pk = signer.verifying_key().to_bytes();
        let b = BootstrapBundle::signed(vec![test_descriptor(7, 500)], 1_000, &signer);
        let descriptors = b.verify_and_validate(&[pk], 1_100).unwrap();
        assert_eq!(descriptors.len(), 1);
    }

    #[test]
    fn wrong_version_rejected_before_signature_check() {
        // Even if the signature would verify, a wrong version byte MUST
        // error out. We deliberately DO NOT re-sign after bumping the byte.
        let signer = sk(1);
        let pk = signer.verifying_key().to_bytes();
        let mut b = BootstrapBundle::signed(vec![], 1_000, &signer);
        b.version = 0x02;
        let err = b.verify_and_validate(&[pk], 1_100).unwrap_err();
        assert_eq!(err, BundleError::WrongVersion(0x02));
    }

    #[test]
    fn version_zero_rejected() {
        let mut b = BootstrapBundle::signed(vec![], 1_000, &sk(1));
        b.version = 0x00;
        assert!(matches!(
            b.verify_and_validate(&[sk(1).verifying_key().to_bytes()], 1_100),
            Err(BundleError::WrongVersion(0x00))
        ));
    }

    #[test]
    fn stale_bundle_rejected() {
        let signer = sk(2);
        let pk = signer.verifying_key().to_bytes();
        let b = BootstrapBundle::signed(vec![], 1_000, &signer);
        let now = 1_000 + BUNDLE_MAX_AGE_SECS + 1;
        let err = b.verify_and_validate(&[pk], now).unwrap_err();
        assert!(matches!(err, BundleError::Stale { .. }));
    }

    #[test]
    fn exactly_at_max_age_accepted() {
        let signer = sk(3);
        let pk = signer.verifying_key().to_bytes();
        let b = BootstrapBundle::signed(vec![], 1_000, &signer);
        let now = 1_000 + BUNDLE_MAX_AGE_SECS;
        assert!(b.verify_and_validate(&[pk], now).is_ok());
    }

    #[test]
    fn signature_mismatch_rejected() {
        let signer = sk(1);
        let wrong_pk = sk(2).verifying_key().to_bytes();
        let b = BootstrapBundle::signed(vec![], 1_000, &signer);
        let err = b.verify_and_validate(&[wrong_pk], 1_100).unwrap_err();
        assert_eq!(err, BundleError::SignatureInvalid);
    }

    #[test]
    fn tampering_with_descriptor_invalidates_signature() {
        let signer = sk(4);
        let pk = signer.verifying_key().to_bytes();
        let mut b = BootstrapBundle::signed(vec![test_descriptor(1, 100)], 1_000, &signer);
        b.descriptors[0].bandwidth_estimate = 9_999;
        let err = b.verify_and_validate(&[pk], 1_100).unwrap_err();
        assert_eq!(err, BundleError::SignatureInvalid);
    }

    #[test]
    fn cbor_roundtrip_preserves_signature() {
        let signer = sk(5);
        let pk = signer.verifying_key().to_bytes();
        let b = BootstrapBundle::signed(
            vec![test_descriptor(1, 100), test_descriptor(2, 200)],
            1_000,
            &signer,
        );
        let bytes = b.to_cbor().unwrap();
        let back = BootstrapBundle::from_cbor(&bytes).unwrap();
        assert!(back.verify_and_validate(&[pk], 1_100).is_ok());
    }

    #[test]
    fn verify_order_version_before_signature() {
        // Empty authority list → signature check cannot succeed. But if
        // version is wrong, we should see WrongVersion, not
        // NoTrustedAuthority. This pins the ordering.
        let mut b = BootstrapBundle::signed(vec![], 1_000, &sk(1));
        b.version = 0xFF;
        let err = b.verify_and_validate(&[], 1_100).unwrap_err();
        assert_eq!(err, BundleError::WrongVersion(0xFF));
    }

    #[test]
    fn verify_order_signature_before_freshness() {
        // Stale AND wrong-sig bundle → sig error reported, not freshness.
        let signer = sk(1);
        let wrong_pk = sk(2).verifying_key().to_bytes();
        let b = BootstrapBundle::signed(vec![], 1_000, &signer);
        let far_future = 1_000 + BUNDLE_MAX_AGE_SECS + 100_000;
        let err = b.verify_and_validate(&[wrong_pk], far_future).unwrap_err();
        assert_eq!(err, BundleError::SignatureInvalid);
    }
}
