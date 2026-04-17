//! Identity rotation payload (PNP-002 §7).
//!
//! When a user regenerates their identity, the OLD Ed25519 key signs an
//! `IdentityRotationPayload` attesting the handoff to a new PeerId + new
//! Ed25519 public key. The payload is delivered to every contact through
//! their existing Double Ratchet session as a PNP-001 envelope with
//! `msg_type = 0x13` (IDENTITY_ROTATE). A receiver verifies the signature
//! with the OLD pubkey stored at original contact-add time and, if valid,
//! auto-remaps the contact record to the new PeerId while preserving the
//! Double Ratchet session.
//!
//! The signed byte sequence is domain-separated by the constant
//! [`IDENTITY_ROTATION_DOMAIN`] to prevent cross-protocol signature reuse,
//! and uses big-endian length encoding consistent with PNP-001 conventions.

use crate::address::PeerId;
use ed25519_dalek::{Signer, Verifier};
use parolnet_crypto::{CryptoError, IdentityKeyPair};
use serde::{Deserialize, Serialize};

/// Grace window (seconds) during which the old PeerId remains valid after
/// rotation. After this window the rotating party MUST zeroize the old
/// Ed25519 secret key and stop accepting messages on the old PeerId.
/// (`7 * 24 * 3600 = 604800`)
pub const GRACE_WINDOW_SECS: u64 = 7 * 24 * 3600;

/// Domain separation tag for the identity-rotation signature.
///
/// Including this prefix in the signed bytes prevents an Ed25519 signature
/// produced for some other PNP-XXX protocol from being replayed as a valid
/// rotation attestation.
pub const IDENTITY_ROTATION_DOMAIN: &[u8] = b"ParolNet-IdentityRotation-v1";

/// A signed attestation that `old_peer_id` has rotated to `new_peer_id`.
///
/// Signed by the OLD Ed25519 secret key over
/// `IDENTITY_ROTATION_DOMAIN || old_peer_id || new_peer_id ||
/// new_ed25519_pub || rotated_at.to_be_bytes() ||
/// grace_expires_at.to_be_bytes()` (see [`canonical_signing_bytes`]).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityRotationPayload {
    /// SHA-256 of the old Ed25519 public key.
    pub old_peer_id: [u8; 32],
    /// SHA-256 of the new Ed25519 public key.
    pub new_peer_id: [u8; 32],
    /// New Ed25519 public key (raw bytes).
    pub new_ed25519_pub: [u8; 32],
    /// Unix seconds at signing time.
    pub rotated_at: u64,
    /// `rotated_at + GRACE_WINDOW_SECS` (604800 seconds / 7 days).
    pub grace_expires_at: u64,
    /// Ed25519 signature by the OLD secret key over
    /// [`canonical_signing_bytes`] output (always 64 bytes).
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Produce the exact byte sequence that the rotation signature covers.
///
/// Callers MUST use this helper for both signing and verification so that
/// the domain separator and field order remain consistent across the codebase.
pub fn canonical_signing_bytes(
    old_peer_id: &[u8; 32],
    new_peer_id: &[u8; 32],
    new_ed25519_pub: &[u8; 32],
    rotated_at: u64,
    grace_expires_at: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(IDENTITY_ROTATION_DOMAIN.len() + 32 * 3 + 8 * 2);
    buf.extend_from_slice(IDENTITY_ROTATION_DOMAIN);
    buf.extend_from_slice(old_peer_id);
    buf.extend_from_slice(new_peer_id);
    buf.extend_from_slice(new_ed25519_pub);
    buf.extend_from_slice(&rotated_at.to_be_bytes());
    buf.extend_from_slice(&grace_expires_at.to_be_bytes());
    buf
}

/// Generate a fresh identity and sign an `IdentityRotationPayload` attesting
/// the handoff from the caller's current identity to the new one.
///
/// The caller is responsible for delivering the payload to all contacts with
/// established Double Ratchet sessions and for retaining the OLD identity
/// for the grace window (PNP-002 §7). The new `IdentityKeyPair` replaces the
/// caller's active identity only after the rotation record has been persisted.
///
/// `now_secs` is the current Unix timestamp at signing time; the returned
/// payload's `grace_expires_at` is always set to `now_secs + GRACE_WINDOW_SECS`.
pub fn rotate_identity(
    old: &IdentityKeyPair,
    now_secs: u64,
) -> Result<(IdentityKeyPair, IdentityRotationPayload), CryptoError> {
    let new = IdentityKeyPair::generate();

    let old_peer_id: [u8; 32] = PeerId::from_public_key(&old.public_key_bytes()).0;
    let new_pub = new.public_key_bytes();
    let new_peer_id: [u8; 32] = PeerId::from_public_key(&new_pub).0;

    let rotated_at = now_secs;
    let grace_expires_at = rotated_at.saturating_add(GRACE_WINDOW_SECS);

    let signed_bytes = canonical_signing_bytes(
        &old_peer_id,
        &new_peer_id,
        &new_pub,
        rotated_at,
        grace_expires_at,
    );
    let sig = old.signing_key.sign(&signed_bytes);

    let payload = IdentityRotationPayload {
        old_peer_id,
        new_peer_id,
        new_ed25519_pub: new_pub,
        rotated_at,
        grace_expires_at,
        signature: sig.to_bytes().to_vec(),
    };

    Ok((new, payload))
}

/// Verify a received `IdentityRotationPayload` against a stored OLD pubkey.
///
/// Returns `Ok(())` iff:
///
/// 1. `grace_expires_at == rotated_at + GRACE_WINDOW_SECS` (604800s),
/// 2. `old_peer_id == SHA-256(old_ed25519_pub)`,
/// 3. `new_peer_id == SHA-256(new_ed25519_pub)`,
/// 4. `signature` is a valid Ed25519 signature by `old_ed25519_pub` over
///    [`canonical_signing_bytes`] of the payload fields.
///
/// Any failure returns `CryptoError::SignatureVerificationFailed`.
pub fn verify_identity_rotation(
    payload: &IdentityRotationPayload,
    old_ed25519_pub: &[u8; 32],
) -> Result<(), CryptoError> {
    // Grace window length MUST be exactly 7 days. (PNP-002-MUST-038)
    let expected_grace = payload
        .rotated_at
        .checked_add(GRACE_WINDOW_SECS)
        .ok_or(CryptoError::SignatureVerificationFailed)?;
    if payload.grace_expires_at != expected_grace {
        return Err(CryptoError::SignatureVerificationFailed);
    }

    // PeerIds MUST be SHA-256 of their respective pubkeys.
    let expected_old_pid = PeerId::from_public_key(old_ed25519_pub).0;
    if expected_old_pid != payload.old_peer_id {
        return Err(CryptoError::SignatureVerificationFailed);
    }
    let expected_new_pid = PeerId::from_public_key(&payload.new_ed25519_pub).0;
    if expected_new_pid != payload.new_peer_id {
        return Err(CryptoError::SignatureVerificationFailed);
    }

    if payload.signature.len() != 64 {
        return Err(CryptoError::SignatureVerificationFailed);
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&payload.signature);

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(old_ed25519_pub)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;

    let signed = canonical_signing_bytes(
        &payload.old_peer_id,
        &payload.new_peer_id,
        &payload.new_ed25519_pub,
        payload.rotated_at,
        payload.grace_expires_at,
    );
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(&signed, &sig)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bytes_begin_with_domain_separator() {
        let bytes = canonical_signing_bytes(
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            100,
            100 + GRACE_WINDOW_SECS,
        );
        assert!(bytes.starts_with(IDENTITY_ROTATION_DOMAIN));
    }

    #[test]
    fn canonical_bytes_length_is_deterministic() {
        let bytes =
            canonical_signing_bytes(&[0u8; 32], &[0u8; 32], &[0u8; 32], 0, GRACE_WINDOW_SECS);
        assert_eq!(bytes.len(), IDENTITY_ROTATION_DOMAIN.len() + 32 * 3 + 8 * 2);
    }

    #[test]
    fn grace_window_constant_is_seven_days() {
        assert_eq!(GRACE_WINDOW_SECS, 604_800);
    }

    #[test]
    fn rotate_then_verify_round_trip() {
        let old = IdentityKeyPair::generate();
        let old_pub = old.public_key_bytes();
        let (new, payload) = rotate_identity(&old, 1_700_000_000).unwrap();
        assert_ne!(new.public_key_bytes(), old_pub, "new key differs");
        assert_eq!(payload.rotated_at, 1_700_000_000);
        assert_eq!(payload.grace_expires_at, 1_700_000_000 + GRACE_WINDOW_SECS);
        verify_identity_rotation(&payload, &old_pub).expect("valid sig MUST verify");
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let old = IdentityKeyPair::generate();
        let old_pub = old.public_key_bytes();
        let (_new, mut payload) = rotate_identity(&old, 1_700_000_000).unwrap();
        payload.signature[0] ^= 0x01;
        assert!(verify_identity_rotation(&payload, &old_pub).is_err());
    }

    #[test]
    fn mismatched_grace_window_fails_verification() {
        let old = IdentityKeyPair::generate();
        let old_pub = old.public_key_bytes();
        let (_new, mut payload) = rotate_identity(&old, 1_700_000_000).unwrap();
        payload.grace_expires_at += 1;
        assert!(verify_identity_rotation(&payload, &old_pub).is_err());
    }

    #[test]
    fn verify_rejects_signature_over_payload_without_domain_separator() {
        // A signature produced over just the field bytes (no domain tag) must
        // NOT be accepted by verify_identity_rotation, which requires the
        // domain-separated byte sequence.
        let old = IdentityKeyPair::generate();
        let old_pub = old.public_key_bytes();
        let new = IdentityKeyPair::generate();
        let new_pub = new.public_key_bytes();
        let old_pid = PeerId::from_public_key(&old_pub).0;
        let new_pid = PeerId::from_public_key(&new_pub).0;
        let rotated_at = 1_700_000_000u64;
        let grace = rotated_at + GRACE_WINDOW_SECS;

        // Sign WITHOUT the domain separator.
        let mut undomained = Vec::new();
        undomained.extend_from_slice(&old_pid);
        undomained.extend_from_slice(&new_pid);
        undomained.extend_from_slice(&new_pub);
        undomained.extend_from_slice(&rotated_at.to_be_bytes());
        undomained.extend_from_slice(&grace.to_be_bytes());
        let sig = old.signing_key.sign(&undomained);

        let payload = IdentityRotationPayload {
            old_peer_id: old_pid,
            new_peer_id: new_pid,
            new_ed25519_pub: new_pub,
            rotated_at,
            grace_expires_at: grace,
            signature: sig.to_bytes().to_vec(),
        };
        assert!(verify_identity_rotation(&payload, &old_pub).is_err());
    }
}
