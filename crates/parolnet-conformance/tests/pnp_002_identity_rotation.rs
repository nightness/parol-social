//! PNP-002 §8 conformance — H5 identity rotation.
//!
//! Covers the six normative clauses introduced in PNP-002 v0.3:
//!
//! * PNP-002-MUST-036 — signature by OLD key.
//! * PNP-002-MUST-037 — verification with OLD pubkey.
//! * PNP-002-MUST-038 — `grace_expires_at == rotated_at + 604800`.
//! * PNP-002-MUST-039 — zeroize OLD secret after grace window (client-side;
//!   this file asserts the payload carries the correct `grace_expires_at`
//!   so the PWA scheduler can drive the zeroize).
//! * PNP-002-SHOULD-011 — grace window acceptance (modelled as a correctly
//!   emitted `grace_expires_at` so receivers can enforce the window).
//! * PNP-002-SHOULD-012 — surfacing the rotation (modelled as: the verify
//!   path returns a *distinguishable* success so the PWA can surface it).

use ed25519_dalek::Signer;
use parolnet_clause::clause;
use parolnet_crypto::IdentityKeyPair;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::identity_rotation::{
    GRACE_WINDOW_SECS, IDENTITY_ROTATION_DOMAIN, IdentityRotationPayload, canonical_signing_bytes,
    rotate_identity, verify_identity_rotation,
};

// -- §8.4 clause 1: signature is produced by the OLD key ---------------------

#[clause("PNP-002-MUST-036")]
#[test]
fn rotation_payload_signature_verifies_with_old_pubkey() {
    let old = IdentityKeyPair::generate();
    let (new, payload) = rotate_identity(&old, 1_700_000_000).unwrap();
    // Sanity: new PeerId MUST differ from the old PeerId.
    assert_ne!(
        PeerId::from_public_key(&old.public_key_bytes()),
        PeerId::from_public_key(&new.public_key_bytes()),
    );
    verify_identity_rotation(&payload, &old.public_key_bytes())
        .expect("OLD-key-signed payload MUST verify (PNP-002-MUST-036)");
}

#[clause("PNP-002-MUST-036")]
#[test]
fn payload_signed_by_wrong_key_fails_verification() {
    // Signature made with the NEW key instead of the OLD key — must be rejected.
    let old = IdentityKeyPair::generate();
    let (new, mut payload) = rotate_identity(&old, 1_700_000_000).unwrap();
    // Re-sign with the NEW key so it looks like an attestation by the wrong party.
    let signed = canonical_signing_bytes(
        &payload.old_peer_id,
        &payload.new_peer_id,
        &payload.new_ed25519_pub,
        payload.rotated_at,
        payload.grace_expires_at,
    );
    payload.signature = new.signing_key.sign(&signed).to_bytes().to_vec();
    assert!(
        verify_identity_rotation(&payload, &old.public_key_bytes()).is_err(),
        "signature by NEW key must NOT verify under OLD pubkey (PNP-002-MUST-036)"
    );
}

// -- §8.4 clause 2: receiver verifies with OLD pubkey ------------------------

#[clause("PNP-002-MUST-037")]
#[test]
fn verification_with_stranger_pubkey_is_rejected() {
    let old = IdentityKeyPair::generate();
    let stranger = IdentityKeyPair::generate();
    let (_new, payload) = rotate_identity(&old, 1_700_000_000).unwrap();
    assert!(
        verify_identity_rotation(&payload, &stranger.public_key_bytes()).is_err(),
        "verifying against an unrelated pubkey MUST fail (PNP-002-MUST-037)"
    );
}

#[clause("PNP-002-MUST-037")]
#[test]
fn tampered_signature_byte_fails_verification() {
    let old = IdentityKeyPair::generate();
    let (_new, mut payload) = rotate_identity(&old, 1_700_000_000).unwrap();
    // Flip one bit of the signature — must fail Ed25519 verification.
    payload.signature[0] ^= 0x01;
    assert!(
        verify_identity_rotation(&payload, &old.public_key_bytes()).is_err(),
        "tampered signature MUST NOT verify (PNP-002-MUST-037)"
    );
}

// -- §8.4 clause 3: grace_expires_at == rotated_at + 604800 ------------------

#[clause("PNP-002-MUST-038")]
#[test]
fn grace_window_length_is_exactly_seven_days() {
    let old = IdentityKeyPair::generate();
    let (_new, payload) = rotate_identity(&old, 1_700_000_000).unwrap();
    assert_eq!(payload.rotated_at, 1_700_000_000);
    assert_eq!(payload.grace_expires_at, 1_700_000_000 + 604_800);
    assert_eq!(GRACE_WINDOW_SECS, 604_800);
}

#[clause("PNP-002-MUST-038")]
#[test]
fn mismatched_grace_window_is_rejected() {
    let old = IdentityKeyPair::generate();
    let (_new, mut payload) = rotate_identity(&old, 1_700_000_000).unwrap();
    // Bump grace by one second — receiver MUST reject.
    payload.grace_expires_at += 1;
    // Re-sign over the tampered values so the failure is only due to the
    // grace-window invariant, not a naive signature check.
    let tampered = canonical_signing_bytes(
        &payload.old_peer_id,
        &payload.new_peer_id,
        &payload.new_ed25519_pub,
        payload.rotated_at,
        payload.grace_expires_at,
    );
    payload.signature = old.signing_key.sign(&tampered).to_bytes().to_vec();
    assert!(
        verify_identity_rotation(&payload, &old.public_key_bytes()).is_err(),
        "grace_expires_at != rotated_at + 604800 MUST be rejected (PNP-002-MUST-038)"
    );
}

// -- §8.4 clause 4: zeroize OLD secret after grace window --------------------

#[clause("PNP-002-MUST-039")]
#[test]
fn rotation_payload_carries_grace_timestamp_for_client_scheduler() {
    // The rotating client drives zeroization off `grace_expires_at`; the
    // payload MUST therefore encode a valid, spec-compliant deadline so the
    // scheduler has a correct wall-clock time. (PNP-002-MUST-039)
    let old = IdentityKeyPair::generate();
    let now = 1_700_000_000u64;
    let (_new, payload) = rotate_identity(&old, now).unwrap();
    assert!(
        payload.grace_expires_at > now,
        "grace deadline MUST be strictly in the future"
    );
    assert_eq!(
        payload.grace_expires_at - payload.rotated_at,
        GRACE_WINDOW_SECS,
    );
}

// -- §8.4 clause 5: accept both PeerIds during grace window ------------------

#[clause("PNP-002-SHOULD-011")]
#[test]
fn grace_window_bounds_accept_both_peer_ids() {
    // The client-side SHOULD rule is driven off (rotated_at, grace_expires_at).
    // This test asserts the payload encodes a window whose length is
    // representable as seconds and falls within 7 days as required by §8.4.
    let old = IdentityKeyPair::generate();
    let (_new, payload) = rotate_identity(&old, 1_700_000_000).unwrap();
    let window = payload.grace_expires_at - payload.rotated_at;
    assert_eq!(
        window, 604_800,
        "grace window MUST be 7 days so receiver can bound acceptance (PNP-002-SHOULD-011)"
    );
}

// -- §8.4 clause 6: surface rotation in contact UI ---------------------------

#[clause("PNP-002-SHOULD-012")]
#[test]
fn successful_verify_returns_distinguishable_outcome_for_ui_surface() {
    // The UI surface is driven by the OK vs Err discriminator returned from
    // verify_identity_rotation. A failing verify returns Err so the PWA can
    // drop-silently; a succeeding verify returns Ok so the PWA can surface
    // a "contact rotated identity" badge. (PNP-002-SHOULD-012)
    let old = IdentityKeyPair::generate();
    let (_new, payload) = rotate_identity(&old, 1_700_000_000).unwrap();
    assert!(verify_identity_rotation(&payload, &old.public_key_bytes()).is_ok());

    let stranger = IdentityKeyPair::generate();
    assert!(verify_identity_rotation(&payload, &stranger.public_key_bytes()).is_err());
}

// -- Domain-separation binding -----------------------------------------------

#[test]
fn domain_separator_prefix_is_exact_literal() {
    assert_eq!(IDENTITY_ROTATION_DOMAIN, b"ParolNet-IdentityRotation-v1");
    let bytes = canonical_signing_bytes(&[0u8; 32], &[0u8; 32], &[0u8; 32], 0, GRACE_WINDOW_SECS);
    assert!(bytes.starts_with(IDENTITY_ROTATION_DOMAIN));
}

#[test]
fn signature_over_undomained_bytes_is_rejected() {
    // An attacker-produced Ed25519 signature over the field bytes WITHOUT
    // the domain separator must not verify — this is the whole point of
    // §8.3 domain separation.
    let old = IdentityKeyPair::generate();
    let new = IdentityKeyPair::generate();
    let old_pub = old.public_key_bytes();
    let new_pub = new.public_key_bytes();
    let old_pid = PeerId::from_public_key(&old_pub).0;
    let new_pid = PeerId::from_public_key(&new_pub).0;
    let rotated_at = 1_700_000_000u64;
    let grace = rotated_at + GRACE_WINDOW_SECS;

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

    assert!(
        verify_identity_rotation(&payload, &old_pub).is_err(),
        "signature without domain separator MUST be rejected"
    );
}

#[test]
fn rotate_produces_fresh_new_peer_id() {
    let old = IdentityKeyPair::generate();
    let (new, payload) = rotate_identity(&old, 1_700_000_000).unwrap();
    assert_ne!(new.public_key_bytes(), old.public_key_bytes());
    let expected_new_pid = PeerId::from_public_key(&new.public_key_bytes()).0;
    assert_eq!(payload.new_peer_id, expected_new_pid);
    let expected_old_pid = PeerId::from_public_key(&old.public_key_bytes()).0;
    assert_eq!(payload.old_peer_id, expected_old_pid);
}
