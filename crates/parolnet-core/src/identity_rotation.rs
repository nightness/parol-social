//! Client-side orchestration for H5 identity rotation (PNP-002 §7).
//!
//! Wraps [`parolnet_protocol::identity_rotation::rotate_identity`] with the
//! per-contact envelope-build step: for each active Double Ratchet session
//! the helper signs once with the OLD identity and encrypts the resulting
//! payload into a PNP-001 envelope with `msg_type = 0x13` (IDENTITY_ROTATE)
//! addressed to that contact.
//!
//! The caller is responsible for:
//!
//! * Delivering each returned envelope to the corresponding peer.
//! * Persisting a `retired_identity` record so the old Ed25519 secret key
//!   can be zeroized after the 7-day grace window (PNP-002-MUST-039).
//! * Swapping the active identity with
//!   [`crate::ParolNet::replace_identity_preserving_sessions`] **after** the
//!   rotation record is persisted so restart semantics stay consistent.

use crate::envelope::encrypt_into_envelope;
use crate::{CoreError, session::SessionManager};
use parolnet_crypto::IdentityKeyPair;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::identity_rotation::{
    IdentityRotationPayload, rotate_identity as rotate_keypair,
};

/// Envelope produced for one contact during a rotation.
pub struct RotationEnvelope {
    /// Destination peer. This is the contact's CURRENT PeerId (not ours).
    pub peer_id: PeerId,
    /// Wire-ready PNP-001 envelope hex-free bytes (bucket-padded).
    pub envelope_bytes: Vec<u8>,
}

/// Rotate the caller's identity and produce per-contact envelopes.
///
/// Steps:
///
/// 1. Generate a fresh `IdentityKeyPair` and sign an
///    [`IdentityRotationPayload`] with the OLD key.
/// 2. Serialize the payload to JSON (matching the PWA's envelope inner-
///    payload convention for structured messages).
/// 3. For every peer with an active session in `sessions`, encrypt the JSON
///    into a PNP-001 envelope with `msg_type = 0x13`.
///
/// Returns `(new_identity, payload, envelopes)`. The caller MUST retain the
/// OLD identity until `grace_expires_at` so inbound messages to the old
/// PeerId still decrypt.
pub fn rotate_identity_for_peers(
    current_identity: &IdentityKeyPair,
    sessions: &SessionManager,
    now_secs: u64,
) -> Result<
    (
        IdentityKeyPair,
        IdentityRotationPayload,
        Vec<RotationEnvelope>,
    ),
    CoreError,
> {
    const MSG_TYPE_IDENTITY_ROTATE: u8 = 0x13;

    let (new_identity, payload) =
        rotate_keypair(current_identity, now_secs).map_err(CoreError::Crypto)?;

    let payload_json = serde_json::to_vec(&PayloadJson::from(&payload))
        .map_err(|e| CoreError::SessionError(format!("rotation payload JSON: {e}")))?;

    let peers: Vec<PeerId> = sessions
        .export_all()
        .into_iter()
        .map(|(pid, _)| PeerId(pid))
        .collect();

    let mut envelopes = Vec::with_capacity(peers.len());
    for peer_id in peers {
        let env = sessions.with_session_mut(&peer_id, |ratchet| {
            encrypt_into_envelope(
                ratchet,
                &peer_id,
                MSG_TYPE_IDENTITY_ROTATE,
                &payload_json,
                now_secs,
            )
        })?;
        envelopes.push(RotationEnvelope {
            peer_id,
            envelope_bytes: env,
        });
    }

    Ok((new_identity, payload, envelopes))
}

/// JSON projection of the rotation payload — emitted over the wire as the
/// envelope's inner plaintext. The receiver parses this with `serde_json`
/// (native) or `JSON.parse` (PWA) before calling `verify_identity_rotation`.
///
/// Fields are encoded as lowercase hex strings (for `[u8; 32]` and the
/// signature) so the JS side doesn't need a base64 or CBOR decoder.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PayloadJson {
    pub old_peer_id: String,
    pub new_peer_id: String,
    pub new_ed25519_pub: String,
    pub rotated_at: u64,
    pub grace_expires_at: u64,
    pub signature: String,
}

impl From<&IdentityRotationPayload> for PayloadJson {
    fn from(p: &IdentityRotationPayload) -> Self {
        Self {
            old_peer_id: hex::encode(p.old_peer_id),
            new_peer_id: hex::encode(p.new_peer_id),
            new_ed25519_pub: hex::encode(p.new_ed25519_pub),
            rotated_at: p.rotated_at,
            grace_expires_at: p.grace_expires_at,
            signature: hex::encode(&p.signature),
        }
    }
}

impl TryFrom<&PayloadJson> for IdentityRotationPayload {
    type Error = CoreError;

    fn try_from(p: &PayloadJson) -> Result<Self, Self::Error> {
        fn decode_32(s: &str) -> Result<[u8; 32], CoreError> {
            let v = hex::decode(s).map_err(|e| CoreError::SessionError(format!("hex: {e}")))?;
            if v.len() != 32 {
                return Err(CoreError::SessionError("expected 32 bytes".into()));
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            Ok(a)
        }
        Ok(IdentityRotationPayload {
            old_peer_id: decode_32(&p.old_peer_id)?,
            new_peer_id: decode_32(&p.new_peer_id)?,
            new_ed25519_pub: decode_32(&p.new_ed25519_pub)?,
            rotated_at: p.rotated_at,
            grace_expires_at: p.grace_expires_at,
            signature: hex::decode(&p.signature)
                .map_err(|e| CoreError::SessionError(format!("hex: {e}")))?,
        })
    }
}
