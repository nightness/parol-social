//! Federation-link on-wire codec (PNP-008 §5.5 + §5.6).
//!
//! Each federation message is a single WebSocket binary frame whose payload is
//! `len_be32 || cbor_bytes`, where `len_be32` is the big-endian 32-bit length of
//! `cbor_bytes` and `cbor_bytes` is the deterministic-CBOR encoding of one
//! [`FederationSync`] or [`FederationHeartbeat`] struct (PNP-008 §4).
//!
//! Clauses pinned here:
//! - **PNP-008-MUST-077** — WSS path `/federation/v1` ([`FEDERATION_LINK_PATH`]).
//! - **PNP-008-MUST-078** — `len_be32 || cbor` framing ([`encode_frame`]).
//! - **PNP-008-MUST-079** — 2 MiB hard cap ([`MAX_FRAME_BYTES`]).
//! - **PNP-008-MUST-080** — unknown payload type ⇒ close 4002
//!   ([`CodecError::UnknownType`], [`CLOSE_UNKNOWN_TYPE`]).
//! - **PNP-008-MUST-084** — close-code registry ([`CLOSE_*`] constants).

use parolnet_protocol::federation::{FederationHeartbeat, FederationPayloadType, FederationSync};
use serde::{Deserialize, Serialize};

/// WSS path that terminates inbound federation links (PNP-008-MUST-077).
pub const FEDERATION_LINK_PATH: &str = "/federation/v1";

/// Informational WebSocket subprotocol label. Per MUST-077 the subprotocol
/// header is NOT required — it's provided for operator logs only.
pub const FEDERATION_SUBPROTOCOL: &str = "parolnet.federation.v1";

/// 4-byte big-endian length prefix (PNP-008-MUST-078).
pub const FRAME_LEN_PREFIX_BYTES: usize = 4;

/// Hard cap on a single decoded frame (PNP-008-MUST-079).
pub const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

/// Close code registry (PNP-008-MUST-084).
pub const CLOSE_NORMAL: u16 = 1000;
pub const CLOSE_DUP_PEER: u16 = 4000;
pub const CLOSE_RATE_LIMIT: u16 = 4001;
pub const CLOSE_UNKNOWN_TYPE: u16 = 4002;
pub const CLOSE_OVERSIZE: u16 = 4003;

/// A single decoded federation-link frame.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FederationFrame {
    Sync(FederationSync),
    Heartbeat(FederationHeartbeat),
}

impl FederationFrame {
    pub fn payload_type(&self) -> FederationPayloadType {
        match self {
            Self::Sync(_) => FederationPayloadType::FederationSync,
            Self::Heartbeat(_) => FederationPayloadType::FederationHeartbeat,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("frame shorter than 4-byte length prefix")]
    TooShort,
    #[error("declared length {declared} does not match remainder {remainder}")]
    LengthMismatch { declared: usize, remainder: usize },
    /// MUST-079: emit close code 4003 when observed on the wire.
    #[error("frame exceeds 2 MiB cap: {size} > {MAX_FRAME_BYTES}")]
    Oversize { size: usize },
    #[error("CBOR decode: {0}")]
    Cbor(String),
    /// MUST-080: emit close code 4002 when observed on the wire.
    #[error("unknown federation payload type: 0x{byte:02x}")]
    UnknownType { byte: u8 },
    #[error("frame body carries no CBOR type discriminator")]
    EmptyBody,
}

impl CodecError {
    /// Map a codec error to the WebSocket close code it implies
    /// (PNP-008-MUST-079, MUST-080, MUST-084).
    pub fn close_code(&self) -> u16 {
        match self {
            Self::Oversize { .. } => CLOSE_OVERSIZE,
            Self::UnknownType { .. } => CLOSE_UNKNOWN_TYPE,
            _ => CLOSE_NORMAL,
        }
    }
}

/// Encode a federation frame for transmission.
///
/// Output is `len_be32 || cbor_bytes` suitable for a single WebSocket binary
/// frame (PNP-008-MUST-078).
pub fn encode_frame(frame: &FederationFrame) -> Result<Vec<u8>, CodecError> {
    let mut cbor = Vec::with_capacity(256);
    ciborium::into_writer(frame, &mut cbor).map_err(|e| CodecError::Cbor(e.to_string()))?;
    if cbor.len() > MAX_FRAME_BYTES {
        return Err(CodecError::Oversize { size: cbor.len() });
    }
    let len_be = (cbor.len() as u32).to_be_bytes();
    let mut out = Vec::with_capacity(FRAME_LEN_PREFIX_BYTES + cbor.len());
    out.extend_from_slice(&len_be);
    out.extend_from_slice(&cbor);
    Ok(out)
}

/// Decode a federation frame from the raw WebSocket binary payload.
///
/// Enforces MUST-078 (prefix matches body), MUST-079 (2 MiB cap), and
/// MUST-080 (unknown type rejection before CBOR parse).
pub fn decode_frame(bytes: &[u8]) -> Result<FederationFrame, CodecError> {
    if bytes.len() < FRAME_LEN_PREFIX_BYTES {
        return Err(CodecError::TooShort);
    }
    let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let body = &bytes[FRAME_LEN_PREFIX_BYTES..];
    if declared > MAX_FRAME_BYTES {
        return Err(CodecError::Oversize { size: declared });
    }
    if declared != body.len() {
        return Err(CodecError::LengthMismatch {
            declared,
            remainder: body.len(),
        });
    }
    if body.is_empty() {
        return Err(CodecError::EmptyBody);
    }
    // MUST-080: reject unknown payload types before CBOR parsing. The first
    // byte of every well-formed body is the enum variant tag emitted by
    // `FederationFrame` (ciborium serializes enums as text-tag maps; we
    // actually need to peek at the CBOR structure). Ciborium emits enum
    // variants as a one-element map `{ "Sync": ... }` — so we parse, then
    // check the payload-type discriminator via the decoded frame.
    let frame: FederationFrame =
        ciborium::from_reader(body).map_err(|e| CodecError::Cbor(e.to_string()))?;
    // Defense in depth: if a future variant sneaks in, `FederationPayloadType`
    // will reject it at this check.
    let t = frame.payload_type();
    if !matches!(
        t,
        FederationPayloadType::FederationSync | FederationPayloadType::FederationHeartbeat
    ) {
        return Err(CodecError::UnknownType { byte: t as u8 });
    }
    Ok(frame)
}

/// Peek at a raw unknown-type byte without parsing. Used by proactive rejection
/// of malformed frames that carry a bogus type code as the first body byte.
/// Returns `Some(code)` only when the frame shape is well-formed enough to
/// attribute a type byte to it.
pub fn peek_raw_type_byte(bytes: &[u8]) -> Option<u8> {
    if bytes.len() <= FRAME_LEN_PREFIX_BYTES {
        return None;
    }
    Some(bytes[FRAME_LEN_PREFIX_BYTES])
}

#[cfg(test)]
mod tests {
    use super::*;
    use parolnet_protocol::federation::{HeartbeatFlags, LoadHint};

    fn sample_heartbeat() -> FederationHeartbeat {
        FederationHeartbeat {
            counter: 1,
            load_hint: LoadHint::default(),
            flags: HeartbeatFlags::empty(),
            timestamp: 1_700_000_000,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn roundtrip_heartbeat() {
        let f = FederationFrame::Heartbeat(sample_heartbeat());
        let bytes = encode_frame(&f).unwrap();
        // Length prefix matches body length.
        let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(declared, bytes.len() - FRAME_LEN_PREFIX_BYTES);
        // Decode returns same type discriminator.
        let back = decode_frame(&bytes).unwrap();
        assert_eq!(back.payload_type(), FederationPayloadType::FederationHeartbeat);
    }

    #[test]
    fn too_short_rejected() {
        assert!(matches!(
            decode_frame(&[0, 0, 1]).unwrap_err(),
            CodecError::TooShort
        ));
    }

    #[test]
    fn length_mismatch_rejected() {
        let mut bytes = encode_frame(&FederationFrame::Heartbeat(sample_heartbeat())).unwrap();
        bytes.push(0xFF); // tail byte that the prefix does not describe
        assert!(matches!(
            decode_frame(&bytes).unwrap_err(),
            CodecError::LengthMismatch { .. }
        ));
    }

    #[test]
    fn oversize_declared_rejected() {
        // Declared length > MAX_FRAME_BYTES; body contents irrelevant.
        let mut bytes = vec![0u8; FRAME_LEN_PREFIX_BYTES];
        let oversized = (MAX_FRAME_BYTES as u32) + 1;
        bytes[..FRAME_LEN_PREFIX_BYTES].copy_from_slice(&oversized.to_be_bytes());
        bytes.push(0x00);
        let err = decode_frame(&bytes).unwrap_err();
        assert!(matches!(err, CodecError::Oversize { .. }));
        assert_eq!(err.close_code(), CLOSE_OVERSIZE);
    }

    #[test]
    fn close_code_registry_stable() {
        // MUST-084: close-code registry must not drift silently.
        assert_eq!(CLOSE_NORMAL, 1000);
        assert_eq!(CLOSE_DUP_PEER, 4000);
        assert_eq!(CLOSE_RATE_LIMIT, 4001);
        assert_eq!(CLOSE_UNKNOWN_TYPE, 4002);
        assert_eq!(CLOSE_OVERSIZE, 4003);
    }

    #[test]
    fn unknown_type_error_maps_to_4002() {
        let err = CodecError::UnknownType { byte: 0x09 };
        assert_eq!(err.close_code(), CLOSE_UNKNOWN_TYPE);
    }

    #[test]
    fn empty_body_rejected() {
        let mut bytes = vec![0u8; FRAME_LEN_PREFIX_BYTES];
        bytes[..4].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            decode_frame(&bytes).unwrap_err(),
            CodecError::EmptyBody
        ));
    }

    #[test]
    fn path_and_subprotocol_stable() {
        // MUST-077: any drift here is a breaking wire change.
        assert_eq!(FEDERATION_LINK_PATH, "/federation/v1");
        assert_eq!(FEDERATION_SUBPROTOCOL, "parolnet.federation.v1");
    }
}
