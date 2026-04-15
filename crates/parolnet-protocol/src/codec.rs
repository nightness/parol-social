//! CBOR codec for wire protocol types (PNP-001 Section 3.8).
//!
//! Rules:
//! - All CBOR encoding MUST use definite-length encoding
//! - Map keys MUST be text strings in lexicographic order
//! - Implementations MUST reject duplicate map keys
//! - Implementations MUST ignore unknown map keys (forward compatibility)

use crate::address::PeerId;
use crate::envelope::{CleartextHeader, Envelope};
use crate::{ProtocolCodec, ProtocolError};
use serde::{Deserialize, Serialize};

/// Standard CBOR codec using ciborium.
pub struct CborCodec;

/// Serializable form of the cleartext header as a CBOR array.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct WireHeader {
    version: u8,
    msg_type: u8,
    #[serde(with = "serde_bytes")]
    dest_peer_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    message_id: Vec<u8>,
    timestamp: u64,
    ttl_and_hops: u16,
    #[serde(with = "serde_bytes")]
    source_hint: Option<Vec<u8>>,
}

impl From<&CleartextHeader> for WireHeader {
    fn from(h: &CleartextHeader) -> Self {
        Self {
            version: h.version,
            msg_type: h.msg_type,
            dest_peer_id: h.dest_peer_id.0.to_vec(),
            message_id: h.message_id.to_vec(),
            timestamp: h.timestamp,
            ttl_and_hops: h.ttl_and_hops,
            source_hint: h.source_hint.map(|p| p.0.to_vec()),
        }
    }
}

impl TryFrom<WireHeader> for CleartextHeader {
    type Error = ProtocolError;

    fn try_from(w: WireHeader) -> Result<Self, ProtocolError> {
        if w.dest_peer_id.len() != 32 {
            return Err(ProtocolError::CborDecode(
                "dest_peer_id must be 32 bytes".into(),
            ));
        }
        if w.message_id.len() != 16 {
            return Err(ProtocolError::CborDecode(
                "message_id must be 16 bytes".into(),
            ));
        }
        let mut dest = [0u8; 32];
        dest.copy_from_slice(&w.dest_peer_id);
        let mut mid = [0u8; 16];
        mid.copy_from_slice(&w.message_id);

        let source_hint = match w.source_hint {
            Some(ref bytes) if bytes.len() == 32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(bytes);
                Some(PeerId(s))
            }
            Some(_) => {
                return Err(ProtocolError::CborDecode(
                    "source_hint must be 32 bytes".into(),
                ));
            }
            None => None,
        };

        Ok(CleartextHeader {
            version: w.version,
            msg_type: w.msg_type,
            dest_peer_id: PeerId(dest),
            message_id: mid,
            timestamp: w.timestamp,
            ttl_and_hops: w.ttl_and_hops,
            source_hint,
        })
    }
}

/// Serialize a cleartext header to CBOR bytes.
pub fn encode_header(header: &CleartextHeader) -> Result<Vec<u8>, ProtocolError> {
    let wire: WireHeader = header.into();
    let mut buf = Vec::new();
    ciborium::into_writer(&wire, &mut buf).map_err(|e| ProtocolError::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// Maximum header size in bytes (prevents DoS via oversized CBOR headers).
const MAX_HEADER_SIZE: usize = 512;

/// Deserialize a cleartext header from CBOR bytes.
///
/// Logs a warning if the timestamp is not properly coarsened (divisible by 300).
/// Non-coarsened timestamps are not rejected for backwards compatibility, but
/// they indicate a non-compliant sender that may be leaking timing information.
pub fn decode_header(bytes: &[u8]) -> Result<CleartextHeader, ProtocolError> {
    if bytes.len() > MAX_HEADER_SIZE {
        return Err(ProtocolError::CborDecode(format!(
            "header too large: {} bytes exceeds maximum {}",
            bytes.len(),
            MAX_HEADER_SIZE
        )));
    }

    let wire: WireHeader =
        ciborium::from_reader(bytes).map_err(|e| ProtocolError::CborDecode(e.to_string()))?;

    if wire.version != 1 {
        return Err(ProtocolError::InvalidVersion {
            expected: 1,
            got: wire.version,
        });
    }

    // Warn if timestamp is not coarsened (not divisible by 300).
    // Don't reject — backwards compatibility — but the sender is non-compliant
    // and may be leaking precise timing information.
    if !wire.timestamp.is_multiple_of(300) {
        tracing::warn!(
            timestamp = wire.timestamp,
            "received header with non-coarsened timestamp (not divisible by 300); \
             sender may be leaking timing information"
        );
    }

    wire.try_into()
}

impl ProtocolCodec for CborCodec {
    fn encode(&self, envelope: &Envelope) -> Result<Vec<u8>, ProtocolError> {
        let header_bytes = encode_header(&envelope.header)?;

        let mut output = Vec::new();
        // Length-prefixed header (4 bytes BE length + header CBOR)
        let header_len = header_bytes.len() as u32;
        output.extend_from_slice(&header_len.to_be_bytes());
        output.extend_from_slice(&header_bytes);
        // Encrypted payload
        output.extend_from_slice(&envelope.encrypted_payload);
        // MAC (16 bytes)
        output.extend_from_slice(&envelope.mac);

        Ok(output)
    }

    fn decode(&self, bytes: &[u8]) -> Result<Envelope, ProtocolError> {
        if bytes.len() < 4 {
            return Err(ProtocolError::CborDecode(
                "too short for header length".into(),
            ));
        }

        let header_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if header_len > MAX_HEADER_SIZE {
            return Err(ProtocolError::CborDecode(format!(
                "header length {} exceeds maximum {}",
                header_len, MAX_HEADER_SIZE
            )));
        }
        let header_end = 4 + header_len;

        if bytes.len() < header_end + 16 {
            return Err(ProtocolError::CborDecode(
                "too short for header + MAC".into(),
            ));
        }

        let header = decode_header(&bytes[4..header_end])?;

        let mac_start = bytes.len() - 16;
        let encrypted_payload = bytes[header_end..mac_start].to_vec();
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&bytes[mac_start..]);

        Ok(Envelope {
            header,
            encrypted_payload,
            mac,
        })
    }
}
