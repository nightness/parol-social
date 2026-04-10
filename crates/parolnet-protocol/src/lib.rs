//! # parolnet-protocol
//!
//! Wire protocol types and traits for ParolNet (PNP-001).
//!
//! This crate defines:
//! - `PeerId` — peer identity derived from SHA-256 of Ed25519 public key
//! - `Envelope` — the wire-level message unit with cleartext header + encrypted payload + MAC
//! - `MessageType` — TEXT, FILE, CONTROL, DECOY, HANDSHAKE, RELAY_CONTROL
//! - `PaddingStrategy` — pad all messages to fixed bucket sizes
//! - `ProtocolCodec` — CBOR serialization for all wire types
//! - Handshake state machine types (PNP-002)
//! - Ephemeral message metadata
//!
//! This crate has no async runtime dependency and compiles to WASM.

pub mod address;
pub mod codec;
pub mod envelope;
pub mod ephemeral;
pub mod error;
pub mod file;
pub mod handshake;
pub mod media;
pub mod message;
pub mod padding;

pub use address::PeerId;
pub use error::ProtocolError;

/// Bucket sizes for message padding (PNP-001 Section 3.6).
/// All envelopes MUST be padded to one of these sizes.
pub const BUCKET_SIZES: [usize; 4] = [256, 1024, 4096, 16384];

/// CBOR codec for encoding/decoding wire protocol types.
pub trait ProtocolCodec: Send + Sync {
    fn encode(&self, envelope: &envelope::Envelope) -> Result<Vec<u8>, ProtocolError>;
    fn decode(&self, bytes: &[u8]) -> Result<envelope::Envelope, ProtocolError>;
}

/// Message padding strategy (PNP-001 Section 3.6).
///
/// All messages MUST be padded to the next bucket size before encryption.
/// This prevents message length from leaking content type or size.
pub trait PaddingStrategy: Send + Sync {
    /// Pad plaintext to the next bucket size.
    fn pad(&self, plaintext: &[u8]) -> Vec<u8>;
    /// Remove padding, returning the original plaintext.
    fn unpad(&self, padded: &[u8]) -> Result<Vec<u8>, ProtocolError>;
}
