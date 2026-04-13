//! Gossip envelope — the wire format for epidemic message propagation (PNP-005).

use crate::ProtocolError;
use crate::address::PeerId;
use serde::{Deserialize, Serialize};

/// Gossip payload types (PNP-005 Section 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum GossipPayloadType {
    /// Relay directory entry (PNP-004).
    RelayDescriptor = 0x01,
    /// End-to-end encrypted user message.
    UserMessage = 0x02,
    /// Peer address advertisement.
    PeerAnnouncement = 0x03,
    /// Group key rotation metadata.
    GroupMetadata = 0x04,
    /// Key or relay revocation.
    Revocation = 0x05,
}

impl GossipPayloadType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::RelayDescriptor),
            0x02 => Some(Self::UserMessage),
            0x03 => Some(Self::PeerAnnouncement),
            0x04 => Some(Self::GroupMetadata),
            0x05 => Some(Self::Revocation),
            _ => None,
        }
    }

    /// Required proof-of-work difficulty for this payload type.
    pub fn pow_difficulty(&self) -> u8 {
        match self {
            Self::RelayDescriptor => 20,
            _ => 16,
        }
    }
}

/// Gossip envelope (PNP-005 Section 3.1).
///
/// This wraps a payload with gossip metadata for epidemic propagation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GossipEnvelope {
    /// Protocol version (must be 1).
    pub v: u8,
    /// Message ID: SHA-256(payload || sender || nonce).
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    /// Sender PeerId.
    pub src: PeerId,
    /// Sender's Ed25519 public key (32 bytes). SHA-256(src_pubkey) == src.
    #[serde(with = "serde_bytes")]
    pub src_pubkey: Vec<u8>,
    /// Origin timestamp (unix seconds).
    pub ts: u64,
    /// Expiry timestamp (unix seconds, max 24 hours from ts).
    pub exp: u64,
    /// Remaining TTL (default 7, max 15).
    pub ttl: u8,
    /// Hops traversed (informational).
    pub hops: u8,
    /// 1024-bit bloom filter of peers who have seen this message.
    #[serde(with = "serde_bytes")]
    pub seen: Vec<u8>,
    /// Proof-of-work nonce (8 bytes).
    #[serde(with = "serde_bytes")]
    pub pow: Vec<u8>,
    /// Ed25519 signature over the envelope (excluding signature itself).
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    /// Payload type.
    pub payload_type: u8,
    /// Payload bytes (max 65536).
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

/// Maximum payload size per PNP-005.
pub const MAX_GOSSIP_PAYLOAD: usize = 65536;

/// Default TTL for gossip messages.
pub const DEFAULT_TTL: u8 = 7;

/// Maximum TTL.
pub const MAX_TTL: u8 = 15;

/// Maximum message age before considered expired (24 hours).
pub const MAX_MESSAGE_AGE_SECS: u64 = 86400;

/// Default gossip fanout.
pub const DEFAULT_FANOUT: usize = 3;

impl GossipEnvelope {
    /// Encode this envelope to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| ProtocolError::CborEncode(format!("CBOR encode: {e}")))?;
        Ok(buf)
    }

    /// Decode a gossip envelope from CBOR bytes.
    pub fn from_cbor(data: &[u8]) -> Result<Self, ProtocolError> {
        ciborium::from_reader(data)
            .map_err(|e| ProtocolError::CborDecode(format!("CBOR decode: {e}")))
    }

    /// Get the message ID as a fixed-size array.
    pub fn message_id(&self) -> Option<[u8; 32]> {
        if self.id.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&self.id);
            Some(arr)
        } else {
            None
        }
    }

    /// Get the PoW nonce as a fixed-size array.
    pub fn pow_nonce(&self) -> Option<[u8; 8]> {
        if self.pow.len() == 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&self.pow);
            Some(arr)
        } else {
            None
        }
    }

    /// Check basic structural validity.
    pub fn is_valid_structure(&self) -> bool {
        self.v == 1
            && self.id.len() == 32
            && self.src_pubkey.len() == 32
            && self.pow.len() == 8
            && self.sig.len() == 64
            && self.seen.len() == 128
            && self.payload.len() <= MAX_GOSSIP_PAYLOAD
            && self.ttl <= MAX_TTL
    }

    /// Check if this message has expired.
    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs >= self.exp
    }

    /// Bytes to sign/verify (everything except the signature field).
    pub fn signable_bytes(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update([self.v]);
        hasher.update(&self.id);
        hasher.update(self.src.0);
        hasher.update(&self.src_pubkey);
        hasher.update(self.ts.to_be_bytes());
        hasher.update(self.exp.to_be_bytes());
        hasher.update([self.ttl]);
        hasher.update([self.hops]);
        hasher.update(&self.seen);
        hasher.update(&self.pow);
        hasher.update([self.payload_type]);
        hasher.update(&self.payload);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gossip_envelope_cbor_roundtrip() {
        let env = GossipEnvelope {
            v: 1,
            id: vec![0xAA; 32],
            src: PeerId([0xBB; 32]),
            src_pubkey: vec![0xCC; 32],
            ts: 1000,
            exp: 87400,
            ttl: 7,
            hops: 0,
            seen: vec![0; 128],
            pow: vec![0; 8],
            sig: vec![0; 64],
            payload_type: GossipPayloadType::UserMessage as u8,
            payload: b"hello world".to_vec(),
        };

        let encoded = env.to_cbor().unwrap();
        let decoded = GossipEnvelope::from_cbor(&encoded).unwrap();

        assert_eq!(decoded.v, 1);
        assert_eq!(decoded.id, vec![0xAA; 32]);
        assert_eq!(decoded.ttl, 7);
        assert_eq!(decoded.payload, b"hello world");
        assert!(decoded.is_valid_structure());
    }

    #[test]
    fn test_gossip_payload_type_pow_difficulty() {
        assert_eq!(GossipPayloadType::RelayDescriptor.pow_difficulty(), 20);
        assert_eq!(GossipPayloadType::UserMessage.pow_difficulty(), 16);
        assert_eq!(GossipPayloadType::PeerAnnouncement.pow_difficulty(), 16);
    }

    #[test]
    fn test_gossip_envelope_expiry() {
        let env = GossipEnvelope {
            v: 1,
            id: vec![0; 32],
            src: PeerId([0; 32]),
            src_pubkey: vec![0; 32],
            ts: 1000,
            exp: 2000,
            ttl: 7,
            hops: 0,
            seen: vec![0; 128],
            pow: vec![0; 8],
            sig: vec![0; 64],
            payload_type: 0x02,
            payload: vec![],
        };

        assert!(!env.is_expired(1500));
        assert!(env.is_expired(2000));
        assert!(env.is_expired(3000));
    }

    #[test]
    fn test_gossip_envelope_invalid_structure() {
        let mut env = GossipEnvelope {
            v: 1,
            id: vec![0; 32],
            src: PeerId([0; 32]),
            src_pubkey: vec![0; 32],
            ts: 1000,
            exp: 2000,
            ttl: 7,
            hops: 0,
            seen: vec![0; 128],
            pow: vec![0; 8],
            sig: vec![0; 64],
            payload_type: 0x02,
            payload: vec![],
        };
        assert!(env.is_valid_structure());

        env.v = 2;
        assert!(!env.is_valid_structure());

        env.v = 1;
        env.id = vec![0; 16]; // wrong length
        assert!(!env.is_valid_structure());

        // wrong src_pubkey length
        env.id = vec![0; 32];
        env.src_pubkey = vec![0; 16];
        assert!(!env.is_valid_structure());
    }

    #[test]
    fn test_gossip_envelope_signed_roundtrip() {
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();
        let peer_id = PeerId(Sha256::digest(pubkey_bytes).into());

        let mut env = GossipEnvelope {
            v: 1,
            id: vec![0xAA; 32],
            src: peer_id,
            src_pubkey: pubkey_bytes.to_vec(),
            ts: 1000,
            exp: 87400,
            ttl: 7,
            hops: 0,
            seen: vec![0; 128],
            pow: vec![0; 8],
            sig: vec![0u8; 64],
            payload_type: GossipPayloadType::UserMessage as u8,
            payload: b"test payload".to_vec(),
        };

        let signable = env.signable_bytes();
        let signature = signing_key.sign(&signable);
        env.sig = signature.to_bytes().to_vec();

        // Verify the signature
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&pubkey_bytes).unwrap();
        let sig = Signature::from_bytes(env.sig.as_slice().try_into().unwrap());
        let signable2 = env.signable_bytes();
        assert!(vk.verify(&signable2, &sig).is_ok());
    }

    #[test]
    fn test_gossip_envelope_tampered_signature_rejected() {
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};

        let signing_key = SigningKey::from_bytes(&[99u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();
        let peer_id = PeerId(Sha256::digest(pubkey_bytes).into());

        let mut env = GossipEnvelope {
            v: 1,
            id: vec![0xBB; 32],
            src: peer_id,
            src_pubkey: pubkey_bytes.to_vec(),
            ts: 2000,
            exp: 88400,
            ttl: 5,
            hops: 0,
            seen: vec![0; 128],
            pow: vec![0; 8],
            sig: vec![0u8; 64],
            payload_type: GossipPayloadType::UserMessage as u8,
            payload: b"tamper test".to_vec(),
        };

        let signable = env.signable_bytes();
        let signature = signing_key.sign(&signable);
        env.sig = signature.to_bytes().to_vec();

        // Tamper with the payload
        env.payload = b"tampered payload".to_vec();

        // Verification should fail
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&pubkey_bytes).unwrap();
        let sig = Signature::from_bytes(env.sig.as_slice().try_into().unwrap());
        let signable2 = env.signable_bytes();
        assert!(vk.verify(&signable2, &sig).is_err());
    }
}
