//! Envelope — the wire-level message unit (PNP-001 Section 3.1).

use crate::address::PeerId;
use crate::message::MessageFlags;
use serde::{Deserialize, Serialize};

/// Cleartext header visible to relays (PNP-001 Section 3.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleartextHeader {
    pub version: u8,
    pub msg_type: u8,
    pub dest_peer_id: PeerId,
    pub message_id: [u8; 16],
    /// Coarsened timestamp: `floor(unix_epoch_seconds / 300) * 300`
    pub timestamp: u64,
    /// Upper 8 bits: TTL, lower 8 bits: hop count.
    pub ttl_and_hops: u16,
    /// Optional source PeerId hint (None for anonymous messages).
    pub source_hint: Option<PeerId>,
}

impl CleartextHeader {
    /// Create a new CleartextHeader with an automatically coarsened timestamp.
    ///
    /// The timestamp is rounded down to the nearest 5-minute (300s) boundary
    /// to prevent timing correlation attacks. This is the preferred constructor
    /// and should be used instead of setting fields directly.
    ///
    /// # Examples
    ///
    /// ```
    /// use parolnet_protocol::{envelope::CleartextHeader, PeerId};
    ///
    /// let h = CleartextHeader::new(1, 0x01, PeerId([0u8; 32]), [0u8; 16], 1_700_000_001, 7, None);
    /// assert!(h.is_timestamp_coarsened());
    /// assert_eq!(h.timestamp % 300, 0);
    /// assert_eq!(h.ttl(), 7);
    /// assert_eq!(h.hop_count(), 0);
    /// ```
    pub fn new(
        version: u8,
        msg_type: u8,
        dest_peer_id: PeerId,
        message_id: [u8; 16],
        unix_secs: u64,
        ttl: u8,
        source_hint: Option<PeerId>,
    ) -> Self {
        Self {
            version,
            msg_type,
            dest_peer_id,
            message_id,
            timestamp: Self::coarsen_timestamp(unix_secs),
            ttl_and_hops: (ttl as u16) << 8,
            source_hint,
        }
    }

    pub fn ttl(&self) -> u8 {
        (self.ttl_and_hops >> 8) as u8
    }

    pub fn hop_count(&self) -> u8 {
        (self.ttl_and_hops & 0xFF) as u8
    }

    /// Increment hop count, saturating at 255.
    ///
    /// # Examples
    ///
    /// ```
    /// use parolnet_protocol::{envelope::CleartextHeader, PeerId};
    ///
    /// let mut h = CleartextHeader::new(1, 0x01, PeerId([0u8; 32]), [0u8; 16], 0, 7, None);
    /// h.increment_hop();
    /// assert_eq!(h.hop_count(), 1);
    /// assert_eq!(h.ttl(), 7, "TTL unchanged by hop increment");
    /// ```
    pub fn increment_hop(&mut self) {
        let hops = self.hop_count().saturating_add(1);
        self.ttl_and_hops = (self.ttl_and_hops & 0xFF00) | (hops as u16);
    }

    /// Create a coarsened timestamp from current time.
    pub fn coarsen_timestamp(unix_secs: u64) -> u64 {
        (unix_secs / 300) * 300
    }

    /// Check whether the timestamp is properly coarsened (divisible by 300).
    pub fn is_timestamp_coarsened(&self) -> bool {
        self.timestamp.is_multiple_of(300)
    }
}

/// Encrypted payload content (PNP-001 Section 3.3).
/// This is what's inside the encrypted portion of the envelope.
///
/// Field order is lexicographic per PNP-001-MUST-023 (deterministic CBOR).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadContent {
    pub body: Vec<u8>,
    pub chain: u32,
    pub flags: MessageFlags,
    pub pad: Vec<u8>,
    pub seq: u64,
}

/// The complete envelope as transmitted on the wire.
#[derive(Clone, Debug)]
pub struct Envelope {
    pub header: CleartextHeader,
    /// Encrypted payload bytes (includes AEAD ciphertext).
    pub encrypted_payload: Vec<u8>,
    /// 16-byte AEAD authentication tag.
    pub mac: [u8; 16],
}

impl Envelope {
    /// Verify the MAC in constant time using `subtle::ConstantTimeEq`.
    ///
    /// Returns `true` if `expected_mac` matches `self.mac` in constant time,
    /// preventing timing side-channel attacks.
    pub fn verify_mac(&self, expected_mac: &[u8; 16]) -> bool {
        use subtle::ConstantTimeEq;
        self.mac.ct_eq(expected_mac).into()
    }

    /// Verify that the total envelope size matches a valid bucket size.
    pub fn is_valid_size(&self) -> bool {
        let total = self.total_size();
        crate::BUCKET_SIZES.contains(&total)
    }

    /// Compute the total wire size of this envelope.
    ///
    /// This is the size as encoded by `CborCodec`: 4-byte header length prefix +
    /// CBOR header + encrypted payload + 16-byte MAC.
    pub fn total_size(&self) -> usize {
        use crate::codec::encode_header;
        let header_len = encode_header(&self.header).map(|h| h.len()).unwrap_or(0);
        4 + header_len + self.encrypted_payload.len() + 16
    }
}
