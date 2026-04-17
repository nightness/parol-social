//! PNP-005 conformance — gossip mesh & envelope validation.

use parolnet_clause::clause;
use parolnet_protocol::gossip::{
    GossipEnvelope, GossipPayloadType, DEFAULT_FANOUT, DEFAULT_TTL, MAX_GOSSIP_PAYLOAD, MAX_TTL,
};
use parolnet_protocol::PeerId;

fn sample_envelope() -> GossipEnvelope {
    GossipEnvelope {
        v: 1,
        id: vec![0x11; 32],
        src: PeerId([0x22; 32]),
        src_pubkey: vec![0x33; 32],
        ts: 1_700_000_000,
        exp: 1_700_000_000 + 3600,
        ttl: DEFAULT_TTL,
        hops: 0,
        seen: vec![0u8; 128],
        pow: vec![0u8; 8],
        sig: vec![0u8; 64],
        payload_type: GossipPayloadType::UserMessage as u8,
        payload: vec![0xABu8; 256],
    }
}

// -- §3.1 version field -------------------------------------------------------

#[clause("PNP-005-MUST-001", "PNP-005-MUST-012")]
#[test]
fn v_must_be_one_or_envelope_is_rejected() {
    let mut e = sample_envelope();
    e.v = 1;
    assert!(e.is_valid_structure());

    for bad in [0u8, 2, 99, 255] {
        let mut e2 = sample_envelope();
        e2.v = bad;
        assert!(
            !e2.is_valid_structure(),
            "version {bad} must be rejected (PNP-005-MUST-001/012)"
        );
        let bytes = e2.to_cbor().unwrap();
        GossipEnvelope::from_cbor(&bytes).expect_err(
            "decoder MUST reject envelope with v != 1 (PNP-005-MUST-012)",
        );
    }
}

// -- §3.2 GossipPayloadType registry -----------------------------------------

#[clause("PNP-005-MUST-010")]
#[test]
fn payload_type_registry_covers_defined_codes() {
    for code in 0x01u8..=0x05u8 {
        let t = GossipPayloadType::from_u8(code)
            .unwrap_or_else(|| panic!("code {code:#04x} rejected"));
        assert_eq!(t as u8, code);
    }
    assert!(GossipPayloadType::from_u8(0x06).is_none());
    assert!(GossipPayloadType::from_u8(0x00).is_none());
}

// -- §5.4 / §3.1 Anonymous envelope --------------------------------------------

#[clause("PNP-005-MUST-005", "PNP-005-MUST-006")]
#[test]
fn make_anonymous_zeros_src_and_empties_pubkey() {
    let mut e = sample_envelope();
    e.make_anonymous();
    assert_eq!(e.src, PeerId([0u8; 32]), "MUST-005: src must be 32 zero bytes");
    assert!(e.src_pubkey.is_empty(), "MUST-006: src_pubkey must be empty");
    assert!(e.is_anonymous());
    assert!(e.is_valid_structure(), "anonymous envelope must still pass structural check");
}

#[clause("PNP-005-MUST-005")]
#[test]
fn anonymous_envelope_with_nonzero_src_is_rejected() {
    let mut e = sample_envelope();
    e.src_pubkey = vec![]; // pretend anonymous...
    // ...but leave src non-zero
    assert!(
        !e.is_valid_structure(),
        "anonymous claim with non-zero src MUST fail structural check"
    );
}

// -- §5.1 Expiry check --------------------------------------------------------

#[clause("PNP-005-MUST-013")]
#[test]
fn expired_envelope_is_recognized() {
    let e = sample_envelope();
    assert!(!e.is_expired(e.ts));
    assert!(!e.is_expired(e.exp - 1));
    assert!(e.is_expired(e.exp));
    assert!(e.is_expired(e.exp + 1));
}

// -- §5.5 TTL bounds ----------------------------------------------------------

#[clause("PNP-005-MUST-025")]
#[test]
fn default_ttl_is_seven() {
    assert_eq!(DEFAULT_TTL, 7);
}

#[clause("PNP-005-MUST-025")]
#[test]
fn ttl_has_upper_bound_fifteen() {
    assert_eq!(MAX_TTL, 15);
    let mut e = sample_envelope();
    e.ttl = 16;
    let bytes = e.to_cbor().unwrap();
    GossipEnvelope::from_cbor(&bytes).expect_err(
        "ttl > 15 MUST be rejected at decode time (PNP-005-MUST-025)",
    );
}

// -- §5.5 Expiry cap (exp ≤ ts + 86400) ---------------------------------------

#[clause("PNP-005-MUST-026")]
#[test]
fn expiry_beyond_24_hours_is_rejected() {
    let mut e = sample_envelope();
    e.exp = e.ts + 86400 + 1;
    let bytes = e.to_cbor().unwrap();
    GossipEnvelope::from_cbor(&bytes).expect_err(
        "exp > ts + 86400 MUST be rejected (PNP-005-MUST-026)",
    );
}

// -- §5.1 Payload size bound --------------------------------------------------

#[clause("PNP-005-MUST-019")]
#[test]
fn oversize_payload_is_rejected() {
    assert_eq!(MAX_GOSSIP_PAYLOAD, 65536);
    let mut e = sample_envelope();
    e.payload = vec![0u8; MAX_GOSSIP_PAYLOAD + 1];
    let bytes = e.to_cbor().unwrap();
    GossipEnvelope::from_cbor(&bytes).expect_err(
        "payload > 65536 bytes MUST be rejected (PNP-005-MUST-019)",
    );
}

// -- §5.6 PoW difficulty for RELAY_DESCRIPTOR ---------------------------------

#[clause("PNP-005-MUST-036")]
#[test]
fn relay_descriptor_requires_20_bit_pow() {
    assert_eq!(
        GossipPayloadType::RelayDescriptor.pow_difficulty(),
        20,
        "PNP-005-MUST-036: RELAY_DESCRIPTOR difficulty must be 20 bits"
    );
}

#[clause("PNP-005-MUST-035")]
#[test]
fn non_relay_payloads_require_16_bit_pow_floor() {
    for t in [
        GossipPayloadType::UserMessage,
        GossipPayloadType::PeerAnnouncement,
        GossipPayloadType::GroupMetadata,
        GossipPayloadType::Revocation,
    ] {
        assert!(
            t.pow_difficulty() >= 16,
            "every gossip payload type MUST have PoW difficulty >= 16 (PNP-005-MUST-035), got {t:?}={}",
            t.pow_difficulty()
        );
    }
}

// -- §3.1 Signature does not cover hops/seen (MUST-003) ------------------------

#[clause("PNP-005-MUST-003")]
#[test]
fn signable_bytes_excludes_hops_and_seen() {
    let e = sample_envelope();
    let base = e.signable_bytes();
    let mut mutated = e.clone();
    mutated.hops = 99;
    mutated.seen = vec![0xFFu8; 128];
    assert_eq!(
        base,
        mutated.signable_bytes(),
        "MUST-003: signable_bytes must be stable under hops/seen mutation"
    );
}

#[clause("PNP-005-MUST-003")]
#[test]
fn signable_bytes_covers_all_other_fields() {
    let base = sample_envelope();
    let baseline = base.signable_bytes();

    let mutators: Vec<Box<dyn Fn(&mut GossipEnvelope)>> = vec![
        Box::new(|e| e.v = 0),
        Box::new(|e| e.id[0] ^= 0xFF),
        Box::new(|e| e.ts += 1),
        Box::new(|e| e.exp += 1),
        Box::new(|e| e.ttl = e.ttl.wrapping_add(1)),
        Box::new(|e| e.pow[0] ^= 0xFF),
        Box::new(|e| e.payload_type = 0xEE),
        Box::new(|e| e.payload[0] ^= 0xFF),
    ];
    for m in mutators {
        let mut ev = base.clone();
        m(&mut ev);
        assert_ne!(
            baseline,
            ev.signable_bytes(),
            "MUST-003: every non-relay-modified field must be covered by the signable digest"
        );
    }
}

// -- §3.1 Message ID length ---------------------------------------------------

#[clause("PNP-005-MUST-011")]
#[test]
fn malformed_id_length_is_rejected_at_decode() {
    let mut e = sample_envelope();
    e.id = vec![0u8; 31]; // one byte short
    let bytes = e.to_cbor().unwrap();
    GossipEnvelope::from_cbor(&bytes).expect_err(
        "id field != 32 bytes MUST be rejected (PNP-005-MUST-011)",
    );
}

// -- §5.2 Default fanout ------------------------------------------------------

#[clause("PNP-005-MUST-020")]
#[test]
fn default_fanout_is_three() {
    assert_eq!(DEFAULT_FANOUT, 3);
}
