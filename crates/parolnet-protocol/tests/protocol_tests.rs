use parolnet_protocol::*;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::codec::CborCodec;
use parolnet_protocol::envelope::{CleartextHeader, Envelope};
use parolnet_protocol::handshake::{HandshakeState, HandshakeType};
use parolnet_protocol::message::{MessageFlags, MessageType};
use parolnet_protocol::padding::{self, BucketPadding};

// ── PeerId Tests ────────────────────────────────────────────────

#[test]
fn test_peer_id_from_public_key() {
    let pubkey = [0xABu8; 32];
    let peer_id = PeerId::from_public_key(&pubkey);
    assert_eq!(peer_id.as_bytes().len(), 32);
    assert_eq!(PeerId::from_public_key(&pubkey), peer_id);
}

#[test]
fn test_peer_id_display() {
    let peer_id = PeerId([0xAB; 32]);
    let s = format!("{peer_id}");
    assert!(s.contains("abababab"));
    assert!(s.ends_with("..."));
}

// ── Message Type Tests ──────────────────────────────────────────

#[test]
fn test_message_type_roundtrip() {
    for code in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06] {
        assert!(MessageType::from_u8(code).is_some());
    }
    assert!(MessageType::from_u8(0xFF).is_none());
}

// ── Timestamp Tests ─────────────────────────────────────────────

#[test]
fn test_timestamp_coarsening() {
    assert_eq!(CleartextHeader::coarsen_timestamp(1000), 900);
    assert_eq!(CleartextHeader::coarsen_timestamp(300), 300);
    assert_eq!(CleartextHeader::coarsen_timestamp(0), 0);
    assert_eq!(CleartextHeader::coarsen_timestamp(599), 300);
}

// ── TTL / Hops Tests ────────────────────────────────────────────

#[test]
fn test_ttl_and_hops() {
    let mut header = make_test_header();
    assert_eq!(header.ttl(), 7);
    assert_eq!(header.hop_count(), 0);

    header.increment_hop();
    assert_eq!(header.ttl(), 7);
    assert_eq!(header.hop_count(), 1);
}

// ── Bucket Padding Tests ────────────────────────────────────────

#[test]
fn test_bucket_selection() {
    assert_eq!(padding::select_bucket(100), Some(256));
    assert_eq!(padding::select_bucket(256), Some(256));
    assert_eq!(padding::select_bucket(257), Some(1024));
    assert_eq!(padding::select_bucket(1024), Some(1024));
    assert_eq!(padding::select_bucket(4096), Some(4096));
    assert_eq!(padding::select_bucket(16384), Some(16384));
    assert_eq!(padding::select_bucket(16385), None);
}

#[test]
fn test_padding_roundtrip() {
    let padder = BucketPadding;

    for msg in [b"hello".as_slice(), b"", &[0xAB; 100], &[0xFF; 1000]] {
        let padded = padder.pad(msg);
        assert!(BUCKET_SIZES.contains(&padded.len()), "padded len {} not a bucket size", padded.len());
        let unpadded = padder.unpad(&padded).unwrap();
        assert_eq!(unpadded, msg);
    }
}

#[test]
fn test_padding_exact_bucket_boundaries() {
    let padder = BucketPadding;

    // 252 bytes of data + 4 byte prefix = 256 exactly
    let data = vec![0xAB; 252];
    let padded = padder.pad(&data);
    assert_eq!(padded.len(), 256);
    assert_eq!(padder.unpad(&padded).unwrap(), data);

    // 253 bytes of data + 4 byte prefix = 257 → bucket 1024
    let data = vec![0xAB; 253];
    let padded = padder.pad(&data);
    assert_eq!(padded.len(), 1024);
    assert_eq!(padder.unpad(&padded).unwrap(), data);
}

#[test]
fn test_padding_invalid_bucket_size() {
    let padder = BucketPadding;
    let bad_data = vec![0u8; 100]; // not a bucket size
    assert!(padder.unpad(&bad_data).is_err());
}

#[test]
fn test_padding_large_message() {
    let padder = BucketPadding;
    let data = vec![0xCD; 10000];
    let padded = padder.pad(&data);
    assert_eq!(padded.len(), 16384);
    assert_eq!(padder.unpad(&padded).unwrap(), data);
}

// ── CBOR Codec Tests ────────────────────────────────────────────

fn make_test_header() -> CleartextHeader {
    CleartextHeader {
        version: 1,
        msg_type: 0x01,
        dest_peer_id: PeerId([0xAB; 32]),
        message_id: [0xCD; 16],
        timestamp: CleartextHeader::coarsen_timestamp(1700000000),
        ttl_and_hops: (7 << 8) | 0,
        source_hint: None,
    }
}

fn make_test_envelope() -> Envelope {
    Envelope {
        header: make_test_header(),
        encrypted_payload: vec![0xEE; 64],
        mac: [0xFF; 16],
    }
}

#[test]
fn test_codec_header_roundtrip() {
    use parolnet_protocol::codec::{encode_header, decode_header};

    let header = make_test_header();
    let bytes = encode_header(&header).unwrap();
    let decoded = decode_header(&bytes).unwrap();

    assert_eq!(decoded.version, header.version);
    assert_eq!(decoded.msg_type, header.msg_type);
    assert_eq!(decoded.dest_peer_id, header.dest_peer_id);
    assert_eq!(decoded.message_id, header.message_id);
    assert_eq!(decoded.timestamp, header.timestamp);
    assert_eq!(decoded.ttl_and_hops, header.ttl_and_hops);
    assert_eq!(decoded.source_hint, header.source_hint);
}

#[test]
fn test_codec_header_with_source_hint() {
    use parolnet_protocol::codec::{encode_header, decode_header};

    let mut header = make_test_header();
    header.source_hint = Some(PeerId([0x12; 32]));

    let bytes = encode_header(&header).unwrap();
    let decoded = decode_header(&bytes).unwrap();
    assert_eq!(decoded.source_hint, Some(PeerId([0x12; 32])));
}

#[test]
fn test_codec_envelope_roundtrip() {
    let codec = CborCodec;
    let envelope = make_test_envelope();

    let bytes = codec.encode(&envelope).unwrap();
    let decoded = codec.decode(&bytes).unwrap();

    assert_eq!(decoded.header.version, envelope.header.version);
    assert_eq!(decoded.header.dest_peer_id, envelope.header.dest_peer_id);
    assert_eq!(decoded.encrypted_payload, envelope.encrypted_payload);
    assert_eq!(decoded.mac, envelope.mac);
}

#[test]
fn test_codec_rejects_invalid_version() {
    use parolnet_protocol::codec::{encode_header, decode_header};

    let mut header = make_test_header();
    header.version = 99;

    // Encode with bad version
    let bytes = encode_header(&header);
    // encode_header doesn't validate, but decode_header should reject
    if let Ok(bytes) = bytes {
        assert!(decode_header(&bytes).is_err());
    }
}

#[test]
fn test_envelope_total_size() {
    let envelope = make_test_envelope();
    let size = envelope.total_size();
    assert!(size > 0);
    // 4 (header len prefix) + header CBOR + 64 (payload) + 16 (MAC)
    assert!(size > 84);
}

// ── MessageFlags Tests ──────────────────────────────────────────

#[test]
fn test_flags_default_all_zero() {
    assert_eq!(MessageFlags::default().0, 0);
}

#[test]
fn test_flags_set_and_check_decoy() {
    let mut flags = MessageFlags::default();
    flags.set_decoy();
    assert!(flags.is_decoy());
}

#[test]
fn test_flags_set_and_check_ack() {
    let mut flags = MessageFlags::default();
    flags.set_requires_ack();
    assert!(flags.requires_ack());
}

#[test]
fn test_flags_set_and_check_fragment() {
    let mut flags = MessageFlags::default();
    flags.set_fragment();
    assert!(flags.is_fragment());
}

#[test]
fn test_flags_set_and_check_final_fragment() {
    let mut flags = MessageFlags::default();
    flags.set_final_fragment();
    assert!(flags.is_final_fragment());
}

#[test]
fn test_flags_multiple_set() {
    let mut flags = MessageFlags::default();
    flags.set_decoy();
    flags.set_fragment();
    assert!(flags.is_decoy());
    assert!(flags.is_fragment());
    assert!(!flags.requires_ack());
    assert!(!flags.is_final_fragment());
}

#[test]
fn test_flags_raw_bits() {
    assert!(MessageFlags(0x01).is_decoy());
    assert!(MessageFlags(0x02).requires_ack());
    assert!(MessageFlags(0x04).is_fragment());
    assert!(MessageFlags(0x08).is_final_fragment());
}

// ── Handshake Type Tests ────────────────────────────────────────

#[test]
fn test_handshake_state_all_variants() {
    let states = [
        HandshakeState::Init,
        HandshakeState::Offered,
        HandshakeState::Accepted,
        HandshakeState::Established,
        HandshakeState::Rekeying,
        HandshakeState::Closed,
    ];
    // Verify all variants are distinct
    for i in 0..states.len() {
        for j in (i + 1)..states.len() {
            assert_ne!(states[i], states[j]);
        }
    }
}

#[test]
fn test_handshake_type_repr_values() {
    assert_eq!(HandshakeType::Init as u8, 0x01);
    assert_eq!(HandshakeType::Response as u8, 0x02);
    assert_eq!(HandshakeType::Rekey as u8, 0x03);
    assert_eq!(HandshakeType::Close as u8, 0x04);
    assert_eq!(HandshakeType::BootstrapInit as u8, 0x10);
    assert_eq!(HandshakeType::BootstrapResp as u8, 0x11);
    assert_eq!(HandshakeType::SasConfirm as u8, 0x12);
}

// ── Error Path Tests ────────────────────────────────────────────

#[test]
fn test_codec_decode_truncated() {
    let codec = CborCodec;
    assert!(codec.decode(&[0x00, 0x01]).is_err());
}

#[test]
fn test_codec_decode_garbage() {
    let codec = CborCodec;
    assert!(codec.decode(&[0xFF; 100]).is_err());
}

#[test]
fn test_padding_unpad_corrupted_length() {
    let padder = BucketPadding;
    let mut data = vec![0u8; 256];
    // Set length prefix to 300 (exceeds 256-byte bucket)
    let len_bytes = 300u32.to_be_bytes();
    data[0..4].copy_from_slice(&len_bytes);
    assert!(padder.unpad(&data).is_err());
}

#[test]
fn test_ttl_increment_at_max() {
    let mut header = CleartextHeader {
        version: 1,
        msg_type: 0x01,
        dest_peer_id: PeerId([0xAB; 32]),
        message_id: [0xCD; 16],
        timestamp: 0,
        ttl_and_hops: (7 << 8) | 255, // hop_count = 255
        source_hint: None,
    };
    header.increment_hop();
    assert_eq!(header.hop_count(), 255); // saturates, no overflow
}

#[test]
fn test_envelope_is_valid_size_true() {
    // Build an envelope and adjust encrypted_payload so total_size() hits a bucket size
    let header = CleartextHeader {
        version: 1,
        msg_type: 0x01,
        dest_peer_id: PeerId([0xAB; 32]),
        message_id: [0xCD; 16],
        timestamp: CleartextHeader::coarsen_timestamp(1700000000),
        ttl_and_hops: (7 << 8) | 0,
        source_hint: None,
    };

    // Compute header CBOR size to figure out how large encrypted_payload must be
    let header_cbor_len = parolnet_protocol::codec::encode_header(&header).unwrap().len();
    // total_size = 4 + header_cbor_len + encrypted_payload.len() + 16
    // We want total_size == 1024
    let payload_len = 1024 - 4 - header_cbor_len - 16;

    let envelope = Envelope {
        header,
        encrypted_payload: vec![0xEE; payload_len],
        mac: [0xFF; 16],
    };

    assert_eq!(envelope.total_size(), 1024);
    assert!(envelope.is_valid_size());
}

#[test]
fn test_padding_unpad_too_short() {
    let padder = BucketPadding;
    assert!(padder.unpad(&[0x00, 0x01, 0x02]).is_err());
}

// ── New Message Type Tests ─────────────────────────────────────

#[test]
fn test_new_message_types() {
    // Audio through CallSignal from_u8 roundtrip
    assert_eq!(MessageType::from_u8(0x07), Some(MessageType::Audio));
    assert_eq!(MessageType::from_u8(0x08), Some(MessageType::Video));
    assert_eq!(MessageType::from_u8(0x09), Some(MessageType::FileChunk));
    assert_eq!(MessageType::from_u8(0x0A), Some(MessageType::FileControl));
    assert_eq!(MessageType::from_u8(0x0B), Some(MessageType::CallSignal));

    // Verify repr roundtrip
    assert_eq!(MessageType::Audio as u8, 0x07);
    assert_eq!(MessageType::Video as u8, 0x08);
    assert_eq!(MessageType::FileChunk as u8, 0x09);
    assert_eq!(MessageType::FileControl as u8, 0x0A);
    assert_eq!(MessageType::CallSignal as u8, 0x0B);

    // Invalid codes still return None
    assert!(MessageType::from_u8(0x0C).is_none());
    assert!(MessageType::from_u8(0x00).is_none());
}

// ── File Transfer Tests ────────────────────────────────────────

#[test]
fn test_file_offer_total_chunks() {
    use parolnet_protocol::file::FileOffer;

    // 10000 byte file with 4096 chunk size = 3 chunks
    let offer = FileOffer {
        file_id: [0u8; 16],
        file_name: "test.bin".to_string(),
        file_size: 10000,
        chunk_size: 4096,
        sha256: [0u8; 32],
        mime_type: None,
    };
    assert_eq!(offer.total_chunks(), 3);

    // 0 byte file = 1 chunk
    let empty = FileOffer {
        file_size: 0,
        ..offer.clone()
    };
    assert_eq!(empty.total_chunks(), 1);

    // Exact multiple: 8192 / 4096 = 2
    let exact = FileOffer {
        file_size: 8192,
        ..offer.clone()
    };
    assert_eq!(exact.total_chunks(), 2);
}

#[test]
fn test_file_action_serialization() {
    use parolnet_protocol::file::{FileOffer, FileControl, FileAction};

    let offer = FileOffer {
        file_id: [0xAB; 16],
        file_name: "photo.jpg".to_string(),
        file_size: 1024000,
        chunk_size: 4096,
        sha256: [0xCD; 32],
        mime_type: Some("image/jpeg".to_string()),
    };

    // Serialize and deserialize FileOffer via CBOR
    let mut buf = Vec::new();
    ciborium::into_writer(&offer, &mut buf).unwrap();
    let decoded: FileOffer = ciborium::from_reader(&buf[..]).unwrap();
    assert_eq!(decoded.file_id, offer.file_id);
    assert_eq!(decoded.file_name, offer.file_name);
    assert_eq!(decoded.file_size, offer.file_size);
    assert_eq!(decoded.sha256, offer.sha256);
    assert_eq!(decoded.mime_type, Some("image/jpeg".to_string()));

    // Serialize and deserialize FileControl via CBOR
    let control = FileControl {
        file_id: [0xAB; 16],
        action: FileAction::Accept,
        resume_from: None,
    };
    let mut buf2 = Vec::new();
    ciborium::into_writer(&control, &mut buf2).unwrap();
    let decoded_ctrl: FileControl = ciborium::from_reader(&buf2[..]).unwrap();
    assert_eq!(decoded_ctrl.file_id, control.file_id);
    assert!(decoded_ctrl.resume_from.is_none());
}

// ── Media / Call Tests ─────────────────────────────────────────

#[test]
fn test_call_state_distinct() {
    use parolnet_protocol::media::CallState;

    let states = [
        CallState::Idle,
        CallState::Offering,
        CallState::Ringing,
        CallState::Active,
        CallState::Ended,
        CallState::Rejected,
    ];
    for i in 0..states.len() {
        for j in (i + 1)..states.len() {
            assert_ne!(states[i], states[j], "{:?} should differ from {:?}", states[i], states[j]);
        }
    }
}

#[test]
fn test_video_config_default() {
    use parolnet_protocol::media::{VideoConfig, VideoCodec};

    let config = VideoConfig::default();
    assert_eq!(config.width, 320);
    assert_eq!(config.height, 240);
    assert_eq!(config.bitrate_kbps, 200);
    assert_eq!(config.codec, VideoCodec::VP8);
}
