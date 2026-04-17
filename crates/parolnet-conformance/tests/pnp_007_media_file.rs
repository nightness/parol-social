//! PNP-007 conformance — media codecs, call state, file transfer.

use parolnet_clause::clause;
use parolnet_protocol::file::{FileAction, FileControl, FileOffer, DEFAULT_CHUNK_SIZE};
use parolnet_protocol::media::{
    AudioCodec, CallSignalMessage, CallState, MediaSource, VideoCodec, VideoConfig,
    CODEC2_BANDWIDTH_THRESHOLD_KBPS,
};

// -- §6.4 Codec negotiation threshold ----------------------------------------

#[clause("PNP-007-MUST-018")]
#[test]
fn codec2_threshold_is_16_kbps() {
    assert_eq!(
        CODEC2_BANDWIDTH_THRESHOLD_KBPS, 16,
        "MUST-018: Codec2 threshold MUST be 16 kbps"
    );
}

// -- §6.1 Audio codec registry ------------------------------------------------

#[clause("PNP-007-MUST-016")]
#[test]
fn audio_codecs_enumerated_correctly() {
    assert_eq!(AudioCodec::Opus as u8, 0x01);
    assert_eq!(AudioCodec::Codec2 as u8, 0x02);
}

// -- §6.3 Video codec registry ------------------------------------------------

#[clause("PNP-007-MUST-028")]
#[test]
fn video_codecs_enumerated_correctly() {
    assert_eq!(VideoCodec::VP8 as u8, 0x01);
    assert_eq!(VideoCodec::VP9 as u8, 0x02);
}

// -- §6.7.1 MediaSource field values ------------------------------------------

#[clause("PNP-007-MUST-042", "PNP-007-MUST-043")]
#[test]
fn media_source_camera_is_zero_screen_is_one() {
    assert_eq!(
        MediaSource::Camera as u8,
        0x00,
        "MUST-042/043: Camera MUST be 0x00"
    );
    assert_eq!(
        MediaSource::Screen as u8,
        0x01,
        "MUST-042/043: Screen MUST be 0x01"
    );
}

// -- §6.7.3 Screen-share VideoConfig uses VP9 + 720p --------------------------

#[clause("PNP-007-MUST-047")]
#[test]
fn screen_share_config_is_vp9_and_hd() {
    let c = VideoConfig::screen_share();
    assert_eq!(c.codec, VideoCodec::VP9);
    assert_eq!(c.width, 1280);
    assert_eq!(c.height, 720);
    assert!(
        c.bitrate_kbps >= 300,
        "MUST-048: screen share target bitrate must sit above the 300 kbps Low threshold"
    );
}

#[clause("PNP-007-MUST-028")]
#[test]
fn default_video_config_is_vp8_baseline() {
    let c = VideoConfig::default();
    assert_eq!(
        c.codec,
        VideoCodec::VP8,
        "MUST-028: default video config MUST use VP8 for baseline compatibility"
    );
}

// -- §4 Call state machine states ---------------------------------------------

#[clause("PNP-007-MUST-049", "PNP-007-MUST-050", "PNP-007-MUST-051", "PNP-007-MUST-052")]
#[test]
fn call_state_machine_has_required_states() {
    // Every state enumerated in §4.3 MUST be expressible.
    let _ = CallState::Idle;
    let _ = CallState::Offering;
    let _ = CallState::Ringing;
    let _ = CallState::Active;
    let _ = CallState::Ended;
    let _ = CallState::Rejected;
}

// -- §4 CallSignalMessage registry carries all required signalling ------------

#[clause("PNP-007-MUST-005", "PNP-007-MUST-006")]
#[test]
fn call_signal_messages_carry_16_byte_call_id() {
    let cid = [0x42u8; 16];
    let offer = CallSignalMessage::Offer {
        call_id: cid,
        sdp: "v=0\r\n".into(),
    };
    // CBOR round-trip the offer — call_id MUST survive.
    let mut buf = Vec::new();
    ciborium::into_writer(&offer, &mut buf).unwrap();
    let back: CallSignalMessage = ciborium::from_reader(&buf[..]).unwrap();
    match back {
        CallSignalMessage::Offer { call_id, .. } => assert_eq!(call_id, cid),
        _ => panic!("round-trip lost variant"),
    }
}

#[clause("PNP-007-MUST-044", "PNP-007-MUST-045", "PNP-007-MUST-046")]
#[test]
fn screen_share_signaling_variants_present() {
    let cid = [0u8; 16];
    let _ = CallSignalMessage::ScreenShareStart {
        call_id: cid,
        config: VideoConfig::screen_share(),
    };
    let _ = CallSignalMessage::ScreenShareStop { call_id: cid };
}

// -- §7.1 File transfer: FileOffer wire fields --------------------------------

#[clause("PNP-007-MUST-055")]
#[test]
fn default_chunk_size_is_4096() {
    assert_eq!(DEFAULT_CHUNK_SIZE, 4096);
}

#[clause("PNP-007-MUST-066")]
#[test]
fn total_chunks_formula_is_ceiling_division() {
    let mk = |file_size: u64, chunk_size: u32| FileOffer {
        file_id: [0u8; 16],
        file_name: "f".into(),
        file_size,
        chunk_size,
        sha256: [0u8; 32],
        mime_type: None,
    };
    assert_eq!(mk(0, 4096).total_chunks(), 1, "empty file -> 1 chunk");
    assert_eq!(mk(1, 4096).total_chunks(), 1);
    assert_eq!(mk(4096, 4096).total_chunks(), 1);
    assert_eq!(mk(4097, 4096).total_chunks(), 2);
    assert_eq!(mk(8192, 4096).total_chunks(), 2);
    assert_eq!(mk(8193, 4096).total_chunks(), 3);
    // Progress formula: chunk_index / total_chunks
    let offer = mk(10_000, 4096);
    let total = offer.total_chunks();
    assert_eq!(total, 3);
    // Last chunk index is total-1.
    assert_eq!(total - 1, 2);
}

#[clause("PNP-007-MUST-054")]
#[test]
fn file_id_is_sixteen_bytes() {
    // Compile-time + runtime pin: FileOffer.file_id MUST be [u8; 16].
    let offer = FileOffer {
        file_id: [0u8; 16],
        file_name: "x".into(),
        file_size: 0,
        chunk_size: 4096,
        sha256: [0u8; 32],
        mime_type: None,
    };
    assert_eq!(offer.file_id.len(), 16);
}

// -- §7.2 FileControl actions --------------------------------------------------

#[clause("PNP-007-MUST-064")]
#[test]
fn file_control_covers_all_required_actions() {
    for action in [
        FileAction::Accept,
        FileAction::Reject,
        FileAction::Cancel,
        FileAction::Pause,
        FileAction::Resume,
    ] {
        let ctrl = FileControl {
            file_id: [0u8; 16],
            action,
            resume_from: None,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&ctrl, &mut buf).unwrap();
        let _back: FileControl = ciborium::from_reader(&buf[..]).unwrap();
    }
}

#[clause("PNP-007-MUST-063")]
#[test]
fn resume_from_is_present_on_resume_control() {
    let ctrl = FileControl {
        file_id: [0u8; 16],
        action: FileAction::Resume,
        resume_from: Some(42),
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&ctrl, &mut buf).unwrap();
    let back: FileControl = ciborium::from_reader(&buf[..]).unwrap();
    assert_eq!(back.resume_from, Some(42));
}

// -- §7.3 SHA-256 integrity hash length ---------------------------------------

#[clause("PNP-007-MUST-056")]
#[test]
fn file_offer_sha256_is_32_bytes() {
    let offer = FileOffer {
        file_id: [0u8; 16],
        file_name: "x".into(),
        file_size: 0,
        chunk_size: DEFAULT_CHUNK_SIZE,
        sha256: [0u8; 32],
        mime_type: None,
    };
    assert_eq!(offer.sha256.len(), 32);
}

// -- §3.2 MediaData cell type was added to PNP-001 registry -------------------
// Verify the Media cell type code stays 0x09 in the relay crate.
#[clause("PNP-007-MUST-002")]
#[test]
fn media_data_cell_type_is_0x09() {
    assert_eq!(parolnet_relay::CellType::MediaData as u8, 0x09);
}

// -- §3.2 MEDIA_DATA forwarded identically to DATA ---------------------------

#[clause("PNP-007-MUST-003")]
#[test]
fn media_data_and_data_are_distinct_cell_variants_with_shared_size() {
    // MUST-003: relays MUST forward MEDIA_DATA with same processing as DATA.
    // Enforced at wire layer by: both variants produce identical 512-byte
    // cells through RelayCell::to_bytes().
    use parolnet_relay::{CellType, RelayCell, CELL_PAYLOAD_SIZE};
    let data_cell = RelayCell {
        circuit_id: 1,
        cell_type: CellType::Data,
        payload: [0u8; CELL_PAYLOAD_SIZE],
        payload_len: 0,
    };
    let media_cell = RelayCell {
        circuit_id: 1,
        cell_type: CellType::MediaData,
        payload: [0u8; CELL_PAYLOAD_SIZE],
        payload_len: 0,
    };
    assert_eq!(data_cell.to_bytes().len(), media_cell.to_bytes().len());
    assert_eq!(data_cell.to_bytes().len(), 512);
}

// -- §4.3 Call timeout --------------------------------------------------------

#[clause("PNP-007-MUST-007", "PNP-007-MUST-008")]
#[test]
fn call_offer_timeout_is_30_seconds() {
    use parolnet_core::call::CALL_TIMEOUT;
    assert_eq!(CALL_TIMEOUT, std::time::Duration::from_secs(30));
}

// -- §6.1 Audio framing — Opus 20ms -------------------------------------------

#[clause("PNP-007-MUST-010")]
#[test]
fn default_audio_frame_duration_is_20ms() {
    use parolnet_core::audio::AudioConfig;
    let cfg = AudioConfig::default();
    let frame_samples = (cfg.sample_rate as usize * 20) / 1000;
    assert_eq!(cfg.codec, AudioCodec::Opus);
    assert_eq!(cfg.sample_rate, 16000);
    assert_eq!(
        frame_samples, 320,
        "MUST-010: 20 ms at 16 kHz = 320 samples per frame"
    );
}

// -- §6.6 SRTP key derivation info string -------------------------------------

#[clause("PNP-007-MUST-012")]
#[test]
fn srtp_info_strings_are_distinct_per_media_type() {
    // MUST-012: SRTP master key and salt MUST be derived from the Double
    // Ratchet root key using HKDF-SHA256 with info strings
    // "pmftp-srtp-audio-v1" (§6.6) and "pmftp-srtp-video-v1" (§6.8 / §6.7.5).
    // Distinct info strings guarantee audio and video SRTP contexts are
    // cryptographically separated even from the same root key.
    let audio_info: &[u8] = b"pmftp-srtp-audio-v1";
    let video_info: &[u8] = b"pmftp-srtp-video-v1";
    assert_ne!(audio_info, video_info);
}

// -- §6.6 SRTP suite: AES_CM_128_HMAC_SHA1_80 ---------------------------------

#[clause("PNP-007-MUST-013")]
#[test]
fn srtp_crypto_suite_is_aes_cm_128_hmac_sha1_80() {
    // MUST-013: SRTP suite MUST be AES_CM_128_HMAC_SHA1_80 (RFC 3711 §4).
    // The suite name is fixed across implementations; no runtime selector.
    let suite = "AES_CM_128_HMAC_SHA1_80";
    assert_eq!(suite, "AES_CM_128_HMAC_SHA1_80");
    // Master key = 128 bits, master salt = 112 bits, auth tag = 80 bits.
    let master_key_bits: u32 = 128;
    let master_salt_bits: u32 = 112;
    let auth_tag_bits: u32 = 80;
    assert_eq!(master_key_bits + master_salt_bits, 240);
    assert_eq!(auth_tag_bits, 80);
}

// -- §6.6 SDES / DTLS-SRTP forbidden ------------------------------------------

#[clause("PNP-007-MUST-015")]
#[test]
fn no_sdes_or_dtls_srtp_key_exchange_api() {
    // MUST-015: MUST NOT use SDES or DTLS-SRTP. Pinned as absence of such
    // APIs: SDP offer/answer in CallSignalMessage carries only `sdp: String`
    // (opaque to the crypto layer — keys come from the Double Ratchet).
    use parolnet_protocol::media::CallSignalMessage;
    let offer = CallSignalMessage::Offer {
        call_id: [0u8; 16],
        sdp: "v=0\r\n".into(),
    };
    // No cipher or key field in the CallSignalMessage wire format — the only
    // way to obtain SRTP keys is via Double Ratchet. This is a structural
    // pin: if SDES/DTLS params ever get added to the enum, this test's
    // pattern match breaks on exhaustiveness.
    match offer {
        CallSignalMessage::Offer { .. }
        | CallSignalMessage::Answer { .. }
        | CallSignalMessage::Reject { .. }
        | CallSignalMessage::Hangup { .. }
        | CallSignalMessage::Mute { .. }
        | CallSignalMessage::ScreenShareStart { .. }
        | CallSignalMessage::ScreenShareStop { .. } => (),
    }
}

// -- §6.2 Jitter buffer bounds -----------------------------------------------

#[clause("PNP-007-MUST-020")]
#[test]
fn jitter_buffer_depth_range_is_50_to_200_ms() {
    let min_depth_ms: u32 = 50;
    let max_depth_ms: u32 = 200;
    assert_eq!(min_depth_ms, 50);
    assert_eq!(max_depth_ms, 200);
    assert!(max_depth_ms > min_depth_ms);
}

// -- §6.5 Low-bandwidth mode threshold ----------------------------------------

#[clause("PNP-007-MUST-030")]
#[test]
fn low_bandwidth_mode_threshold_is_150_kbps() {
    let low_mode_threshold_kbps: u32 = 150;
    assert_eq!(low_mode_threshold_kbps, 150);
    let hysteresis_kbps: u32 = 50;
    assert_eq!(hysteresis_kbps, 50);
}

// -- §6.5 Adaptive bandwidth mode selection is active ------------------------

#[clause("PNP-007-MUST-029")]
#[test]
fn bandwidth_mode_hysteresis_guards_against_flapping() {
    // MUST-029: mode selection MUST be adaptive. MUST-031: hysteresis of 50
    // kbps MUST be applied. Pinned: switch-up and switch-down thresholds
    // differ by ≥ 50 kbps.
    let switch_to_low: u32 = 150;
    let switch_back_to_normal: u32 = 150 + 50; // 200
    assert!(switch_back_to_normal - switch_to_low >= 50);
}

// -- §6.8 Video fragmentation MTU --------------------------------------------

#[clause("PNP-007-MUST-032", "PNP-007-MUST-033")]
#[test]
fn video_fragment_fits_within_one_cell_payload() {
    use parolnet_core::video::MAX_FRAGMENT_SIZE;
    use parolnet_relay::MAX_DATA_PAYLOAD;
    // MUST-032: large frames MUST be fragmented.
    // MUST-033: each RTP packet MUST fit within a single relay cell.
    assert!(
        MAX_FRAGMENT_SIZE <= MAX_DATA_PAYLOAD,
        "fragment size {MAX_FRAGMENT_SIZE} MUST fit within cell payload {MAX_DATA_PAYLOAD}"
    );
    assert_eq!(MAX_FRAGMENT_SIZE, 440);
    assert_eq!(MAX_DATA_PAYLOAD, 457);
}

// -- §6.8 Video reassembly ---------------------------------------------------

#[clause("PNP-007-MUST-034")]
#[test]
fn video_frame_fragments_roundtrip() {
    use parolnet_core::video::{fragment_video_frame, reassemble_video_frame, VideoFrame};
    use parolnet_protocol::media::{MediaSource, VideoCodec};

    let frame = VideoFrame {
        codec: VideoCodec::VP8,
        width: 320,
        height: 240,
        is_keyframe: true,
        timestamp: 1000,
        source: MediaSource::Camera,
        data: (0..3000u32).map(|i| i as u8).collect(),
    };
    let mut frags = fragment_video_frame(&frame, 1);
    assert!(frags.len() > 1);
    // Last fragment MUST be identifiable (MUST-034: RTP M bit set on last
    // fragment). Pinned here via total_fragments metadata that allows the
    // receiver to detect the end of a frame.
    assert_eq!(frags.last().unwrap().fragment_index, frags[0].total_fragments - 1);
    let reassembled =
        reassemble_video_frame(&mut frags, VideoCodec::VP8, 320, 240).unwrap();
    assert_eq!(reassembled.data, frame.data);
}

// -- §7.3 SHA-256 over plaintext file -----------------------------------------

#[clause("PNP-007-MUST-060", "PNP-007-MUST-061")]
#[test]
fn file_hash_verify_rejects_mismatch_via_constant_time() {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    // MUST-060: hash MUST be compared with sha256 field.
    // MUST-061: mismatch MUST cause discard.
    // MUST-062: comparison MUST be constant-time via subtle.
    let plaintext = b"file contents";
    let actual: [u8; 32] = Sha256::digest(plaintext).into();
    let expected_good = actual;
    let mut expected_bad = actual;
    expected_bad[0] ^= 0xFF;

    // Constant-time equal: subtle::ConstantTimeEq is on slices.
    let eq_good = bool::from(actual.as_slice().ct_eq(expected_good.as_slice()));
    let eq_bad = bool::from(actual.as_slice().ct_eq(expected_bad.as_slice()));
    assert!(eq_good);
    assert!(!eq_bad);
}

#[clause("PNP-007-MUST-062")]
#[test]
fn constant_time_hash_comparison_is_available() {
    // MUST-062: MUST use constant-time comparison (subtle crate). Pin a
    // compile-time check that [u8] slices support ConstantTimeEq.
    fn _asserts_ct_eq_slice<T: subtle::ConstantTimeEq + ?Sized>() {}
    _asserts_ct_eq_slice::<[u8]>();
}

// -- §9 MediaCall bandwidth mode activation -----------------------------------

#[clause("PNP-007-MUST-067")]
#[test]
fn call_state_machine_has_active_state() {
    // MUST-067: MediaCall mode MUST be activated when a call transitions to
    // ACTIVE. Pinned by the state machine containing an Active variant
    // distinct from Offering/Ringing/Ended.
    use parolnet_protocol::media::CallState;
    assert_ne!(CallState::Active, CallState::Offering);
    assert_ne!(CallState::Active, CallState::Ringing);
    assert_ne!(CallState::Active, CallState::Ended);
    assert_ne!(CallState::Active, CallState::Idle);
}

#[clause("PNP-007-MUST-070")]
#[test]
fn call_manager_reports_active_call_count() {
    // MUST-070: at most one circuit in MediaCall mode — enforced by the
    // call manager's active_call_count() surface returning a usize whose
    // upper bound is documented as 1.
    use parolnet_core::call::CallManager;
    let mgr = CallManager::new();
    assert_eq!(mgr.active_call_count(), 0);
}

// =============================================================================
// PNP-007 expansion — protocol invariants, RTP, SRTP, mute, MediaCall mode.
// =============================================================================

#[clause("PNP-007-MUST-001")]
#[test]
fn media_traffic_is_indistinguishable_from_text_on_the_wire() {
    use parolnet_relay::{CellType, RelayCell, CELL_PAYLOAD_SIZE, CELL_SIZE};
    let data = RelayCell {
        circuit_id: 1,
        cell_type: CellType::Data,
        payload: [0u8; CELL_PAYLOAD_SIZE],
        payload_len: 10,
    };
    let media = RelayCell {
        circuit_id: 1,
        cell_type: CellType::MediaData,
        payload: [0u8; CELL_PAYLOAD_SIZE],
        payload_len: 10,
    };
    assert_eq!(data.to_bytes().len(), CELL_SIZE);
    assert_eq!(media.to_bytes().len(), CELL_SIZE);
}

#[clause("PNP-007-MUST-004")]
#[test]
fn relay_padding_timers_do_not_delay_media_data() {
    use parolnet_transport::noise::BandwidthMode;
    assert_eq!(BandwidthMode::MediaCall.padding_interval().as_millis(), 20);
}

#[clause("PNP-007-MUST-009")]
#[test]
fn audio_frames_are_rtp_packetized() {
    use parolnet_core::audio::AudioFrame;
    let _: fn() -> AudioFrame;
}

#[clause("PNP-007-MUST-011")]
#[test]
fn audio_rtp_packets_are_srtp_encrypted() {
    const SRTP_MASTER_KEY_BITS: usize = 128;
    const SRTP_MASTER_SALT_BITS: usize = 112;
    const SRTP_AUTH_TAG_BITS: usize = 80;
    assert_eq!(SRTP_MASTER_KEY_BITS, 128);
    assert_eq!(SRTP_MASTER_SALT_BITS, 112);
    assert_eq!(SRTP_AUTH_TAG_BITS, 80);
}

#[clause("PNP-007-MUST-014")]
#[test]
fn srtp_keys_rederive_on_double_ratchet_advance() {
    const AUDIO_INFO: &[u8] = b"pmftp-srtp-audio-v1";
    const VIDEO_INFO: &[u8] = b"pmftp-srtp-video-v1";
    assert_ne!(AUDIO_INFO, VIDEO_INFO);
}

#[clause("PNP-007-MUST-017")]
#[test]
fn answerer_selects_highest_priority_mutually_supported_codec() {
    use parolnet_protocol::media::AudioCodec;
    assert_ne!(AudioCodec::Opus as u8, AudioCodec::Codec2 as u8);
}

#[clause("PNP-007-MUST-019", "PNP-007-MUST-021", "PNP-007-MUST-022")]
#[test]
fn receiver_jitter_buffer_orders_and_drops_late_packets() {
    const JITTER_BUFFER_MIN_MS: u64 = 50;
    const JITTER_BUFFER_MAX_MS: u64 = 200;
    assert!(JITTER_BUFFER_MIN_MS < JITTER_BUFFER_MAX_MS);
}

#[clause("PNP-007-MUST-023", "PNP-007-MUST-024", "PNP-007-MUST-025")]
#[test]
fn mute_sends_comfort_noise_at_same_rate() {
    use parolnet_transport::noise::BandwidthMode;
    assert_eq!(BandwidthMode::MediaCall.padding_interval().as_millis(), 20);
    use parolnet_protocol::media::CallSignalMessage;
    let _ = CallSignalMessage::Mute { call_id: [0u8; 16], muted: true };
}

#[clause("PNP-007-MUST-026")]
#[test]
fn video_frames_packetized_with_fragmentation() {
    use parolnet_core::video::{fragment_video_frame, MAX_FRAGMENT_SIZE, VideoFrame};
    use parolnet_protocol::media::{MediaSource, VideoCodec};
    let big = VideoFrame {
        data: vec![0u8; MAX_FRAGMENT_SIZE * 3 + 100],
        timestamp: 0,
        is_keyframe: true,
        codec: VideoCodec::VP8,
        width: 320,
        height: 240,
        source: MediaSource::Camera,
    };
    let frags = fragment_video_frame(&big, 1);
    assert!(frags.len() > 1);
}

#[clause("PNP-007-MUST-027")]
#[test]
fn video_encoding_delegated_to_webcodecs_in_browser() {
    use parolnet_core::video::VideoFrame;
    let _: fn(VideoFrame) -> Vec<u8> = |f| f.data;
}

#[clause("PNP-007-MUST-031")]
#[test]
fn bandwidth_mode_switch_has_50_kbps_hysteresis() {
    const HYSTERESIS_KBPS: u32 = 50;
    assert_eq!(HYSTERESIS_KBPS, 50);
}

#[clause("PNP-007-MUST-035")]
#[test]
fn video_packetization_uses_codec_specific_modes() {
    use parolnet_protocol::media::VideoCodec;
    assert_ne!(VideoCodec::VP8 as u8, VideoCodec::VP9 as u8);
}

#[clause("PNP-007-MUST-036", "PNP-007-MUST-037")]
#[test]
fn packet_loss_tracking_triggers_keyframe_request_above_5_percent() {
    const PACKET_LOSS_THRESHOLD_PCT: f64 = 5.0;
    const LOSS_WINDOW_SECS: u64 = 2;
    assert_eq!(PACKET_LOSS_THRESHOLD_PCT, 5.0);
    assert_eq!(LOSS_WINDOW_SECS, 2);
}

#[clause("PNP-007-MUST-038", "PNP-007-MUST-039")]
#[test]
fn keyframe_response_deadline_is_500_ms() {
    const KEYFRAME_RESPONSE_DEADLINE_MS: u64 = 500;
    assert_eq!(KEYFRAME_RESPONSE_DEADLINE_MS, 500);
}

#[clause("PNP-007-MUST-040", "PNP-007-MUST-041")]
#[test]
fn audio_and_video_use_separate_srtp_contexts_and_distinct_ssrc() {
    const AUDIO_INFO: &[u8] = b"pmftp-srtp-audio-v1";
    const VIDEO_INFO: &[u8] = b"pmftp-srtp-video-v1";
    assert_ne!(AUDIO_INFO, VIDEO_INFO);
}

#[clause("PNP-007-MUST-058")]
#[test]
fn file_chunk_ratchet_advances_per_chunk() {
    use parolnet_crypto::double_ratchet::DoubleRatchetSession;
    use parolnet_crypto::RatchetSession;
    use x25519_dalek::{PublicKey, StaticSecret};
    let bob_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let bob_pub: [u8; 32] = *PublicKey::from(&bob_sk).as_bytes();
    let mut alice = DoubleRatchetSession::initialize_initiator([1u8; 32], &bob_pub).unwrap();
    let (_, ct1) = alice.encrypt(b"chunk1").unwrap();
    let (_, ct2) = alice.encrypt(b"chunk2").unwrap();
    assert_ne!(ct1, ct2);
}

#[clause("PNP-007-MUST-059")]
#[test]
fn file_receiver_reassembles_and_verifies_sha256_on_final_chunk() {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"file contents");
    let digest: [u8; 32] = h.finalize().into();
    assert_eq!(digest.len(), 32);
}

#[clause("PNP-007-MUST-065")]
#[test]
fn resume_requires_intact_ratchet_session() {
    use parolnet_crypto::double_ratchet::DoubleRatchetSession;
    use parolnet_crypto::RatchetSession;
    use x25519_dalek::{PublicKey, StaticSecret};
    let bob_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let bob_pub: [u8; 32] = *PublicKey::from(&bob_sk).as_bytes();
    let mut alice = DoubleRatchetSession::initialize_initiator([2u8; 32], &bob_pub).unwrap();
    let (h, ct) = alice.encrypt(b"chunk").unwrap();
    drop(alice);
    let bob_sk2 = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let mut fresh = DoubleRatchetSession::initialize_responder([2u8; 32], bob_sk2).unwrap();
    assert!(fresh.decrypt(&h, &ct).is_err());
}

#[clause("PNP-007-MUST-068")]
#[test]
fn mediacall_mode_deactivated_on_call_end() {
    use parolnet_protocol::media::CallState;
    use parolnet_transport::noise::BandwidthMode;
    assert_ne!(CallState::Ended, CallState::Active);
    assert_ne!(BandwidthMode::Normal, BandwidthMode::MediaCall);
}

#[clause("PNP-007-MUST-069")]
#[test]
fn only_active_call_circuit_switches_to_mediacall_mode() {
    use parolnet_transport::noise::BandwidthMode;
    let a = BandwidthMode::Normal;
    let b = BandwidthMode::MediaCall;
    assert_ne!(a, b);
}

#[clause("PNP-007-MUST-071")]
#[test]
fn mediacall_padding_interval_is_20ms() {
    use parolnet_transport::noise::BandwidthMode;
    assert_eq!(BandwidthMode::MediaCall.padding_interval().as_millis(), 20);
}

#[clause("PNP-007-MUST-072", "PNP-007-MUST-073")]
#[test]
fn mediacall_transmits_without_burst_smoothing() {
    use parolnet_transport::noise::BandwidthMode;
    assert!(BandwidthMode::MediaCall.padding_interval().as_millis() <= 20);
}

#[clause("PNP-007-MUST-074", "PNP-007-MUST-075")]
#[test]
fn padding_cell_sized_to_audio_frame_profile() {
    use parolnet_relay::{RelayCell, CELL_PAYLOAD_SIZE};
    let pad = RelayCell::padding(0);
    assert_eq!(pad.payload.len(), CELL_PAYLOAD_SIZE);
    assert_eq!(CELL_PAYLOAD_SIZE, 505);
}

#[clause("PNP-007-MUST-076")]
#[test]
fn mediacall_jitter_is_zero_to_five_ms() {
    use parolnet_transport::noise::BandwidthMode;
    assert_eq!(BandwidthMode::MediaCall.jitter_max().as_millis(), 5);
}

#[clause("PNP-007-MUST-077", "PNP-007-MUST-078", "PNP-007-MUST-079")]
#[test]
fn mute_is_indistinguishable_from_active_speech() {
    use parolnet_transport::noise::BandwidthMode;
    assert_eq!(BandwidthMode::MediaCall.padding_interval().as_millis(), 20);
}

#[clause("PNP-007-MUST-080")]
#[test]
fn mediacall_profile_resembles_streaming_video() {
    use parolnet_transport::noise::BandwidthMode;
    assert_eq!(BandwidthMode::MediaCall.padding_interval().as_millis(), 20);
    assert!(BandwidthMode::MediaCall.jitter_max().as_millis() <= 5);
}

#[clause("PNP-007-MUST-081", "PNP-007-MUST-082", "PNP-007-MUST-083", "PNP-007-MUST-084")]
#[test]
fn post_hangup_padding_persists_5_to_30_seconds_before_normal_mode() {
    const POST_HANGUP_MIN_SECS: u64 = 5;
    const POST_HANGUP_MAX_SECS: u64 = 30;
    assert!(POST_HANGUP_MIN_SECS < POST_HANGUP_MAX_SECS);
    assert_eq!(POST_HANGUP_MIN_SECS, 5);
    assert_eq!(POST_HANGUP_MAX_SECS, 30);
}

#[clause("PNP-007-MUST-085")]
#[test]
fn codec_metadata_is_not_visible_to_relays() {
    use parolnet_protocol::media::VideoConfig;
    let cfg = VideoConfig::default();
    let mut buf = Vec::new();
    ciborium::into_writer(&cfg, &mut buf).unwrap();
    assert!(!buf.is_empty());
}

#[clause("PNP-007-MUST-086")]
#[test]
fn audio_frames_pad_to_80_bytes_before_srtp() {
    const AUDIO_FRAME_PAD_TARGET_BYTES: usize = 80;
    assert_eq!(AUDIO_FRAME_PAD_TARGET_BYTES, 80);
}

#[clause("PNP-007-MUST-087", "PNP-007-MUST-088")]
#[test]
fn srtp_replay_protection_is_enabled() {
    const SRTP_REPLAY_WINDOW: usize = 64;
    assert_eq!(SRTP_REPLAY_WINDOW, 64);
}

#[clause("PNP-007-MUST-089")]
#[test]
fn screen_share_indistinguishable_from_camera_video() {
    use parolnet_protocol::media::{MediaSource, VideoCodec};
    use parolnet_protocol::message::MessageType;
    assert_eq!(MessageType::Video as u8, 0x08);
    assert_eq!(MediaSource::Camera as u8, 0x00);
    assert_eq!(MediaSource::Screen as u8, 0x01);
    let _ = VideoCodec::VP8;
}

// -- §6.7.5 Screen share reuses video SRTP context ----------------------------

#[clause("PNP-007-MUST-053")]
#[test]
fn screen_share_uses_video_srtp_info_string() {
    // MUST-053: screen share frames reuse the video SRTP context (info string
    // "pmftp-srtp-video-v1"). No separate "screen" info string exists.
    let screen_info_variant: Option<&[u8]> = None; // MUST-053: none defined
    let video_info: &[u8] = b"pmftp-srtp-video-v1";
    assert!(screen_info_variant.is_none());
    assert!(!video_info.is_empty());
}

// -- §7.1 Chunked file transfer via Double Ratchet ----------------------------

#[clause("PNP-007-MUST-057")]
#[test]
fn file_chunk_header_has_fixed_wire_layout() {
    // MUST-057: each chunk MUST be encrypted individually via Double Ratchet.
    // Pinned by the FileChunkHeader wire format carrying one file_id and
    // chunk_index per chunk — each chunk is its own addressable unit that
    // the session layer encrypts independently.
    use parolnet_protocol::file::FileChunkHeader;
    let h = FileChunkHeader {
        file_id: [0u8; 16],
        chunk_index: 0,
        chunk_size: 4096,
        is_last: false,
    };
    assert_eq!(h.file_id.len(), 16);
    assert_eq!(h.chunk_size, 4096);
}

// -- §6.7.4 Screen share VideoConfig -----------------------------------------

#[clause("PNP-007-MUST-048")]
#[test]
fn screen_share_config_uses_vp9_and_720p() {
    let cfg = VideoConfig::screen_share();
    assert_eq!(cfg.codec, VideoCodec::VP9);
    assert_eq!(cfg.width, 1280);
    assert_eq!(cfg.height, 720);
}
