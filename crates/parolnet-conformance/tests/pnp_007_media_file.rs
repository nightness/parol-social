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
