use parolnet_core::ParolNet;
use parolnet_core::bootstrap;
use parolnet_core::config::ParolNetConfig;
use parolnet_core::decoy::DecoyState;
use parolnet_crypto::SharedSecret;
use parolnet_protocol::address::PeerId;

// ── Config Tests ────────────────────────────────────────────────

#[test]
fn test_default_config() {
    let config = ParolNetConfig::default();
    assert!(!config.decoy_mode);
    assert!(config.storage_path.is_none());
    assert_eq!(config.circuit_pool_size, 3);
}

// ── Decoy Mode Tests ────────────────────────────────────────────

#[test]
fn test_decoy_state() {
    assert_ne!(DecoyState::Normal, DecoyState::Active);
}

#[test]
fn test_decoy_mode_toggle() {
    let mut client = ParolNet::new(ParolNetConfig::default());
    assert!(!client.is_decoy_mode());

    client.enter_decoy_mode();
    assert!(client.is_decoy_mode());

    client.exit_decoy_mode();
    assert!(!client.is_decoy_mode());
}

// ── Bootstrap Tests ─────────────────────────────────────────────

#[test]
fn test_qr_payload_roundtrip() {
    let ik = [0xAB; 32];
    let encoded = bootstrap::generate_qr_payload(&ik, Some("relay.example.com:443")).unwrap();
    let decoded = bootstrap::parse_qr_payload(&encoded).unwrap();

    assert_eq!(decoded.v, 1);
    assert_eq!(decoded.ik.len(), 32);
    assert_eq!(decoded.seed.len(), 32);
    assert_eq!(decoded.relay, Some("relay.example.com:443".to_string()));
    assert_eq!(decoded.net, 1); // internet relay
}

#[test]
fn test_qr_payload_without_relay() {
    let ik = [0xAB; 32];
    let encoded = bootstrap::generate_qr_payload(&ik, None).unwrap();
    let decoded = bootstrap::parse_qr_payload(&encoded).unwrap();

    assert_eq!(decoded.relay, None);
    assert_eq!(decoded.net, 2); // LAN
}

#[test]
fn test_bootstrap_secret_symmetric() {
    let seed = [0x42; 32];
    let alice_ik = [1u8; 32];
    let bob_ik = [2u8; 32];

    // Both peers should derive the same secret regardless of order
    let bs_alice = bootstrap::derive_bootstrap_secret(&seed, &alice_ik, &bob_ik).unwrap();
    let bs_bob = bootstrap::derive_bootstrap_secret(&seed, &bob_ik, &alice_ik).unwrap();

    assert_eq!(bs_alice, bs_bob);
}

#[test]
fn test_bootstrap_secret_different_seeds() {
    let alice_ik = [1u8; 32];
    let bob_ik = [2u8; 32];

    let bs1 = bootstrap::derive_bootstrap_secret(&[1u8; 32], &alice_ik, &bob_ik).unwrap();
    let bs2 = bootstrap::derive_bootstrap_secret(&[2u8; 32], &alice_ik, &bob_ik).unwrap();

    assert_ne!(bs1, bs2);
}

#[test]
fn test_bootstrap_proof_roundtrip() {
    let bs = [0xAB; 32];
    let ik = [1u8; 32];
    let ek = [2u8; 32];
    let nonce = [3u8; 16];

    let proof = bootstrap::compute_bootstrap_proof(&bs, &ik, &ek, &nonce).unwrap();
    assert!(bootstrap::verify_bootstrap_proof(&bs, &ik, &ek, &nonce, &proof).unwrap());
}

#[test]
fn test_bootstrap_proof_wrong_secret_fails() {
    let bs = [0xAB; 32];
    let ik = [1u8; 32];
    let ek = [2u8; 32];
    let nonce = [3u8; 16];

    let proof = bootstrap::compute_bootstrap_proof(&bs, &ik, &ek, &nonce).unwrap();
    let wrong_bs = [0xCD; 32];
    assert!(!bootstrap::verify_bootstrap_proof(&wrong_bs, &ik, &ek, &nonce, &proof).unwrap());
}

#[test]
fn test_sas_computation() {
    let bs = [0x42; 32];
    let ik_a = [1u8; 32];
    let ik_b = [2u8; 32];
    let ek_a = [3u8; 32];
    let ek_b = [4u8; 32];

    let sas = bootstrap::compute_sas(&bs, &ik_a, &ik_b, &ek_a, &ek_b).unwrap();

    // SAS should be exactly 6 digits
    assert_eq!(sas.len(), 6);
    assert!(sas.chars().all(|c| c.is_ascii_digit()));

    // Same inputs should produce same SAS
    let sas2 = bootstrap::compute_sas(&bs, &ik_a, &ik_b, &ek_a, &ek_b).unwrap();
    assert_eq!(sas, sas2);
}

// ── Client API Tests ────────────────────────────────────────────

#[test]
fn test_client_creation() {
    let client = ParolNet::new(ParolNetConfig::default());
    assert_eq!(client.peer_id().as_bytes().len(), 32);
    assert_eq!(client.session_count(), 0);
}

#[test]
fn test_client_qr_generation() {
    let client = ParolNet::new(ParolNetConfig::default());
    let qr = client.generate_qr(None).unwrap();
    assert!(!qr.is_empty());

    // Should be parseable
    let payload = bootstrap::parse_qr_payload(&qr).unwrap();
    assert_eq!(payload.ik, client.public_key().to_vec());
}

#[test]
fn test_client_session_lifecycle() {
    let alice = ParolNet::new(ParolNetConfig::default());
    let bob = ParolNet::new(ParolNetConfig::default());

    // Generate a ratchet key for Bob
    use rand::rngs::OsRng;
    let bob_ratchet = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let bob_ratchet_pub = *x25519_dalek::PublicKey::from(&bob_ratchet).as_bytes();

    // Alice establishes session with Bob
    alice
        .establish_session(
            bob.peer_id(),
            SharedSecret([0x42; 32]),
            &bob_ratchet_pub,
            true,
        )
        .unwrap();

    assert!(alice.has_session(&bob.peer_id()));
    assert_eq!(alice.session_count(), 1);

    // Alice encrypts a message
    let (_header, ciphertext) = alice.send(&bob.peer_id(), b"hello bob").unwrap();
    assert!(!ciphertext.is_empty());
}

// ── Panic Wipe Tests ────────────────────────────────────────────

#[test]
fn test_panic_wipe_clears_sessions() {
    let mut client = ParolNet::new(ParolNetConfig::default());

    use rand::rngs::OsRng;
    let ratchet = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let ratchet_pub = *x25519_dalek::PublicKey::from(&ratchet).as_bytes();

    client
        .establish_session(
            PeerId([1; 32]),
            SharedSecret([0x42; 32]),
            &ratchet_pub,
            true,
        )
        .unwrap();

    assert_eq!(client.session_count(), 1);

    client.panic_wipe().unwrap();
    assert_eq!(client.session_count(), 0);
}

#[test]
fn test_panic_wipe_with_storage() {
    let dir = std::env::temp_dir().join("parolnet_test_wipe");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("test.dat"), b"sensitive data").unwrap();

    let mut client = ParolNet::new(ParolNetConfig {
        storage_path: Some(dir.clone()),
        ..Default::default()
    });

    client.panic_wipe().unwrap();
    assert!(!dir.exists());
}

// ── Missing API Coverage Tests ──────────────────────────────────

#[test]
fn test_process_qr_roundtrip() {
    let alice = ParolNet::new(ParolNetConfig::default());
    let qr_data = alice.generate_qr(None).unwrap();

    let bob = ParolNet::new(ParolNetConfig::default());
    let (payload, _bs) = bob.process_qr(&qr_data).unwrap();

    assert_eq!(payload.ik, alice.public_key().to_vec());
}

#[test]
fn test_process_qr_invalid_data() {
    let client = ParolNet::new(ParolNetConfig::default());
    let result = client.process_qr(&[0xFF; 10]);
    assert!(result.is_err());
}

#[test]
fn test_send_without_session_fails() {
    let client = ParolNet::new(ParolNetConfig::default());
    let random_peer = PeerId([0xAB; 32]);
    let result = client.send(&random_peer, b"hello");
    assert!(result.is_err());
    match result.unwrap_err() {
        parolnet_core::CoreError::NoSession => {}
        other => panic!("expected NoSession, got: {other:?}"),
    }
}

#[test]
fn test_multiple_sessions() {
    use rand::rngs::OsRng;

    let client = ParolNet::new(ParolNetConfig::default());

    for i in 0..3u8 {
        let peer_id = PeerId([i + 10; 32]);
        let shared_secret = SharedSecret([i + 1; 32]);
        let ratchet_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let ratchet_pub = *x25519_dalek::PublicKey::from(&ratchet_secret).as_bytes();

        client
            .establish_session(peer_id, shared_secret, &ratchet_pub, true)
            .unwrap();
    }

    assert_eq!(client.session_count(), 3);

    // Send a message to each peer
    for i in 0..3u8 {
        let peer_id = PeerId([i + 10; 32]);
        let (_header, ciphertext) = client.send(&peer_id, b"test message").unwrap();
        assert!(!ciphertext.is_empty());
    }
}

// ── Bootstrap Edge Case Tests ───────────────────────────────────

#[test]
fn test_bootstrap_secret_same_peer() {
    let seed = [0x42; 32];
    let same_ik = [1u8; 32];

    // derive_bootstrap_secret where our_ik == their_ik
    let result = bootstrap::derive_bootstrap_secret(&seed, &same_ik, &same_ik);
    assert!(result.is_ok());
}

#[test]
fn test_sas_different_inputs() {
    let bs1 = [0x42; 32];
    let bs2 = [0x43; 32];
    let ik_a = [1u8; 32];
    let ik_b = [2u8; 32];
    let ek_a = [3u8; 32];
    let ek_b = [4u8; 32];

    let sas1 = bootstrap::compute_sas(&bs1, &ik_a, &ik_b, &ek_a, &ek_b).unwrap();
    let sas2 = bootstrap::compute_sas(&bs2, &ik_a, &ik_b, &ek_a, &ek_b).unwrap();

    assert_ne!(sas1, sas2);
}

// ── Panic Wipe Edge Case Tests ──────────────────────────────────

#[test]
fn test_panic_wipe_nonexistent_storage() {
    let nonexistent = std::path::PathBuf::from("/tmp/parolnet_test_nonexistent_dir_xyz");
    // Make sure it really doesn't exist
    let _ = std::fs::remove_dir_all(&nonexistent);

    let mut client = ParolNet::new(ParolNetConfig {
        storage_path: Some(nonexistent.clone()),
        ..Default::default()
    });

    // Should succeed even though the directory doesn't exist
    client.panic_wipe().unwrap();
}

#[test]
fn test_panic_wipe_nested_storage() {
    let dir = std::env::temp_dir().join("parolnet_test_nested_wipe");
    let sub = dir.join("subdir");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("secret.dat"), b"top secret").unwrap();
    std::fs::write(dir.join("root.dat"), b"also secret").unwrap();

    let mut client = ParolNet::new(ParolNetConfig {
        storage_path: Some(dir.clone()),
        ..Default::default()
    });

    client.panic_wipe().unwrap();
    assert!(!dir.exists());
}

// ── File Transfer Tests ─────────────────────────────────────────

#[test]
fn test_file_transfer_small_file() {
    use parolnet_core::file_transfer::{FileTransferReceiver, FileTransferSender};

    let data = b"hello world, this is a test file!".to_vec();
    let mut sender = FileTransferSender::new(data.clone(), "test.txt".into(), None);
    let mut receiver = FileTransferReceiver::new(sender.offer.clone());

    while let Some((header, chunk)) = sender.next() {
        receiver.receive_chunk(&header, chunk).unwrap();
    }

    assert!(sender.is_complete());
    assert!(receiver.is_complete());

    let assembled = receiver.assemble().unwrap();
    assert_eq!(assembled, data);
}

#[test]
fn test_file_transfer_large_file() {
    use parolnet_core::file_transfer::{FileTransferReceiver, FileTransferSender};

    // 100KB file — should produce 25 chunks at 4096 bytes each
    let data = vec![0xABu8; 100_000];
    let mut sender = FileTransferSender::new(
        data.clone(),
        "large.bin".into(),
        Some("application/octet-stream".into()),
    );
    let mut receiver = FileTransferReceiver::new(sender.offer.clone());

    assert_eq!(sender.total_chunks(), 25); // ceil(100000/4096) = 25

    let mut count = 0;
    while let Some((header, chunk)) = sender.next() {
        receiver.receive_chunk(&header, chunk).unwrap();
        count += 1;
    }
    assert_eq!(count, 25);

    let assembled = receiver.assemble().unwrap();
    assert_eq!(assembled, data);
}

#[test]
fn test_file_transfer_empty_file() {
    use parolnet_core::file_transfer::{FileTransferReceiver, FileTransferSender};

    let data = vec![];
    let mut sender = FileTransferSender::new(data.clone(), "empty.txt".into(), None);
    let mut receiver = FileTransferReceiver::new(sender.offer.clone());

    assert_eq!(sender.total_chunks(), 1);

    let (header, chunk) = sender.next().unwrap();
    assert!(header.is_last);
    assert!(chunk.is_empty());
    receiver.receive_chunk(&header, chunk).unwrap();

    assert!(sender.is_complete());
    assert!(receiver.is_complete());
    let assembled = receiver.assemble().unwrap();
    assert_eq!(assembled, data);
}

#[test]
fn test_file_transfer_resume() {
    use parolnet_core::file_transfer::{FileTransferReceiver, FileTransferSender};

    let data = vec![0xCDu8; 20_000]; // 5 chunks
    let mut sender = FileTransferSender::new(data.clone(), "resume.bin".into(), None);
    let mut receiver = FileTransferReceiver::new(sender.offer.clone());

    // Send first 3 chunks
    for _ in 0..3 {
        let (header, chunk) = sender.next().unwrap();
        receiver.receive_chunk(&header, chunk).unwrap();
    }

    assert_eq!(sender.progress(), (3, 5));
    assert_eq!(receiver.progress(), (3, 5));
    assert!(!receiver.is_complete());

    // Simulate interruption — create new sender, resume from chunk 3
    let mut sender2 = FileTransferSender::new(data.clone(), "resume.bin".into(), None);
    sender2.offer.file_id = sender.offer.file_id; // same file
    sender2.resume_from(3);

    while let Some((header, chunk)) = sender2.next() {
        receiver.receive_chunk(&header, chunk).unwrap();
    }

    assert!(receiver.is_complete());
    let assembled = receiver.assemble().unwrap();
    assert_eq!(assembled, data);
}

#[test]
fn test_file_transfer_integrity_failure() {
    use parolnet_core::file_transfer::{FileTransferReceiver, FileTransferSender};

    let data = b"original data".to_vec();
    let mut sender = FileTransferSender::new(data, "test.txt".into(), None);
    let mut receiver = FileTransferReceiver::new(sender.offer.clone());

    // Tamper with chunk data
    let (header, mut chunk) = sender.next().unwrap();
    if !chunk.is_empty() {
        chunk[0] ^= 0xFF;
    }
    receiver.receive_chunk(&header, chunk).unwrap();

    // Assembly should fail SHA-256 check
    assert!(receiver.assemble().is_err());
}

#[test]
fn test_file_transfer_progress() {
    use parolnet_core::file_transfer::FileTransferSender;

    let data = vec![0u8; 8192]; // exactly 2 chunks
    let mut sender = FileTransferSender::new(data, "progress.bin".into(), None);

    assert_eq!(sender.progress(), (0, 2));
    sender.next();
    assert_eq!(sender.progress(), (1, 2));
    sender.next();
    assert_eq!(sender.progress(), (2, 2));
    assert!(sender.is_complete());
}

// ── Audio Codec Tests ───────────────────────────────────────────

#[test]
fn test_opus_encode_decode_roundtrip() {
    use parolnet_core::audio::{AudioConfig, AudioDecoder, AudioEncoder};

    let config = AudioConfig::default(); // Opus, 16kHz, mono
    let mut encoder = AudioEncoder::new(&config).unwrap();
    let mut decoder = AudioDecoder::new(&config).unwrap();

    // Generate 20ms of silence (320 samples at 16kHz)
    let pcm_input = vec![0i16; encoder.frame_samples()];

    let encoded = encoder.encode(&pcm_input).unwrap();
    assert!(!encoded.is_empty());
    assert!(encoded.len() < 200); // Opus should compress silence heavily

    let decoded = decoder.decode(&encoded).unwrap();
    assert!(!decoded.is_empty());
    // Decoded length should match input (320 samples)
    assert_eq!(decoded.len(), pcm_input.len());
}

#[test]
fn test_codec2_encode_decode_roundtrip() {
    use parolnet_core::audio::{AudioConfig, AudioDecoder, AudioEncoder};

    let config = AudioConfig::low_bandwidth(); // Codec2, 8kHz
    let mut encoder = AudioEncoder::new(&config).unwrap();
    let mut decoder = AudioDecoder::new(&config).unwrap();

    // Generate one frame of silence (samples_per_frame for MODE_3200 = 160)
    let pcm_input = vec![0i16; encoder.frame_samples()];

    let encoded = encoder.encode(&pcm_input).unwrap();
    assert!(!encoded.is_empty());
    assert!(encoded.len() <= 16); // Codec2 3200bps: 8 bytes per frame

    let decoded = decoder.decode(&encoded).unwrap();
    assert!(!decoded.is_empty());
    assert_eq!(decoded.len(), pcm_input.len());
}

#[test]
fn test_audio_config_default() {
    use parolnet_core::audio::AudioConfig;
    use parolnet_protocol::media::AudioCodec;

    let config = AudioConfig::default();
    assert_eq!(config.codec, AudioCodec::Opus);
    assert_eq!(config.sample_rate, 16000);
    assert_eq!(config.channels, 1);
}

#[test]
fn test_audio_config_low_bandwidth() {
    use parolnet_core::audio::AudioConfig;
    use parolnet_protocol::media::AudioCodec;

    let config = AudioConfig::low_bandwidth();
    assert_eq!(config.codec, AudioCodec::Codec2);
    assert_eq!(config.sample_rate, 8000);
}

// ── Video Framing Tests ─────────────────────────────────────────

#[test]
fn test_video_fragment_small_frame() {
    use parolnet_core::video::{VideoFrame, fragment_video_frame, reassemble_video_frame};
    use parolnet_protocol::media::{MediaSource, VideoCodec};

    let frame = VideoFrame {
        codec: VideoCodec::VP8,
        width: 320,
        height: 240,
        is_keyframe: true,
        timestamp: 1000,
        source: MediaSource::Camera,
        data: vec![0xAB; 200], // fits in one fragment
    };

    let fragments = fragment_video_frame(&frame, 1);
    assert_eq!(fragments.len(), 1);
    assert!(fragments[0].is_keyframe);
    assert_eq!(fragments[0].data.len(), 200);

    let mut frags = fragments;
    let reassembled = reassemble_video_frame(&mut frags, VideoCodec::VP8, 320, 240).unwrap();
    assert_eq!(reassembled.data, frame.data);
    assert!(reassembled.is_keyframe);
}

#[test]
fn test_video_fragment_large_frame() {
    use parolnet_core::video::{
        MAX_FRAGMENT_SIZE, VideoFrame, fragment_video_frame, reassemble_video_frame,
    };
    use parolnet_protocol::media::{MediaSource, VideoCodec};

    // 10KB frame -- should split into ceil(10000/440) = 23 fragments
    let frame = VideoFrame {
        codec: VideoCodec::VP8,
        width: 640,
        height: 480,
        is_keyframe: false,
        timestamp: 2000,
        source: MediaSource::Camera,
        data: vec![0xCD; 10_000],
    };

    let fragments = fragment_video_frame(&frame, 42);
    let expected_count = 10_000_usize.div_ceil(MAX_FRAGMENT_SIZE);
    assert_eq!(fragments.len(), expected_count);

    // Verify sequential fragment indices
    for (i, frag) in fragments.iter().enumerate() {
        assert_eq!(frag.fragment_index, i as u16);
        assert_eq!(frag.total_fragments, expected_count as u16);
        assert_eq!(frag.frame_id, 42);
    }

    let mut frags = fragments;
    let reassembled = reassemble_video_frame(&mut frags, VideoCodec::VP8, 640, 480).unwrap();
    assert_eq!(reassembled.data, frame.data);
}

#[test]
fn test_video_fragment_empty_frame() {
    use parolnet_core::video::{VideoFrame, fragment_video_frame};
    use parolnet_protocol::media::{MediaSource, VideoCodec};

    let frame = VideoFrame {
        codec: VideoCodec::VP9,
        width: 320,
        height: 240,
        is_keyframe: false,
        timestamp: 0,
        source: MediaSource::Camera,
        data: vec![],
    };

    let fragments = fragment_video_frame(&frame, 0);
    assert_eq!(fragments.len(), 1);
    assert!(fragments[0].data.is_empty());
}

#[test]
fn test_video_reassemble_missing_fragment() {
    use parolnet_core::video::{VideoFragment, reassemble_video_frame};
    use parolnet_protocol::media::{MediaSource, VideoCodec};

    // Only provide fragment 0 of 3
    let mut fragments = vec![VideoFragment {
        frame_id: 1,
        fragment_index: 0,
        total_fragments: 3,
        is_keyframe: true,
        timestamp: 100,
        source: MediaSource::Camera,
        data: vec![0xAB; 100],
    }];

    let result = reassemble_video_frame(&mut fragments, VideoCodec::VP8, 320, 240);
    assert!(result.is_err());
}

// ── Call Signaling Tests ────────────────────────────────────────

#[test]
fn test_call_offer_answer_hangup() {
    use parolnet_core::call::Call;
    use parolnet_protocol::media::{CallSignalMessage, CallState};

    let call_id = [0x11; 16];
    let peer = PeerId([1; 32]);
    let mut call = Call::new_outgoing(call_id, peer);
    assert_eq!(call.state, CallState::Offering);

    let answer = CallSignalMessage::Answer {
        call_id,
        sdp: "v=0...".into(),
    };
    call.handle_signal(&answer).unwrap();
    assert_eq!(call.state, CallState::Active);
    assert!(call.started_at.is_some());

    let hangup = CallSignalMessage::Hangup { call_id };
    call.handle_signal(&hangup).unwrap();
    assert_eq!(call.state, CallState::Ended);
}

#[test]
fn test_call_offer_reject() {
    use parolnet_core::call::Call;
    use parolnet_protocol::media::{CallSignalMessage, CallState};

    let call_id = [0xAB; 16];
    let peer = PeerId([1; 32]);
    let mut call = Call::new_outgoing(call_id, peer);

    let reject = CallSignalMessage::Reject { call_id };
    call.handle_signal(&reject).unwrap();
    assert_eq!(call.state, CallState::Rejected);
}

#[test]
fn test_call_incoming_answer() {
    use parolnet_core::call::CallManager;
    use parolnet_protocol::media::CallState;

    let manager = CallManager::new();
    let call_id = [0xCD; 16];
    let peer = PeerId([2; 32]);

    manager.incoming_call(call_id, peer);
    assert_eq!(manager.get_state(&call_id), Some(CallState::Ringing));

    manager.answer(&call_id).unwrap();
    assert_eq!(manager.get_state(&call_id), Some(CallState::Active));
    assert_eq!(manager.active_call_count(), 1);

    manager.hangup(&call_id).unwrap();
    assert_eq!(manager.get_state(&call_id), Some(CallState::Ended));
    assert_eq!(manager.active_call_count(), 0);
}

#[test]
fn test_call_incoming_reject() {
    use parolnet_core::call::CallManager;
    use parolnet_protocol::media::CallState;

    let manager = CallManager::new();
    let call_id = [0xEF; 16];
    let peer = PeerId([3; 32]);

    manager.incoming_call(call_id, peer);
    manager.reject(&call_id).unwrap();
    assert_eq!(manager.get_state(&call_id), Some(CallState::Rejected));
}

#[test]
fn test_call_mute_toggle() {
    use parolnet_core::call::CallManager;

    let manager = CallManager::new();
    let call_id = [0x42; 16];
    let peer = PeerId([4; 32]);

    manager.incoming_call(call_id, peer);

    // Can't mute before answering
    assert!(manager.toggle_mute(&call_id, true).is_err());

    manager.answer(&call_id).unwrap();
    manager.toggle_mute(&call_id, true).unwrap();
    manager.toggle_mute(&call_id, false).unwrap();
}

#[test]
fn test_call_wrong_id_fails() {
    use parolnet_core::call::Call;
    use parolnet_protocol::media::CallSignalMessage;

    let call_id = [0x01; 16];
    let wrong_id = [0x02; 16];
    let peer = PeerId([1; 32]);
    let mut call = Call::new_outgoing(call_id, peer);

    let answer = CallSignalMessage::Answer {
        call_id: wrong_id,
        sdp: "".into(),
    };
    assert!(call.handle_signal(&answer).is_err());
}

#[test]
fn test_call_manager_prune() {
    use parolnet_core::call::CallManager;

    let manager = CallManager::new();

    // Start 1 call, register 2 incoming, reject 2, keep 1 active
    let _id1 = manager.start_call(PeerId([1; 32])).unwrap();
    let id2 = [0xAA; 16];
    let id3 = [0xBB; 16];
    manager.incoming_call(id2, PeerId([2; 32]));
    manager.incoming_call(id3, PeerId([3; 32]));

    manager.reject(&id2).unwrap();
    manager.reject(&id3).unwrap();

    assert_eq!(manager.total_call_count(), 3);
    let pruned = manager.prune_finished();
    assert_eq!(pruned, 2);
    assert_eq!(manager.total_call_count(), 1);
}

#[test]
fn test_call_cannot_answer_twice() {
    use parolnet_core::call::CallManager;

    let manager = CallManager::new();
    let call_id = [0x99; 16];
    manager.incoming_call(call_id, PeerId([5; 32]));

    manager.answer(&call_id).unwrap();
    // Second answer should fail (already active)
    assert!(manager.answer(&call_id).is_err());
}

// ── PNP-007 Spec Conformance Tests ──────────────────────────────

#[test]
fn test_pnp007_call_timeout_is_30_seconds() {
    use parolnet_core::call::CALL_TIMEOUT;
    assert_eq!(CALL_TIMEOUT, std::time::Duration::from_secs(30));
}

#[test]
fn test_pnp007_default_chunk_size_is_4096() {
    use parolnet_protocol::file::DEFAULT_CHUNK_SIZE;
    assert_eq!(DEFAULT_CHUNK_SIZE, 4096);
}

#[test]
fn test_pnp007_opus_frame_samples_320() {
    use parolnet_core::audio::{AudioConfig, AudioEncoder};
    let config = AudioConfig::default();
    let encoder = AudioEncoder::new(&config).unwrap();
    assert_eq!(encoder.frame_samples(), 320); // 16kHz * 20ms
}

#[test]
fn test_pnp007_codec2_frame_samples_160() {
    use parolnet_core::audio::{AudioConfig, AudioEncoder};
    let config = AudioConfig::low_bandwidth();
    let encoder = AudioEncoder::new(&config).unwrap();
    assert_eq!(encoder.frame_samples(), 160); // 8kHz * 20ms
}

#[test]
fn test_pnp007_codec2_threshold_16kbps() {
    use parolnet_protocol::media::CODEC2_BANDWIDTH_THRESHOLD_KBPS;
    assert_eq!(CODEC2_BANDWIDTH_THRESHOLD_KBPS, 16);
}

#[test]
fn test_pnp007_media_call_padding_20ms() {
    use parolnet_transport::noise::BandwidthMode;
    assert_eq!(
        BandwidthMode::MediaCall.padding_interval(),
        std::time::Duration::from_millis(20)
    );
}

#[test]
fn test_pnp007_media_call_jitter_5ms() {
    use parolnet_transport::noise::BandwidthMode;
    assert_eq!(
        BandwidthMode::MediaCall.jitter_max(),
        std::time::Duration::from_millis(5)
    );
}

#[test]
fn test_pnp007_video_fragment_max_440() {
    use parolnet_core::video::MAX_FRAGMENT_SIZE;
    assert_eq!(MAX_FRAGMENT_SIZE, 440);
}

#[test]
fn test_pnp007_media_data_cell_type_0x09() {
    use parolnet_relay::CellType;
    assert_eq!(CellType::MediaData as u8, 0x09);
}

#[test]
fn test_pnp007_message_type_audio_0x07() {
    use parolnet_protocol::message::MessageType;
    assert_eq!(MessageType::Audio as u8, 0x07);
    assert_eq!(MessageType::Video as u8, 0x08);
    assert_eq!(MessageType::FileChunk as u8, 0x09);
    assert_eq!(MessageType::FileControl as u8, 0x0A);
    assert_eq!(MessageType::CallSignal as u8, 0x0B);
}

#[test]
fn test_pnp007_video_config_defaults() {
    use parolnet_protocol::media::VideoConfig;
    let config = VideoConfig::default();
    assert_eq!(config.width, 320);
    assert_eq!(config.height, 240);
    assert_eq!(config.bitrate_kbps, 200);
    assert_eq!(config.keyframe_interval, 60); // 2 seconds at 30fps
}

#[test]
fn test_pnp007_cell_size_512() {
    use parolnet_relay::CELL_SIZE;
    assert_eq!(CELL_SIZE, 512);
}

#[test]
fn test_pnp007_max_data_payload_457() {
    use parolnet_relay::MAX_DATA_PAYLOAD;
    assert_eq!(MAX_DATA_PAYLOAD, 457);
}

#[test]
fn test_pnp007_required_hops_3() {
    use parolnet_relay::REQUIRED_HOPS;
    assert_eq!(REQUIRED_HOPS, 3);
}

#[test]
fn test_pnp007_media_data_cell_roundtrip() {
    use parolnet_relay::{CELL_PAYLOAD_SIZE, CELL_SIZE, CellType, RelayCell};

    let cell = RelayCell {
        circuit_id: 42,
        cell_type: CellType::MediaData,
        payload: [0xAB; CELL_PAYLOAD_SIZE],
        payload_len: 80,
    };

    let bytes = cell.to_bytes();
    assert_eq!(bytes.len(), CELL_SIZE);

    let parsed = RelayCell::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.cell_type, CellType::MediaData);
    assert_eq!(parsed.circuit_id, 42);
    assert_eq!(parsed.payload_len, 80);
}

#[test]
fn test_pnp007_cell_type_from_u8_all_variants() {
    use parolnet_relay::CellType;
    assert_eq!(CellType::from_u8(0x01), Some(CellType::Create));
    assert_eq!(CellType::from_u8(0x05), Some(CellType::Data));
    assert_eq!(CellType::from_u8(0x07), Some(CellType::Padding));
    assert_eq!(CellType::from_u8(0x09), Some(CellType::MediaData));
    assert_eq!(CellType::from_u8(0xFF), None);
}

#[test]
fn test_pnp007_message_type_from_u8_media_types() {
    use parolnet_protocol::message::MessageType;
    assert_eq!(MessageType::from_u8(0x07), Some(MessageType::Audio));
    assert_eq!(MessageType::from_u8(0x08), Some(MessageType::Video));
    assert_eq!(MessageType::from_u8(0x09), Some(MessageType::FileChunk));
    assert_eq!(MessageType::from_u8(0x0A), Some(MessageType::FileControl));
    assert_eq!(MessageType::from_u8(0x0B), Some(MessageType::CallSignal));
    assert_eq!(MessageType::from_u8(0xFF), None);
}

#[test]
fn test_pnp007_bandwidth_mode_dummy_traffic() {
    use parolnet_transport::noise::BandwidthMode;
    // MediaCall should have minimal dummy traffic (spec says 0%, impl uses 10%)
    let pct = BandwidthMode::MediaCall.dummy_traffic_percent();
    assert!(pct <= 10);
}

#[test]
fn test_pnp007_all_bandwidth_modes_ordering() {
    use parolnet_transport::noise::BandwidthMode;
    // MediaCall should have the shortest padding interval
    assert!(BandwidthMode::MediaCall.padding_interval() < BandwidthMode::High.padding_interval());
    assert!(BandwidthMode::High.padding_interval() < BandwidthMode::Normal.padding_interval());
    assert!(BandwidthMode::Normal.padding_interval() < BandwidthMode::Low.padding_interval());
}

#[test]
fn test_pnp007_audio_codec_enum_values() {
    use parolnet_protocol::media::AudioCodec;
    assert_eq!(AudioCodec::Opus as u8, 0x01);
    assert_eq!(AudioCodec::Codec2 as u8, 0x02);
}

#[test]
fn test_pnp007_video_codec_enum_values() {
    use parolnet_protocol::media::VideoCodec;
    assert_eq!(VideoCodec::VP8 as u8, 0x01);
    assert_eq!(VideoCodec::VP9 as u8, 0x02);
}

#[test]
fn test_pnp007_call_state_machine_offering_to_active() {
    use parolnet_core::call::Call;
    use parolnet_protocol::media::{CallSignalMessage, CallState};

    let call_id = [0x42; 16];
    let mut call = Call::new_outgoing(call_id, PeerId([1; 32]));
    assert_eq!(call.state, CallState::Offering);

    call.handle_signal(&CallSignalMessage::Answer {
        call_id,
        sdp: "v=0".into(),
    })
    .unwrap();
    assert_eq!(call.state, CallState::Active);
}

#[test]
fn test_pnp007_call_state_machine_offering_to_rejected() {
    use parolnet_core::call::Call;
    use parolnet_protocol::media::{CallSignalMessage, CallState};

    let call_id = [0x42; 16];
    let mut call = Call::new_outgoing(call_id, PeerId([1; 32]));
    call.handle_signal(&CallSignalMessage::Reject { call_id })
        .unwrap();
    assert_eq!(call.state, CallState::Rejected);
}

#[test]
fn test_pnp007_call_state_machine_ringing_to_rejected() {
    use parolnet_core::call::Call;
    use parolnet_protocol::media::{CallSignalMessage, CallState};

    let call_id = [0x42; 16];
    let mut call = Call::new_incoming(call_id, PeerId([1; 32]));
    assert_eq!(call.state, CallState::Ringing);

    call.handle_signal(&CallSignalMessage::Reject { call_id })
        .unwrap();
    assert_eq!(call.state, CallState::Rejected);
}

#[test]
fn test_pnp007_file_offer_total_chunks() {
    use parolnet_protocol::file::FileOffer;

    let offer = FileOffer {
        file_id: [0; 16],
        file_name: "test.bin".into(),
        file_size: 10000,
        chunk_size: 4096,
        sha256: [0; 32],
        mime_type: None,
    };
    assert_eq!(offer.total_chunks(), 3); // ceil(10000/4096) = 3

    let offer_empty = FileOffer {
        file_id: [0; 16],
        file_name: "empty.bin".into(),
        file_size: 0,
        chunk_size: 4096,
        sha256: [0; 32],
        mime_type: None,
    };
    assert_eq!(offer_empty.total_chunks(), 1); // empty file = 1 chunk

    let offer_exact = FileOffer {
        file_id: [0; 16],
        file_name: "exact.bin".into(),
        file_size: 8192,
        chunk_size: 4096,
        sha256: [0; 32],
        mime_type: None,
    };
    assert_eq!(offer_exact.total_chunks(), 2); // exact boundary
}

// ── Audio Coverage Tests ────────────────────────────────────────

#[test]
fn test_opus_encode_sine_wave() {
    use parolnet_core::audio::{AudioConfig, AudioDecoder, AudioEncoder};
    let config = AudioConfig::default();
    let mut encoder = AudioEncoder::new(&config).unwrap();
    let mut decoder = AudioDecoder::new(&config).unwrap();

    // Generate a 440Hz sine wave (20ms at 16kHz)
    let samples = encoder.frame_samples();
    let pcm: Vec<i16> = (0..samples)
        .map(|i| {
            let t = i as f64 / 16000.0;
            (f64::sin(2.0 * std::f64::consts::PI * 440.0 * t) * 16000.0) as i16
        })
        .collect();

    let encoded = encoder.encode(&pcm).unwrap();
    assert!(!encoded.is_empty());

    let decoded = decoder.decode(&encoded).unwrap();
    assert_eq!(decoded.len(), pcm.len());
    // Don't check exact values -- lossy codec
}

#[test]
fn test_codec2_encode_sine_wave() {
    use parolnet_core::audio::{AudioConfig, AudioDecoder, AudioEncoder};
    let config = AudioConfig::low_bandwidth();
    let mut encoder = AudioEncoder::new(&config).unwrap();
    let mut decoder = AudioDecoder::new(&config).unwrap();

    let samples = encoder.frame_samples();
    let pcm: Vec<i16> = (0..samples)
        .map(|i| {
            let t = i as f64 / 8000.0;
            (f64::sin(2.0 * std::f64::consts::PI * 440.0 * t) * 8000.0) as i16
        })
        .collect();

    let encoded = encoder.encode(&pcm).unwrap();
    let decoded = decoder.decode(&encoded).unwrap();
    assert_eq!(decoded.len(), pcm.len());
}

#[test]
fn test_opus_multiple_frames() {
    use parolnet_core::audio::{AudioConfig, AudioDecoder, AudioEncoder};
    let config = AudioConfig::default();
    let mut encoder = AudioEncoder::new(&config).unwrap();
    let mut decoder = AudioDecoder::new(&config).unwrap();

    // Encode and decode 10 consecutive frames
    for i in 0..10 {
        let pcm = vec![(i * 100) as i16; encoder.frame_samples()];
        let encoded = encoder.encode(&pcm).unwrap();
        let decoded = decoder.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), pcm.len());
    }
}

#[test]
fn test_codec2_multiple_frames() {
    use parolnet_core::audio::{AudioConfig, AudioDecoder, AudioEncoder};
    let config = AudioConfig::low_bandwidth();
    let mut encoder = AudioEncoder::new(&config).unwrap();
    let mut decoder = AudioDecoder::new(&config).unwrap();

    for i in 0..10 {
        let pcm = vec![(i * 50) as i16; encoder.frame_samples()];
        let encoded = encoder.encode(&pcm).unwrap();
        let decoded = decoder.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), pcm.len());
    }
}

#[test]
fn test_opus_compressed_size_reasonable() {
    use parolnet_core::audio::{AudioConfig, AudioEncoder};
    let config = AudioConfig::default();
    let mut encoder = AudioEncoder::new(&config).unwrap();

    let pcm = vec![0i16; encoder.frame_samples()];
    let encoded = encoder.encode(&pcm).unwrap();

    // Opus at 24kbps for 20ms should produce ~60 bytes
    // Silence should compress even smaller
    assert!(
        encoded.len() < 200,
        "Opus frame too large: {} bytes",
        encoded.len()
    );
    // Should fit in relay cell payload (457 bytes)
    assert!(encoded.len() < 457);
}

#[test]
fn test_codec2_compressed_size_tiny() {
    use parolnet_core::audio::{AudioConfig, AudioEncoder};
    let config = AudioConfig::low_bandwidth();
    let mut encoder = AudioEncoder::new(&config).unwrap();

    let pcm = vec![0i16; encoder.frame_samples()];
    let encoded = encoder.encode(&pcm).unwrap();

    // Codec2 at 3200bps for 20ms = 64 bits = 8 bytes
    assert!(
        encoded.len() <= 16,
        "Codec2 frame too large: {} bytes",
        encoded.len()
    );
}

#[test]
fn test_audio_encoder_codec_type_field() {
    use parolnet_core::audio::{AudioConfig, AudioEncoder};
    use parolnet_protocol::media::AudioCodec;

    let opus_enc = AudioEncoder::new(&AudioConfig::default()).unwrap();
    assert_eq!(opus_enc.codec_type, AudioCodec::Opus);

    let c2_enc = AudioEncoder::new(&AudioConfig::low_bandwidth()).unwrap();
    assert_eq!(c2_enc.codec_type, AudioCodec::Codec2);
}

#[test]
fn test_audio_decoder_codec_type_field() {
    use parolnet_core::audio::{AudioConfig, AudioDecoder};
    use parolnet_protocol::media::AudioCodec;

    let opus_dec = AudioDecoder::new(&AudioConfig::default()).unwrap();
    assert_eq!(opus_dec.codec_type, AudioCodec::Opus);

    let c2_dec = AudioDecoder::new(&AudioConfig::low_bandwidth()).unwrap();
    assert_eq!(c2_dec.codec_type, AudioCodec::Codec2);
}

#[test]
fn test_audio_frame_struct() {
    use parolnet_core::audio::AudioFrame;
    use parolnet_protocol::media::AudioCodec;

    let frame = AudioFrame {
        codec: AudioCodec::Opus,
        sequence: 42,
        timestamp: 1000,
        data: vec![0xAB; 60],
    };
    assert_eq!(frame.codec, AudioCodec::Opus);
    assert_eq!(frame.sequence, 42);
    assert_eq!(frame.data.len(), 60);

    // Test clone
    let cloned = frame.clone();
    assert_eq!(cloned.data, frame.data);
}

// ── Video Coverage Tests ────────────────────────────────────────

#[test]
fn test_video_fragment_exact_boundary() {
    use parolnet_core::video::{MAX_FRAGMENT_SIZE, VideoFrame, fragment_video_frame};
    use parolnet_protocol::media::{MediaSource, VideoCodec};

    // Data exactly MAX_FRAGMENT_SIZE -- should be 1 fragment
    let frame = VideoFrame {
        codec: VideoCodec::VP8,
        width: 320,
        height: 240,
        is_keyframe: false,
        timestamp: 0,
        source: MediaSource::Camera,
        data: vec![0xAB; MAX_FRAGMENT_SIZE],
    };
    let frags = fragment_video_frame(&frame, 1);
    assert_eq!(frags.len(), 1);

    // Data = MAX_FRAGMENT_SIZE + 1 -- should be 2 fragments
    let frame2 = VideoFrame {
        codec: VideoCodec::VP8,
        width: 320,
        height: 240,
        is_keyframe: false,
        timestamp: 0,
        source: MediaSource::Camera,
        data: vec![0xAB; MAX_FRAGMENT_SIZE + 1],
    };
    let frags2 = fragment_video_frame(&frame2, 2);
    assert_eq!(frags2.len(), 2);
    assert_eq!(frags2[0].data.len(), MAX_FRAGMENT_SIZE);
    assert_eq!(frags2[1].data.len(), 1);
}

#[test]
fn test_video_fragment_keyframe_only_on_first() {
    use parolnet_core::video::{VideoFrame, fragment_video_frame};
    use parolnet_protocol::media::{MediaSource, VideoCodec};

    let frame = VideoFrame {
        codec: VideoCodec::VP9,
        width: 640,
        height: 480,
        is_keyframe: true,
        timestamp: 100,
        source: MediaSource::Camera,
        data: vec![0; 1000], // multiple fragments
    };
    let frags = fragment_video_frame(&frame, 1);
    assert!(frags.len() > 1);
    assert!(frags[0].is_keyframe);
    for frag in &frags[1..] {
        assert!(!frag.is_keyframe);
    }
}

#[test]
fn test_video_reassemble_wrong_frame_id() {
    use parolnet_core::video::{VideoFragment, reassemble_video_frame};
    use parolnet_protocol::media::{MediaSource, VideoCodec};

    let mut fragments = vec![
        VideoFragment {
            frame_id: 1,
            fragment_index: 0,
            total_fragments: 2,
            is_keyframe: false,
            timestamp: 0,
            source: MediaSource::Camera,
            data: vec![1],
        },
        VideoFragment {
            frame_id: 2,
            fragment_index: 1,
            total_fragments: 2,
            is_keyframe: false,
            timestamp: 0,
            source: MediaSource::Camera,
            data: vec![2],
        },
    ];
    let result = reassemble_video_frame(&mut fragments, VideoCodec::VP8, 320, 240);
    assert!(result.is_err());
}

#[test]
fn test_video_reassemble_out_of_order() {
    use parolnet_core::video::{VideoFrame, fragment_video_frame, reassemble_video_frame};
    use parolnet_protocol::media::{MediaSource, VideoCodec};

    let frame = VideoFrame {
        codec: VideoCodec::VP8,
        width: 320,
        height: 240,
        is_keyframe: true,
        timestamp: 500,
        source: MediaSource::Camera,
        data: vec![0xCD; 1000],
    };
    let mut frags = fragment_video_frame(&frame, 7);

    // Reverse order -- reassemble should sort by fragment_index
    frags.reverse();

    let reassembled = reassemble_video_frame(&mut frags, VideoCodec::VP8, 320, 240).unwrap();
    assert_eq!(reassembled.data, frame.data);
}

#[test]
fn test_video_fragment_preserves_timestamp() {
    use parolnet_core::video::{VideoFrame, fragment_video_frame};
    use parolnet_protocol::media::{MediaSource, VideoCodec};

    let frame = VideoFrame {
        codec: VideoCodec::VP8,
        width: 320,
        height: 240,
        is_keyframe: false,
        timestamp: 12345,
        source: MediaSource::Camera,
        data: vec![0; 1000],
    };
    let frags = fragment_video_frame(&frame, 99);
    for frag in &frags {
        assert_eq!(frag.timestamp, 12345);
        assert_eq!(frag.frame_id, 99);
    }
}

#[test]
fn test_video_reassemble_empty_fragments_vec() {
    use parolnet_core::video::reassemble_video_frame;
    use parolnet_protocol::media::VideoCodec;

    let mut fragments = vec![];
    let result = reassemble_video_frame(&mut fragments, VideoCodec::VP8, 320, 240);
    assert!(result.is_err());
}

#[test]
fn test_video_fragment_non_keyframe() {
    use parolnet_core::video::{VideoFrame, fragment_video_frame};
    use parolnet_protocol::media::{MediaSource, VideoCodec};

    let frame = VideoFrame {
        codec: VideoCodec::VP8,
        width: 320,
        height: 240,
        is_keyframe: false,
        timestamp: 0,
        source: MediaSource::Camera,
        data: vec![0; 1000],
    };
    let frags = fragment_video_frame(&frame, 1);
    // None of the fragments should be marked as keyframe
    for frag in &frags {
        assert!(!frag.is_keyframe);
    }
}

#[test]
fn test_video_config_vp9() {
    use parolnet_protocol::media::{VideoCodec, VideoConfig};

    let config = VideoConfig {
        width: 640,
        height: 480,
        bitrate_kbps: 500,
        keyframe_interval: 60,
        codec: VideoCodec::VP9,
    };
    assert_eq!(config.codec, VideoCodec::VP9);
    assert_eq!(config.width, 640);
}

// ── Call Manager Coverage ───────────────────────────────────────

#[test]
fn test_call_hangup_from_offering() {
    use parolnet_core::call::Call;
    use parolnet_protocol::media::{CallSignalMessage, CallState};

    let call_id = [1; 16];
    let mut call = Call::new_outgoing(call_id, PeerId([1; 32]));
    call.handle_signal(&CallSignalMessage::Hangup { call_id })
        .unwrap();
    assert_eq!(call.state, CallState::Ended);
}

#[test]
fn test_call_hangup_from_ringing() {
    use parolnet_core::call::Call;
    use parolnet_protocol::media::{CallSignalMessage, CallState};

    let call_id = [2; 16];
    let mut call = Call::new_incoming(call_id, PeerId([2; 32]));
    call.handle_signal(&CallSignalMessage::Hangup { call_id })
        .unwrap();
    assert_eq!(call.state, CallState::Ended);
}

#[test]
fn test_call_hangup_from_active() {
    use parolnet_core::call::CallManager;
    use parolnet_protocol::media::CallState;

    let manager = CallManager::new();
    let id = [4; 16];
    manager.incoming_call(id, PeerId([4; 32]));
    manager.answer(&id).unwrap();
    assert_eq!(manager.get_state(&id), Some(CallState::Active));
    manager.hangup(&id).unwrap();
    assert_eq!(manager.get_state(&id), Some(CallState::Ended));
}

#[test]
fn test_call_duration_tracking() {
    use parolnet_core::call::Call;
    use parolnet_protocol::media::CallSignalMessage;

    let call_id = [1; 16];
    let mut call = Call::new_outgoing(call_id, PeerId([1; 32]));
    assert!(call.duration().is_none()); // Not active yet

    call.handle_signal(&CallSignalMessage::Answer {
        call_id,
        sdp: "".into(),
    })
    .unwrap();
    assert!(call.duration().is_some()); // Now active

    let dur = call.duration().unwrap();
    assert!(dur.as_millis() < 1000); // Should be near-instant in test
}

#[test]
fn test_call_manager_get_nonexistent() {
    use parolnet_core::call::CallManager;
    let manager = CallManager::new();
    assert_eq!(manager.get_state(&[0xFF; 16]), None);
}

#[test]
fn test_call_mute_not_active_fails() {
    use parolnet_core::call::Call;
    use parolnet_protocol::media::CallSignalMessage;

    let call_id = [1; 16];
    let mut call = Call::new_outgoing(call_id, PeerId([1; 32]));
    let mute = CallSignalMessage::Mute {
        call_id,
        muted: true,
    };
    assert!(call.handle_signal(&mute).is_err()); // Can't mute while Offering
}

#[test]
fn test_call_offer_signal_on_existing_call_fails() {
    use parolnet_core::call::Call;
    use parolnet_protocol::media::CallSignalMessage;

    let call_id = [1; 16];
    let mut call = Call::new_outgoing(call_id, PeerId([1; 32]));
    let offer = CallSignalMessage::Offer {
        call_id,
        sdp: "v=0".into(),
    };
    assert!(call.handle_signal(&offer).is_err());
}

#[test]
fn test_call_answer_wrong_state_fails() {
    use parolnet_core::call::Call;
    use parolnet_protocol::media::{CallSignalMessage, CallState};

    // Can't answer a call that is already Active
    let call_id = [1; 16];
    let mut call = Call::new_outgoing(call_id, PeerId([1; 32]));
    call.handle_signal(&CallSignalMessage::Answer {
        call_id,
        sdp: "".into(),
    })
    .unwrap();
    assert_eq!(call.state, CallState::Active);
    // Second answer should fail
    assert!(
        call.handle_signal(&CallSignalMessage::Answer {
            call_id,
            sdp: "".into()
        })
        .is_err()
    );
}

#[test]
fn test_call_reject_from_wrong_state_fails() {
    use parolnet_core::call::Call;
    use parolnet_protocol::media::CallSignalMessage;

    let call_id = [1; 16];
    let mut call = Call::new_outgoing(call_id, PeerId([1; 32]));
    // Move to Active
    call.handle_signal(&CallSignalMessage::Answer {
        call_id,
        sdp: "".into(),
    })
    .unwrap();
    // Can't reject an active call
    assert!(
        call.handle_signal(&CallSignalMessage::Reject { call_id })
            .is_err()
    );
}

#[test]
fn test_call_is_timed_out() {
    use parolnet_core::call::Call;

    let call = Call::new_outgoing([1; 16], PeerId([1; 32]));
    // Just created, should not be timed out
    assert!(!call.is_timed_out());
}

#[test]
fn test_call_manager_cleanup_timed_out() {
    use parolnet_core::call::CallManager;

    let manager = CallManager::new();
    // Just-created calls should not be timed out
    let _id = manager.start_call(PeerId([1; 32])).unwrap();
    let timed_out = manager.cleanup_timed_out();
    assert!(timed_out.is_empty());
}

#[test]
fn test_call_manager_reject_offering() {
    use parolnet_core::call::CallManager;
    use parolnet_protocol::media::CallState;

    let manager = CallManager::new();
    let id = manager.start_call(PeerId([1; 32])).unwrap();
    assert_eq!(manager.get_state(&id), Some(CallState::Offering));
    manager.reject(&id).unwrap();
    assert_eq!(manager.get_state(&id), Some(CallState::Rejected));
}

#[test]
fn test_call_manager_hangup_nonexistent_fails() {
    use parolnet_core::call::CallManager;

    let manager = CallManager::new();
    assert!(manager.hangup(&[0xFF; 16]).is_err());
}

#[test]
fn test_call_manager_toggle_mute_nonexistent_fails() {
    use parolnet_core::call::CallManager;

    let manager = CallManager::new();
    assert!(manager.toggle_mute(&[0xFF; 16], true).is_err());
}

#[test]
fn test_call_manager_answer_nonexistent_fails() {
    use parolnet_core::call::CallManager;

    let manager = CallManager::new();
    assert!(manager.answer(&[0xFF; 16]).is_err());
}

#[test]
fn test_call_manager_multiple_active_calls() {
    use parolnet_core::call::CallManager;

    let manager = CallManager::new();
    let id1 = [1; 16];
    let id2 = [2; 16];
    manager.incoming_call(id1, PeerId([1; 32]));
    manager.incoming_call(id2, PeerId([2; 32]));
    manager.answer(&id1).unwrap();
    manager.answer(&id2).unwrap();
    assert_eq!(manager.active_call_count(), 2);
    assert_eq!(manager.total_call_count(), 2);
}

// ── File Transfer Coverage ──────────────────────────────────────

#[test]
fn test_file_transfer_exact_chunk_boundary() {
    use parolnet_core::file_transfer::{FileTransferReceiver, FileTransferSender};

    // Exactly 2 chunks: 8192 bytes at 4096 chunk size
    let data = vec![0xAB; 8192];
    let mut sender = FileTransferSender::new(data.clone(), "exact.bin".into(), None);
    let mut receiver = FileTransferReceiver::new(sender.offer.clone());

    assert_eq!(sender.total_chunks(), 2);

    let (h1, c1) = sender.next().unwrap();
    assert!(!h1.is_last);
    assert_eq!(c1.len(), 4096);
    receiver.receive_chunk(&h1, c1).unwrap();

    let (h2, c2) = sender.next().unwrap();
    assert!(h2.is_last);
    assert_eq!(c2.len(), 4096);
    receiver.receive_chunk(&h2, c2).unwrap();

    assert!(sender.next().is_none());
    assert!(receiver.is_complete());
    assert_eq!(receiver.assemble().unwrap(), data);
}

#[test]
fn test_file_transfer_single_byte() {
    use parolnet_core::file_transfer::{FileTransferReceiver, FileTransferSender};

    let data = vec![0x42];
    let mut sender = FileTransferSender::new(data.clone(), "one.bin".into(), None);
    let mut receiver = FileTransferReceiver::new(sender.offer.clone());

    assert_eq!(sender.total_chunks(), 1);
    let (header, chunk) = sender.next().unwrap();
    assert!(header.is_last);
    assert_eq!(chunk.len(), 1);

    receiver.receive_chunk(&header, chunk).unwrap();
    assert_eq!(receiver.assemble().unwrap(), data);
}

#[test]
fn test_file_transfer_receiver_wrong_file_id() {
    use parolnet_core::file_transfer::{FileTransferReceiver, FileTransferSender};
    use parolnet_protocol::file::FileChunkHeader;

    let data = vec![0; 100];
    let sender = FileTransferSender::new(data, "test.bin".into(), None);
    let mut receiver = FileTransferReceiver::new(sender.offer.clone());

    let wrong_header = FileChunkHeader {
        file_id: [0xFF; 16], // wrong ID
        chunk_index: 0,
        chunk_size: 100,
        is_last: true,
    };
    assert!(receiver.receive_chunk(&wrong_header, vec![0; 100]).is_err());
}

#[test]
fn test_file_transfer_last_chunk_index() {
    use parolnet_core::file_transfer::{FileTransferReceiver, FileTransferSender};

    let data = vec![0; 10000]; // 3 chunks
    let mut sender = FileTransferSender::new(data, "test.bin".into(), None);
    let mut receiver = FileTransferReceiver::new(sender.offer.clone());

    assert_eq!(receiver.last_chunk_index(), None);

    let (h, c) = sender.next().unwrap();
    receiver.receive_chunk(&h, c).unwrap();
    assert_eq!(receiver.last_chunk_index(), Some(0));

    let (h, c) = sender.next().unwrap();
    receiver.receive_chunk(&h, c).unwrap();
    assert_eq!(receiver.last_chunk_index(), Some(1));
}

#[test]
fn test_file_transfer_mime_type_preserved() {
    use parolnet_core::file_transfer::FileTransferSender;

    let sender =
        FileTransferSender::new(vec![0; 100], "photo.png".into(), Some("image/png".into()));
    assert_eq!(sender.offer.mime_type, Some("image/png".into()));
    assert_eq!(sender.offer.file_name, "photo.png");
}

#[test]
fn test_file_transfer_sha256_computed() {
    use parolnet_core::file_transfer::FileTransferSender;

    let data = b"hello world".to_vec();
    let sender = FileTransferSender::new(data, "test.txt".into(), None);
    // SHA-256 of "hello world" is well-known
    let expected: [u8; 32] = [
        0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab,
        0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef,
        0xcd, 0xe9,
    ];
    assert_eq!(sender.offer.sha256, expected);
}

#[test]
fn test_file_transfer_receiver_progress() {
    use parolnet_core::file_transfer::{FileTransferReceiver, FileTransferSender};

    let data = vec![0; 12288]; // 3 chunks
    let mut sender = FileTransferSender::new(data, "prog.bin".into(), None);
    let mut receiver = FileTransferReceiver::new(sender.offer.clone());

    assert_eq!(receiver.progress(), (0, 3));

    let (h, c) = sender.next().unwrap();
    receiver.receive_chunk(&h, c).unwrap();
    assert_eq!(receiver.progress(), (1, 3));

    let (h, c) = sender.next().unwrap();
    receiver.receive_chunk(&h, c).unwrap();
    assert_eq!(receiver.progress(), (2, 3));

    let (h, c) = sender.next().unwrap();
    receiver.receive_chunk(&h, c).unwrap();
    assert_eq!(receiver.progress(), (3, 3));
    assert!(receiver.is_complete());
}

#[test]
fn test_file_transfer_receiver_not_complete_without_last() {
    use parolnet_core::file_transfer::{FileTransferReceiver, FileTransferSender};

    let data = vec![0; 10000]; // 3 chunks
    let mut sender = FileTransferSender::new(data, "test.bin".into(), None);
    let mut receiver = FileTransferReceiver::new(sender.offer.clone());

    // Send only the first chunk
    let (h, c) = sender.next().unwrap();
    receiver.receive_chunk(&h, c).unwrap();
    assert!(!receiver.is_complete());
    assert!(!receiver.completed);
}

#[test]
fn test_file_transfer_sender_resume_from() {
    use parolnet_core::file_transfer::FileTransferSender;

    let data = vec![0; 20000]; // 5 chunks
    let mut sender = FileTransferSender::new(data, "test.bin".into(), None);
    assert_eq!(sender.progress(), (0, 5));

    sender.resume_from(3);
    assert_eq!(sender.progress(), (3, 5));

    // Should only produce 2 more chunks
    let mut count = 0;
    while sender.next().is_some() {
        count += 1;
    }
    assert_eq!(count, 2);
}

// ── Relay Cell Additional Coverage ──────────────────────────────

#[test]
fn test_relay_padding_cell() {
    use parolnet_relay::{CELL_SIZE, CellType, RelayCell};

    let cell = RelayCell::padding(123);
    assert_eq!(cell.cell_type, CellType::Padding);
    assert_eq!(cell.circuit_id, 123);
    assert_eq!(cell.payload_len, 0);

    let bytes = cell.to_bytes();
    assert_eq!(bytes.len(), CELL_SIZE);
    let parsed = RelayCell::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.cell_type, CellType::Padding);
}

#[test]
fn test_relay_destroy_cell() {
    use parolnet_relay::{CellType, RelayCell};

    let cell = RelayCell::destroy(456, 0x01);
    assert_eq!(cell.cell_type, CellType::Destroy);
    assert_eq!(cell.circuit_id, 456);
    assert_eq!(cell.payload_len, 1);

    let bytes = cell.to_bytes();
    let parsed = RelayCell::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.cell_type, CellType::Destroy);
    assert_eq!(parsed.payload[0], 0x01); // reason byte
}

#[test]
fn test_relay_cell_invalid_type() {
    use parolnet_relay::{CELL_SIZE, RelayCell};

    let mut bytes = [0u8; CELL_SIZE];
    bytes[4] = 0xFF; // invalid cell type
    let result = RelayCell::from_bytes(&bytes);
    assert!(result.is_err());
}

// ── Traffic Shaper Coverage ─────────────────────────────────────

#[test]
fn test_standard_shaper_media_call() {
    use parolnet_transport::noise::{BandwidthMode, StandardShaper};
    use parolnet_transport::traits::TrafficShaper;

    let shaper = StandardShaper {
        mode: BandwidthMode::MediaCall,
    };

    // delay_before_send should be in [20ms, 25ms] range
    let delay = shaper.delay_before_send();
    assert!(delay >= std::time::Duration::from_millis(20));
    assert!(delay <= std::time::Duration::from_millis(25));

    // dummy_traffic_interval should match padding_interval
    let interval = shaper.dummy_traffic_interval();
    assert_eq!(interval, Some(std::time::Duration::from_millis(20)));
}

#[test]
fn test_standard_shaper_shape_messages() {
    use parolnet_transport::noise::{BandwidthMode, StandardShaper};
    use parolnet_transport::traits::TrafficShaper;

    let shaper = StandardShaper {
        mode: BandwidthMode::MediaCall,
    };

    let messages: Vec<Vec<u8>> = (0..5).map(|i| vec![i; 80]).collect();
    let shaped = shaper.shape(messages);
    assert_eq!(shaped.len(), 5);

    // Each shaped message should have timing >= base interval (20ms)
    for (delay, msg) in &shaped {
        assert!(*delay >= std::time::Duration::from_millis(20));
        assert_eq!(msg.len(), 80);
    }
}

// ── File Protocol Types Coverage ────────────────────────────────

#[test]
fn test_file_action_variants() {
    use parolnet_protocol::file::{FileAction, FileControl};

    let ctrl = FileControl {
        file_id: [0; 16],
        action: FileAction::Accept,
        resume_from: None,
    };
    assert!(ctrl.resume_from.is_none());

    let resume_ctrl = FileControl {
        file_id: [0; 16],
        action: FileAction::Resume,
        resume_from: Some(5),
    };
    assert_eq!(resume_ctrl.resume_from, Some(5));
}

#[test]
fn test_file_chunk_header_serialization() {
    use parolnet_protocol::file::FileChunkHeader;

    let header = FileChunkHeader {
        file_id: [0xAB; 16],
        chunk_index: 42,
        chunk_size: 4096,
        is_last: false,
    };

    // CBOR roundtrip
    let mut buf = Vec::new();
    ciborium::into_writer(&header, &mut buf).unwrap();
    let decoded: FileChunkHeader = ciborium::from_reader(&buf[..]).unwrap();
    assert_eq!(decoded.file_id, header.file_id);
    assert_eq!(decoded.chunk_index, 42);
    assert_eq!(decoded.chunk_size, 4096);
    assert!(!decoded.is_last);
}

#[test]
fn test_file_offer_serialization() {
    use parolnet_protocol::file::FileOffer;

    let offer = FileOffer {
        file_id: [0x42; 16],
        file_name: "photo.jpg".into(),
        file_size: 123456,
        chunk_size: 4096,
        sha256: [0xCD; 32],
        mime_type: Some("image/jpeg".into()),
    };

    let mut buf = Vec::new();
    ciborium::into_writer(&offer, &mut buf).unwrap();
    let decoded: FileOffer = ciborium::from_reader(&buf[..]).unwrap();
    assert_eq!(decoded.file_name, "photo.jpg");
    assert_eq!(decoded.file_size, 123456);
    assert_eq!(decoded.mime_type, Some("image/jpeg".into()));
}

// ── Call Signal Serialization ───────────────────────────────────

#[test]
fn test_call_signal_message_serialization() {
    use parolnet_protocol::media::CallSignalMessage;

    let offer = CallSignalMessage::Offer {
        call_id: [0x11; 16],
        sdp: "v=0\r\n".into(),
    };

    let mut buf = Vec::new();
    ciborium::into_writer(&offer, &mut buf).unwrap();
    let decoded: CallSignalMessage = ciborium::from_reader(&buf[..]).unwrap();
    match decoded {
        CallSignalMessage::Offer { call_id, sdp } => {
            assert_eq!(call_id, [0x11; 16]);
            assert_eq!(sdp, "v=0\r\n");
        }
        _ => panic!("expected Offer variant"),
    }
}

#[test]
fn test_call_signal_hangup_serialization() {
    use parolnet_protocol::media::CallSignalMessage;

    let hangup = CallSignalMessage::Hangup {
        call_id: [0xFF; 16],
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&hangup, &mut buf).unwrap();
    let decoded: CallSignalMessage = ciborium::from_reader(&buf[..]).unwrap();
    match decoded {
        CallSignalMessage::Hangup { call_id } => assert_eq!(call_id, [0xFF; 16]),
        _ => panic!("expected Hangup variant"),
    }
}

#[test]
fn test_call_signal_mute_serialization() {
    use parolnet_protocol::media::CallSignalMessage;

    let mute = CallSignalMessage::Mute {
        call_id: [0xAB; 16],
        muted: true,
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&mute, &mut buf).unwrap();
    let decoded: CallSignalMessage = ciborium::from_reader(&buf[..]).unwrap();
    match decoded {
        CallSignalMessage::Mute { call_id, muted } => {
            assert_eq!(call_id, [0xAB; 16]);
            assert!(muted);
        }
        _ => panic!("expected Mute variant"),
    }
}

// ── Video Config Serialization ──────────────────────────────────

#[test]
fn test_video_config_serialization() {
    use parolnet_protocol::media::VideoConfig;

    let config = VideoConfig::default();
    let mut buf = Vec::new();
    ciborium::into_writer(&config, &mut buf).unwrap();
    let decoded: VideoConfig = ciborium::from_reader(&buf[..]).unwrap();
    assert_eq!(decoded.width, config.width);
    assert_eq!(decoded.height, config.height);
    assert_eq!(decoded.bitrate_kbps, config.bitrate_kbps);
    assert_eq!(decoded.keyframe_interval, config.keyframe_interval);
}

// ── Message Flags Coverage ──────────────────────────────────────

#[test]
fn test_message_flags() {
    use parolnet_protocol::message::MessageFlags;

    let mut flags = MessageFlags::default();
    assert!(!flags.is_decoy());
    assert!(!flags.requires_ack());
    assert!(!flags.is_fragment());
    assert!(!flags.is_final_fragment());

    flags.set_decoy();
    assert!(flags.is_decoy());

    flags.set_requires_ack();
    assert!(flags.requires_ack());

    flags.set_fragment();
    assert!(flags.is_fragment());

    flags.set_final_fragment();
    assert!(flags.is_final_fragment());
}

// ── Padding Enforcement Tests ──────────────────────────────────

/// Verify that `send()` automatically pads messages to bucket sizes
/// and `recv()` recovers the original plaintext.
#[test]
fn test_send_recv_padding_roundtrip() {
    use parolnet_protocol::BUCKET_SIZES;
    use rand::rngs::OsRng;

    let alice = ParolNet::new(ParolNetConfig::default());
    let bob = ParolNet::new(ParolNetConfig::default());

    // Bob generates a ratchet keypair
    let bob_ratchet_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let bob_ratchet_pub = *x25519_dalek::PublicKey::from(&bob_ratchet_secret).as_bytes();

    // Alice establishes as initiator, Bob as responder
    alice
        .establish_session(
            bob.peer_id(),
            SharedSecret([0x42; 32]),
            &bob_ratchet_pub,
            true,
        )
        .unwrap();
    bob.establish_responder_session(
        alice.peer_id(),
        SharedSecret([0x42; 32]),
        bob_ratchet_secret.to_bytes(),
    )
    .unwrap();

    // Send a short message from Alice to Bob
    let original = b"hello bob";
    let (header, ciphertext) = alice.send(&bob.peer_id(), original).unwrap();

    // The ciphertext should be larger than the original message due to
    // bucket padding + AEAD overhead. Verify ciphertext length is at least
    // the smallest bucket size (padding was applied before encryption).
    assert!(
        ciphertext.len() >= BUCKET_SIZES[0],
        "ciphertext length {} should be >= smallest bucket size {}",
        ciphertext.len(),
        BUCKET_SIZES[0]
    );

    // Bob decrypts and gets the original plaintext back (unpadded automatically)
    let decrypted = bob.recv(&alice.peer_id(), &header, &ciphertext).unwrap();
    assert_eq!(
        decrypted, original,
        "decrypted message must match original plaintext"
    );
}
