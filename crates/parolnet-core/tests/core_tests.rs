use parolnet_core::bootstrap;
use parolnet_core::config::ParolNetConfig;
use parolnet_core::decoy::DecoyState;
use parolnet_core::ParolNet;
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

    let shared_secret = SharedSecret([0x42; 32]);

    // Generate a ratchet key for Bob
    use rand::rngs::OsRng;
    let bob_ratchet = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
    let bob_ratchet_pub = *x25519_dalek::PublicKey::from(&bob_ratchet).as_bytes();

    // Alice establishes session with Bob
    alice
        .establish_session(bob.peer_id(), shared_secret.clone(), &bob_ratchet_pub, true)
        .unwrap();

    assert!(alice.has_session(&bob.peer_id()));
    assert_eq!(alice.session_count(), 1);

    // Alice encrypts a message
    let (header, ciphertext) = alice.send(&bob.peer_id(), b"hello bob").unwrap();
    assert!(!ciphertext.is_empty());
}

// ── Panic Wipe Tests ────────────────────────────────────────────

#[test]
fn test_panic_wipe_clears_sessions() {
    let mut client = ParolNet::new(ParolNetConfig::default());

    use rand::rngs::OsRng;
    let ratchet = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
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
        let ratchet_secret = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
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
    use parolnet_core::file_transfer::{FileTransferSender, FileTransferReceiver};

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
    use parolnet_core::file_transfer::{FileTransferSender, FileTransferReceiver};

    // 100KB file — should produce 25 chunks at 4096 bytes each
    let data = vec![0xABu8; 100_000];
    let mut sender = FileTransferSender::new(data.clone(), "large.bin".into(), Some("application/octet-stream".into()));
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
    use parolnet_core::file_transfer::{FileTransferSender, FileTransferReceiver};

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
    use parolnet_core::file_transfer::{FileTransferSender, FileTransferReceiver};

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
    use parolnet_core::file_transfer::{FileTransferSender, FileTransferReceiver};

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
    use parolnet_core::file_transfer::{FileTransferSender, FileTransferReceiver};

    let data = vec![0u8; 8192]; // exactly 2 chunks
    let mut sender = FileTransferSender::new(data, "progress.bin".into(), None);

    assert_eq!(sender.progress(), (0, 2));
    sender.next();
    assert_eq!(sender.progress(), (1, 2));
    sender.next();
    assert_eq!(sender.progress(), (2, 2));
    assert!(sender.is_complete());
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
    let id1 = manager.start_call(PeerId([1; 32])).unwrap();
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
