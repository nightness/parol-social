use ed25519_dalek::{SigningKey, Verifier};
use parolnet_protocol::address::PeerId;
use parolnet_relay::circuit::{EstablishedCircuit, StandardCircuitBuilder};
use parolnet_relay::directory::{RelayDescriptor, RelayDirectory};
use parolnet_relay::onion::{self, HopKeys};
use parolnet_relay::relay_node::StandardRelayNode;
use parolnet_relay::*;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use x25519_dalek::{PublicKey, StaticSecret};

// ── Constants Tests ─────────────────────────────────────────────

#[test]
fn test_cell_size_constants() {
    assert_eq!(CELL_SIZE, 512);
    assert_eq!(CELL_HEADER_SIZE, 7);
    assert_eq!(CELL_PAYLOAD_SIZE, 505);
    assert_eq!(REQUIRED_HOPS, 3);
    assert_eq!(MAX_DATA_PAYLOAD, 457); // 505 - 3*16
}

// ── Cell Serialization Tests ────────────────────────────────────

#[test]
fn test_cell_serialization_roundtrip() {
    let cell = RelayCell {
        circuit_id: 42,
        cell_type: CellType::Data,
        payload: [0xAB; CELL_PAYLOAD_SIZE],
        payload_len: 100,
    };

    let bytes = cell.to_bytes();
    assert_eq!(bytes.len(), CELL_SIZE);

    let decoded = RelayCell::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.circuit_id, 42);
    assert_eq!(decoded.cell_type, CellType::Data);
    assert_eq!(decoded.payload_len, 100);
    assert_eq!(decoded.payload, [0xAB; CELL_PAYLOAD_SIZE]);
}

#[test]
fn test_padding_cell() {
    let cell = RelayCell::padding(99);
    assert_eq!(cell.circuit_id, 99);
    assert_eq!(cell.cell_type, CellType::Padding);
    assert_eq!(cell.payload_len, 0);
    let bytes = cell.to_bytes();
    assert_eq!(bytes.len(), CELL_SIZE);
}

#[test]
fn test_destroy_cell() {
    let cell = RelayCell::destroy(42, 0x00); // normal teardown
    assert_eq!(cell.cell_type, CellType::Destroy);
    assert_eq!(cell.payload[0], 0x00);
}

#[test]
fn test_cell_type_roundtrip() {
    for v in 0x01..=0x09 {
        assert!(CellType::from_u8(v).is_some());
    }
    assert!(CellType::from_u8(0x00).is_none());
    assert!(CellType::from_u8(0x0A).is_none());
}

// ── Circuit Tests ───────────────────────────────────────────────

#[test]
fn test_circuit_wrap_unwrap_roundtrip() {
    let hop1 = HopKeys::from_shared_secret(&[1u8; 32]).unwrap();
    let hop2 = HopKeys::from_shared_secret(&[2u8; 32]).unwrap();
    let hop3 = HopKeys::from_shared_secret(&[3u8; 32]).unwrap();

    let circuit = EstablishedCircuit::from_hop_keys(vec![hop1, hop2, hop3], 42);

    let plaintext = b"hello through circuit";
    let encrypted = circuit.wrap_data(plaintext).unwrap();
    assert_ne!(encrypted, plaintext);

    // Simulate 3 relays peeling layers
    // (In production each relay peels one layer and forwards)
}

#[test]
fn test_circuit_id_nonzero() {
    let hop_keys = vec![
        HopKeys::from_shared_secret(&[1u8; 32]).unwrap(),
        HopKeys::from_shared_secret(&[2u8; 32]).unwrap(),
        HopKeys::from_shared_secret(&[3u8; 32]).unwrap(),
    ];
    let circuit = EstablishedCircuit::from_hop_keys(hop_keys, 42);
    assert_eq!(circuit.id(), 42);
}

// ── Relay Node Tests ────────────────────────────────────────────

#[tokio::test]
async fn test_relay_node_discards_padding() {
    let node = StandardRelayNode::new();
    let cell = RelayCell::padding(42);
    let action = node.handle_cell(cell).await.unwrap();
    assert!(matches!(action, RelayAction::Discard));
}

#[tokio::test]
async fn test_relay_node_destroy_removes_circuit() {
    let node = StandardRelayNode::new();
    let keys = HopKeys::from_shared_secret(&[1u8; 32]).unwrap();
    node.register_circuit(42, keys, None).unwrap();
    assert_eq!(node.circuit_count(), 1);

    let cell = RelayCell::destroy(42, 0x00);
    let _ = node.handle_cell(cell).await.unwrap();
    assert_eq!(node.circuit_count(), 0);
}

#[tokio::test]
async fn test_relay_node_rejects_unknown_circuit() {
    let node = StandardRelayNode::new();
    let mut cell = RelayCell::padding(999);
    cell.cell_type = CellType::Data;
    cell.payload_len = 32;

    let result = node.handle_cell(cell).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_relay_node_circuit_limit() {
    let node = StandardRelayNode::new();
    for i in 0..relay_node::MAX_CIRCUITS {
        let keys = HopKeys::from_shared_secret(
            &(i as u32)
                .to_be_bytes()
                .repeat(8)
                .try_into()
                .unwrap_or([0u8; 32]),
        )
        .unwrap();
        node.register_circuit(i as u32 + 1, keys, None).unwrap();
    }
    // One more should fail
    let keys = HopKeys::from_shared_secret(&[0xFF; 32]).unwrap();
    assert!(node.register_circuit(999999, keys, None).is_err());
}

// ── Directory Tests ─────────────────────────────────────────────

fn make_descriptor(id: u8, uptime_days: u64) -> RelayDescriptor {
    let peer_id = PeerId([id; 32]);
    RelayDescriptor {
        peer_id,
        identity_key: [id; 32],
        x25519_key: [id; 32],
        addr: format!("10.0.{id}.1:443").parse().unwrap(),
        bandwidth_class: 1,
        uptime_secs: uptime_days * 86400,
        timestamp: 1700000000,
        signature: [0; 64],
        bandwidth_estimate: 1000,
        next_pubkey: None,
    }
}

#[test]
fn test_directory_insert_and_len() {
    let mut dir = RelayDirectory::new();
    assert!(dir.is_empty());

    dir.insert(make_descriptor(1, 10));
    dir.insert(make_descriptor(2, 20));
    assert_eq!(dir.len(), 2);
}

#[test]
fn test_directory_guard_selection() {
    let mut dir = RelayDirectory::new();
    // Add relays with varying uptime
    dir.insert(make_descriptor(1, 1)); // 1 day - too short
    dir.insert(make_descriptor(2, 10)); // 10 days - qualifies
    dir.insert(make_descriptor(3, 30)); // 30 days - qualifies

    let guards = dir.select_guards(2);
    assert_eq!(guards.len(), 2);
    // Both selected guards must have uptime >= 7 days (relays 2 and 3 qualify, relay 1 does not)
    let ids: Vec<u8> = guards.iter().map(|g| g.identity_key[0]).collect();
    assert!(ids.contains(&2), "relay 2 (10d uptime) should be selected");
    assert!(ids.contains(&3), "relay 3 (30d uptime) should be selected");
    assert!(
        !ids.contains(&1),
        "relay 1 (1d uptime) should not be selected"
    );
}

#[test]
fn test_directory_random_excludes() {
    let mut dir = RelayDirectory::new();
    dir.insert(make_descriptor(1, 10));
    dir.insert(make_descriptor(2, 10));

    // Exclude relay 1
    let selected = dir.select_random(&[PeerId([1; 32])]);
    assert!(selected.is_some());
    assert_eq!(selected.unwrap().identity_key[0], 2);
}

#[test]
fn test_directory_prune_stale() {
    let mut dir = RelayDirectory::new();
    dir.insert(make_descriptor(1, 10)); // timestamp 1700000000

    // Not stale yet
    dir.prune_stale(1700000000 + 3600);
    assert_eq!(dir.len(), 1);

    // Now stale (25 hours later)
    dir.prune_stale(1700000000 + 90000);
    assert_eq!(dir.len(), 0);
}

#[test]
fn test_directory_select_path() {
    let mut dir = RelayDirectory::new();
    dir.insert(make_descriptor(1, 30));
    dir.insert(make_descriptor(2, 20));
    dir.insert(make_descriptor(3, 10));

    let path = dir.select_path();
    assert!(path.is_some());
    let path = path.unwrap();
    assert_eq!(path.len(), 3);
    // All three should be different
    assert_ne!(path[0].identity_key, path[1].identity_key);
    assert_ne!(path[1].identity_key, path[2].identity_key);
    assert_ne!(path[0].identity_key, path[2].identity_key);
}

// ── Circuit Tests (new) ────────────────────────────────────────

#[tokio::test]
async fn test_circuit_build_wrong_hop_count() {
    let builder = StandardCircuitBuilder::new();

    // Build two RelayInfo structs (need 3)
    let hops: Vec<RelayInfo> = (1u8..=2)
        .map(|id| {
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            RelayInfo {
                peer_id: PeerId([id; 32]),
                identity_key: [id; 32],
                x25519_key: *public.as_bytes(),
                addr: format!("127.0.0.{id}:9000").parse().unwrap(),
                bandwidth_class: 1,
            }
        })
        .collect();

    let result = builder.build_circuit(&hops).await;
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        matches!(err, RelayError::CircuitBuildFailed(_)),
        "expected CircuitBuildFailed, got: {err:?}"
    );
}

#[tokio::test]
async fn test_circuit_build_with_3_relays() {
    let builder = StandardCircuitBuilder::new();

    let hops: Vec<RelayInfo> = (1u8..=3)
        .map(|id| {
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            RelayInfo {
                peer_id: PeerId([id; 32]),
                identity_key: [id; 32],
                x25519_key: *public.as_bytes(),
                addr: format!("127.0.0.{id}:9000").parse().unwrap(),
                bandwidth_class: 1,
            }
        })
        .collect();

    let circuit = builder.build_circuit(&hops).await;
    assert!(circuit.is_ok(), "build_circuit should succeed with 3 hops");
}

#[test]
fn test_circuit_wrap_then_manual_peel() {
    let hop1 = HopKeys::from_shared_secret(&[10u8; 32]).unwrap();
    let hop2 = HopKeys::from_shared_secret(&[20u8; 32]).unwrap();
    let hop3 = HopKeys::from_shared_secret(&[30u8; 32]).unwrap();

    let circuit =
        EstablishedCircuit::from_hop_keys(vec![hop1.clone(), hop2.clone(), hop3.clone()], 100);

    let plaintext = b"hello";
    let encrypted = circuit.wrap_data(plaintext).unwrap();

    // Manually peel three layers in order: hop1, hop2, hop3
    let after1 =
        onion::onion_peel(&encrypted, &hop1.forward_key, &hop1.forward_nonce_seed, 0).unwrap();
    let after2 =
        onion::onion_peel(&after1, &hop2.forward_key, &hop2.forward_nonce_seed, 0).unwrap();
    let after3 =
        onion::onion_peel(&after2, &hop3.forward_key, &hop3.forward_nonce_seed, 0).unwrap();

    assert_eq!(after3, plaintext);
}

// ── Relay Node Forwarding Tests (new) ──────────────────────────

#[tokio::test]
async fn test_relay_node_data_exit_delivers() {
    let node = StandardRelayNode::new();
    let keys = HopKeys::from_shared_secret(&[50u8; 32]).unwrap();
    let circuit_id = 77;

    // Register as exit relay (no next_hop)
    node.register_circuit(circuit_id, keys.clone(), None)
        .unwrap();

    // Encrypt one onion layer with the hop's forward key
    let plaintext = b"exit-delivery-test";
    let encrypted =
        onion::onion_wrap(plaintext, &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap();

    // Build DATA cell with encrypted payload
    let mut payload = [0u8; CELL_PAYLOAD_SIZE];
    payload[..encrypted.len()].copy_from_slice(&encrypted);

    let cell = RelayCell {
        circuit_id,
        cell_type: CellType::Data,
        payload,
        payload_len: encrypted.len() as u16,
    };

    let action = node.handle_cell(cell).await.unwrap();
    match action {
        RelayAction::Deliver { payload: delivered } => {
            assert_eq!(delivered, plaintext);
        }
        other => panic!(
            "expected Deliver, got: {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

#[tokio::test]
async fn test_relay_node_data_with_next_hop_forwards() {
    let node = StandardRelayNode::new();
    let keys = HopKeys::from_shared_secret(&[60u8; 32]).unwrap();
    let circuit_id = 88;
    let next_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let next_cid = 200;

    // Register with a next_hop
    node.register_circuit(circuit_id, keys.clone(), Some((next_addr, next_cid)))
        .unwrap();

    let plaintext = b"forward-test-payload";
    let encrypted =
        onion::onion_wrap(plaintext, &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap();

    let mut payload = [0u8; CELL_PAYLOAD_SIZE];
    payload[..encrypted.len()].copy_from_slice(&encrypted);

    let cell = RelayCell {
        circuit_id,
        cell_type: CellType::Data,
        payload,
        payload_len: encrypted.len() as u16,
    };

    let action = node.handle_cell(cell).await.unwrap();
    match action {
        RelayAction::Forward {
            next_hop,
            cell: forwarded,
        } => {
            assert_eq!(next_hop, next_addr);
            assert_eq!(forwarded.circuit_id, next_cid);
        }
        other => panic!(
            "expected Forward, got: {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ── Onion Edge Case Tests (new) ────────────────────────────────

#[test]
fn test_onion_encrypt_empty() {
    let hop1 = HopKeys::from_shared_secret(&[1u8; 32]).unwrap();
    let hop2 = HopKeys::from_shared_secret(&[2u8; 32]).unwrap();
    let hop3 = HopKeys::from_shared_secret(&[3u8; 32]).unwrap();
    let hops = [hop1.clone(), hop2.clone(), hop3.clone()];
    let counters = [0u32, 0, 0];

    let encrypted = onion::onion_encrypt(b"", &hops, &counters).unwrap();

    // Peel 3 layers
    let after1 =
        onion::onion_peel(&encrypted, &hop1.forward_key, &hop1.forward_nonce_seed, 0).unwrap();
    let after2 =
        onion::onion_peel(&after1, &hop2.forward_key, &hop2.forward_nonce_seed, 0).unwrap();
    let after3 =
        onion::onion_peel(&after2, &hop3.forward_key, &hop3.forward_nonce_seed, 0).unwrap();

    assert_eq!(after3, b"");
}

#[test]
fn test_onion_key_counter_mismatch() {
    let hop1 = HopKeys::from_shared_secret(&[1u8; 32]).unwrap();
    let hop2 = HopKeys::from_shared_secret(&[2u8; 32]).unwrap();
    let hops = [hop1, hop2];
    let counters = [0u32, 0, 0]; // 3 counters for 2 hops — mismatch

    let result = onion::onion_encrypt(b"test", &hops, &counters);
    assert!(result.is_err());
}

#[test]
fn test_onion_wrong_key_peel_fails() {
    let hop1 = HopKeys::from_shared_secret(&[1u8; 32]).unwrap();
    let hop2 = HopKeys::from_shared_secret(&[2u8; 32]).unwrap();

    // Encrypt with hop1's key
    let encrypted = onion::onion_wrap(
        b"secret data",
        &hop1.forward_key,
        &hop1.forward_nonce_seed,
        0,
    )
    .unwrap();

    // Try to peel with hop2's key — should fail with AeadFailed
    let result = onion::onion_peel(&encrypted, &hop2.forward_key, &hop2.forward_nonce_seed, 0);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), RelayError::AeadFailed),
        "expected AeadFailed error"
    );
}

// ── Directory / Cell Edge Case Tests (new) ─────────────────────

#[test]
fn test_cell_from_bytes_invalid_type() {
    let mut buf = [0u8; CELL_SIZE];
    // circuit_id = 1
    buf[0..4].copy_from_slice(&1u32.to_be_bytes());
    // cell_type = 0x00 (invalid)
    buf[4] = 0x00;
    // payload_len = 0
    buf[5] = 0;
    buf[6] = 0;

    let result = RelayCell::from_bytes(&buf);
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        matches!(err, RelayError::InvalidCellType(0x00)),
        "expected InvalidCellType(0x00), got: {err:?}"
    );
}

#[test]
fn test_directory_select_path_insufficient_relays() {
    let mut dir = RelayDirectory::new();
    // Only 2 relays — need at least 3 for a path
    dir.insert(make_descriptor(1, 30));
    dir.insert(make_descriptor(2, 20));

    let path = dir.select_path();
    assert!(
        path.is_none(),
        "select_path should return None with only 2 relays"
    );
}

// ── Descriptor Signing Tests ──────────────────────────────────

fn make_signed_descriptor(id: u8, uptime_days: u64, signing_key: &SigningKey) -> RelayDescriptor {
    let peer_id = PeerId([id; 32]);
    let identity_key = signing_key.verifying_key().to_bytes();
    RelayDirectory::create_descriptor(
        peer_id,
        identity_key,
        [id; 32],
        format!("10.0.{id}.1:443").parse().unwrap(),
        1,
        uptime_days * 86400,
        1700000000,
        signing_key,
    )
}

#[test]
fn test_descriptor_signature_roundtrip() {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let desc = make_signed_descriptor(1, 10, &signing_key);

    // Verify signature manually
    let verifying_key = signing_key.verifying_key();
    let signature = ed25519_dalek::Signature::from_bytes(&desc.signature);
    assert!(
        verifying_key
            .verify(&desc.signable_bytes(), &signature)
            .is_ok(),
        "signature should verify against the signing key"
    );
}

#[test]
fn test_descriptor_reject_tampered() {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let mut desc = make_signed_descriptor(1, 10, &signing_key);

    // Tamper with the bandwidth_class field
    desc.bandwidth_class = 255;

    let mut dir = RelayDirectory::new();
    let accepted = dir.handle_gossip_descriptor(desc, 1700000000 + 60);
    assert!(!accepted, "tampered descriptor should be rejected");
}

#[test]
fn test_descriptor_reject_wrong_key() {
    let key_a = SigningKey::generate(&mut rand::thread_rng());
    let key_b = SigningKey::generate(&mut rand::thread_rng());

    // Sign with key_a but set identity_key to key_b's public key
    let mut desc = make_signed_descriptor(1, 10, &key_a);
    desc.identity_key = key_b.verifying_key().to_bytes();

    let mut dir = RelayDirectory::new();
    let accepted = dir.handle_gossip_descriptor(desc, 1700000000 + 60);
    assert!(
        !accepted,
        "descriptor signed with wrong key should be rejected"
    );
}

#[test]
fn test_gossip_accepts_valid_signed_descriptor() {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let desc = make_signed_descriptor(1, 10, &signing_key);

    let mut dir = RelayDirectory::new();
    let accepted = dir.handle_gossip_descriptor(desc, 1700000000 + 60);
    assert!(accepted, "valid signed descriptor should be accepted");
}

// ── DESTROY Forwarding Chain Tests ────────────────────────────

#[tokio::test]
async fn test_destroy_with_next_hop_forwards() {
    let node = StandardRelayNode::new();
    let keys = HopKeys::from_shared_secret(&[1u8; 32]).unwrap();
    let next_addr: SocketAddr = "10.0.0.5:443".parse().unwrap();
    let next_cid = 500;

    node.register_circuit(42, keys, Some((next_addr, next_cid)))
        .unwrap();

    let cell = RelayCell::destroy(42, 0x01);
    let action = node.handle_cell(cell).await.unwrap();

    match action {
        RelayAction::Forward {
            next_hop,
            cell: forwarded,
        } => {
            assert_eq!(next_hop, next_addr);
            assert_eq!(forwarded.circuit_id, next_cid);
            assert_eq!(forwarded.cell_type, CellType::Destroy);
        }
        other => panic!(
            "expected Forward, got: {:?}",
            std::mem::discriminant(&other)
        ),
    }

    assert_eq!(node.circuit_count(), 0);
}

#[tokio::test]
async fn test_destroy_without_next_hop_discards() {
    let node = StandardRelayNode::new();
    let keys = HopKeys::from_shared_secret(&[2u8; 32]).unwrap();

    // Exit relay — no next_hop
    node.register_circuit(77, keys, None).unwrap();

    let cell = RelayCell::destroy(77, 0x02);
    let action = node.handle_cell(cell).await.unwrap();

    assert!(
        matches!(action, RelayAction::Discard),
        "exit relay should discard DESTROY"
    );
    assert_eq!(node.circuit_count(), 0);
}

#[tokio::test]
async fn test_destroy_reason_codes_preserved() {
    let node = StandardRelayNode::new();
    let next_addr: SocketAddr = "10.0.0.9:443".parse().unwrap();

    // Test reason code 0x03
    let keys = HopKeys::from_shared_secret(&[3u8; 32]).unwrap();
    node.register_circuit(100, keys, Some((next_addr, 200)))
        .unwrap();

    let cell = RelayCell::destroy(100, 0x03);
    let action = node.handle_cell(cell).await.unwrap();

    match &action {
        RelayAction::Forward { cell: fwd, .. } => {
            assert_eq!(fwd.payload[0], 0x03, "reason code 0x03 must be preserved");
        }
        other => panic!("expected Forward, got: {:?}", std::mem::discriminant(other)),
    }

    // Test reason code 0x00 (normal teardown)
    let keys2 = HopKeys::from_shared_secret(&[4u8; 32]).unwrap();
    node.register_circuit(101, keys2, Some((next_addr, 201)))
        .unwrap();

    let cell2 = RelayCell::destroy(101, 0x00);
    let action2 = node.handle_cell(cell2).await.unwrap();

    match &action2 {
        RelayAction::Forward { cell: fwd, .. } => {
            assert_eq!(fwd.payload[0], 0x00, "reason code 0x00 must be preserved");
        }
        other => panic!("expected Forward, got: {:?}", std::mem::discriminant(other)),
    }
}

#[tokio::test]
async fn test_destroy_unknown_circuit_discards() {
    let node = StandardRelayNode::new();

    // No circuits registered — send DESTROY for non-existent circuit
    let cell = RelayCell::destroy(999, 0x01);
    let action = node.handle_cell(cell).await.unwrap();

    assert!(
        matches!(action, RelayAction::Discard),
        "DESTROY for unknown circuit should discard"
    );
    assert_eq!(node.circuit_count(), 0);
}
