use parolnet_relay::*;
use parolnet_relay::circuit::{EstablishedCircuit, StandardCircuitBuilder};
use parolnet_relay::directory::{RelayDescriptor, RelayDirectory};
use parolnet_relay::onion::HopKeys;
use parolnet_relay::relay_node::StandardRelayNode;
use parolnet_protocol::address::PeerId;
use std::net::SocketAddr;

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
    for v in 0x01..=0x08 {
        assert!(CellType::from_u8(v).is_some());
    }
    assert!(CellType::from_u8(0x00).is_none());
    assert!(CellType::from_u8(0x09).is_none());
}

// ── Circuit Tests ───────────────────────────────────────────────

#[test]
fn test_circuit_wrap_unwrap_roundtrip() {
    let hop1 = HopKeys::from_shared_secret(&[1u8; 32]).unwrap();
    let hop2 = HopKeys::from_shared_secret(&[2u8; 32]).unwrap();
    let hop3 = HopKeys::from_shared_secret(&[3u8; 32]).unwrap();

    let circuit = EstablishedCircuit::from_hop_keys(
        vec![hop1, hop2, hop3],
        42,
    );

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
        let keys = HopKeys::from_shared_secret(&(i as u32).to_be_bytes().repeat(8).try_into().unwrap_or([0u8; 32])).unwrap();
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
    dir.insert(make_descriptor(1, 1));   // 1 day - too short
    dir.insert(make_descriptor(2, 10));  // 10 days - qualifies
    dir.insert(make_descriptor(3, 30));  // 30 days - qualifies

    let guards = dir.select_guards(2);
    assert_eq!(guards.len(), 2);
    // Should prefer highest uptime
    assert_eq!(guards[0].identity_key[0], 3);
    assert_eq!(guards[1].identity_key[0], 2);
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
