use parolnet_mesh::gossip::{DedupFilter, ProofOfWork, SeenBloomFilter};
use parolnet_mesh::peer_table::PeerScore;
use parolnet_mesh::store_forward::InMemoryStore;
use parolnet_mesh::MessageStore;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::envelope::{CleartextHeader, Envelope};
use std::time::Duration;

// ── Peer Score Tests ────────────────────────────────────────────

#[test]
fn test_peer_score_initialization() {
    let score = PeerScore::new(PeerId([0; 32]));
    assert_eq!(score.score, 100);
    assert!(!score.is_banned());
}

#[test]
fn test_peer_score_banning() {
    let mut score = PeerScore::new(PeerId([0; 32]));
    for _ in 0..11 {
        score.penalize_invalid();
    }
    assert!(score.is_banned());
}

#[test]
fn test_peer_score_max() {
    let mut score = PeerScore::new(PeerId([0; 32]));
    for _ in 0..200 {
        score.reward();
    }
    assert_eq!(score.score, 200);
}

// ── Bloom Filter Tests ──────────────────────────────────────────

#[test]
fn test_bloom_filter_insert_and_check() {
    let mut bloom = SeenBloomFilter::new();
    let peer = PeerId([0xAB; 32]);

    assert!(!bloom.probably_contains(&peer));
    bloom.insert(&peer);
    assert!(bloom.probably_contains(&peer));
}

#[test]
fn test_bloom_filter_different_peers() {
    let mut bloom = SeenBloomFilter::new();
    let peer1 = PeerId([1; 32]);
    let peer2 = PeerId([2; 32]);

    bloom.insert(&peer1);
    assert!(bloom.probably_contains(&peer1));
    // peer2 probably not in the filter (low FP rate for 1 entry)
    // This could occasionally fail due to false positives, but
    // with 1024 bits and 1 entry it's extremely unlikely
    assert!(!bloom.probably_contains(&peer2));
}

#[test]
fn test_bloom_filter_multiple_inserts() {
    let mut bloom = SeenBloomFilter::new();
    for i in 0..50u8 {
        bloom.insert(&PeerId([i; 32]));
    }
    // All inserted peers should be found
    for i in 0..50u8 {
        assert!(bloom.probably_contains(&PeerId([i; 32])));
    }
}

// ── Dedup Filter Tests ──────────────────────────────────────────

#[test]
fn test_dedup_filter_mark_and_check() {
    let dedup = DedupFilter::new();
    let id = [0xAB; 32];

    assert!(!dedup.is_seen(&id));
    dedup.mark_seen(id);
    assert!(dedup.is_seen(&id));
}

#[test]
fn test_dedup_filter_rotate() {
    let dedup = DedupFilter::new();
    let id1 = [1u8; 32];
    let id2 = [2u8; 32];

    dedup.mark_seen(id1);
    dedup.rotate();

    // id1 should still be seen (in previous buffer)
    assert!(dedup.is_seen(&id1));

    dedup.mark_seen(id2);
    dedup.rotate();

    // id1 should be gone (was in previous, now discarded)
    assert!(!dedup.is_seen(&id1));
    // id2 should still be seen
    assert!(dedup.is_seen(&id2));
}

// ── Proof-of-Work Tests ─────────────────────────────────────────

#[test]
fn test_pow_compute_and_verify() {
    let msg_id = [0xAB; 32];
    let sender = PeerId([0xCD; 32]);
    let timestamp = 1700000000u64;
    let difficulty = 8; // low difficulty for fast test

    let nonce = ProofOfWork::compute(&msg_id, &sender, timestamp, difficulty);
    assert!(ProofOfWork::verify(&msg_id, &sender, timestamp, &nonce, difficulty));
}

#[test]
fn test_pow_wrong_nonce_fails() {
    let msg_id = [0xAB; 32];
    let sender = PeerId([0xCD; 32]);
    let timestamp = 1700000000u64;

    let nonce = ProofOfWork::compute(&msg_id, &sender, timestamp, 8);
    // Tamper with nonce
    let mut bad_nonce = nonce;
    bad_nonce[0] ^= 0xFF;
    // Bad nonce very likely fails (could theoretically still pass, but probability is ~2^-8)
    // Use higher difficulty to make collision essentially impossible
    let nonce16 = ProofOfWork::compute(&msg_id, &sender, timestamp, 16);
    let mut bad16 = nonce16;
    bad16[0] ^= 0xFF;
    assert!(!ProofOfWork::verify(&msg_id, &sender, timestamp, &bad16, 16));
}

#[test]
fn test_pow_difficulty_zero() {
    // Difficulty 0 should accept any nonce
    assert!(ProofOfWork::verify(&[0; 32], &PeerId([0; 32]), 0, &[0; 8], 0));
}

// ── Store-and-Forward Tests ─────────────────────────────────────

fn make_test_envelope(dest: PeerId) -> Envelope {
    Envelope {
        header: CleartextHeader {
            version: 1,
            msg_type: 0x01,
            dest_peer_id: dest,
            message_id: [0; 16],
            timestamp: 1700000000,
            ttl_and_hops: (7 << 8) | 0,
            source_hint: None,
        },
        encrypted_payload: vec![0xEE; 64],
        mac: [0xFF; 16],
    }
}

#[tokio::test]
async fn test_store_and_retrieve() {
    let store = InMemoryStore::new();
    let peer = PeerId([1; 32]);
    let envelope = make_test_envelope(peer);

    store.store(&envelope, Duration::from_secs(3600)).await.unwrap();
    assert_eq!(store.count_for_peer(&peer), 1);

    let messages = store.retrieve(&peer).await.unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(store.count_for_peer(&peer), 0); // cleared after retrieve
}

#[tokio::test]
async fn test_store_limit_eviction() {
    let store = InMemoryStore::new();
    let peer = PeerId([1; 32]);

    // Store more than MAX_MESSAGES_PER_PEER
    for i in 0..260u16 {
        let mut env = make_test_envelope(peer);
        env.header.message_id[0] = (i & 0xFF) as u8;
        env.header.message_id[1] = (i >> 8) as u8;
        store.store(&env, Duration::from_secs(3600)).await.unwrap();
    }

    // Should be capped at MAX_MESSAGES_PER_PEER
    assert!(store.count_for_peer(&peer) <= 256);
}

#[tokio::test]
async fn test_store_expire() {
    let store = InMemoryStore::new();
    let peer = PeerId([1; 32]);
    let envelope = make_test_envelope(peer);

    // Store with 0 TTL (expires immediately)
    store.store(&envelope, Duration::from_secs(0)).await.unwrap();

    // Small delay to ensure expiry
    tokio::time::sleep(Duration::from_millis(10)).await;

    let expired = store.expire().await.unwrap();
    assert_eq!(expired, 1);
    assert_eq!(store.count_for_peer(&peer), 0);
}

// ── Additional Bloom Filter Tests ───────────────────────────────

#[test]
fn test_bloom_filter_false_positive_rate() {
    let mut bloom = SeenBloomFilter::new();

    // Insert 100 distinct PeerIds
    for i in 0u8..100 {
        bloom.insert(&PeerId([i; 32]));
    }

    // Verify all inserted entries are found
    for i in 0u8..100 {
        assert!(bloom.probably_contains(&PeerId([i; 32])));
    }

    // Check 1000 non-inserted PeerIds and count false positives
    let mut false_positives = 0u32;
    for i in 100u16..1100 {
        let mut id = [0u8; 32];
        id[0] = (i & 0xFF) as u8;
        id[1] = (i >> 8) as u8;
        if bloom.probably_contains(&PeerId(id)) {
            false_positives += 1;
        }
    }

    // FP rate should be < 5% (fewer than 50 out of 1000)
    assert!(
        false_positives < 50,
        "False positive rate too high: {false_positives}/1000 = {}%",
        false_positives as f64 / 10.0
    );
}

// ── Additional Dedup Filter Tests ───────────────────────────────

#[test]
fn test_dedup_filter_len() {
    let dedup = DedupFilter::new();
    for i in 0u8..10 {
        dedup.mark_seen([i; 32]);
    }
    assert_eq!(dedup.len(), 10);
}

#[test]
fn test_dedup_filter_double_rotate_clears() {
    let dedup = DedupFilter::new();
    let id = [0xAA; 32];

    dedup.mark_seen(id);
    assert!(dedup.is_seen(&id));

    dedup.rotate(); // id moves to previous
    assert!(dedup.is_seen(&id)); // still visible in previous

    dedup.rotate(); // previous is discarded
    assert!(!dedup.is_seen(&id)); // id is gone
}

// ── Additional Store-and-Forward Tests ──────────────────────────

#[tokio::test]
async fn test_store_retrieve_empty_peer() {
    let store = InMemoryStore::new();
    let peer = PeerId([0xFF; 32]);

    let messages = store.retrieve(&peer).await.unwrap();
    assert!(messages.is_empty());
}

#[tokio::test]
async fn test_store_multiple_peers() {
    let store = InMemoryStore::new();
    let peer_a = PeerId([1; 32]);
    let peer_b = PeerId([2; 32]);
    let peer_c = PeerId([3; 32]);

    // Store 2 messages for peer_a, 3 for peer_b, 1 for peer_c
    for i in 0..2u8 {
        let mut env = make_test_envelope(peer_a);
        env.header.message_id[0] = i;
        store.store(&env, Duration::from_secs(3600)).await.unwrap();
    }
    for i in 0..3u8 {
        let mut env = make_test_envelope(peer_b);
        env.header.message_id[0] = i;
        store.store(&env, Duration::from_secs(3600)).await.unwrap();
    }
    {
        let env = make_test_envelope(peer_c);
        store.store(&env, Duration::from_secs(3600)).await.unwrap();
    }

    assert_eq!(store.count_for_peer(&peer_a), 2);
    assert_eq!(store.count_for_peer(&peer_b), 3);
    assert_eq!(store.count_for_peer(&peer_c), 1);

    // Retrieve each independently and verify counts
    let msgs_a = store.retrieve(&peer_a).await.unwrap();
    assert_eq!(msgs_a.len(), 2);
    assert_eq!(store.count_for_peer(&peer_a), 0); // cleared after retrieve

    let msgs_b = store.retrieve(&peer_b).await.unwrap();
    assert_eq!(msgs_b.len(), 3);

    let msgs_c = store.retrieve(&peer_c).await.unwrap();
    assert_eq!(msgs_c.len(), 1);
}

#[tokio::test]
async fn test_store_eviction_order() {
    let store = InMemoryStore::new();
    let peer = PeerId([1; 32]);

    // Store exactly MAX_MESSAGES_PER_PEER (256) messages
    for i in 0..256u16 {
        let mut env = make_test_envelope(peer);
        env.header.message_id[0] = (i & 0xFF) as u8;
        env.header.message_id[1] = (i >> 8) as u8;
        store.store(&env, Duration::from_secs(3600)).await.unwrap();
    }
    assert_eq!(store.count_for_peer(&peer), 256);

    // Store one more — should trigger eviction, count stays at 256
    let mut env = make_test_envelope(peer);
    env.header.message_id[0] = 0xFF;
    env.header.message_id[1] = 0xFF;
    store.store(&env, Duration::from_secs(3600)).await.unwrap();
    assert_eq!(store.count_for_peer(&peer), 256);
}

// ── Additional Proof-of-Work Tests ──────────────────────────────

#[test]
fn test_pow_difficulty_16() {
    let msg_id = [0x42; 32];
    let sender = PeerId([0x13; 32]);
    let timestamp = 1700000000u64;
    let difficulty = 16;

    let nonce = ProofOfWork::compute(&msg_id, &sender, timestamp, difficulty);
    assert!(ProofOfWork::verify(&msg_id, &sender, timestamp, &nonce, difficulty));
}

#[test]
fn test_pow_different_inputs_different_nonces() {
    let msg_id_1 = [0x01; 32];
    let msg_id_2 = [0x02; 32];
    let sender = PeerId([0xAA; 32]);
    let timestamp = 1700000000u64;
    let difficulty = 8;

    let nonce_1 = ProofOfWork::compute(&msg_id_1, &sender, timestamp, difficulty);
    let nonce_2 = ProofOfWork::compute(&msg_id_2, &sender, timestamp, difficulty);

    // Both should verify correctly
    assert!(ProofOfWork::verify(&msg_id_1, &sender, timestamp, &nonce_1, difficulty));
    assert!(ProofOfWork::verify(&msg_id_2, &sender, timestamp, &nonce_2, difficulty));

    // Nonces should differ for different inputs
    assert_ne!(nonce_1, nonce_2);
}
