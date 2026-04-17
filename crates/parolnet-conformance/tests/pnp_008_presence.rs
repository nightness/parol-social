//! PNP-008 v0.3 conformance — presence + peer lookup (H12 Phase 2).
//!
//! These tests pin clauses PNP-008-MUST-063 through PNP-008-MUST-070 which
//! describe the relay-side `GET /peers/presence` and `GET /peers/lookup`
//! endpoints plus the federation-cache discipline that underpins client-side
//! cross-relay routing (Option α).

use parolnet_clause::clause;
use parolnet_protocol::address::PeerId;
use parolnet_relay::presence::{
    PresenceAuthority, PresenceConfig, PresenceEntry, presence_signable_bytes,
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use sha2::{Digest, Sha256};

fn sk(seed: u8) -> SigningKey {
    let mut s = [0u8; 32];
    s[0] = seed;
    SigningKey::from_bytes(&s)
}

fn relay_identity(signing: &SigningKey) -> PeerId {
    let pk = signing.verifying_key().to_bytes();
    PeerId(Sha256::digest(pk).into())
}

// -- §10.5 Presence endpoint --------------------------------------------------

#[clause("PNP-008-MUST-063", "PNP-008-MUST-064")]
#[test]
fn local_presence_returns_signed_entries_for_connected_peers() {
    // MUST-063: the endpoint covers currently-connected peers.
    // MUST-064: each entry carries an Ed25519 signature over the canonical hash.
    let home_sk = sk(1);
    let home_rid = relay_identity(&home_sk);
    let mut auth =
        PresenceAuthority::new(home_rid, home_sk.clone(), PresenceConfig::default());

    let peer_a = PeerId([0x11; 32]);
    let peer_b = PeerId([0x22; 32]);
    auth.upsert_local(peer_a, 1_700_000_100);
    auth.upsert_local(peer_b, 1_700_000_200);

    let entries = auth.local_presence();
    assert_eq!(entries.len(), 2);

    let vk = home_sk.verifying_key();
    for entry in &entries {
        let digest = presence_signable_bytes(&home_rid, &entry.peer_id, entry.last_seen);
        let signature = Signature::from_bytes(&entry.signature);
        vk.verify(&digest, &signature)
            .expect("presence signature must verify under home relay's key");
    }

    // Disconnected peers must not appear in subsequent snapshots.
    auth.remove_local(&peer_a);
    let rows = auth.local_presence();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].peer_id, peer_b);
}

#[clause("PNP-008-MUST-064")]
#[test]
fn presence_signable_bytes_matches_hand_computed_canonical_layout() {
    // Hand-compute SHA-256(relay_peer_id || peer_id || last_seen.to_be_bytes())
    // and confirm the helper produces the same bytes.
    let relay = PeerId([0xAB; 32]);
    let peer = PeerId([0xCD; 32]);
    let last_seen: u64 = 0x0102_0304_0506_0708;

    let mut expected_input = Vec::with_capacity(32 + 32 + 8);
    expected_input.extend_from_slice(&relay.0);
    expected_input.extend_from_slice(&peer.0);
    expected_input.extend_from_slice(&last_seen.to_be_bytes());
    let expected = Sha256::digest(&expected_input);

    let got = presence_signable_bytes(&relay, &peer, last_seen);
    assert_eq!(&got[..], &expected[..]);
}

// -- §10.6 Peer lookup --------------------------------------------------------

#[clause("PNP-008-MUST-065")]
#[test]
fn lookup_answers_from_local_before_federation() {
    // MUST-065: locally-connected peers outrank federation-cache entries.
    let home_sk = sk(2);
    let home_rid = relay_identity(&home_sk);
    let mut auth = PresenceAuthority::new(home_rid, home_sk, PresenceConfig::default());
    auth.set_own_public_url("http://home.example".into());

    let peer = PeerId([0x33; 32]);

    // Seed a federation entry claiming `peer` lives at "http://other.example".
    let other_sk = sk(3);
    let other_rid = relay_identity(&other_sk);
    let digest = presence_signable_bytes(&other_rid, &peer, 10);
    let sig = other_sk.sign(&digest);
    let fed_entry = PresenceEntry {
        peer_id: peer,
        last_seen: 10,
        signature: sig.to_bytes(),
    };
    auth.merge_federation_presence(
        "http://other.example",
        other_rid,
        &other_sk.verifying_key(),
        vec![fed_entry],
        1_000,
    );

    // Now the peer actually connects locally; the local answer must win.
    auth.upsert_local(peer, 2_000);
    let hit = auth.lookup(&peer, 1_000).expect("local should answer");
    assert_eq!(hit.home_relay_url, "http://home.example");
    assert_eq!(hit.last_seen, 2_000);
}

#[clause("PNP-008-MUST-068")]
#[test]
fn lookup_signature_verifies_under_home_relay_key() {
    // MUST-068: clients verify the lookup signature against the home relay's
    // Ed25519 key. Here we mimic the client path: get a LookupResult and
    // verify it with an independently constructed VerifyingKey.
    let home_sk = sk(4);
    let home_rid = relay_identity(&home_sk);
    let mut auth =
        PresenceAuthority::new(home_rid, home_sk.clone(), PresenceConfig::default());
    auth.set_own_public_url("http://verify.example".into());

    let peer = PeerId([0x44; 32]);
    auth.upsert_local(peer, 1_234_567);
    let result = auth.lookup(&peer, 0).expect("hit expected");

    let vk = home_sk.verifying_key();
    let digest = presence_signable_bytes(&home_rid, &peer, result.last_seen);
    let sig = Signature::from_bytes(&result.signature);
    vk.verify(&digest, &sig)
        .expect("LookupResult signature must verify under home relay key");
}

// -- §10.7 Federation cache TTL -----------------------------------------------

#[clause("PNP-008-MUST-067", "PNP-008-MUST-070")]
#[test]
fn federation_entry_past_ttl_is_treated_as_miss() {
    // MUST-067: client-side cache TTL ≤ 3600 s — equivalent invariant on the
    //   relay side enforces the same upper bound on federation-cache entries.
    // MUST-070: federation-cache entries expire at ≤ 3600 s.
    let home_sk = sk(5);
    let home_rid = relay_identity(&home_sk);
    let cfg = PresenceConfig {
        federation_ttl_secs: 3600,
        ..PresenceConfig::default()
    };
    assert!(cfg.federation_ttl_secs <= 3600);
    let mut auth = PresenceAuthority::new(home_rid, home_sk, cfg);

    let other_sk = sk(6);
    let other_rid = relay_identity(&other_sk);
    let peer = PeerId([0x55; 32]);
    let digest = presence_signable_bytes(&other_rid, &peer, 77);
    let sig = other_sk.sign(&digest);
    let entry = PresenceEntry {
        peer_id: peer,
        last_seen: 77,
        signature: sig.to_bytes(),
    };
    auth.merge_federation_presence(
        "http://cached.example",
        other_rid,
        &other_sk.verifying_key(),
        vec![entry],
        1_000,
    );

    // In-window: present.
    assert!(auth.lookup(&peer, 1_000 + 3_599).is_some());
    // At TTL boundary and beyond: miss.
    assert!(auth.lookup(&peer, 1_000 + 3_600).is_none());
    assert!(auth.lookup(&peer, 1_000 + 7_200).is_none());
}

#[clause("PNP-008-MUST-064")]
#[test]
fn federation_merge_rejects_bad_signature() {
    // MUST-064: entries whose signatures don't verify MUST be dropped. The
    //   merge helper is the enforcement point on the relay side.
    let home_sk = sk(7);
    let home_rid = relay_identity(&home_sk);
    let mut auth = PresenceAuthority::new(home_rid, home_sk, PresenceConfig::default());

    let claimed_home_sk = sk(8);
    let claimed_home_rid = relay_identity(&claimed_home_sk);
    let impostor_sk = sk(9);

    let peer = PeerId([0x66; 32]);
    // Sign under impostor_sk, claim it came from claimed_home_sk.
    let digest = presence_signable_bytes(&claimed_home_rid, &peer, 111);
    let sig = impostor_sk.sign(&digest);
    let bad_entry = PresenceEntry {
        peer_id: peer,
        last_seen: 111,
        signature: sig.to_bytes(),
    };

    let stats = auth.merge_federation_presence(
        "http://spoof.example",
        claimed_home_rid,
        &claimed_home_sk.verifying_key(),
        vec![bad_entry],
        500,
    );
    assert_eq!(stats.accepted, 0);
    assert_eq!(stats.rejected, 1);
    assert!(auth.lookup(&peer, 500).is_none());
}

// -- §10.6 / §10.7 Rate limit + poll interval ---------------------------------

#[clause("PNP-008-MUST-066")]
#[test]
fn default_lookup_rate_limit_matches_spec() {
    // MUST-066: relay MUST rate-limit /peers/lookup to ≤ 10 req/s per client.
    // The default PresenceConfig encodes the policy knob.
    let cfg = PresenceConfig::default();
    assert!(cfg.lookup_rate_limit_per_sec <= 10);
    assert_eq!(cfg.lookup_rate_limit_per_sec, 10);
}

#[clause("PNP-008-MUST-069")]
#[test]
fn default_federation_poll_interval_matches_spec() {
    // MUST-069: federation poll interval MUST be ≤ 300 s.
    let cfg = PresenceConfig::default();
    assert!(cfg.federation_poll_interval_secs <= 300);
}
