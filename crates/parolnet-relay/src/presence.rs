//! Relay peer presence + lookup (PNP-008 §Presence / §Peer Lookup, v0.3).
//!
//! Each relay exposes its currently-connected peers over `GET /peers/presence`
//! so that client libraries (and federation peers) can discover where a given
//! `PeerId` lives. Presence entries are Ed25519-signed by the home relay's
//! identity key over the canonical hash
//! `SHA-256(relay_peer_id || peer_id || last_seen_be_u64)`, allowing clients
//! to verify authenticity against the authority-endorsed relay directory.
//!
//! The authoritative state for a peer is held only by its *home relay* (the
//! one the peer is currently connected to). Federation peers pull each other's
//! `/peers/presence` endpoint every 5 minutes and merge results into a local
//! cache with a 1 hr TTL so that cross-relay lookups can be answered without
//! forcing a live federation round-trip on every request.
//!
//! This module defines the in-memory authority; the HTTP binding lives in
//! `parolnet-relay-server`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parolnet_protocol::address::PeerId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Serde helper for `[u8; 64]` arrays (Ed25519 signatures). Mirrors the
/// pattern used in `crate::authority`.
mod sig_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(bytes.as_slice()).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = serde_bytes::ByteBuf::deserialize(deserializer)?.into_vec();
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len()))
        })
    }
}

/// One peer's presence entry as published by the relay over
/// `GET /peers/presence`.
///
/// The signature binds `(relay_peer_id, peer_id, last_seen)` together so that
/// a client (or federation peer) who trusts `relay_peer_id` via the authority
/// directory can confirm this relay actually claimed `peer_id` is connected
/// at `last_seen` — a dishonest relay cannot reuse another relay's signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceEntry {
    pub peer_id: PeerId,
    pub last_seen: u64,
    #[serde(with = "sig_bytes")]
    pub signature: [u8; 64],
}

/// Result of a successful `/peers/lookup` query.
///
/// `home_relay_url` is the public URL the client should connect to in order
/// to reach `peer_id`; for locally-connected peers this is the answering
/// relay's own public URL (from configuration), for federation-cache hits it
/// is whichever peer relay originally published the entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LookupResult {
    pub home_relay_url: String,
    pub last_seen: u64,
    #[serde(with = "sig_bytes")]
    pub signature: [u8; 64],
}

/// Compute the canonical hash a presence entry signs over.
///
/// PNP-008-MUST clauses pin this exact layout:
/// `SHA-256(relay_peer_id || peer_id || last_seen.to_be_bytes())`.
///
/// Mirrors the pattern of `AuthorityEndorsement::signable_bytes` — the output
/// is a 32-byte digest that a client verifies against the relay's Ed25519
/// verifying key (obtained from the authority-verified directory).
pub fn presence_signable_bytes(
    relay_peer_id: &PeerId,
    peer_id: &PeerId,
    last_seen: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(relay_peer_id.0);
    hasher.update(peer_id.0);
    hasher.update(last_seen.to_be_bytes());
    hasher.finalize().into()
}

/// Tunable parameters for the presence authority. Defaults track PNP-008 §Presence.
#[derive(Clone, Debug)]
pub struct PresenceConfig {
    /// Federation-cache TTL. Entries past this age are treated as misses.
    /// PNP-008 caps this at 3600 s.
    pub federation_ttl_secs: u64,
    /// How often each relay polls peer relays' `/peers/presence`.
    /// PNP-008 caps this at 300 s.
    pub federation_poll_interval_secs: u64,
    /// Per-client rate limit for `/peers/lookup`. PNP-008 pins this at 10 req/s.
    pub lookup_rate_limit_per_sec: u32,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            federation_ttl_secs: 3600,
            federation_poll_interval_secs: 300,
            lookup_rate_limit_per_sec: 10,
        }
    }
}

/// Errors surfaced when merging presence entries from a federation peer.
#[derive(Debug, thiserror::Error)]
pub enum PresenceError {
    #[error("invalid Ed25519 pubkey for home relay: {0}")]
    InvalidHomePubkey(String),
    #[error("signature verification failed for peer {0}")]
    SignatureInvalid(String),
}

/// Holder of secret relay signing material — zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct ZeroizingSigningKey {
    bytes: [u8; 32],
}

impl ZeroizingSigningKey {
    fn new(sk: &SigningKey) -> Self {
        Self {
            bytes: sk.to_bytes(),
        }
    }

    fn to_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.bytes)
    }
}

/// In-memory authority tracking "who is connected to this relay" + "who is
/// connected to the federation peers we pull from".
///
/// The authority signs locally-produced presence entries with the relay's
/// Ed25519 identity key and verifies federation entries against each peer
/// relay's advertised pubkey before storing them.
pub struct PresenceAuthority {
    relay_peer_id: PeerId,
    signing_key: ZeroizingSigningKey,
    own_public_url: Option<String>,
    config: PresenceConfig,
    /// Peers currently connected to THIS relay. Authoritative.
    local: HashMap<PeerId, PresenceEntry>,
    /// Federation-cache entries pulled from peer relays. Lazy-evicted.
    federation: HashMap<PeerId, FederationRecord>,
}

/// A single cached federation entry with provenance metadata.
#[derive(Clone, Debug)]
struct FederationRecord {
    entry: PresenceEntry,
    home_relay_url: String,
    cached_at: u64,
}

impl PresenceAuthority {
    /// Build a new authority with the relay's own identity + signing key.
    pub fn new(relay_peer_id: PeerId, signing_key: SigningKey, config: PresenceConfig) -> Self {
        Self {
            relay_peer_id,
            signing_key: ZeroizingSigningKey::new(&signing_key),
            own_public_url: None,
            config,
            local: HashMap::new(),
            federation: HashMap::new(),
        }
    }

    /// Set the public URL that will be returned to lookup clients as the
    /// `home_relay_url` for locally-connected peers. Typically derived from
    /// `PUBLIC_URL` / `RELAY_PORT` at startup.
    pub fn set_own_public_url(&mut self, url: String) {
        self.own_public_url = Some(url);
    }

    /// Configured defaults.
    pub fn config(&self) -> &PresenceConfig {
        &self.config
    }

    /// Relay identity key (useful for building `home_relay_url` answers).
    pub fn relay_peer_id(&self) -> &PeerId {
        &self.relay_peer_id
    }

    /// Sign a presence-row for `(peer_id, last_seen)` under this relay's key.
    fn sign_entry(&self, peer_id: PeerId, last_seen: u64) -> PresenceEntry {
        let digest = presence_signable_bytes(&self.relay_peer_id, &peer_id, last_seen);
        let signing = self.signing_key.to_signing_key();
        let sig = signing.sign(&digest);
        PresenceEntry {
            peer_id,
            last_seen,
            signature: sig.to_bytes(),
        }
    }

    /// Record or refresh a locally-connected peer. Called on connect and on
    /// every message/heartbeat.
    pub fn upsert_local(&mut self, peer_id: PeerId, last_seen: u64) {
        let entry = self.sign_entry(peer_id, last_seen);
        self.local.insert(peer_id, entry);
    }

    /// Remove a peer from the local set on disconnect.
    pub fn remove_local(&mut self, peer_id: &PeerId) {
        self.local.remove(peer_id);
    }

    /// Snapshot of all locally-connected peers for `GET /peers/presence`.
    pub fn local_presence(&self) -> Vec<PresenceEntry> {
        self.local.values().cloned().collect()
    }

    /// Answer `GET /peers/lookup?id=`. Local entries take priority over
    /// federation-cache entries; federation entries past `federation_ttl_secs`
    /// are treated as misses.
    pub fn lookup(&self, peer_id: &PeerId, now_secs: u64) -> Option<LookupResult> {
        if let Some(entry) = self.local.get(peer_id) {
            let home = self
                .own_public_url
                .clone()
                .unwrap_or_else(|| String::from(""));
            return Some(LookupResult {
                home_relay_url: home,
                last_seen: entry.last_seen,
                signature: entry.signature,
            });
        }

        if let Some(rec) = self.federation.get(peer_id)
            && now_secs.saturating_sub(rec.cached_at) < self.config.federation_ttl_secs
        {
            return Some(LookupResult {
                home_relay_url: rec.home_relay_url.clone(),
                last_seen: rec.entry.last_seen,
                signature: rec.entry.signature,
            });
        }
        None
    }

    /// Merge a batch of presence entries pulled from `from_url` (a federation
    /// peer). Each entry's signature MUST verify under `home_pubkey`, the
    /// Ed25519 verifying key the caller resolved for that relay (typically
    /// from the authority-verified `/directory` cache). Entries with invalid
    /// signatures are rejected and counted in the returned tally; valid ones
    /// are stored in the federation cache keyed by `peer_id`.
    ///
    /// `home_relay_peer_id` is the `PeerId` of the relay at `from_url`; it is
    /// required because the signature canonicalization includes the home
    /// relay's `PeerId`, not its URL.
    pub fn merge_federation_presence(
        &mut self,
        from_url: &str,
        home_relay_peer_id: PeerId,
        home_pubkey: &VerifyingKey,
        entries: Vec<PresenceEntry>,
        now_secs: u64,
    ) -> MergeStats {
        let mut stats = MergeStats::default();
        for entry in entries {
            let digest =
                presence_signable_bytes(&home_relay_peer_id, &entry.peer_id, entry.last_seen);
            let sig = Signature::from_bytes(&entry.signature);
            if home_pubkey.verify(&digest, &sig).is_err() {
                stats.rejected += 1;
                continue;
            }
            self.federation.insert(
                entry.peer_id,
                FederationRecord {
                    entry,
                    home_relay_url: from_url.to_string(),
                    cached_at: now_secs,
                },
            );
            stats.accepted += 1;
        }
        stats
    }

    /// Drop federation entries past TTL. Safe to call opportunistically; the
    /// lookup path already treats expired entries as misses, so this is only
    /// a memory-pressure relief.
    pub fn tick_evict(&mut self, now_secs: u64) {
        let ttl = self.config.federation_ttl_secs;
        self.federation
            .retain(|_, rec| now_secs.saturating_sub(rec.cached_at) < ttl);
    }

    /// Count of locally-connected peers (for observability).
    pub fn local_count(&self) -> usize {
        self.local.len()
    }

    /// Count of cached federation peers (for observability; includes expired
    /// entries until `tick_evict` runs).
    pub fn federation_count(&self) -> usize {
        self.federation.len()
    }
}

/// Bookkeeping returned from `merge_federation_presence`.
#[derive(Clone, Copy, Debug, Default)]
pub struct MergeStats {
    pub accepted: usize,
    pub rejected: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signing_key(seed: u8) -> SigningKey {
        let mut s = [0u8; 32];
        s[0] = seed;
        SigningKey::from_bytes(&s)
    }

    fn relay_identity(sk: &SigningKey) -> PeerId {
        let pk = sk.verifying_key().to_bytes();
        PeerId(Sha256::digest(pk).into())
    }

    #[test]
    fn upsert_then_local_presence_round_trip() {
        let sk = test_signing_key(1);
        let rid = relay_identity(&sk);
        let mut auth = PresenceAuthority::new(rid, sk.clone(), PresenceConfig::default());

        let peer = PeerId([0x11; 32]);
        auth.upsert_local(peer, 1_700_000_000);

        let rows = auth.local_presence();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].peer_id, peer);
        assert_eq!(rows[0].last_seen, 1_700_000_000);

        // Signature must verify under the relay's pubkey.
        let digest = presence_signable_bytes(&rid, &peer, 1_700_000_000);
        let vk = sk.verifying_key();
        let sig = Signature::from_bytes(&rows[0].signature);
        assert!(vk.verify(&digest, &sig).is_ok());
    }

    #[test]
    fn lookup_prefers_local_over_federation() {
        let sk = test_signing_key(2);
        let rid = relay_identity(&sk);
        let mut auth = PresenceAuthority::new(rid, sk, PresenceConfig::default());
        auth.set_own_public_url("http://home.example".into());

        // Craft a federation entry for the same peer under a different relay.
        let peer = PeerId([0x22; 32]);
        let other_sk = test_signing_key(3);
        let other_rid = relay_identity(&other_sk);
        let fake_entry = {
            let digest = presence_signable_bytes(&other_rid, &peer, 42);
            let sig = other_sk.sign(&digest);
            PresenceEntry {
                peer_id: peer,
                last_seen: 42,
                signature: sig.to_bytes(),
            }
        };
        let stats = auth.merge_federation_presence(
            "http://other.example",
            other_rid,
            &other_sk.verifying_key(),
            vec![fake_entry],
            1_000,
        );
        assert_eq!(stats.accepted, 1);
        assert_eq!(stats.rejected, 0);

        // Same peer is also locally connected; lookup must prefer local.
        auth.upsert_local(peer, 999);
        let res = auth.lookup(&peer, 1_000).expect("hit expected");
        assert_eq!(res.home_relay_url, "http://home.example");
        assert_eq!(res.last_seen, 999);
    }

    #[test]
    fn federation_entry_past_ttl_is_a_miss() {
        let sk = test_signing_key(4);
        let rid = relay_identity(&sk);
        let cfg = PresenceConfig {
            federation_ttl_secs: 100,
            ..PresenceConfig::default()
        };
        let mut auth = PresenceAuthority::new(rid, sk, cfg);

        let peer = PeerId([0x33; 32]);
        let other_sk = test_signing_key(5);
        let other_rid = relay_identity(&other_sk);
        let entry = {
            let digest = presence_signable_bytes(&other_rid, &peer, 10);
            let sig = other_sk.sign(&digest);
            PresenceEntry {
                peer_id: peer,
                last_seen: 10,
                signature: sig.to_bytes(),
            }
        };
        let stats = auth.merge_federation_presence(
            "http://stale.example",
            other_rid,
            &other_sk.verifying_key(),
            vec![entry],
            1_000,
        );
        assert_eq!(stats.accepted, 1);

        // At cached_at + 99 the entry is still live.
        assert!(auth.lookup(&peer, 1_099).is_some());
        // At cached_at + TTL it becomes a miss.
        assert!(auth.lookup(&peer, 1_100).is_none());
    }

    #[test]
    fn federation_merge_rejects_invalid_signature() {
        let sk = test_signing_key(6);
        let rid = relay_identity(&sk);
        let mut auth = PresenceAuthority::new(rid, sk, PresenceConfig::default());

        let other_sk = test_signing_key(7);
        let other_rid = relay_identity(&other_sk);
        let peer = PeerId([0x44; 32]);
        // Sign under a DIFFERENT key than we'll tell merge to verify against.
        let impostor_sk = test_signing_key(8);
        let digest = presence_signable_bytes(&other_rid, &peer, 50);
        let sig = impostor_sk.sign(&digest);
        let bad = PresenceEntry {
            peer_id: peer,
            last_seen: 50,
            signature: sig.to_bytes(),
        };
        let stats = auth.merge_federation_presence(
            "http://spoof.example",
            other_rid,
            &other_sk.verifying_key(),
            vec![bad],
            1_000,
        );
        assert_eq!(stats.accepted, 0);
        assert_eq!(stats.rejected, 1);
        assert!(auth.lookup(&peer, 1_000).is_none());
    }

    #[test]
    fn remove_local_clears_entry() {
        let sk = test_signing_key(9);
        let rid = relay_identity(&sk);
        let mut auth = PresenceAuthority::new(rid, sk, PresenceConfig::default());
        let peer = PeerId([0x55; 32]);
        auth.upsert_local(peer, 10);
        assert_eq!(auth.local_count(), 1);
        auth.remove_local(&peer);
        assert_eq!(auth.local_count(), 0);
        assert!(auth.lookup(&peer, 10).is_none());
    }

    #[test]
    fn tick_evict_drops_expired() {
        let sk = test_signing_key(10);
        let rid = relay_identity(&sk);
        let cfg = PresenceConfig {
            federation_ttl_secs: 100,
            ..PresenceConfig::default()
        };
        let mut auth = PresenceAuthority::new(rid, sk, cfg);

        let other_sk = test_signing_key(11);
        let other_rid = relay_identity(&other_sk);
        let peer = PeerId([0x66; 32]);
        let digest = presence_signable_bytes(&other_rid, &peer, 1);
        let sig = other_sk.sign(&digest);
        let entry = PresenceEntry {
            peer_id: peer,
            last_seen: 1,
            signature: sig.to_bytes(),
        };
        auth.merge_federation_presence(
            "http://x.example",
            other_rid,
            &other_sk.verifying_key(),
            vec![entry],
            500,
        );
        assert_eq!(auth.federation_count(), 1);
        auth.tick_evict(550); // elapsed=50, within TTL=100
        assert_eq!(auth.federation_count(), 1);
        auth.tick_evict(600); // elapsed=100, >= TTL → evicted
        assert_eq!(auth.federation_count(), 0);
    }

    #[test]
    fn presence_signable_bytes_is_stable() {
        let rid = PeerId([0xAA; 32]);
        let peer = PeerId([0xBB; 32]);
        let a = presence_signable_bytes(&rid, &peer, 1234);
        let b = presence_signable_bytes(&rid, &peer, 1234);
        assert_eq!(a, b);
        let c = presence_signable_bytes(&rid, &peer, 1235);
        assert_ne!(a, c);
    }

    #[test]
    fn defaults_match_spec_caps() {
        let cfg = PresenceConfig::default();
        assert!(cfg.federation_poll_interval_secs <= 300);
        assert!(cfg.federation_ttl_secs <= 3600);
        assert_eq!(cfg.lookup_rate_limit_per_sec, 10);
    }
}
