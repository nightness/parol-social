# PNP-008: Relay Federation & Network Resilience

**Version:** 0.4
**Status:** CANDIDATE
**Last-Updated:** 2026-04-17

## Changelog

- **v0.4 (2026-04-17):** Tightened §8 Bootstrap Channels with six supplemental MUST clauses (`PNP-008-MUST-071` through `PNP-008-MUST-076`) covering BootstrapBundle version gating, 7-day freshness bound, DHT BEP-44 salt constant, per-channel 10-second attempt timeout, seed-list load-without-network invariant, and HTTPS content-type rejection. Addresses stale-bundle replay, cross-network DHT collisions, and content-sniffing attacks. No wire-format changes — existing clients that already validate signatures remain interoperable once they apply the new bounds.
- **v0.3 (2026-04-17):** Added §Presence (`GET /peers/presence`), §Peer Lookup (`GET /peers/lookup?id=`), and §Federation Presence Fetch describing the 5-min poll and 1-hr TTL federation cache that underpins H12 Phase 2 cross-relay routing (client-side Option α). Added 8 new MUST clauses `PNP-008-MUST-063` through `PNP-008-MUST-070`. No breaking changes to the v0.2 federation state machine.
- **v0.2 (2026-04-17):** Full rewrite from phased implementation plan to RFC-2119 normative specification. Split implementation roadmap to `/FEDERATION-IMPLEMENTATION.md`. Defined wire formats for `FederationSync` (0x06), `FederationHeartbeat` (0x07), `BridgeAnnouncement` (0x08) gossip payload types. Defined federation peer state machine, IBLT sync parameters, descriptor endorsement chain, reputation score rules, bootstrap channel fallback, bridge descriptor format. Added numbered `PNP-008-(MUST|SHOULD|MAY)-NNN` clause IDs.
- **v0.1:** Initial phased implementation plan (now at `/FEDERATION-IMPLEMENTATION.md`).

---

## 1. Purpose & Scope

This specification defines how ParolNet relays discover each other across administrative boundaries, maintain consistent views of the relay directory under partitions, score peer behavior, operate bridge relays outside the public directory, and bootstrap into the network through multiple independent channels. The goal is **survivability under regional censorship and single-host takedowns**.

Non-goals:
- Onion circuit construction (see PNP-004).
- User-to-user gossip message dissemination (see PNP-005).
- LAN discovery or QR/passphrase pairing (see PNP-003).

Throughout this document the key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY**, **REQUIRED**, and **OPTIONAL** are to be interpreted as described in RFC 2119.

---

## 2. Terminology

- **Authority** — A long-lived Ed25519 keypair whose public component ships compiled into ParolNet releases. Authorities endorse relay descriptors. Analogous to Tor directory authorities.
- **Relay Descriptor** — Signed record containing a relay's `PeerId`, transport endpoints, public keys, capabilities, and timestamp. Defined in PNP-005 §4.
- **Endorsed Descriptor** — A relay descriptor carrying one or more authority signatures covering the descriptor bytes.
- **Federation Peer** — A relay that has established a persistent federation link to another relay per §5.
- **Federation Link** — A TLS-camouflaged (PNP-006 §2) long-lived connection between two federation peers used exclusively for directory synchronization and heartbeat.
- **Bridge Relay** — A relay whose descriptor is deliberately excluded from public gossip; discoverable only through out-of-band channels (§9).
- **Reputation Score** — Floating-point value in `[0.0, 1.0]` maintained locally for each known relay (§7).
- **Bootstrap Channel** — A mechanism by which a node obtains an initial set of relay descriptors without any prior network state (§8).

---

## 3. Cryptographic Primitives

All primitives are those specified in PNP-001 §2. In particular:

**PNP-008-MUST-001**: Relay descriptor signatures MUST be Ed25519 over the deterministic CBOR encoding of the descriptor body (excluding the signature field).

**PNP-008-MUST-002**: Authority endorsement signatures MUST be Ed25519 computed over the deterministic CBOR encoding of the descriptor *including* the relay's own signature but *excluding* the `endorsements` array.

**PNP-008-MUST-003**: Federation peer identity MUST be authenticated using the peer's relay descriptor public key via the PNP-002 handshake, layered inside the PNP-006 TLS camouflage.

**PNP-008-SHOULD-001**: Authorities SHOULD store their private keys in an HSM or equivalent offline-signing configuration and SHOULD rotate endorsement keys at most annually.

---

## 4. Gossip Payload Types

Extending the message-type allocation registry in PNP-001 §3.4:

| Code | Name | Direction | Payload Summary |
|------|------|-----------|-----------------|
| 0x06 | `FederationSync` | relay ↔ relay | IBLT-encoded set of known descriptor IDs + delta request |
| 0x07 | `FederationHeartbeat` | relay ↔ relay | Liveness probe with monotonic counter |
| 0x08 | `BridgeAnnouncement` | bridge → recipient | Out-of-band bridge descriptor delivery (never gossiped) |

**PNP-008-MUST-004**: Type codes 0x06–0x08 MUST NOT be emitted over the public gossip mesh defined in PNP-005; they are confined to federation links established per §5 (0x06, 0x07) or out-of-band channels per §9 (0x08).

**PNP-008-MUST-005**: A relay receiving 0x06 or 0x07 on a non-federation transport MUST drop the message and MUST NOT penalize the sender (permitting legitimate NAT rebinding).

### 4.1 FederationSync (0x06)

```
struct FederationSync {
    sync_id: [u8; 16],                       // request correlation ID
    since_timestamp: u64,                    // only descriptors with ts >= this
    iblt: Iblt,                              // set of descriptor digests held locally
    scope: SyncScope,                        // DescriptorsOnly | DescriptorsAndGossipIds
    requested_digests: Option<Vec<Digest>>,  // explicit fetch list after IBLT decode
    response_descriptors: Option<Vec<RelayDescriptor>>,
    signature: [u8; 64],                     // Ed25519 by sender's relay key
    timestamp: u64,
}
```

**PNP-008-MUST-006**: `sync_id` MUST be a cryptographically random 128-bit value; receivers MUST reject duplicate `sync_id` seen within the last 5 minutes.

**PNP-008-MUST-007**: `signature` MUST cover all preceding fields in deterministic CBOR encoding. A receiver MUST verify the signature against the federation peer's relay descriptor public key before processing.

**PNP-008-MUST-008**: `timestamp` MUST be within ±300 seconds of the receiver's clock; messages outside this window MUST be rejected as replayed.

**PNP-008-MUST-009**: When `requested_digests` is present, the receiver MUST either populate `response_descriptors` with matching descriptors (for known entries) or omit unknown entries; it MUST NOT fabricate descriptors.

### 4.2 FederationHeartbeat (0x07)

```
struct FederationHeartbeat {
    counter: u64,                  // monotonically increasing per sender
    load_hint: LoadHint,           // { circuits: u32, bandwidth_bps: u64 }
    flags: HeartbeatFlags,         // BRIDGE_CAPABLE, ACCEPTING_CIRCUITS, READ_ONLY
    signature: [u8; 64],
    timestamp: u64,
}
```

**PNP-008-MUST-010**: `counter` MUST strictly increase within a single federation link; a receiver MUST drop heartbeats with non-increasing `counter` and MUST treat repeated violations as a peer protocol fault per §7.

**PNP-008-MUST-011**: A federation peer MUST emit a heartbeat at least every 60 seconds. A receiver MUST consider the peer unreachable after 180 seconds of silence.

**PNP-008-SHOULD-002**: `load_hint` fields SHOULD reflect current operating state averaged over the last 60 seconds. Senders SHOULD NOT report values designed to attract or repel traffic.

### 4.3 BridgeAnnouncement (0x08)

```
struct BridgeAnnouncement {
    bridge_descriptor: BridgeDescriptor,   // see §9
    issued_at: u64,
    expires_at: u64,                       // MUST NOT exceed issued_at + 7 * 86400
    distribution_token: [u8; 32],          // uniquely identifies this disclosure
    signature: [u8; 64],                   // Ed25519 by bridge operator
}
```

**PNP-008-MUST-012**: `BridgeAnnouncement` messages MUST NOT be forwarded beyond the immediate recipient and MUST NOT be inserted into any gossip mesh or public directory.

**PNP-008-MUST-013**: Recipients MUST reject `BridgeAnnouncement` where `now > expires_at` or where `expires_at - issued_at > 7 * 86400`.

**PNP-008-MUST-014**: Implementations MUST NOT log, export, or sync `distribution_token` values across nodes; tokens are private to the recipient.

---

## 5. Federation Peer State Machine

Each relay maintains an independent state per potential federation peer.

```
      +---------+
      |  INIT   |
      +----+----+
           | connect()
           v
      +---------+    bad signature / timeout
      |HANDSHAKE|---------------------------+
      +----+----+                           |
           | valid handshake + desc         |
           v                                |
      +---------+                           |
      |  SYNC   |  initial FederationSync   |
      +----+----+                           |
           | IBLT decoded                   |
           v                                |
      +---------+                           |
      |  ACTIVE |<-- heartbeats, periodic   |
      +----+----+    syncs every 300 s      |
           | 180 s silence OR fault         |
           v                                |
      +---------+                           |
      |  IDLE   |------- reconnect delay ---+
      +----+----+       (§5.3 backoff)
           |
           | banned per §7
           v
      +---------+
      | BANNED  |
      +---------+
```

### 5.1 Peer Selection

**PNP-008-MUST-015**: A relay MUST maintain no more than 8 concurrent ACTIVE federation peers.

**PNP-008-MUST-016**: A relay SHOULD select federation peers such that no two peers share the same IPv4 /16 or IPv6 /32 subnet, except where fewer than 3 candidates from distinct subnets are known.

**PNP-008-MUST-017**: A relay MUST include at least one federation peer endorsed by each authority it trusts, when such an endorsed peer is reachable, to prevent eclipse by a single authority's compromise.

### 5.2 Handshake

**PNP-008-MUST-018**: Federation links MUST be initiated inside the TLS camouflage profile defined in PNP-006 §2 and MUST complete the PNP-002 handshake before any `FederationSync` (0x06) or `FederationHeartbeat` (0x07) message is exchanged.

**PNP-008-MUST-019**: A relay MUST close the underlying transport if the peer's relay descriptor cannot be verified against a locally known descriptor or fetched live and verified against an authority endorsement per §6.3.

### 5.3 Reconnect Backoff

**PNP-008-MUST-020**: After a failed connection attempt, a relay MUST NOT retry the same peer sooner than the computed backoff: `delay = min(3600, 30 * 2^failures) ± jitter_25%` seconds.

**PNP-008-MUST-021**: After a successful ACTIVE session ends, `failures` MUST be reset to 0 only after at least one subsequent ACTIVE session of ≥ 300 seconds duration.

### 5.4 Rate Limiting

**PNP-008-MUST-022**: Per-federation-peer, a relay MUST enforce a token bucket rate limit of at most 100 descriptor deliveries per minute and at most 10 `FederationSync` initiations per hour. Exceeding either limit MUST trigger a reputation decrement per §7.

---

## 6. Directory Synchronization

### 6.1 Full Sync

**PNP-008-MUST-023**: Upon entering SYNC state, a relay MUST issue a `FederationSync` with an IBLT summarizing all known descriptor digests whose `timestamp > now - 24*3600`.

**PNP-008-SHOULD-003**: Relays SHOULD perform an incremental re-sync every 300 seconds (±30 s jitter) while ACTIVE.

### 6.2 IBLT Sizing

IBLT cell counts are tiered to match expected set-difference sizes:

| Tier | Cells | Hashes | Intended |Δ| |
|------|-------|--------|-----------|
| S    | 80    | 3      | ≤ 20 |
| M    | 400   | 3      | ≤ 100 |
| L    | 2000  | 4      | ≤ 500 |

**PNP-008-MUST-024**: Senders MUST select the smallest tier whose expected decode probability exceeds 0.99 given the current directory size; if decode fails, receivers MUST respond with an upgraded-tier `FederationSync` containing `requested_digests` empty and the larger IBLT.

**PNP-008-MUST-025**: Implementations MUST cap IBLT cells at 2000; requests exceeding this bound MUST be rejected.

**PNP-008-MUST-026**: IBLT hash seeds MUST be derived from `HKDF(salt="PNP-008-IBLT", info=sync_id, out=len(cells))` to prevent precomputed collision attacks across sessions.

### 6.3 Descriptor Validation

**PNP-008-MUST-027**: Every received `RelayDescriptor` MUST be verified by:
1. Checking descriptor signature against the embedded relay public key;
2. Checking at least one authority endorsement signature against a compiled-in authority key OR against an authority certified by a trusted authority path of depth ≤ 1;
3. Checking `timestamp > now - 7*86400` (descriptors older than 7 days MUST be rejected).

**PNP-008-MUST-028**: Descriptors failing any check MUST be dropped without being stored, forwarded, or used for routing.

**PNP-008-MUST-029**: The count of failed validations per federation peer MUST be recorded and MUST contribute to the `malformed_contrib` reputation term in §7.

### 6.4 Conflict Resolution

**PNP-008-MUST-030**: When a received descriptor has the same `peer_id` as a locally stored descriptor:
- If the received `timestamp` is strictly greater, the local descriptor MUST be replaced;
- If timestamps are equal, the descriptor with the lexicographically smaller deterministic-CBOR encoding MUST be retained (deterministic tie-break, not first-arrival);
- If the received `timestamp` is strictly lesser, it MUST be discarded without generating any peer score penalty (legitimate race).

### 6.5 Descriptor Expiry

**PNP-008-MUST-031**: Relays MUST remove descriptors from the active directory once `timestamp + 7*86400 < now`.

**PNP-008-SHOULD-004**: Relays SHOULD retain expired descriptor digests for an additional 24 hours to suppress re-acceptance of replays.

---

## 7. Reputation & Peer Scoring

Each relay maintains per-peer reputation state:

```
struct Reputation {
    score: f64,            // [0.0, 1.0], initial 0.5
    successes: u64,
    failures: u64,
    malformed_contrib: u64,
    flags: RelayFlags,
    last_update: u64,
}
```

### 7.1 Score Update

**PNP-008-MUST-032**: On each observed event, score MUST be updated by EWMA:
`score ← 0.9 * score + 0.1 * observation`
where `observation ∈ [0.0, 1.0]` is the normalized success value of that event.

**PNP-008-MUST-033**: Events and their observation values:

| Event | Observation |
|-------|-------------|
| Successful federation sync round | 1.0 |
| Heartbeat on time | 1.0 |
| Heartbeat missed (180 s silence) | 0.0 |
| Descriptor with valid signature | 1.0 |
| Descriptor with invalid signature | 0.0 |
| Rate limit exceeded | 0.0 |
| Replay within window | 0.0 |

### 7.2 Flags

**PNP-008-MUST-034**: A relay MUST set `SUSPECT` when `score < 0.2` for more than 15 consecutive minutes; it MUST cease new circuit selection for SUSPECT peers but MAY keep the federation link open for observation.

**PNP-008-MUST-035**: A relay MUST set `BANNED` when `score < 0.05` OR when a peer emits more than 3 invalid signatures within any 60-second window; BANNED peers MUST be disconnected and MUST NOT be reconnected for ≥ 24 hours.

**PNP-008-SHOULD-005**: A relay SHOULD promote a peer to `STABLE` after ≥ 7 consecutive days ACTIVE with `score ≥ 0.8` and SHOULD prefer STABLE peers for circuit construction when available.

**PNP-008-MAY-001**: A relay MAY promote a peer to `GUARD_ELIGIBLE` if STABLE for ≥ 30 days; guard selection policy is defined in PNP-004 §4.

### 7.3 Persistence

**PNP-008-MUST-036**: Reputation state MUST be persisted to durable storage at intervals not exceeding 10 minutes and on clean shutdown.

**PNP-008-MUST-037**: Persisted reputation MUST NOT be exported, synced, or otherwise leave the node; it is a private local signal.

---

## 8. Bootstrap Channels

A node with no prior state MUST obtain at least one valid relay descriptor before it can participate. Channels are attempted in priority order with a per-channel attempt timeout bounded by `PNP-008-MUST-074`.

### 8.1 Channel Registry

| Priority | Channel | Normative Section |
|----------|---------|-------------------|
| 1 | Compiled-in seed relays | §8.2 |
| 2 | DNS TXT | §8.3 |
| 3 | HTTPS directory | §8.4 |
| 4 | Mainline DHT (BEP-44) | §8.5 |
| 5 | Manual / LAN (PNP-003) | PNP-003 §3 |

**PNP-008-MUST-038**: Every channel MUST return data that is independently verifiable via the authority endorsement chain per §6.3. A descriptor fetched through any channel MUST NOT be used if it fails validation, regardless of the channel's perceived trustworthiness.

**PNP-008-MUST-039**: The node MUST NOT trust a bootstrap channel as a routing authority; channels deliver *candidate descriptors only*.

**PNP-008-SHOULD-006**: The node SHOULD stop after obtaining ≥ 3 distinct valid descriptors from at least 2 distinct channels.

### 8.2 Seed Relays

**PNP-008-MUST-040**: Seed relay addresses MUST be compiled into the release binary and MUST include both an IP address and an authority-endorsed public key fingerprint.

**PNP-008-SHOULD-007**: Each release SHOULD ship between 5 and 10 seed addresses operated by independent entities.

### 8.3 DNS TXT

**PNP-008-MUST-041**: DNS TXT bootstrap records MUST be queried at `_parolnet-relay._tcp.<domain>` where `<domain>` is supplied by configuration.

**PNP-008-MUST-042**: The TXT record MUST contain a base64-encoded, deterministic-CBOR-encoded `BootstrapBundle` structure:
```
struct BootstrapBundle {
    version: u8,                       // = 1
    descriptors: Vec<RelayDescriptor>, // each endorsed per §6.3
    issued_at: u64,
    signature: [u8; 64],               // Ed25519 by an authority
}
```

**PNP-008-MUST-043**: The bundle signature MUST be verified against a compiled-in authority key before any descriptor within the bundle is parsed.

**PNP-008-MUST-044**: TXT records may be split across multiple segments by DNS length limits; implementations MUST concatenate all segments of a single TXT record set in lexicographic order before base64 decoding.

### 8.4 HTTPS Directory

**PNP-008-MUST-045**: HTTPS directory URLs MUST be served over TLS and MUST return `application/cbor` bodies containing a `BootstrapBundle` (same format as §8.3).

**PNP-008-MUST-046**: Clients MUST verify the bundle signature independently of the TLS channel; a compromised CA MUST NOT be sufficient to inject descriptors.

**PNP-008-MAY-002**: Clients MAY use domain fronting per PNP-006 §3 when fetching HTTPS directories.

### 8.5 Mainline DHT (BEP-44)

**PNP-008-MUST-047**: DHT bootstrap MUST use BEP-44 mutable items keyed by a compiled-in Ed25519 public key assigned by an authority.

**PNP-008-MUST-048**: The DHT value MUST be a deterministic-CBOR `BootstrapBundle`; the BEP-44 sequence number MUST correspond to `issued_at` truncated to seconds.

**PNP-008-MUST-049**: Retrieved values MUST be signature-verified per §6.3 before any descriptor is used.

### 8.6 Failure Policy

**PNP-008-MUST-050**: If all channels fail for 600 consecutive seconds, the node MUST emit a user-visible "no bootstrap" error and MUST NOT fall back to any unauthenticated discovery mechanism.

**PNP-008-SHOULD-008**: Implementations SHOULD randomize the order within each priority tier (e.g., DNS domains, HTTPS URLs) to avoid deterministic censorship targeting.

### 8.7 Bundle Integrity & Channel Hardening

The clauses in this subsection are supplementary to §§8.2–8.6. They are non-optional security bounds that the individual channel descriptions elided for readability.

**PNP-008-MUST-071**: Receivers MUST reject any `BootstrapBundle` whose `version` byte is not `0x01`. The version byte MUST be validated *before* the signature is verified so malformed bundles are discarded cheaply.

**PNP-008-MUST-072**: Receivers MUST reject any `BootstrapBundle` where `now − issued_at > 7 × 86400` (7 days). The freshness check MUST be applied after the signature verifies but before any descriptor inside the bundle is parsed. An expired bundle constitutes a replay attack; the retrieving channel MUST be treated as failed for the purpose of the fallback chain in §8.6.

**PNP-008-MUST-073**: Mainline DHT (§8.5) BEP-44 mutable-item lookups MUST use the constant salt `"PNP-008-bootstrap"` (ASCII, 17 bytes, no trailing null). Implementations MUST NOT reuse this salt for any other purpose and MUST NOT accept DHT values retrieved under a different salt. The salt domain-separates ParolNet bootstrap records from arbitrary third-party BEP-44 traffic under the same public key.

**PNP-008-MUST-074**: Every bootstrap channel attempt (seed connect, DNS TXT query, HTTPS GET, DHT `get`) MUST enforce a 10-second per-attempt timeout measured from the first outbound byte. A timeout MUST be reported to the fallback chain as a channel failure; implementations MUST NOT retry the same endpoint within 60 seconds of a timeout.

**PNP-008-MUST-075**: Seed-relay bundles (§8.2) MUST be available at node startup without requiring network access. Implementations MUST validate the compiled-in seed bundle signatures before any network channel is attempted and MUST fail startup if the compiled-in bundle fails `PNP-008-MUST-071` or `PNP-008-MUST-072`.

**PNP-008-MUST-076**: HTTPS directory clients (§8.4) MUST reject responses whose `Content-Type` is not `application/cbor` (or `application/cbor; charset=binary`). The rejection MUST happen before body bytes are parsed, even if the body would have been a valid bundle. This defends against content-sniffing attacks where a malicious reverse proxy reclassifies the payload as `text/html` in hopes of triggering a browser-side parser.

---

## 9. Bridge Relays

Bridge relays serve clients in environments where the public directory is actively censored.

### 9.1 Bridge Descriptor

```
struct BridgeDescriptor {
    peer_id: [u8; 32],
    transports: Vec<PluggableTransport>,   // e.g. domain-front, obfs
    public_keys: PublicKeyBundle,          // PNP-002 identity keys
    capabilities: u32,
    issued_at: u64,
    signature: [u8; 64],                   // Ed25519 by bridge operator
    // NOTE: bridge descriptors are NOT authority-endorsed
}
```

**PNP-008-MUST-051**: `BridgeDescriptor` MUST NOT be distributed through any mechanism that gossips, mirrors, or aggregates descriptors — in particular it MUST NOT appear in `FederationSync` (0x06), the PNP-005 mesh, the PNP-003 LAN beacon, or any bootstrap channel defined in §8.

**PNP-008-MUST-052**: Bridge operators MUST rate-limit distribution per user/token to prevent enumeration; recommended limits are ≤ 3 descriptors per email/hour, ≤ 1 per QR session.

**PNP-008-MUST-053**: Bridges MUST serve a plausible cover response (default: a static HTTPS page) to any TCP connection whose first bytes do not match the negotiated pluggable transport handshake.

**PNP-008-MUST-054**: Bridges MUST NOT log client IP addresses beyond the minimum needed for per-IP rate limiting, and MUST purge such logs within 24 hours.

**PNP-008-SHOULD-009**: Bridge descriptors SHOULD be delivered via end-to-end encrypted channels (Signal, PGP email, in-person QR) so the `BridgeAnnouncement` payload itself is confidential.

### 9.2 Client Use of Bridges

**PNP-008-MUST-055**: A client using a bridge MUST route all relay-directory traffic through that bridge until a public relay is confirmed reachable; fallback to direct connection MUST be a deliberate user action.

**PNP-008-MUST-056**: A client MUST NOT report bridge descriptors back to the public directory, authorities, or telemetry endpoints.

**PNP-008-MAY-003**: Clients MAY implement automatic bridge rotation across ≥ 2 configured bridges with per-session random selection.

---

## 10. Security Considerations

### 10.1 Authority Compromise

**PNP-008-MUST-057**: Implementations MUST ship with ≥ 3 independent compiled-in authority public keys and MUST require endorsements from at least 2 distinct authorities before trusting a relay descriptor for guard-position use.

**PNP-008-SHOULD-010**: Release channels SHOULD publish a transparency log of all authority endorsements (analogous to Certificate Transparency) so compromise is detectable by independent observers.

### 10.2 Eclipse Resistance

**PNP-008-MUST-058**: A node MUST NOT accept a consensus of relays where all ACTIVE federation peers share any one of: /16 IPv4 subnet, /32 IPv6 subnet, or autonomous system number, when alternatives are available.

### 10.3 Partition Healing

**PNP-008-MUST-059**: Upon reconnection after a partition, both sides MUST perform a full `FederationSync` (tier selected per §6.2) rather than relying on heartbeat state.

**PNP-008-MUST-060**: Descriptors exchanged during partition healing MUST pass the same validation chain as descriptors from normal sync (§6.3); there is no "trusted partition" bypass.

### 10.4 Reputation Poisoning

**PNP-008-MUST-061**: A peer's reputation MUST NOT be used as an input to any signal published to other nodes; reputation remains local (cf. §7.3). This prevents coordinated slander.

---

## 10.5 Presence

H12 Phase 2 introduces a lightweight presence endpoint so that client libraries and federation peers can answer the question *"which relay is peer X currently connected to?"* without depending on the full PNP-008 federation state machine defined in §§4–7. Presence is intentionally public: any client can query it (subject to rate limiting), because the primary consumer is the end user's own client, and making presence privileged-between-relays only would leak a false privacy claim (see H12 Phase 2 design rationale).

### 10.5.1 `GET /peers/presence`

Returns a CBOR-serialized `Vec<PresenceEntry>` of peers currently connected to this relay:

```
struct PresenceEntry {
    peer_id: bstr32,       // 32-byte PeerId
    last_seen: uint,       // Unix seconds; updated on connect and on heartbeat
    signature: bstr64,     // Ed25519 signature, see §10.5.2
}
```

**PNP-008-MUST-063**: A relay MUST expose `GET /peers/presence` returning a CBOR-serialized `Vec<PresenceEntry>` covering exactly the peers currently connected to that relay. The endpoint MUST NOT include peers buffered-for-delivery-only, peers from the federation cache, or historical entries.

**PNP-008-MUST-064**: Each `PresenceEntry` MUST carry an Ed25519 signature by the relay's identity key over the canonical 32-byte hash `SHA-256(relay_peer_id || peer_id || last_seen.to_be_bytes())`. Clients and federation peers MUST verify this signature against the relay's authority-verified directory entry before trusting the entry; entries that fail to verify MUST be dropped.

### 10.5.2 Canonical Signable Bytes

The canonical byte layout for a presence signature is exactly:

```
sha256_input = relay_peer_id (32 bytes) || peer_id (32 bytes) || last_seen (8 bytes, big-endian u64)
signable = SHA-256(sha256_input)     // 32 bytes
signature = Ed25519(relay_signing_key, signable)
```

The hash is domain-separated by the two concatenated `PeerId` inputs — a signature over one relay's peer can never be replayed as a signature for another relay because each relay's `PeerId` (derived from its Ed25519 pubkey per PNP-002) is distinct.

## 10.6 Peer Lookup

### 10.6.1 `GET /peers/lookup?id=<peer_id_hex>`

Returns a CBOR-serialized `LookupResult` on hit, HTTP 404 on miss:

```
struct LookupResult {
    home_relay_url: tstr,  // public URL of the peer's home relay
    last_seen: uint,       // Unix seconds
    signature: bstr64,     // Ed25519 signature by the home relay (§10.5.2 layout)
}
```

The signature is the same signature carried by the corresponding `PresenceEntry` at the home relay — it binds (home_relay_peer_id, peer_id, last_seen) together so the client can verify it against the home relay's authority-verified directory entry.

**PNP-008-MUST-065**: A relay answering `GET /peers/lookup?id=` MUST consult its own connected-peer presence map first, and only fall back to the federation-cache populated per §10.7 if the peer is not locally connected. This ordering guarantees the freshest authoritative answer always wins over stale federation data.

**PNP-008-MUST-066**: A relay MUST rate-limit `GET /peers/lookup` to at most 10 requests per second per client IP (respecting `X-Forwarded-For` from trusted proxies), rejecting excess requests with HTTP 429.

### 10.6.2 Client Caching & Verification

**PNP-008-MUST-067**: Clients MUST cache `LookupResult` values with a TTL of at most 3600 seconds (1 hour). Expired entries MUST be re-fetched before use.

**PNP-008-MUST-068**: Clients MUST verify the `LookupResult` signature against the Ed25519 verifying key of the claimed `home_relay_url` as drawn from the authority-verified directory entry (§3). A `LookupResult` whose signature does not verify MUST be discarded and MUST NOT be cached.

## 10.7 Federation Presence Fetch

Relays populate their federation-cache by polling each configured peer relay's `/peers/presence` endpoint.

**PNP-008-MUST-069**: Each relay MUST poll every entry of its `PEER_RELAY_URLS` configuration for `/peers/presence` at an interval of at most 300 seconds. Fetch failures MUST be logged and MUST NOT crash the relay.

**PNP-008-MUST-070**: Federation-cache entries MUST expire at a TTL of at most 3600 seconds measured from the time they were fetched. A relay answering `GET /peers/lookup?id=` MUST treat expired federation-cache entries as misses.

Relays verify each fetched `PresenceEntry` signature against the home relay's Ed25519 verifying key (resolved through the authority-verified directory cache) before inserting it into the federation cache. Entries with invalid signatures MUST be rejected — this is a direct corollary of PNP-008-MUST-064.

## 11. Versioning

**PNP-008-MUST-062**: Federation handshake messages MUST include a `protocol_version` byte (currently `0x01`); peers MUST downgrade only to versions explicitly enumerated in a future PNP-008 revision.

**PNP-008-SHOULD-011**: Implementations SHOULD include a capability bitmap in heartbeats to negotiate extensions without full protocol version bumps.

---

## 12. Normative Clause Summary

This specification declares:

- **76 MUST** clauses (`PNP-008-MUST-001` through `PNP-008-MUST-076`)
- **11 SHOULD** clauses (`PNP-008-SHOULD-001` through `PNP-008-SHOULD-011`)
- **3 MAY** clauses (`PNP-008-MAY-001` through `PNP-008-MAY-003`)

Every clause is independently testable and is tracked in `crates/parolnet-conformance` per the PNP-008 test plan.

## 13. Implementation Roadmap

The phased engineering plan for landing PNP-008 in the codebase (file paths, crate boundaries, migration strategy) lives at `/FEDERATION-IMPLEMENTATION.md`. That document is non-normative.
