# PNP-005: ParolNet Gossip/Mesh Protocol

### Status: CANDIDATE
### Version: 0.2
### Date: 2026-04-17

---

## Changelog

**v0.2 (2026-04-17) — Harmonization pass**

- Status bumped from DRAFT to CANDIDATE.
- Added §3.6 "TTL Semantics Scope Table" to distinguish the three different TTL values that appear across the PNP stack (envelope TTL=7, circuit hop count=3, RELAY_DESCRIPTOR gossip TTL=10).
- Pinned IBLT parameters in §5.7 (previously "RECOMMENDED" with no specifics): cell count = 1024, hash function count = 3, keyspace = SHA-256 of message ID → first 8 bytes as 64-bit key.
- Added clause IDs to every RFC 2119 statement (`PNP-005-MUST-NNN`, `-SHOULD-NNN`, `-MAY-NNN`).
- Added note explicitly acknowledging the current implementation-vs-spec gap: obfuscated UDP broadcast is used today; mDNS `_parolnet._tcp.local.` is the normative target.
- Completed cross-reference table.

**v0.1 (2026-04-10)** — Initial draft.

---

## Implementation Note

This specification describes the gossip/mesh design target. Current code implements gossip envelopes, PoW, deduplication, store-forward primitives, and obfuscated UDP broadcast discovery. It does not currently implement mDNS `_parolnet._tcp.local.` discovery as written below. The spec is the authoritative target for conformance testing; the code is expected to converge toward the spec.

---

## 1. Overview

The ParolNet Gossip/Mesh Protocol (PGMP) defines an epidemic message propagation scheme for decentralized message delivery. It operates in two modes: (a) internet-connected gossip, where nodes probabilistically forward messages to a subset of peers, and (b) local mesh networking, where nodes communicate over LAN discovery or future proximity transports (BLE). The protocol provides store-and-forward semantics for delay-tolerant networking, deduplication via bloom filters, and anti-spam through proof-of-work.

PGMP is the substrate for relay directory distribution (PNP-004 §5.6), offline message delivery, and broadcast announcements. It is not intended for real-time chat (use circuits for that); rather, it is optimized for eventual delivery of messages in degraded or partitioned networks.

## 2. Terminology

- **Gossip Message**: A CBOR-encoded envelope containing application payload and gossip metadata.
- **Fanout**: The number of peers a node forwards a message to. Default: 3.
- **TTL (Time-To-Live)**: The maximum number of hops a message may traverse. Default: 7. See §3.6 for scoping distinctions.
- **Expiry**: The absolute Unix timestamp after which a message MUST be discarded. Default: current time + 86400 seconds (24 hours).
- **Bloom Filter**: A space-efficient probabilistic data structure used for deduplication of seen message IDs.
- **Store-and-Forward Buffer**: A bounded, persistent queue of messages destined for currently-offline peers.
- **Proof-of-Work (PoW)**: A computational puzzle attached to each gossip message to rate-limit spam.
- **Set Reconciliation**: A protocol for efficiently determining which messages one peer has that another lacks.

## 3. Message Format

### 3.1 Gossip Envelope

All gossip messages are CBOR-encoded (RFC 8949) maps with the following fields:

```
CBOR Map {
  "v":     uint,          ; Protocol version (MUST be 1)
  "id":    bytes(32),     ; Message ID: SHA-256(payload || sender_peer_id || nonce)
  "src":   bytes(32),     ; Sender PeerId
  "ts":    uint,          ; Origination timestamp (Unix epoch seconds)
  "exp":   uint,          ; Expiry timestamp (Unix epoch seconds)
  "ttl":   uint,          ; Remaining hop count (decremented at each hop)
  "hops":  uint,          ; Number of hops traversed so far (informational)
  "seen":  bytes(128),    ; Bloom filter (1024-bit) of PeerIds that have seen this message
  "pow":   bytes(8),      ; Proof-of-work nonce (see §5.6)
  "sig":   bytes(64),     ; Ed25519 signature by src over all fields except "sig", "seen", and "hops"
  "type":  uint,          ; Payload type (see §3.2)
  "pay":   bytes          ; Payload (type-dependent, max 65536 bytes)
}
```

The `v` field MUST be set to 1. **PNP-005-MUST-001**

Total overhead (excluding payload): approximately 350-400 bytes depending on CBOR encoding.

### 3.2 Payload Types

| Value | Name              | Description                                |
|-------|-------------------|--------------------------------------------|
| 0x01  | RELAY_DESCRIPTOR  | Relay directory entry (PNP-004)            |
| 0x02  | USER_MESSAGE      | End-to-end encrypted user message           |
| 0x03  | PEER_ANNOUNCEMENT | Peer presence/address advertisement        |
| 0x04  | GROUP_METADATA    | Encrypted group key rotation notification  |
| 0x05  | REVOCATION        | Key or relay revocation notice             |
| 0x06-0xFF | Reserved      | Future use                                 |

### 3.3 Bloom Filter for Seen Peers

The "seen" field is a 1024-bit (128-byte) bloom filter with 3 hash functions. Each hash function is defined as:

```
h_k(PeerId) = (SHA-256(k || PeerId) mod 1024)   for k in {0, 1, 2}
```

where `k` is a single byte and `||` denotes concatenation. The bloom filter is mutable: each forwarding node inserts its own PeerId before relaying. **PNP-005-MUST-002** This allows downstream nodes to probabilistically avoid sending the message back to nodes that have already seen it.

The bloom filter and hop count are NOT covered by the signature (the "sig" field signs all fields except "sig", "seen", and "hops"). **PNP-005-MUST-003** This is intentional: the bloom filter is updated and the hop counter is incremented at each relay hop. Including these relay-modified fields would cause signature verification to fail after the first hop.

### 3.4 Proof-of-Work Format

The PoW is computed over a challenge string:

```
challenge = SHA-256("pgmp-pow-v1" || id || src || ts)
```

The sender MUST find an 8-byte nonce such that: **PNP-005-MUST-004**

```
SHA-256(challenge || nonce) has at least D leading zero bits
```

where D is the current difficulty (default: 16, meaning approximately 65536 hash operations). The difficulty MAY be adjusted by network consensus propagated via RELAY_DESCRIPTOR payloads. **PNP-005-MAY-001**

### 3.5 Anonymous Envelopes

For USER_MESSAGE payloads (type 0x02), the sender identity SHOULD be moved inside the encrypted payload body rather than being exposed in the cleartext gossip envelope. **PNP-005-SHOULD-001** This prevents relay nodes from learning who is communicating with whom.

An anonymous envelope is constructed as follows:

1. Set the "src" field to 32 zero bytes: `PeerId([0x00; 32])`. **PNP-005-MUST-005**
2. Set "src_pubkey" to an empty byte string. **PNP-005-MUST-006**
3. The actual sender PeerId and public key MUST be included inside the encrypted "pay" field so the recipient can verify authenticity after decryption. **PNP-005-MUST-007**
4. The "sig" field MUST still contain a valid Ed25519 signature, but the signature is computed over the zeroed src and empty pubkey fields. The recipient verifies the signature using the sender's key extracted from the decrypted payload. **PNP-005-MUST-008**

Anonymous envelopes MUST only be used for USER_MESSAGE types. **PNP-005-MUST-009** RELAY_DESCRIPTOR, PEER_ANNOUNCEMENT, GROUP_METADATA, and REVOCATION messages MUST include a valid non-zero "src" and "src_pubkey" for relay-level verification. **PNP-005-MUST-010**

Validation rules (§5.1) MUST accept anonymous envelopes: if "src" is all zeros and "src_pubkey" is empty, the node SHOULD skip signature verification at the gossip layer (since the signing key is not available) and defer verification to the application layer after decryption. **PNP-005-SHOULD-002**

### 3.6 TTL Semantics Scope Table

The word "TTL" appears at three different layers in the PNP stack with three distinct meanings. This table is normative and resolves scoping ambiguity.

| Field | Scope | Meaning | Default | Range | Defined |
|-------|-------|---------|---------|-------|---------|
| `ttl` (upper 8 bits of ttl_and_hops) | PNP-001 envelope | Maximum relay forwarding hops for a wire envelope | 7 | 0–255 | PNP-001 §3.2 |
| circuit hop count | PNP-004 circuit | Number of onion hops in a relay circuit | 3 (fixed) | 3 only | PNP-004 §5.3 |
| `ttl` (this spec) | PNP-005 gossip | Maximum gossip propagation hops | 7 | 1–15 | PNP-005 §5.3 |
| RELAY_DESCRIPTOR gossip `ttl` | PNP-005 gossip (specific payload) | Gossip hops for relay directory entries | 10 | 1–15 | PNP-005 §5.3 item 5 |

The PNP-001 envelope TTL and the PNP-005 gossip TTL are *independently* decremented — a single gossip message may traverse multiple PNP-001 envelopes at different relay hops. The PNP-004 circuit hop count is a fixed value, not a TTL.

## 4. State Machine

### 4.1 Message Lifecycle

```
     Originator creates message
              |
              v
    +-------------------+
    |   ORIGINATED      |  OP signs, computes PoW, sets TTL, inserts self in bloom
    +--------+----------+
             |
             | Send to fanout peers
             v
    +--------+----------+
    |   IN_TRANSIT       |  Each receiving node:
    |                    |    1. Validate signature, PoW, TTL, expiry
    |                    |    2. Check bloom / local dedup filter
    |                    |    3. If not seen: store, insert self in bloom, decrement TTL
    |                    |    4. Forward to fanout peers (if TTL > 0)
    +--------+----------+
             |
             | TTL reaches 0 or expiry reached
             v
    +--------+----------+
    |   EXPIRED          |  Node removes from buffer, adds ID to dedup filter
    +-------------------+
```

### 4.2 Peer Connection Lifecycle

```
    +-------------------+
    |   DISCONNECTED    |
    +--------+----------+
             |
       Peer discovered (mDNS, gossip, manual)
             |
             v
    +--------+----------+
    |   CONNECTING      |  TLS handshake + mutual PeerId verification
    +--------+----------+
             |
       Handshake complete
             |
             v
    +--------+----------+
    |   SYNCING         |  Set reconciliation of message IDs (§5.7)
    +--------+----------+
             |
       Sync complete
             |
             v
    +--------+----------+
    |   ACTIVE          |  Normal gossip forwarding
    +--------+----------+
             |
       Disconnect / timeout
             |
             v
    +--------+----------+
    |   DISCONNECTED    |  Buffer messages for this peer
    +-------------------+
```

## 5. Processing Rules

### 5.1 Message Validation

Upon receiving a gossip message, a node MUST perform the following checks in order: **PNP-005-MUST-011**

1. **Version check**: "v" MUST equal 1. Unknown versions MUST be silently discarded. **PNP-005-MUST-012**
2. **Expiry check**: If current time >= "exp", the message MUST be discarded. **PNP-005-MUST-013**
3. **TTL check**: If "ttl" equals 0, the message MUST NOT be forwarded further but MAY be delivered locally. **PNP-005-MUST-014**
4. **Signature verification**: The Ed25519 signature MUST be verified against the "src" PeerId's public key. **PNP-005-MUST-015** If the public key is unknown, the node MAY buffer the message for up to 60 seconds while attempting to resolve the key via peer announcement. **PNP-005-MAY-002** If verification fails, the message MUST be discarded and the sending peer SHOULD be penalized (see §5.8). **PNP-005-MUST-016**
5. **Proof-of-work verification**: The PoW MUST meet the current difficulty threshold. Invalid PoW MUST result in message discard. **PNP-005-MUST-017**
6. **Deduplication**: The message ID MUST be checked against the local deduplication bloom filter. If likely already seen, the message MUST be discarded. **PNP-005-MUST-018**
7. **Payload size**: "pay" MUST NOT exceed 65536 bytes. Oversized messages MUST be discarded. **PNP-005-MUST-019**

### 5.2 Message Forwarding

1. If all validation passes and TTL > 0, the node MUST: **PNP-005-MUST-020**
   a. Insert its own PeerId into the "seen" bloom filter.
   b. Decrement "ttl" by 1.
   c. Increment "hops" by 1.
   d. Insert the message ID into its local deduplication bloom filter.
   e. Select up to F peers for forwarding (F = fanout, default 3).
2. Peer selection for forwarding MUST exclude: **PNP-005-MUST-021**
   a. The peer from which the message was received.
   b. Peers whose PeerId is probably present in the "seen" bloom filter.
3. If fewer than F eligible peers are available, the node MUST forward to all eligible peers. **PNP-005-MUST-022**
4. The node MUST add random jitter (0-200ms, uniformly distributed) before forwarding to each peer to prevent timing correlation. **PNP-005-MUST-023** The jitter delay MUST be generated from a cryptographically secure random source and applied independently per forwarding peer. **PNP-005-MUST-024**

### 5.3 TTL and Expiry Rules

1. The originator MUST set "ttl" to a value between 1 and 15. The default is 7. **PNP-005-MUST-025**
2. The originator MUST set "exp" to a value no more than 86400 seconds (24 hours) in the future. **PNP-005-MUST-026**
3. A node MUST NOT increase the TTL of a received message. **PNP-005-MUST-027**
4. A node MUST NOT extend the expiry of a received message. **PNP-005-MUST-028**
5. RELAY_DESCRIPTOR messages (type 0x01) SHOULD use TTL=10 and expiry=21600 (6 hours) to ensure broad distribution. **PNP-005-SHOULD-003**

### 5.4 Store-and-Forward

1. A node SHOULD maintain a store-and-forward buffer for each known peer that is currently disconnected. **PNP-005-SHOULD-004**
2. The per-peer buffer MUST NOT exceed 256 messages or 4 MB, whichever is reached first. **PNP-005-MUST-029**
3. When the buffer is full, eviction MUST proceed in the following priority order: **PNP-005-MUST-030**
   a. Messages with the nearest expiry time (soonest to expire) are evicted first.
   b. Among messages with equal expiry, the message with the lowest remaining TTL is evicted first.
   c. Among messages still tied, the oldest message (by origination timestamp) is evicted first.
4. Upon peer reconnection, the node MUST deliver buffered messages after the sync phase (§5.7) to avoid duplicates. **PNP-005-MUST-031**
5. Expired messages MUST be purged from the buffer during periodic housekeeping (at least every 60 seconds). **PNP-005-MUST-032**

### 5.5 Deduplication Bloom Filter

1. Each node MUST maintain a local bloom filter for recently seen message IDs. **PNP-005-MUST-033**
2. The bloom filter SHOULD be sized for 100,000 entries with a false-positive rate no greater than 0.1%. **PNP-005-SHOULD-005**
3. The recommended implementation is a 1,437,760-bit (175 KB) bloom filter with 7 hash functions.
4. The bloom filter MUST be rotated periodically. **PNP-005-MUST-034** The RECOMMENDED approach is a double-buffer: maintain a "current" and "previous" filter. Every 12 hours, discard "previous", promote "current" to "previous", and allocate a new empty "current". Check both filters for deduplication.

### 5.6 Anti-Spam Proof-of-Work

1. Every gossip message MUST include a valid PoW. **PNP-005-MUST-035**
2. The default difficulty is 16 leading zero bits (approximately 65536 SHA-256 operations, negligible on modern hardware, meaningful at scale).
3. RELAY_DESCRIPTOR messages MUST use difficulty 20 (approximately 1 million operations) to make Sybil relay injection more costly. **PNP-005-MUST-036**
4. The difficulty MAY be adjusted network-wide by including a "pow_difficulty" field in RELAY_DESCRIPTOR messages. Nodes SHOULD adopt the median difficulty advertised by their known relays. **PNP-005-SHOULD-006**
5. A message with insufficient PoW MUST be discarded silently. **PNP-005-MUST-037**

### 5.7 Sync Protocol (Set Reconciliation)

When two peers (re)connect, they MUST perform set reconciliation to determine which messages each side has that the other lacks. **PNP-005-MUST-038**

1. Each peer computes a compact representation of its message ID set using Invertible Bloom Lookup Tables (IBLTs) with the following pinned parameters: **PNP-005-MUST-039**
   - **Cell count**: 1024 cells per IBLT.
   - **Hash function count**: 3 independent hash functions.
   - **Keyspace**: 64-bit keys computed as `first_8_bytes(SHA-256(message_id))`.
   - **Cell fields**: count (int32), keySum (64-bit XOR), hashSum (32-bit XOR of SHA-256 of key, used for peel-off verification).
   - **Encoding**: CBOR array of 1024 maps, each map `{"c": int32, "k": uint64, "h": uint32}`.
   - These parameters support a symmetric difference of up to ~1000 message IDs per reconciliation round with high decoding probability.
2. The sync exchange proceeds as follows:
   a. Both peers simultaneously send a SYNC_OFFER message containing their IBLT (CBOR-encoded, type-prefixed).
   b. Each peer decodes the difference from the received IBLT vs. its own.
   c. Each peer sends SYNC_REQUEST listing message IDs it wants.
   d. Each peer replies with SYNC_DATA containing the requested messages.
3. Sync messages are not gossip messages; they are exchanged directly on the peer TLS connection using the ParolNet Wire Protocol envelope with a dedicated message type.
4. If the symmetric difference exceeds 1,000 messages (IBLT decoding fails), peers SHOULD fall back to a full message ID list exchange, sending IDs in batches of 500. **PNP-005-SHOULD-007**
5. The sync phase MUST complete within 30 seconds. **PNP-005-MUST-040** If it times out, peers MUST proceed to ACTIVE state and accept that some messages may be re-sent (handled by deduplication). **PNP-005-MUST-041**

### 5.8 Peer Scoring

1. Nodes SHOULD maintain a reputation score for each peer, initialized to 100. **PNP-005-SHOULD-008**
2. Delivering a valid, previously-unseen message: +1 (max 200).
3. Delivering an invalid message (bad signature, bad PoW): -10.
4. Delivering an expired message: -2.
5. Delivering a duplicate message: -1.
6. If a peer's score falls below 0, the node SHOULD disconnect and refuse reconnection for 1 hour. **PNP-005-SHOULD-009**
7. Scores SHOULD decay toward 100 at a rate of 1 point per hour. **PNP-005-SHOULD-010**

### 5.9 Peer Discovery

1. **mDNS**: Nodes on a local network MUST advertise via mDNS using service type `_parolnet._tcp.local.` with a TXT record containing the node's PeerId (hex-encoded). **PNP-005-MUST-042** Nodes MUST listen for mDNS announcements and attempt connections to discovered peers. **PNP-005-MUST-043**
2. **Gossip**: PEER_ANNOUNCEMENT messages (type 0x03) carry a node's current network addresses. Nodes SHOULD publish a PEER_ANNOUNCEMENT every 30 minutes and upon address change. **PNP-005-SHOULD-011**
3. **Bootstrap**: For initial network join, a node MAY connect to a set of well-known bootstrap peers whose addresses are compiled into the application. **PNP-005-MAY-003** Bootstrap peers MUST NOT be given any special trust. **PNP-005-MUST-044**
4. **Future**: BLE beacon discovery is reserved for future specification.

## 6. Security Considerations

1. **Message authenticity**: All gossip messages are signed by the originator's Ed25519 key. Signature verification is mandatory and prevents message forgery.
2. **Spam and flooding**: Proof-of-work raises the cost of bulk message injection. The PoW difficulty is adjustable. Combined with per-peer scoring, persistent spammers are isolated.
3. **Sybil attacks on gossip**: An adversary creating many fake peers can bias message propagation. The bloom filter "seen" field limits redundant forwarding, and subnet diversity in peer selection (when applicable) reduces Sybil effectiveness.
4. **Bloom filter manipulation**: The "seen" bloom filter is unsigned and mutable. A malicious relay could clear it to cause message re-propagation (amplification) or stuff it to suppress forwarding. Nodes SHOULD rate-limit messages per source PeerId (maximum 10 messages per minute per source) regardless of bloom filter state. **PNP-005-SHOULD-012**
5. **Replay attacks**: Message IDs include the origination timestamp. Nodes MUST reject messages with timestamps more than 300 seconds in the future (clock skew tolerance) or past the expiry. **PNP-005-MUST-045**
6. **Store-and-forward privacy**: Buffered messages are stored encrypted (the application payload is always E2EE at a higher layer). The gossip metadata (src, TTL, etc.) is visible to the storing node. This is an acceptable tradeoff for delay-tolerant delivery.
7. **Per-source rate limiting**: Nodes MUST enforce per-PeerId rate limiting on incoming gossip messages (maximum 10 messages per 60 seconds per source PeerId). **PNP-005-MUST-046** Messages exceeding this rate MUST be silently dropped. **PNP-005-MUST-047** This mitigates flooding attacks regardless of bloom filter state.

## 7. Privacy Considerations

1. **Source correlation**: The "src" field reveals the originator's PeerId. For user messages (type 0x02), implementations SHOULD use anonymous envelopes (§3.5) to omit the sender identity from the cleartext gossip layer entirely. **PNP-005-SHOULD-013** As a fallback, the "src" SHOULD be a purpose-specific pseudonymous PeerId, not the node's primary identity. **PNP-005-SHOULD-014**
2. **Timing analysis**: Forwarding jitter (§5.2 step 4) provides limited timing protection. For stronger anonymity, messages SHOULD be injected into relay circuits (PNP-004) before entering the gossip layer. **PNP-005-SHOULD-015**
3. **Bloom filter leakage**: The "seen" bloom filter reveals which nodes have handled a message. This is a privacy-utility tradeoff. Nodes operating in high-threat environments MAY set a "privacy" flag in their PEER_ANNOUNCEMENT indicating that their PeerId should NOT be inserted into seen filters by forwarding peers. **PNP-005-MAY-004**
4. **Message accumulation**: A global passive adversary observing many peers could reconstruct message propagation paths. Traffic shaping (PNP-006) and circuit-based delivery (PNP-004) mitigate this for high-sensitivity messages.
5. **Metadata on disk**: Store-and-forward buffers contain gossip metadata. Implementations MUST encrypt buffers at rest using a key derived from the node's identity key. **PNP-005-MUST-048** Implementations SHOULD support a "panic wipe" command that securely erases all buffered data. **PNP-005-SHOULD-016**

## 8. Cross-Protocol References

| Spec | Relationship |
|------|-------------|
| PNP-001 (Wire Protocol) | Gossip messages transmitted as PNP-001 envelopes. PNP-001 envelope TTL and PNP-005 gossip TTL are independent (see §3.6). |
| PNP-002 (Handshake) | Pre-key bundles MAY be distributed via gossip as HANDSHAKE-typed payloads. |
| PNP-004 (Relay Circuit) | RELAY_DESCRIPTOR payload type (0x01) carries relay directory entries. See §5.6 of PNP-004. |
| PNP-006 (Traffic Shaping) | Gossip forwarding jitter (§5.2.4) complements PNP-006 bandwidth-mode padding. |
| PNP-008 (Relay Federation) | Authority-signed relay descriptors propagate via gossip with an extended signature block. |
| PNP-009 (Group Communication) | GROUP_METADATA payload type (0x04) carries group key-rotation notifications. |
