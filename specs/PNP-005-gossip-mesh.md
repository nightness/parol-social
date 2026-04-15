# PNP-005: ParolNet Gossip/Mesh Protocol

### Status: DRAFT
### Version: 0.1
### Date: 2026-04-10

---

## Implementation Note

This specification describes the gossip/mesh design target. Current code implements gossip envelopes, PoW, deduplication, store-forward primitives, and obfuscated UDP broadcast discovery. It does not currently implement mDNS `_parolnet._tcp.local.` discovery as written below.

---

## 1. Overview

The ParolNet Gossip/Mesh Protocol (PGMP) defines an epidemic message propagation scheme for decentralized message delivery. It operates in two modes: (a) internet-connected gossip, where nodes probabilistically forward messages to a subset of peers, and (b) local mesh networking, where nodes communicate over LAN discovery or future proximity transports (BLE). The protocol provides store-and-forward semantics for delay-tolerant networking, deduplication via bloom filters, and anti-spam through proof-of-work.

PGMP is the substrate for relay directory distribution (PNP-004 Section 5.6), offline message delivery, and broadcast announcements. It is not intended for real-time chat (use circuits for that); rather, it is optimized for eventual delivery of messages in degraded or partitioned networks.

## 2. Terminology

- **Gossip Message**: A CBOR-encoded envelope containing application payload and gossip metadata.
- **Fanout**: The number of peers a node forwards a message to. Default: 3.
- **TTL (Time-To-Live)**: The maximum number of hops a message may traverse. Default: 7.
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
  "pow":   bytes(8),      ; Proof-of-work nonce (see Section 5.6)
  "sig":   bytes(64),     ; Ed25519 signature by src over all fields except "sig", "seen", and "hops"
  "type":  uint,          ; Payload type (see Section 3.2)
  "pay":   bytes          ; Payload (type-dependent, max 65536 bytes)
}
```

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

where `k` is a single byte and `||` denotes concatenation. The bloom filter is mutable: each forwarding node inserts its own PeerId before relaying. This allows downstream nodes to probabilistically avoid sending the message back to nodes that have already seen it.

The bloom filter and hop count are NOT covered by the signature (the "sig" field signs all fields except "sig", "seen", and "hops"). This is intentional: the bloom filter is updated and the hop counter is incremented at each relay hop. Including these relay-modified fields would cause signature verification to fail after the first hop.

### 3.4 Proof-of-Work Format

The PoW is computed over a challenge string:

```
challenge = SHA-256("pgmp-pow-v1" || id || src || ts)
```

The sender MUST find an 8-byte nonce such that:

```
SHA-256(challenge || nonce) has at least D leading zero bits
```

where D is the current difficulty (default: 16, meaning approximately 65536 hash operations). The difficulty MAY be adjusted by network consensus propagated via RELAY_DESCRIPTOR payloads.

### 3.5 Anonymous Envelopes

For USER_MESSAGE payloads (type 0x02), the sender identity SHOULD be moved inside the encrypted payload body rather than being exposed in the cleartext gossip envelope. This prevents relay nodes from learning who is communicating with whom.

An anonymous envelope is constructed as follows:

1. Set the "src" field to 32 zero bytes: `PeerId([0x00; 32])`.
2. Set "src_pubkey" to an empty byte string.
3. The actual sender PeerId and public key MUST be included inside the encrypted "pay" field so the recipient can verify authenticity after decryption.
4. The "sig" field MUST still contain a valid Ed25519 signature, but the signature is computed over the zeroed src and empty pubkey fields. The recipient verifies the signature using the sender's key extracted from the decrypted payload.

Anonymous envelopes MUST only be used for USER_MESSAGE types. RELAY_DESCRIPTOR, PEER_ANNOUNCEMENT, GROUP_METADATA, and REVOCATION messages MUST include a valid non-zero "src" and "src_pubkey" for relay-level verification.

Validation rules (Section 5.1) MUST accept anonymous envelopes: if "src" is all zeros and "src_pubkey" is empty, the node SHOULD skip signature verification at the gossip layer (since the signing key is not available) and defer verification to the application layer after decryption.

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
    |   SYNCING         |  Set reconciliation of message IDs (Section 5.7)
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

Upon receiving a gossip message, a node MUST perform the following checks in order:

1. **Version check**: "v" MUST equal 1. Unknown versions MUST be silently discarded.
2. **Expiry check**: If current time >= "exp", the message MUST be discarded.
3. **TTL check**: If "ttl" equals 0, the message MUST NOT be forwarded further but MAY be delivered locally.
4. **Signature verification**: The Ed25519 signature MUST be verified against the "src" PeerId's public key. If the public key is unknown, the node MAY buffer the message for up to 60 seconds while attempting to resolve the key via peer announcement. If verification fails, the message MUST be discarded and the sending peer SHOULD be penalized (see Section 5.8).
5. **Proof-of-work verification**: The PoW MUST meet the current difficulty threshold. Invalid PoW MUST result in message discard.
6. **Deduplication**: The message ID MUST be checked against the local deduplication bloom filter. If likely already seen, the message MUST be discarded.
7. **Payload size**: "pay" MUST NOT exceed 65536 bytes. Oversized messages MUST be discarded.

### 5.2 Message Forwarding

1. If all validation passes and TTL > 0, the node MUST:
   a. Insert its own PeerId into the "seen" bloom filter.
   b. Decrement "ttl" by 1.
   c. Increment "hops" by 1.
   d. Insert the message ID into its local deduplication bloom filter.
   e. Select up to F peers for forwarding (F = fanout, default 3).
2. Peer selection for forwarding MUST exclude:
   a. The peer from which the message was received.
   b. Peers whose PeerId is probably present in the "seen" bloom filter.
3. If fewer than F eligible peers are available, the node MUST forward to all eligible peers.
4. The node MUST add random jitter (0-200ms, uniformly distributed) before forwarding to each peer to prevent timing correlation. The jitter delay MUST be generated from a cryptographically secure random source and applied independently per forwarding peer.

### 5.3 TTL and Expiry Rules

1. The originator MUST set "ttl" to a value between 1 and 15. The default is 7.
2. The originator MUST set "exp" to a value no more than 86400 seconds (24 hours) in the future.
3. A node MUST NOT increase the TTL of a received message.
4. A node MUST NOT extend the expiry of a received message.
5. RELAY_DESCRIPTOR messages (type 0x01) SHOULD use TTL=10 and expiry=21600 (6 hours) to ensure broad distribution.

### 5.4 Store-and-Forward

1. A node SHOULD maintain a store-and-forward buffer for each known peer that is currently disconnected.
2. The per-peer buffer MUST NOT exceed 256 messages or 4 MB, whichever is reached first.
3. When the buffer is full, eviction MUST proceed in the following priority order:
   a. Messages with the nearest expiry time (soonest to expire) are evicted first.
   b. Among messages with equal expiry, the message with the lowest remaining TTL is evicted first.
   c. Among messages still tied, the oldest message (by origination timestamp) is evicted first.
4. Upon peer reconnection, the node MUST deliver buffered messages after the sync phase (Section 5.7) to avoid duplicates.
5. Expired messages MUST be purged from the buffer during periodic housekeeping (at least every 60 seconds).

### 5.5 Deduplication Bloom Filter

1. Each node MUST maintain a local bloom filter for recently seen message IDs.
2. The bloom filter SHOULD be sized for 100,000 entries with a false-positive rate no greater than 0.1%.
3. The recommended implementation is a 1,437,760-bit (175 KB) bloom filter with 7 hash functions.
4. The bloom filter MUST be rotated periodically. The RECOMMENDED approach is a double-buffer: maintain a "current" and "previous" filter. Every 12 hours, discard "previous", promote "current" to "previous", and allocate a new empty "current". Check both filters for deduplication.

### 5.6 Anti-Spam Proof-of-Work

1. Every gossip message MUST include a valid PoW.
2. The default difficulty is 16 leading zero bits (approximately 65536 SHA-256 operations, negligible on modern hardware, meaningful at scale).
3. RELAY_DESCRIPTOR messages MUST use difficulty 20 (approximately 1 million operations) to make Sybil relay injection more costly.
4. The difficulty MAY be adjusted network-wide by including a "pow_difficulty" field in RELAY_DESCRIPTOR messages. Nodes SHOULD adopt the median difficulty advertised by their known relays.
5. A message with insufficient PoW MUST be discarded silently.

### 5.7 Sync Protocol (Set Reconciliation)

When two peers (re)connect, they MUST perform set reconciliation to determine which messages each side has that the other lacks.

1. Each peer computes a compact representation of its message ID set. The RECOMMENDED algorithm is Invertible Bloom Lookup Tables (IBLTs).
2. The sync exchange proceeds as follows:
   a. Both peers simultaneously send a SYNC_OFFER message containing their IBLT (CBOR-encoded, type-prefixed).
   b. Each peer decodes the difference from the received IBLT vs. its own.
   c. Each peer sends SYNC_REQUEST listing message IDs it wants.
   d. Each peer replies with SYNC_DATA containing the requested messages.
3. Sync messages are not gossip messages; they are exchanged directly on the peer TLS connection using the ParolNet Wire Protocol envelope with a dedicated message type.
4. The IBLT SHOULD be sized for a symmetric difference of up to 1,000 messages. If the difference is larger (likely after extended disconnection), peers SHOULD fall back to a full message ID list exchange, sending IDs in batches of 500.
5. The sync phase MUST complete within 30 seconds. If it times out, peers MUST proceed to ACTIVE state and accept that some messages may be re-sent (handled by deduplication).

### 5.8 Peer Scoring

1. Nodes SHOULD maintain a reputation score for each peer, initialized to 100.
2. Delivering a valid, previously-unseen message: +1 (max 200).
3. Delivering an invalid message (bad signature, bad PoW): -10.
4. Delivering an expired message: -2.
5. Delivering a duplicate message: -1.
6. If a peer's score falls below 0, the node SHOULD disconnect and refuse reconnection for 1 hour.
7. Scores SHOULD decay toward 100 at a rate of 1 point per hour.

### 5.9 Peer Discovery

1. **mDNS**: Nodes on a local network MUST advertise via mDNS using service type `_parolnet._tcp.local.` with a TXT record containing the node's PeerId (hex-encoded). Nodes MUST listen for mDNS announcements and attempt connections to discovered peers.
2. **Gossip**: PEER_ANNOUNCEMENT messages (type 0x03) carry a node's current network addresses. Nodes SHOULD publish a PEER_ANNOUNCEMENT every 30 minutes and upon address change.
3. **Bootstrap**: For initial network join, a node MAY connect to a set of well-known bootstrap peers whose addresses are compiled into the application. Bootstrap peers MUST NOT be given any special trust.
4. **Future**: BLE beacon discovery is reserved for future specification.

## 6. Security Considerations

1. **Message authenticity**: All gossip messages are signed by the originator's Ed25519 key. Signature verification is mandatory and prevents message forgery.
2. **Spam and flooding**: Proof-of-work raises the cost of bulk message injection. The PoW difficulty is adjustable. Combined with per-peer scoring, persistent spammers are isolated.
3. **Sybil attacks on gossip**: An adversary creating many fake peers can bias message propagation. The bloom filter "seen" field limits redundant forwarding, and subnet diversity in peer selection (when applicable) reduces Sybil effectiveness.
4. **Bloom filter manipulation**: The "seen" bloom filter is unsigned and mutable. A malicious relay could clear it to cause message re-propagation (amplification) or stuff it to suppress forwarding. Nodes SHOULD rate-limit messages per source PeerId (maximum 10 messages per minute per source) regardless of bloom filter state.
5. **Replay attacks**: Message IDs include the origination timestamp. Nodes MUST reject messages with timestamps more than 300 seconds in the future (clock skew tolerance) or past the expiry.
6. **Store-and-forward privacy**: Buffered messages are stored encrypted (the application payload is always E2EE at a higher layer). The gossip metadata (src, TTL, etc.) is visible to the storing node. This is an acceptable tradeoff for delay-tolerant delivery.
7. **Per-source rate limiting**: Nodes MUST enforce per-PeerId rate limiting on incoming gossip messages (maximum 10 messages per 60 seconds per source PeerId). Messages exceeding this rate MUST be silently dropped. This mitigates flooding attacks regardless of bloom filter state.

## 7. Privacy Considerations

1. **Source correlation**: The "src" field reveals the originator's PeerId. For user messages (type 0x02), implementations SHOULD use anonymous envelopes (Section 3.5) to omit the sender identity from the cleartext gossip layer entirely. As a fallback, the "src" SHOULD be a purpose-specific pseudonymous PeerId, not the node's primary identity.
2. **Timing analysis**: Forwarding jitter (Section 5.2 step 4) provides limited timing protection. For stronger anonymity, messages SHOULD be injected into relay circuits (PNP-004) before entering the gossip layer.
3. **Bloom filter leakage**: The "seen" bloom filter reveals which nodes have handled a message. This is a privacy-utility tradeoff. Nodes operating in high-threat environments MAY set a "privacy" flag in their PEER_ANNOUNCEMENT indicating that their PeerId should NOT be inserted into seen filters by forwarding peers.
4. **Message accumulation**: A global passive adversary observing many peers could reconstruct message propagation paths. Traffic shaping (PNP-006) and circuit-based delivery (PNP-004) mitigate this for high-sensitivity messages.
5. **Metadata on disk**: Store-and-forward buffers contain gossip metadata. Implementations MUST encrypt buffers at rest using a key derived from the node's identity key. Implementations SHOULD support a "panic wipe" command that securely erases all buffered data.
