# PNP-001: ParolNet Wire Protocol

### Status: CANDIDATE
### Version: 0.6
### Date: 2026-04-17

---

## Changelog

**v0.6 (2026-04-17) — Envelope fragmentation & reassembly**

- Added §3.9 "Fragmentation" defining the normative reassembly algorithm for application bodies that overflow the 16384-byte bucket ceiling. Formalizes use of the `is_fragment` and `is_final_fragment` flag bits (already reserved in §3.3 v0.3) and introduces two optional plaintext fields `fragment_id` (16 random bytes shared across all fragments of one message) and `fragment_seq` (u32, 0-based).
- Allocated clauses `PNP-001-MUST-053` through `PNP-001-MUST-062` covering fragment identity, in-order & out-of-order reassembly, per-sender buffer caps, 30-second reassembly timeout, AAD binding of fragment metadata, and duplicate-fragment handling. Closes the last wire-format ambiguity that was blocking multi-envelope message transport through 3-hop onion circuits.
- Added `specs/vectors/PNP-001/fragment_*.json` test vectors.
- §3.3 plaintext map description extended to list the two new optional keys; lex ordering (MUST-023) preserved.

**v0.5 (2026-04-17) — Outer Relay Frame + H9 Privacy Pass token auth**

- Added §4 "Outer Relay Frame" specifying the JSON envelope the relay sees on the WebSocket (wraps the CBOR envelope defined in §3). The frame is `{type, to, token, payload}`; the prior `from` field is removed — relays no longer learn per-frame sender identity.
- Added §4.2 "Token Auth (Privacy Pass)" defining the VOPRF-backed rotating-token scheme (RFC 9578 Privacy Pass + RFC 9497 VOPRF, ciphersuite `Ristretto255-SHA512`). Epoch length 3600 s, grace window 300 s, per-client budget 8192 tokens/epoch.
- Allocated clauses `PNP-001-MUST-048` through `PNP-001-MUST-052` for the new outer-frame / token-auth rules.

**v0.4 (2026-04-17) — Identity rotation message type**

- Extended §3.4 Message Types table to include code `0x13 IDENTITY_ROTATE` from PNP-002 §7 (H5 identity rotation). Reserved-code range shifted to `0x14–0xFF`.

**v0.3 (2026-04-17) — Wire-level envelope padding + AAD binding**

- §3.1 Envelope Structure rewritten: envelope is now a 4-element CBOR array `[cleartext_header, ratchet_header, encrypted_payload, padding]`. The Double Ratchet header is carried explicitly so the receiver can advance state before AEAD decryption. Padding is applied to the serialized envelope (wire level), not inside the plaintext payload, so the final CBOR byte sequence lands exactly on a bucket boundary.
- §3.3 Encrypted Payload: removed the `pad` field from the plaintext CBOR map. Padding is now a sibling field of the ciphertext at the envelope level, not a field inside the ciphertext. The plaintext map is now `{body, chain, flags, seq}` in lexicographic order.
- §3.5 MAC: the 16-byte AEAD tag is now the trailing 16 bytes of the `encrypted_payload` byte-string (in-place, as produced by ChaCha20-Poly1305 / AES-256-GCM). There is no separate `mac` field on the wire.
- §3.6 Padding Scheme rewritten: padding is applied to the serialized envelope. The sender iteratively sizes `padding` so that `len(CBOR(envelope))` equals exactly the chosen bucket size. A single fixpoint iteration suffices to absorb the CBOR `bstr` length-prefix tier delta.
- PNP-001-MUST-007 (AAD binding) now reads as: AEAD AAD is `ratchet_public_key || CBOR(cleartext_header)`. The session AEAD tag therefore binds both the Double Ratchet identity of the message and every relay-visible field.

**v0.2 (2026-04-17) — Harmonization pass**

- Status bumped from DRAFT to CANDIDATE (spec is now the authoritative oracle for conformance tests).
- Extended §3.4 Message Types table to include codes 0x07–0x11 from PNP-007 and PNP-009. PNP-001 is now the canonical message-type registry.
- Added §5.4 "Replay / Seen-Message Windows" — single table consolidating all cache retention and timestamp windows that appear across this spec.
- Added §6.6 "AEAD Layering" — clarifies that PNP-001 governs the *session-layer* AEAD and that PNP-004 onion layers have independent cipher rules (ChaCha20-Poly1305 only; no negotiation).
- Added §9 "Nonce Construction Catalog" — names the four nonce schemes used across the stack (`N-SESSION`, `N-HANDSHAKE`, `N-ONION`, `N-SENDERKEY`) to prevent cross-context nonce misuse.
- Added numbered normative clause IDs (`PNP-001-MUST-NNN`, `-SHOULD-NNN`, `-MAY-NNN`) to every RFC 2119 statement. IDs are stable across versions — new clauses receive new numbers, retired clauses retain their numbers as `RESERVED`.
- Completed §8 cross-reference table.

**v0.1 (2026-04-10)** — Initial draft.

---

## Implementation Note

This document is a protocol design target. Current code implements envelope and padding helpers, but the user-facing PWA path does not yet make all traffic indistinguishable from normal HTTPS traffic end to end.

## 1. Overview

The ParolNet Wire Protocol (PWP) defines the envelope format for all messages transmitted between peers in the ParolNet network. Every message -- whether it carries user content, control signaling, handshake material, or decoy traffic -- is encapsulated in a single, uniform envelope. The protocol is designed so that an observer with access to the wire sees only fixed-size, encrypted, authenticated blobs that are indistinguishable from one another in structure and from normal HTTPS traffic in transit.

PWP sits above the transport layer (TLS 1.3 over TCP or WebSocket) and below session-layer protocols such as the Handshake Protocol (PNP-002) and application-layer message handling.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

- **Peer**: Any node in the ParolNet network, identified by a PeerId.
- **PeerId**: A 32-byte value computed as `SHA-256(Ed25519_identity_public_key)`.
- **Envelope**: The complete wire-level unit of transmission.
- **Bucket Size**: One of the four fixed sizes to which all envelopes are padded: 256, 1024, 4096, or 16384 bytes.
- **Coarsened Timestamp**: A Unix timestamp truncated to the nearest 5-minute (300-second) boundary: `floor(unix_epoch_seconds / 300) * 300`.
- **Decoy Message**: A message carrying no semantic content, generated to provide cover traffic.
- **Hop**: One relay forwarding step between the origin and the destination.
- **AEAD**: Authenticated Encryption with Associated Data. The session-layer AEAD cipher is either ChaCha20-Poly1305 (primary / MTI) or AES-256-GCM (optional). Relay-layer (onion) AEAD cipher rules are defined in PNP-004; they are scoped independently and are NOT negotiable.
- **Clause ID**: A stable identifier of the form `PNP-XXX-(MUST|SHOULD|MAY)-NNN` placed at the end of a normative sentence. Used by the `parolnet-conformance` test suite and the `cargo xtask clauses` coverage gate.

## 3. Message Format

### 3.1 Envelope Structure

Every envelope on the wire is a single definite-length CBOR array with four elements. The final serialized byte sequence is the envelope as it appears on the wire.

```
Envelope = CBOR Array(4 items):
  [0] cleartext_header    : CBOR array (see §3.2)
  [1] ratchet_header      : CBOR array [ratchet_pub(32B), prev_chain_len, msg_number]
  [2] encrypted_payload   : bstr   -- ciphertext including 16-byte AEAD tag (§3.5)
  [3] padding             : bstr   -- wire-level random padding (§3.6)
```

```
+-----------+-----------+---------------------+------------+
| cleartext | ratchet   | encrypted_payload   |  padding   |
| header    | header    | (ciphertext||tag)   | (bstr)     |
+-----------+-----------+---------------------+------------+
|<---------- total CBOR length == bucket size ------------>|
```

The total envelope (the serialized CBOR array, including its own outer length prefixes) MUST equal exactly one of the bucket sizes: 256, 1024, 4096, or 16384 bytes. **PNP-001-MUST-001**

Using an array (rather than a map) at the outer level keeps the envelope compact enough that small messages still fit in the 256-byte bucket after accounting for the cleartext header, the ratchet header, and AEAD overhead. The ratchet header is carried on the wire so the receiver can advance the Double Ratchet state before AEAD decryption; it is NOT covered by the session AEAD tag but it IS covered through the `ratchet_public_key` component of the AEAD AAD (see §3.3 / MUST-007).

### 3.2 Cleartext Header

The cleartext header is the only portion of the envelope visible to intermediary relays. It is CBOR-encoded (RFC 8949) as a definite-length CBOR array. **PNP-001-MUST-002**

```
Cleartext Header = CBOR Array(6 or 7 items):
  [0] version        : uint8       -- Protocol version. MUST be 0x01 for this spec.
  [1] msg_type        : uint8       -- Message type code (see Section 3.4).
  [2] dest_peer_id    : bstr(32)   -- Destination PeerId. 32 bytes.
  [3] message_id      : bstr(16)   -- Random 128-bit message identifier.
  [4] timestamp       : uint64     -- Coarsened Unix timestamp (5-min bucket).
  [5] ttl_and_hops    : uint16     -- Upper 8 bits: TTL (max remaining hops).
                                      Lower 8 bits: hop count (hops so far).
  [6] source_hint     : bstr(32)   -- OPTIONAL. Source PeerId hint.
                        / null         If omitted for anonymity, encode as CBOR null.
```

The `version` field MUST be set to 0x01 for this specification. **PNP-001-MUST-003**

Field details:

| Field | CBOR Major Type | Size | Notes |
|-------|----------------|------|-------|
| version | 0 (unsigned int) | 1 byte value | MUST be 1 |
| msg_type | 0 (unsigned int) | 1 byte value | See Section 3.4 |
| dest_peer_id | 2 (byte string) | 32 bytes | SHA-256 of destination Ed25519 public key |
| message_id | 2 (byte string) | 16 bytes | Cryptographically random, unique per message |
| timestamp | 0 (unsigned int) | 8 bytes value | `floor(now / 300) * 300` |
| ttl_and_hops | 0 (unsigned int) | 2 byte value | TTL in bits [15:8], hops in bits [7:0] |
| source_hint | 2 (byte string) / 7 (simple: null) | 32 bytes or 1 byte | OPTIONAL sender identity hint |

### 3.3 Encrypted Payload

The encrypted payload carries the actual message content. It is encrypted using the session AEAD (ChaCha20-Poly1305 or AES-256-GCM) derived from the Double Ratchet session state. **PNP-001-MUST-004**

```
Plaintext (before encryption) = CBOR Map (keys in lexicographic order):
  {
    "body"         : bstr,            -- The application-layer content
                                      -- (one fragment's slice if is_fragment=1).
    "chain"        : uint32,          -- Ratchet chain index.
    "flags"        : uint8,           -- Bitfield (see below).
    "fragment_id"  : bstr (16 bytes), -- OPTIONAL; present iff is_fragment=1.
                                      -- See §3.9.
    "fragment_seq" : uint32,          -- OPTIONAL; present iff is_fragment=1.
                                      -- See §3.9.
    "seq"          : uint64           -- Sequence number within the Double
                                      -- Ratchet chain (independent of fragment_seq).
  }
```

The plaintext CBOR map MUST NOT contain a `pad` field. Wire-level padding is carried as a sibling of `encrypted_payload` at the envelope level (see §3.1 and §3.6); it is NOT inside the AEAD ciphertext.

Flags bitfield:

| Bit | Meaning |
|-----|---------|
| 0 | `is_decoy`: 1 if this is a decoy message |
| 1 | `requires_ack`: 1 if sender expects acknowledgment |
| 2 | `is_fragment`: 1 if this is a fragment of a larger message |
| 3 | `is_final_fragment`: 1 if this is the last fragment |
| 4-7 | Reserved, MUST be 0 **PNP-001-MUST-005** |

The AEAD nonce for the session layer MUST be constructed per scheme `N-SESSION` defined in §9:

```
nonce (12 bytes) = chain_index (4 bytes, big-endian) || seq_number (8 bytes, big-endian)
```

**PNP-001-MUST-006**

The AEAD additional authenticated data (AAD) MUST be the concatenation of the sender's current Double Ratchet public key (the `ratchet_public_key` field from the wire ratchet header, 32 bytes) followed by the serialized CBOR bytes of the cleartext header:

```
AAD = ratchet_public_key || CBOR(cleartext_header)
```

**PNP-001-MUST-007**

This construction makes the AEAD tag tamper-evident with respect to (a) every relay-visible field in the cleartext header, and (b) the Double Ratchet identity of the sending state. A relay cannot rewrite `dest_peer_id`, `msg_type`, `message_id`, `timestamp`, `ttl_and_hops`, or `source_hint` without causing AEAD tag verification to fail on the receiver. An attacker cannot attach a stolen ciphertext to a different ratchet public key without the same tag failure. The `ratchet_header` fields `previous_chain_length` and `message_number` are NOT part of AAD; they are used only to drive the receiver's key-derivation step, whose output becomes the AEAD key itself — any tampering there produces a key that does not match the sender and therefore also fails AEAD verification.

### 3.4 Message Types

Codes 0x01–0x06 are allocated by this specification. Codes 0x07–0x0B are allocated by PNP-007 (Media & File Transfer). Codes 0x0C–0x12 are allocated by PNP-009 (Group Communication). Code 0x13 is allocated by PNP-002 (Handshake Protocol) for identity rotation. PNP-001 is the canonical registry — new message types MUST be assigned here in future revisions.

| Code | Name | Allocated By | Description |
|------|------|-------------|-------------|
| 0x01 | TEXT | PNP-001 | User text message |
| 0x02 | FILE | PNP-001 | File transfer payload or fragment |
| 0x03 | CONTROL | PNP-001 | Session control (ack, typing indicator, read receipt) |
| 0x04 | DECOY | PNP-001 | Cover traffic; indistinguishable from real messages |
| 0x05 | HANDSHAKE | PNP-001 | Session establishment (PNP-002 messages) |
| 0x06 | RELAY_CONTROL | PNP-001 | Relay-layer signaling (routing, keepalive, congestion) |
| 0x07 | AUDIO | PNP-007 | Audio stream frame (Opus/Codec2) |
| 0x08 | VIDEO | PNP-007 | Video stream frame |
| 0x09 | FILE_CHUNK | PNP-007 | File transfer chunk (see PNP-007 §5) |
| 0x0A | FILE_CONTROL | PNP-007 | File transfer control signaling |
| 0x0B | CALL_SIGNAL | PNP-007 | Call state-machine signaling |
| 0x0C | GROUP_TEXT | PNP-009 | Group text message (sender-key encrypted) |
| 0x0D | GROUP_CALL_SIGNAL | PNP-009 | Group call state-machine signaling |
| 0x0E | GROUP_FILE_OFFER | PNP-009 | Group file offer |
| 0x0F | GROUP_FILE_CHUNK | PNP-009 | Group file transfer chunk |
| 0x10 | GROUP_FILE_CONTROL | PNP-009 | Group file transfer control |
| 0x11 | SENDER_KEY_DISTRIBUTION | PNP-009 | Sender key distribution |
| 0x12 | GROUP_ADMIN | PNP-009 | Group admin operation (invite, member add/remove; see PNP-009 §6.2) |
| 0x13 | IDENTITY_ROTATE | PNP-002 | Signed identity rotation notification (see PNP-002 §7) |

Codes 0x14–0xFF are reserved for future assignment.

Implementations MUST treat unrecognized message type codes as DECOY and silently discard them after decryption. **PNP-001-MUST-008**

### 3.5 MAC

The AEAD tag is the trailing 16 bytes of `encrypted_payload` (produced in-place by ChaCha20-Poly1305 or AES-256-GCM). There is NO separate `mac` field on the wire. The tag authenticates the ciphertext and the AAD defined in §3.3 (`ratchet_public_key || CBOR(cleartext_header)`). **PNP-001-MUST-009**

### 3.6 Padding Scheme

All envelopes MUST be padded to the smallest bucket size that can accommodate the complete envelope after CBOR serialization. **PNP-001-MUST-010** The bucket sizes are:

```
BUCKET_SIZES = [256, 1024, 4096, 16384]
```

Padding is applied to the serialized envelope (wire level), NOT to the plaintext inside the AEAD. The `padding` field of the envelope absorbs whatever bytes are needed so that the final CBOR byte sequence is exactly one bucket size long. The padding bytes are cryptographically random — a relay MUST NOT be able to distinguish padding from any other `bstr` content on the wire.

The padding procedure is:

1. Serialize the cleartext header to CBOR bytes: `H`.
2. Encrypt the plaintext map (per §3.3) under the session AEAD using `AAD = ratchet_public_key || H`. Let the ciphertext (including the 16-byte tag) be `C`.
3. Serialize the envelope `[cleartext_header, ratchet_header, C, bstr(0)]` (empty padding) to CBOR bytes and measure its length `L0`.
4. Select the smallest bucket size `B` such that `B >= L0`. If `L0` exceeds the largest bucket, the message MUST be fragmented. **PNP-001-MUST-011**
5. Compute an initial `pad_length = B - L0 - cbor_bstr_header_size(B - L0)` and fill `pad_length` cryptographically random bytes into the `padding` field. **PNP-001-MUST-012**
6. Re-serialize the envelope and measure its length `L1`. If `L1 != B` (this happens when growing `padding` crossed a CBOR `bstr` length-prefix tier boundary at 24 / 256 / 65536 bytes), adjust `pad_length` by `B - L1` and re-serialize once. One fixpoint iteration is sufficient because the CBOR length-prefix overhead is monotonic in `pad_length`.
7. The final envelope bytes MUST be exactly `B` bytes long. **PNP-001-MUST-013**

Implementations MUST NOT leak the original message size through timing, error responses, or any other side channel. **PNP-001-MUST-014**

### 3.7 Decoy Messages

Decoy messages MUST be constructed identically to real messages:

1. The `msg_type` in the cleartext header MUST be set to 0x04 (DECOY) by default. **PNP-001-MUST-015** However, when decoys are used for traffic analysis resistance, an implementation MAY set `msg_type` to any valid type code (such as 0x01) so that even the type field does not distinguish real from decoy traffic at the cleartext header level. **PNP-001-MAY-001**
2. The `dest_peer_id` SHOULD be a valid PeerId known to the sender (e.g., a recent contact or a well-known relay). **PNP-001-SHOULD-001**
3. The `body` field MUST contain cryptographically random bytes of a plausible length. **PNP-001-MUST-016**
4. The `is_decoy` flag (bit 0 of `flags`) MUST be set to 1 inside the encrypted payload so the recipient can discard it after decryption. **PNP-001-MUST-017**
5. All other fields (message_id, timestamp, ttl_and_hops) MUST be populated normally. **PNP-001-MUST-018**

An intermediary relay MUST NOT be able to distinguish a decoy from a real message. **PNP-001-MUST-019**

### 3.8 CBOR Encoding Rules

1. All CBOR encoding MUST use definite-length encoding. Indefinite-length encoding MUST NOT be used. **PNP-001-MUST-020**
2. Integer values MUST use the shortest CBOR encoding that can represent the value. **PNP-001-MUST-021**
3. Byte strings MUST use definite-length encoding. **PNP-001-MUST-022**
4. Map keys in the encrypted payload MUST be text strings and MUST appear in lexicographic order. **PNP-001-MUST-023**
5. Implementations MUST reject envelopes containing duplicate map keys. **PNP-001-MUST-024**
6. Implementations MUST ignore unknown map keys in the encrypted payload (forward compatibility). **PNP-001-MUST-025**

### 3.9 Fragmentation

Application bodies that would produce an envelope larger than the 16384-byte ceiling (§3.6) MUST be fragmented. Each fragment is a fully-formed envelope (own ratchet header, own AEAD tag, bucket-padded per §3.6) carrying one slice of the body plus reassembly metadata.

#### 3.9.1 Fragment identity & ordering

**PNP-001-MUST-053**: When a sender decides to fragment a message it MUST generate a cryptographically random 16-byte `fragment_id` and include it in the plaintext map (§3.3) of every fragment produced from that message. A `fragment_id` MUST NOT be reused across different source messages.

**PNP-001-MUST-054**: Each fragment MUST carry a `fragment_seq` value in the plaintext map — a 0-based monotonically increasing `uint32` indexing its position in the original body. The first fragment has `fragment_seq = 0`.

**PNP-001-MUST-055**: Exactly one fragment in a message MUST have its `is_final_fragment` bit set (§3.3 bit 3); that fragment MUST also have the highest `fragment_seq` value of the message.

**PNP-001-MUST-056**: The `is_fragment` bit (§3.3 bit 2) MUST be set on every fragment of a fragmented message. If `is_fragment = 0` the `fragment_id` and `fragment_seq` fields MUST be absent from the plaintext map; if `is_fragment = 1` both fields MUST be present (MUST-024 still forbids duplicate keys regardless).

#### 3.9.2 AAD binding

**PNP-001-MUST-057**: When `is_fragment = 1`, the AEAD AAD defined in §3.3 is extended to `ratchet_public_key || CBOR(cleartext_header) || fragment_id || fragment_seq_be`, where `fragment_seq_be` is the 4-byte big-endian encoding of `fragment_seq`. This prevents a relay from reshuffling fragments across messages or splicing a fragment from one message into another while keeping the AEAD tag valid.

#### 3.9.3 Reassembly

**PNP-001-MUST-058**: Receivers MUST buffer fragments keyed by `(sender_peer_id, fragment_id)` until every `fragment_seq` from `0` through the seq of the `is_final_fragment = 1` fragment has been observed, then concatenate the `body` fields in `fragment_seq` order to produce the reassembled message. Fragments arriving out of order MUST be held without dropping until reassembly completes or the timeout expires.

**PNP-001-MUST-059**: Receivers MUST enforce a 30-second reassembly timeout measured from the arrival of the first fragment of a given `(sender, fragment_id)` tuple. On timeout the buffer MUST be dropped without reassembly and MUST NOT be retained.

**PNP-001-MUST-060**: Receivers MUST enforce an 8-messages-per-sender in-flight cap and a 256-fragments-per-message limit. Excess fragments on either limit MUST be dropped; the receiver MAY decrement the sender's peer score per PNP-004 §5.7 if the limits are repeatedly exceeded.

**PNP-001-MUST-061**: Duplicate fragments (same `(sender_peer_id, fragment_id, fragment_seq)` tuple, AEAD-verified) MUST be silently discarded; the first successful instance is retained. A duplicate whose AEAD verification fails MUST cause the original buffer to be dropped under the assumption an attacker is attempting content substitution.

**PNP-001-MUST-062**: Reassembled messages inherit the `msg_type` and all other cleartext-header fields from the fragment with `fragment_seq = 0`; receivers MUST reject the reassembled message if fragments within the same `fragment_id` carry inconsistent values for `msg_type`, `dest_peer_id`, or `source_hint`.

## 4. State Machine

The Wire Protocol itself is stateless at the envelope level. Each envelope is independently parseable. Session state is managed by higher-layer protocols (PNP-002 for handshakes, Double Ratchet for ongoing sessions).

Envelope processing follows this flow:

```
                    +------------------+
                    |  Receive Bytes   |
                    +--------+---------+
                             |
                    +--------v---------+
                    | Validate Length   |
                    | (must be bucket)  |
                    +--------+---------+
                             |
                   +---------v----------+
                   | Decode Cleartext   |
                   | Header (CBOR)      |
                   +---------+----------+
                             |
              +--------------+--------------+
              |                             |
     +--------v--------+          +--------v--------+
     | Dest is self?    |          | Dest is other?  |
     | Decrypt payload  |          | Relay / drop    |
     +--------+---------+          | (check TTL)     |
              |                    +-----------------+
     +--------v---------+
     | Validate MAC     |
     +--------+---------+
              |
     +--------v---------+
     | Decode payload   |
     | (CBOR map)       |
     +--------+---------+
              |
     +--------v---------+
     | Check is_decoy   |-----> Discard silently
     +--------+---------+
              |
     +--------v---------+
     | Dispatch to       |
     | handler by type   |
     +-------------------+
```

## 5. Processing Rules

### 5.1 Sending

1. A sender MUST populate all cleartext header fields. **PNP-001-MUST-026**
2. A sender MUST set `timestamp` to the current coarsened timestamp. Implementations MUST NOT use the actual wall-clock time directly. **PNP-001-MUST-027**
3. A sender MUST generate a cryptographically random `message_id` for each envelope. **PNP-001-MUST-028**
4. A sender MUST set `ttl_and_hops` with TTL in the upper 8 bits and hop count 0x00 in the lower 8 bits. **PNP-001-MUST-029**
5. A sender SHOULD set a default TTL of 7. **PNP-001-SHOULD-002** A sender MAY use a lower TTL for latency-sensitive messages. **PNP-001-MAY-002**
6. A sender SHOULD omit `source_hint` (encoding it as CBOR null) unless the recipient needs it for initial contact resolution. **PNP-001-SHOULD-003**
7. A sender MUST pad the envelope to the appropriate bucket size per Section 3.6. **PNP-001-MUST-030**
8. A sender SHOULD generate decoy messages at random intervals to maintain a minimum baseline traffic rate. **PNP-001-SHOULD-004**

### 5.2 Relaying

1. A relay MUST increment the hop count (lower 8 bits of `ttl_and_hops`) by 1. **PNP-001-MUST-031**
2. A relay MUST drop the envelope if the hop count equals or exceeds the TTL (upper 8 bits). **PNP-001-MUST-032**
3. A relay MUST NOT modify any other cleartext header fields. **PNP-001-MUST-033**
4. A relay MUST NOT attempt to decrypt the payload. **PNP-001-MUST-034**
5. A relay SHOULD forward the envelope within 50ms plus a random jitter of 0-200ms to frustrate timing correlation. **PNP-001-SHOULD-005**
6. A relay MAY batch-forward multiple envelopes simultaneously. **PNP-001-MAY-003**
7. A relay MUST maintain a seen-message cache keyed by `message_id` and MUST drop duplicate envelopes. **PNP-001-MUST-035** The cache SHOULD retain entries for at least 30 minutes. **PNP-001-SHOULD-006**

### 5.3 Receiving

1. A receiver MUST verify that the envelope length matches a valid bucket size. If not, the envelope MUST be silently discarded. **PNP-001-MUST-036**
2. A receiver MUST verify the AEAD authentication tag. If verification fails, the envelope MUST be silently discarded. **PNP-001-MUST-037**
3. A receiver MUST check the `message_id` against a replay cache. Duplicate message IDs MUST be silently discarded. **PNP-001-MUST-038** The cache SHOULD retain entries for at least 60 minutes. **PNP-001-SHOULD-007**
4. A receiver MUST verify the timestamp is within an acceptable window. The timestamp MUST NOT be more than 30 minutes (6 buckets) in the past or more than 1 bucket (5 minutes) in the future. Messages outside this window MUST be discarded. **PNP-001-MUST-039**
5. A receiver SHOULD process decoy messages (is_decoy flag set) identically to real messages up to the point of application delivery, then discard them. **PNP-001-SHOULD-008**

### 5.4 Replay / Seen-Message Windows

Several caches and windows are defined across this spec. They serve different purposes and have different scopes. This table is normative.

| Window | Purpose | Minimum Duration | Where |
|--------|---------|------------------|-------|
| Timestamp freshness (past) | Reject stale messages | 30 minutes (6 coarsened buckets) | §5.3 item 4 |
| Timestamp freshness (future) | Reject future-dated messages | 5 minutes (1 coarsened bucket) | §5.3 item 4 |
| Relay seen-message cache | Drop duplicate relays | 30 minutes | §5.2 item 7 |
| Receiver replay cache | Reject replayed deliveries | 60 minutes | §5.3 item 3 |

QR-code freshness (30 minutes) is defined in PNP-003 §5.1.6 and is unrelated to the envelope-level windows above.

## 6. Security Considerations

1. **Indistinguishability**: The bucket padding scheme ensures that message lengths do not leak content type or size. Implementations MUST NOT compress payloads before encryption, as compression ratios can leak information about plaintext content (CRIME/BREACH-style attacks). **PNP-001-MUST-040**

2. **Nonce Reuse**: The nonce construction from chain_index and sequence_number guarantees uniqueness within a Double Ratchet session. Implementations MUST NOT reuse a (key, nonce) pair. **PNP-001-MUST-041** If the sequence number overflows 2^64, the session MUST be rekeyed. **PNP-001-MUST-042**

3. **Replay Protection**: The combination of message_id uniqueness checking and timestamp windowing prevents replay attacks. The seen-message cache MUST be persisted across brief restarts (up to 60 minutes of downtime). **PNP-001-MUST-043**

4. **Relay Integrity**: Relays can observe cleartext headers. The `dest_peer_id` reveals the intended recipient to every relay on the path. For stronger anonymity, implementations SHOULD use onion-style layered encryption (PNP-004) where each relay only sees the next hop, not the final destination. **PNP-001-SHOULD-009**

5. **Timing Attacks**: Random relay jitter (§5.2.5) provides partial protection. Implementations SHOULD also implement constant-rate traffic shaping (PNP-006) to prevent traffic analysis. **PNP-001-SHOULD-010**

6. **AEAD Layering**: PNP-001 defines the **session-layer AEAD** applied to the encrypted payload of every envelope. ChaCha20-Poly1305 MUST be the default session-layer AEAD. **PNP-001-MUST-044** AES-256-GCM MAY be used as the session-layer AEAD when hardware AES acceleration is available and both peers explicitly agree during the PNP-002 handshake. **PNP-001-MAY-004** An implementation MUST NOT downgrade from ChaCha20-Poly1305 to AES-256-GCM without explicit peer negotiation. **PNP-001-MUST-045**

   PNP-004 onion layers use a separate, independently scoped AEAD: ChaCha20-Poly1305 ONLY, with no negotiation (see PNP-004 §5.1). The session-layer cipher chosen here does NOT affect the onion-layer cipher.

## 7. Privacy Considerations

1. **Source Anonymity**: The `source_hint` field is OPTIONAL and SHOULD be omitted (CBOR null) in most cases. When it is present, it reveals the sender's identity to any relay that can observe the cleartext header.

2. **Destination Privacy**: The `dest_peer_id` is always visible in the cleartext header. This is a necessary trade-off for relay routing. To mitigate this, peers SHOULD use ephemeral forwarding PeerIds that rotate periodically and are known only to their contacts. **PNP-001-SHOULD-011**

3. **Timestamp Coarsening**: Timestamps are coarsened to 5-minute buckets to prevent precise timing correlation. Implementations MUST NOT include sub-bucket timing information anywhere in the envelope. **PNP-001-MUST-046**

4. **Traffic Analysis**: Fixed bucket sizes and decoy traffic reduce the effectiveness of traffic analysis. However, long-term observation of traffic patterns (volume, timing, source/destination pairs) can still reveal communication patterns. Implementations SHOULD use constant-rate traffic scheduling (PNP-006) where feasible. **PNP-001-SHOULD-012**

5. **Message ID Linkability**: The `message_id` is random and does not link to sender identity. However, if the same message is observed at multiple points in the relay path, the `message_id` can be used to correlate them. Implementations MAY re-encrypt and assign a new `message_id` at each relay hop at the cost of losing deduplication capability. **PNP-001-MAY-005**

## 8. Cross-Protocol References

| Spec | Relationship |
|------|-------------|
| PNP-002 (Handshake) | HANDSHAKE message type (0x05) carries PNP-002 payloads. Session AEAD cipher is negotiated in PNP-002 handshake. |
| PNP-003 (Bootstrap) | Initial session keys derived from PNP-003 bootstrap before any PNP-001 envelope is exchanged. |
| PNP-004 (Relay Circuit) | Envelopes may be carried inside relay circuit DATA cells. Onion-layer AEAD is scoped separately (see §6.6). |
| PNP-005 (Gossip Mesh) | Gossip messages are transmitted as PNP-001 envelopes. |
| PNP-006 (Traffic Shaping) | Governs timing and padding behavior for envelope transmission. |
| PNP-007 (Media & File) | Allocates message-type codes 0x07–0x0B (§3.4). |
| PNP-008 (Relay Federation) | Directory-sync messages are PNP-001 envelopes with RELAY_CONTROL (0x06). |
| PNP-009 (Group Communication) | Allocates message-type codes 0x0C–0x12 (§3.4). |
| PNP-002 (Handshake Protocol) | Allocates message-type code 0x13 IDENTITY_ROTATE (§3.4) for H5 identity rotation. |

## 9. Nonce Construction Catalog

Multiple independently scoped AEAD contexts exist in the ParolNet stack. Each uses its own nonce construction. This catalog names each scheme so that implementations and specifications can reference them unambiguously. **Cross-context nonce reuse is a critical security failure**; each scheme is scoped to one context and MUST NOT be reused elsewhere.

| Scheme | Context | Construction | Size | Defined |
|--------|---------|--------------|------|---------|
| `N-SESSION` | Session-layer envelope AEAD (§3.3) | `chain_index (4B BE) \|\| seq_number (8B BE)` | 12 bytes | PNP-001 §3.3 |
| `N-HANDSHAKE` | PNP-002 X3DH-derived handshake AEAD | HKDF-SHA-256 of shared secret with context label | 12 bytes | PNP-002 §5.2 |
| `N-ONION` | PNP-004 onion-layer AEAD (per hop) | `nonce_seed (12B) XOR counter (12B BE)` | 12 bytes | PNP-004 §5.1.5 |
| `N-SENDERKEY` | PNP-009 group sender-key AEAD | `SHA-256(signing_public_key)[0..4] \|\| chain_index (8B BE)` | 12 bytes | PNP-009 §5.4 |

Implementations MUST NOT construct an AEAD nonce by any scheme other than those listed here in the context specified. **PNP-001-MUST-047** Future nonce schemes MUST be added to this catalog in a future revision of PNP-001.

## 10. Outer Relay Frame

The CBOR envelope defined in §3 is the *inner* wire unit — it is what end-to-end recipients decrypt. When a client pushes that envelope through the WebSocket to a relay, the envelope rides as the `payload` field of a JSON-encoded **outer relay frame**. This section normatively defines that outer frame. Logically it is a layer **above** §3 — the relay sees only the outer frame, never the plaintext of the envelope it carries.

### 10.1 Outer Frame Schema

The outer frame is a JSON object with four required fields:

```
OuterMessageFrame = {
  "type"    : "message",     -- string literal
  "to"      : hex(bstr32),   -- destination PeerId (hex-encoded)
  "token"   : hex(bstr),     -- CBOR-serialized Privacy Pass Token (hex-encoded)
  "payload" : hex(bstr)      -- the §3 envelope, hex-encoded
}
```

The frame MUST carry a non-empty `token` field. There is no `from` field. **PNP-001-MUST-048** The relay therefore does not see a sender identity on any per-frame send; sender authentication is discharged at *issuance* time (§10.2), not at *spend* time.

Any frame that reaches the relay without a valid, non-empty `token` field MUST be dropped silently — no error response is returned, so an adversary cannot probe which identity a frame belonged to.

### 10.2 Token Auth (Privacy Pass)

ParolNet relays authenticate per-frame sends with [RFC 9578] Privacy Pass tokens backed by a [RFC 9497] VOPRF. The ciphersuite is **`Ristretto255-SHA512`** (RFC 9497 §4.1).

**Issuance.** A client presents its long-term Ed25519 identity to the relay over `POST /tokens/issue`:

```
TokenIssueRequest = CBOR map {
  "ed25519_pubkey_hex"    : tstr,                -- 32-byte key, hex
  "ed25519_sig_hex"       : tstr,                -- 64-byte signature, hex
  "challenge_nonce_hex"   : tstr,                -- 32-byte nonce, hex
  "blinded_bytes_list"    : [ bstr, bstr, ... ]  -- up to `budget_per_epoch`
                                                  --   serialized BlindedElements
}
```

The relay MUST reject any issuance request whose Ed25519 signature does not verify under the supplied public key over the supplied challenge nonce. **PNP-001-MUST-052** On success the relay runs `blind_evaluate` (RFC 9497 §3.3.2) on each `BlindedElement` under the **active epoch's** VOPRF secret and returns a `TokenIssueResponse`:

```
TokenIssueResponse = CBOR map {
  "epoch_id"     : bstr(4),         -- opaque 4-byte epoch identifier
  "activated_at" : uint,            -- Unix seconds the epoch started
  "expires_at"   : uint,            -- Unix seconds it fully expires (past grace)
  "ciphersuite"  : tstr("ristretto255-SHA512"),
  "budget"       : uint,            -- per-epoch budget
  "evaluated"    : [ bstr, ... ]    -- serialized EvaluationElements
}
```

The client unblinds each `EvaluationElement` via `OprfClient::finalize` to recover the per-token output, packages each as a `Token`, and stores the batch.

**Spend.** Each outer frame's `token` is the hex-encoded CBOR serialization of:

```
Token = CBOR map {
  "epoch_id"    : bstr(4),
  "nonce"       : bstr(32),   -- the 32-byte VOPRF input chosen at blind time
  "evaluation"  : bstr        -- the client-unblinded VOPRF output
}
```

On receiving an outer frame the relay MUST:

1. Parse the `token` field and identify its epoch by `epoch_id`. If the epoch id matches neither the active nor the prior-within-grace epoch, reject.
2. Recompute `OprfServer::evaluate(sk, nonce)` under the located epoch's VOPRF secret and compare against `token.evaluation` in constant time. If the comparison fails, reject. **PNP-001-MUST-049**
3. Check the per-epoch spent-set for `nonce`. If the nonce is already present, reject. Otherwise insert it and route the frame. **PNP-001-MUST-050**

All three rejection paths drop the frame silently (no error to the sender).

**Epoch rotation.** Each epoch lasts **3600 seconds**. At every epoch boundary the relay generates a fresh VOPRF secret for the new epoch and retains the previous epoch's secret for a **300-second grace window** so tokens that were issued just before the boundary still verify. Once the grace window elapses, the prior secret and its spent-set MUST be dropped. **PNP-001-MUST-051**

| Parameter | Value |
|-----------|-------|
| `epoch_secs` | 3600 |
| `grace_secs` | 300 |
| `budget_per_epoch` | 8192 |
| Ciphersuite | `Ristretto255-SHA512` (RFC 9497 §4.1) |

**Zeroization.** The relay's implementation MUST hold the VOPRF server secret behind a `Zeroize + ZeroizeOnDrop` wrapper so epoch rotation leaves no secret residue in freed heap memory (see `CLAUDE.md` §"Security Invariants").

**Rate-limit.** Each identity is entitled to at most one `TokenIssueResponse` per active epoch; repeat requests from the same `ed25519_pubkey_hex` within a single epoch return `429 Too Many Requests`.

### 10.3 Cross-References

| Construct | Where |
|-----------|-------|
| `Token` type, `TokenAuthority`, epoch rotation | `crates/parolnet-relay/src/tokens.rs` |
| `POST /tokens/issue` + frame router | `crates/parolnet-relay-server/src/main.rs` |
| VOPRF crate | `voprf = "0.5"` (audited, RustCrypto-adjacent) |

[RFC 9497]: https://www.rfc-editor.org/rfc/rfc9497.html
[RFC 9578]: https://www.rfc-editor.org/rfc/rfc9578.html
