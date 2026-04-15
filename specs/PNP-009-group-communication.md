# PNP-009: ParolNet Group Communication Protocol

### Status: DRAFT
### Version: 0.1
### Date: 2026-04-15

---

## Implementation Note

This specification describes the group-communication design target. Current code includes sender-key primitives and core/WASM group helpers. The current PWA does not yet route group text, group files, or group calls through production 3-hop onion circuits as required below.

---

## 1. Overview

The ParolNet Group Communication Protocol (PGCP) extends ParolNet to support N-party communication, including group text messaging, group voice/video calls, and group file transfer. Groups enable up to 256 members for text messaging and file transfer, and up to 8 participants for real-time voice and video calls. All group traffic is routed through existing 3-hop onion relay circuits (PNP-004) and is indistinguishable from 1:1 traffic to any observer -- whether a network intermediary, a compromised relay, or a state-level adversary performing DPI.

PGCP employs two distinct cryptographic strategies optimized for their respective use cases:

1. **Sender Keys** for text and file messages: Each group member maintains a symmetric sender key chain. When sending a message, the sender encrypts once using their own chain key. All other members decrypt using their copy of the sender's chain. This achieves O(1) encryption cost regardless of group size, making it efficient for large groups.

2. **Full-mesh pairwise WebRTC** for voice and video calls: Group calls use direct pairwise Double Ratchet sessions between every pair of participants, preserving the post-compromise security guarantees of the Double Ratchet that sender keys cannot provide for real-time media streams.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

- **Sender Key**: A symmetric key chain held by a single group member and used to encrypt that member's outbound messages. All other group members hold a copy of the sender key to decrypt those messages.
- **Chain Key**: The current symmetric key in a sender key chain. Deriving the next chain key from the current one advances the chain.
- **Chain Index**: A monotonically increasing counter tracking the position in a sender key chain. Each message increments the index by one.
- **Group ID**: A 32-byte cryptographic identifier uniquely identifying a group. Derived from the creator's peer ID and a random nonce.
- **Group Role**: The privilege level of a group member. Either Admin (can modify group membership and metadata) or Member (can send and receive messages).
- **Sender Key Distribution**: A message containing a member's current sender key material, distributed to other group members via pairwise encrypted sessions.
- **Full-Mesh**: A network topology where every participant maintains a direct connection to every other participant. For N participants, this yields N*(N-1)/2 pairwise connections.
- **SFU (Selective Forwarding Unit)**: A server-side media relay that forwards streams selectively. ParolNet does NOT use SFUs; full-mesh is used instead to avoid centralized infrastructure.

## 3. Message Types

### 3.1 New Wire Protocol Message Types

The following message type codes extend the table in PNP-001 Section 3.4:

| Code | Name | Description |
|------|------|-------------|
| 0x0C | GROUP_TEXT | Group text message encrypted with sender key |
| 0x0D | GROUP_CALL_SIGNAL | Group call signaling (invite, join, leave, mute, end) |
| 0x0E | GROUP_FILE_OFFER | File offer to a group |
| 0x0F | GROUP_FILE_CHUNK | File transfer data chunk for a group |
| 0x10 | GROUP_FILE_CONTROL | File transfer control for a group (accept, cancel, pause, resume) |
| 0x11 | SENDER_KEY_DISTRIBUTION | Sender key distribution message |

These message types are carried in the `msg_type` field of the PNP-001 cleartext header. As with all message types, unrecognized codes MUST be treated as DECOY and silently discarded after decryption (PNP-001 Section 3.4).

### 3.2 MessageFlags Extension

Bit 0x10 of the MessageFlags field (PNP-001 Section 3.3) is defined as the **group message flag**. When set, the message is a group message and the payload MUST contain a `group_id` field. Implementations MUST check this bit to determine whether to process a message through the group decryption path or the pairwise decryption path.

## 4. Group Identifiers

### 4.1 Derivation

A Group ID is computed as:

```
GroupId = SHA-256(creator_peer_id || creation_nonce)
```

Where:
- `creator_peer_id` is the 32-byte PeerId of the group creator (SHA-256 of their Ed25519 public key, per PNP-001 Section 2.1).
- `creation_nonce` is a 32-byte cryptographically random value generated at group creation time.

### 4.2 Properties

1. **Collision resistance**: SHA-256 provides 128-bit collision resistance, making accidental GroupId collisions negligible.
2. **No central registry**: GroupIds are derived locally without coordination with any server or registry.
3. **Derivable by creator**: The creator can rederive the GroupId from their own PeerId and the stored creation nonce.
4. **Unlinkable to creator**: Without knowledge of the creation nonce, an observer cannot determine which peer created a given group.

### 4.3 Wire Representation

GroupId is always represented as a 32-byte (256-bit) value. In CBOR encoding, it is a byte string of length 32.

## 5. Sender Key Protocol

### 5.1 Key Generation

Each group member generates their own sender key chain consisting of:

1. A **chain key**: 32-byte random symmetric key, generated from a cryptographically secure random source.
2. An **Ed25519 signing key pair**: Used to sign each message, binding the ciphertext to the sender's identity.
3. A **chain index**: Initialized to 0, incremented with each message sent.

### 5.2 Sender Key Distribution

When a member joins a group or rotates their keys, they distribute their sender key material to all other group members. Distribution MUST occur via pairwise Double Ratchet sessions (PNP-002), ensuring that sender key material is never exposed in transit.

The distribution message is a SENDER_KEY_DISTRIBUTION (0x11) message type containing:

```
SenderKeyDistribution = {
  "sender_peer_id"    : bstr(32),    -- PeerId of the sender key owner
  "chain_key"         : bstr(32),    -- Current symmetric chain key
  "chain_index"       : uint32,      -- Current chain index
  "signing_public_key": bstr(32)     -- Ed25519 public key for signature verification
}
```

Each distribution message MUST be sent individually to each group member through their respective pairwise Double Ratchet session. The sender MUST NOT broadcast sender key material through the group channel.

### 5.3 Symmetric Ratchet

The sender key chain advances using HKDF-SHA-256:

```
next_chain_key = HKDF-SHA-256(
  salt: [0x02],
  ikm:  current_chain_key,
  info: "ParolNet_sender_chain_v1",
  len:  32
)
```

The message key for encryption is derived from the current chain key before advancing:

```
message_key = HKDF-SHA-256(
  salt: [0x01],
  ikm:  current_chain_key,
  info: "ParolNet_sender_key_v1",
  len:  32
)
```

After deriving the message key, the chain key MUST be advanced immediately. The previous chain key MUST be zeroized.

### 5.4 Encryption

Messages are encrypted using ChaCha20-Poly1305 (RFC 8439) with the derived message key. The 12-byte nonce is constructed as:

```
nonce = SHA-256(signing_public_key)[0..8] || chain_index.to_be_bytes()
```

Where:
- `SHA-256(signing_public_key)[0..8]` is the first 8 bytes of the SHA-256 hash of the sender's signing public key.
- `chain_index.to_be_bytes()` is the 4-byte big-endian encoding of the current chain index.

This construction ensures nonce uniqueness: the signing key prefix differentiates senders, and the monotonic chain index differentiates messages from the same sender.

### 5.5 Signature

After encryption, the sender computes an Ed25519 signature over the concatenation:

```
signature = Ed25519_Sign(signing_private_key, chain_index.to_be_bytes() || ciphertext)
```

Recipients MUST verify this signature before decryption. If verification fails, the message MUST be discarded.

### 5.6 SenderKeyMessage Wire Format

```
SenderKeyMessage = {
  "chain_index" : uint32,           -- Sender's chain index for this message
  "ciphertext"  : bstr,             -- ChaCha20-Poly1305 encrypted payload
  "signature"   : bstr(64)          -- Ed25519 signature over (chain_index || ciphertext)
}
```

### 5.7 Out-of-Order Handling

Messages may arrive out of order due to network conditions. Implementations MUST support out-of-order decryption by advancing the chain and storing skipped message keys:

1. If a received `chain_index` is greater than the expected next index, the implementation MUST derive and store all intermediate message keys up to the received index.
2. The maximum number of skipped keys that MAY be stored is MAX_SKIP = 1000. If a message would require skipping more than MAX_SKIP keys, it MUST be discarded.
3. Stored skipped message keys MUST be indexed by `(sender_peer_id, chain_index)`.
4. When a stored key is used for decryption, it MUST be deleted immediately after use.
5. Stored keys SHOULD be expired after 7 days to limit memory consumption.

### 5.8 Replay Protection

The chain index is monotonically increasing. Implementations MUST track the highest chain index received from each sender and MUST reject any message with a chain index that has already been processed (either directly or via a stored skipped key). Duplicate messages MUST be silently discarded.

## 6. Group Membership Management

### 6.1 Roles

Each group member holds one of two roles:

| Role | Permissions |
|------|------------|
| Admin | Send/receive messages, add/remove members, promote/demote admins, update group name, initiate key rotation |
| Member | Send/receive messages |

The group creator is automatically the first Admin. A group MUST have at least one Admin at all times.

### 6.2 Group Operations

Group membership and metadata changes are expressed as signed GroupOperation messages:

```
GroupOperation = {
  "group_id"   : bstr(32),          -- Target group
  "version"    : uint64,            -- Monotonically increasing operation version
  "op_type"    : tstr,              -- Operation type (see below)
  "payload"    : any,               -- Operation-specific payload
  "admin_id"   : bstr(32),          -- PeerId of the admin performing the operation
  "signature"  : bstr(64)           -- Ed25519 signature by admin's identity key
}
```

#### 6.2.1 Operation Types

| op_type | Payload | Description |
|---------|---------|-------------|
| "add_member" | `{ "peer_id": bstr(32), "role": "member" }` | Add a new member to the group |
| "remove_member" | `{ "peer_id": bstr(32) }` | Remove a member from the group |
| "promote_admin" | `{ "peer_id": bstr(32) }` | Promote a member to admin |
| "demote_admin" | `{ "peer_id": bstr(32) }` | Demote an admin to member |
| "update_name" | `{ "name": tstr }` | Change the group display name |
| "rotate_keys" | `{}` | Signal all members to rotate sender keys |

### 6.3 Operation Verification

1. The `signature` field MUST be an Ed25519 signature over the CBOR-encoded GroupOperation with the `signature` field set to a zero-length byte string.
2. Recipients MUST verify that `admin_id` corresponds to a current Admin of the group.
3. Recipients MUST verify the signature against the admin's known Ed25519 public key.
4. If verification fails, the operation MUST be discarded.

### 6.4 Version Ordering

The `version` field is a monotonically increasing counter. Recipients MUST reject any GroupOperation with a `version` less than or equal to the highest version they have already processed for that group. This prevents replay of stale operations.

### 6.5 Distribution

GroupOperations are distributed via the gossip protocol (PNP-005) using GossipPayloadType 0x04. The gossip payload contains the CBOR-encoded GroupOperation. Only group members participate in gossip for a given group's operations; non-members MUST discard gossip payloads for groups they do not belong to.

## 7. Key Rotation

### 7.1 Mandatory Rotation

Key rotation is REQUIRED in the following circumstances:

1. **Member removal**: When any member is removed from the group (voluntarily or by admin action), ALL remaining members MUST generate new sender keys and distribute them to all other remaining members. This prevents the removed member from decrypting future messages.
2. **Suspected compromise**: If any member suspects their key material has been compromised, they MUST immediately rotate their sender key and notify the group admin.

### 7.2 Recommended Rotation

Key rotation is RECOMMENDED:

1. Every 1000 messages sent by a given member.
2. Every 24 hours, regardless of message count.

Implementations SHOULD track message count and time since last rotation and initiate rotation automatically when either threshold is reached.

### 7.3 Rotation Procedure

1. The rotating member generates a new random 32-byte chain key.
2. The rotating member generates a new Ed25519 signing key pair.
3. The chain index is reset to 0.
4. The rotating member creates a new SenderKeyDistribution message containing the new key material.
5. The SenderKeyDistribution MUST be sent to every other group member via their pairwise Double Ratchet session.
6. Recipients MUST replace the old sender key state for that member with the new state upon receipt.
7. The old chain key and signing private key MUST be zeroized immediately after the new key is distributed.

### 7.4 Member Addition

When a new member is added to the group:

1. The admin sends an "add_member" GroupOperation (Section 6.2.1).
2. Each existing member sends their current SenderKeyDistribution to the new member via the pairwise Double Ratchet session between them and the new member.
3. The new member generates their own sender key chain and distributes it to all existing members.
4. Existing members do NOT rotate their keys on member addition (the new member receives the current chain state and can decrypt only messages sent after their addition).

## 8. Group Text Messaging

### 8.1 Sending

To send a text message to a group:

1. The sender constructs the plaintext message payload.
2. The plaintext MUST be padded per the PaddingStrategy trait (PNP-001 Section 3.6) before encryption.
3. The sender derives the message key from their current chain key (Section 5.3).
4. The sender encrypts the padded plaintext with ChaCha20-Poly1305 using the derived message key and constructed nonce (Section 5.4).
5. The sender signs the (chain_index || ciphertext) with their signing key (Section 5.5).
6. The sender constructs a SenderKeyMessage (Section 5.6).
7. The SenderKeyMessage is wrapped in a GROUP_TEXT (0x0C) envelope with the group message flag (0x10) set.
8. The envelope is sent to each of the N-1 other group members via their respective 3-hop onion circuits.

### 8.2 Receiving

To receive a group text message:

1. The recipient checks the group message flag (0x10) in MessageFlags.
2. The recipient looks up the sender's SenderKeyState by the sender's PeerId.
3. The recipient verifies the Ed25519 signature (Section 5.5). If verification fails, the message MUST be discarded.
4. The recipient checks the chain index for replay (Section 5.8). If the index has been seen, the message MUST be discarded.
5. If the chain index is ahead of the expected index, skipped keys are derived and stored (Section 5.7).
6. The recipient derives the message key and decrypts the ciphertext.
7. Padding is removed from the plaintext.
8. The chain key is advanced.

### 8.3 Delivery

Each group message MUST be sent individually to each recipient through their respective pairwise relay circuits. From the perspective of relay nodes, group messages are indistinguishable from 1:1 messages: each transmission is a standard PNP-001 envelope traversing a 3-hop circuit (PNP-004). The group semantics exist only at the application layer.

## 9. Group Call Protocol

### 9.1 Topology

Group calls use a **full-mesh** topology. Each pair of participants establishes a direct pairwise connection through separate 3-hop onion relay circuits. For N participants, this yields N*(N-1)/2 pairwise circuits.

The maximum number of participants in a group call is 8, yielding a maximum of 28 pairwise circuits at full mesh. This limit prevents resource exhaustion on participating nodes.

Sender keys are NOT used for group call media. Each pairwise media stream is encrypted using SRTP keys derived from the pairwise Double Ratchet session between the two participants (PNP-007 Sections 5.2, 6.6). This preserves the post-compromise security guarantees of the Double Ratchet for real-time streams.

### 9.2 Call Identifiers

Each group call is identified by a **Call ID**: a cryptographically random 128-bit (16-byte) value generated by the call initiator. The Call ID MUST be unique and MUST be generated using a cryptographically secure random source.

### 9.3 Signaling Messages

Group call signaling messages are carried as GROUP_CALL_SIGNAL (0x0D) message types. All signaling messages are CBOR-encoded maps:

```
GroupCallInvite = {
  "type"     : "invite",
  "call_id"  : bstr(16),            -- Random 128-bit call identifier
  "group_id" : bstr(32)             -- Group in which the call is initiated
}

GroupCallJoin = {
  "type"     : "join",
  "call_id"  : bstr(16),
  "sdp"      : tstr                 -- SDP offer/answer for pairwise negotiation
}

GroupCallLeave = {
  "type"     : "leave",
  "call_id"  : bstr(16)
}

GroupCallMute = {
  "type"     : "mute",
  "call_id"  : bstr(16),
  "muted"    : bool                 -- true = muted, false = unmuted
}

GroupCallEnd = {
  "type"     : "end_call",
  "call_id"  : bstr(16)
}
```

### 9.4 Call Flow

1. **Initiation**: The initiator generates a Call ID and sends a GroupCallInvite as a group text message (GROUP_TEXT). All group members see the invite.
2. **Joining**: Each member who wishes to join sends a GroupCallJoin message pairwise to every other participant who has already joined. The SDP offer/answer exchange is performed pairwise via Double Ratchet sessions.
3. **SDP Negotiation**: Each pair of participants exchanges SDP offers and answers through their pairwise Double Ratchet session. SRTP keys are derived from the Double Ratchet state per PNP-007 Section 5.2.
4. **Media Flow**: Once SDP negotiation completes for a pair, media flows between them on a dedicated relay circuit. Each participant maintains a separate circuit for each peer in the call.
5. **Leaving**: A participant sends a GroupCallLeave to all other participants. Other participants tear down the pairwise circuits with the leaving participant.
6. **Ending**: Any participant MAY send a GroupCallEnd. Upon receiving it, all participants SHOULD leave the call. The initiator SHOULD send GroupCallEnd when they leave.

### 9.5 Late Join

A participant MAY join an in-progress call at any time by sending GroupCallJoin to all current participants. Current participants are discovered by tracking GroupCallJoin and GroupCallLeave messages for the active Call ID.

### 9.6 Participant Limit

Implementations MUST enforce a maximum of 8 participants per group call. If a 9th participant attempts to join, their GroupCallJoin MUST be rejected by existing participants.

## 10. Group File Transfer

### 10.1 File Offer

A group file transfer begins when the sender transmits a GROUP_FILE_OFFER (0x0E) message:

```
GroupFileOffer = {
  "type"       : "offer",
  "file_id"    : bstr(16),          -- Random 128-bit file transfer identifier
  "group_id"   : bstr(32),          -- Target group
  "file_name"  : tstr,              -- Original file name (UTF-8)
  "file_size"  : uint64,            -- Total file size in bytes
  "chunk_size" : uint32,            -- Chunk size in bytes (default 32768)
  "sha256"     : bstr(32)           -- SHA-256 hash of the complete plaintext file
}
```

1. The `file_id` MUST be cryptographically random and unique per transfer.
2. The `chunk_size` MUST default to 32768 bytes (32 KiB).
3. The `sha256` hash MUST be computed over the plaintext file content before any chunking or encryption.

### 10.2 File Chunks

After sending the offer, the sender transmits file data as GROUP_FILE_CHUNK (0x0F) messages:

```
GroupFileChunk = {
  "file_id"     : bstr(16),
  "chunk_index" : uint64,           -- Zero-based chunk index
  "chunk_data"  : bstr,             -- Chunk payload (up to chunk_size bytes)
  "is_last"     : bool              -- true if this is the final chunk
}
```

Each chunk is encrypted using the sender's sender key chain (Section 5.4). The sender encrypts once; all group members decrypt using their copy of the sender's chain. The chain index advances with each chunk.

### 10.3 File Control

Recipients MAY send GROUP_FILE_CONTROL (0x10) messages to manage the transfer:

```
GroupFileCancel = {
  "type"    : "cancel",
  "file_id" : bstr(16)
}

GroupFilePause = {
  "type"    : "pause",
  "file_id" : bstr(16)
}

GroupFileResume = {
  "type"      : "resume",
  "file_id"   : bstr(16),
  "resume_from" : uint64            -- Chunk index to resume from
}
```

### 10.4 Out-of-Order Reassembly

Chunks MAY arrive out of order. Implementations MUST support reassembly regardless of arrival order by buffering received chunks and tracking which chunk indices have been received.

### 10.5 Integrity Verification

1. Upon receiving the final chunk (`is_last` = true), the receiver MUST reconstruct the complete file and compute its SHA-256 hash.
2. The computed hash MUST be compared with the `sha256` value from the GroupFileOffer.
3. If the hashes do not match, the receiver MUST discard the file and SHOULD notify the user of a transfer integrity failure.
4. Hash comparison MUST use constant-time comparison (the `subtle` crate) to prevent timing side channels.

### 10.6 Resume Support

If a transfer is interrupted, the sender MAY resume by retransmitting from a given chunk index. Recipients track received chunks and can request resumption by sending a GroupFileResume with `resume_from` set to the first missing chunk index.

## 11. Security Considerations

### 11.1 Sender Key Forward Secrecy Limitations

Sender keys provide a weaker form of forward secrecy compared to the Double Ratchet. Because there is no Diffie-Hellman ratchet in the sender key chain, compromise of a chain key reveals all future messages until the next key rotation. Mandatory key rotation (Section 7.1) and recommended periodic rotation (Section 7.2) mitigate this limitation. Implementations MUST enforce the rotation requirements.

### 11.2 Key Rotation on Member Removal

When a member is removed from a group, key rotation is REQUIRED (Section 7.1). All remaining members MUST generate new sender keys and distribute them. Failure to rotate keys after member removal would allow the removed member to continue decrypting group messages.

### 11.3 Admin Operation Authentication

All GroupOperations MUST be signed by an admin's Ed25519 identity key (Section 6.3). Recipients MUST verify both the signature and the admin status of the signer before applying any operation. Unsigned or improperly signed operations MUST be discarded.

### 11.4 Group Membership Confidentiality

Group membership is hidden from non-members and from the network:

1. SenderKeyDistribution messages are sent via pairwise encrypted Double Ratchet sessions, not broadcast.
2. GroupOperation messages are distributed via gossip only among group members.
3. Group metadata (name, member list, roles) is encrypted and accessible only to current members.
4. Relay nodes see only standard encrypted cells and cannot determine whether traffic is group-related or 1:1.

### 11.5 No Sender Key for Media Streams

Group calls deliberately avoid sender keys for media encryption. Real-time media streams use pairwise SRTP keyed from Double Ratchet sessions (Section 9.1). This preserves post-compromise security: if a participant's key material is compromised and later recovered, the Double Ratchet's DH ratchet ensures that future media sessions are secure.

### 11.6 Replay Protection

The monotonically increasing chain index (Section 5.8) provides replay protection for sender key messages. Implementations MUST track processed chain indices per sender and reject duplicates. For group operations, the monotonic version field (Section 6.4) provides equivalent protection.

### 11.7 Memory Exhaustion Mitigation

The MAX_SKIP limit of 1000 (Section 5.7) prevents an attacker from forcing a recipient to derive and store an unbounded number of skipped message keys. An attacker who sends a message with chain_index far ahead of the expected index cannot force more than 1000 key derivations.

### 11.8 Zeroization

All sender key state -- including chain keys, message keys, signing private keys, and skipped message keys -- MUST implement `Zeroize` and `ZeroizeOnDrop` (from the `zeroize` crate). When a sender key is rotated or a member leaves a group, the old key material MUST be zeroized immediately.

The `panic_wipe` handler (PNP-001 Section 7) MUST clear all group state, including all sender key chains, group metadata, and buffered file transfer state.

### 11.9 Group Size Limits

Group size limits prevent resource exhaustion:

- **Text and file transfer**: Maximum 256 members. Each message requires N-1 relay circuit transmissions; 256 is the maximum practical group size.
- **Voice and video calls**: Maximum 8 participants. Full-mesh at 8 participants requires 28 pairwise circuits; beyond this, bandwidth and processing costs become prohibitive.

Implementations MUST enforce these limits and MUST reject operations that would exceed them.

## 12. Wire Format Diagrams

### 12.1 SenderKeyMessage Layout

```
+-----------------------------------------------+
| SenderKeyMessage                               |
+-------------------+---------------------------+
| Field             | Size                      |
+-------------------+---------------------------+
| chain_index       | 4 bytes (uint32, BE)      |
+-------------------+---------------------------+
| ciphertext_len    | 4 bytes (uint32, BE)      |
+-------------------+---------------------------+
| ciphertext        | variable (ciphertext_len) |
+-------------------+---------------------------+
| signature         | 64 bytes (Ed25519)        |
+-------------------+---------------------------+

Total: 72 + ciphertext_len bytes

Byte layout:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        chain_index                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       ciphertext_len                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     ciphertext (variable)                     |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    signature (64 bytes)                       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 12.2 SenderKeyDistribution Layout

```
+-----------------------------------------------+
| SenderKeyDistribution                          |
+---------------------+-------------------------+
| Field               | Size                    |
+---------------------+-------------------------+
| sender_peer_id      | 32 bytes                |
+---------------------+-------------------------+
| chain_key           | 32 bytes                |
+---------------------+-------------------------+
| chain_index         | 4 bytes (uint32, BE)    |
+---------------------+-------------------------+
| signing_public_key  | 32 bytes                |
+---------------------+-------------------------+

Total: 100 bytes (fixed)

Byte layout:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   sender_peer_id (32 bytes)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     chain_key (32 bytes)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        chain_index                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                signing_public_key (32 bytes)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 12.3 GroupOperation Layout

```
+-----------------------------------------------+
| GroupOperation                                 |
+-------------------+---------------------------+
| Field             | Size                      |
+-------------------+---------------------------+
| group_id          | 32 bytes                  |
+-------------------+---------------------------+
| version           | 8 bytes (uint64, BE)      |
+-------------------+---------------------------+
| op_type_len       | 2 bytes (uint16, BE)      |
+-------------------+---------------------------+
| op_type           | variable (UTF-8 string)   |
+-------------------+---------------------------+
| payload_len       | 4 bytes (uint32, BE)      |
+-------------------+---------------------------+
| payload           | variable (CBOR-encoded)   |
+-------------------+---------------------------+
| admin_id          | 32 bytes                  |
+-------------------+---------------------------+
| signature         | 64 bytes (Ed25519)        |
+-------------------+---------------------------+

Byte layout:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     group_id (32 bytes)                       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     version (8 bytes)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         op_type_len           |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
|                     op_type (variable)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       payload_len                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     payload (variable, CBOR)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    admin_id (32 bytes)                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   signature (64 bytes)                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## 13. Conformance

### 13.1 MUST Requirements

Implementations conforming to this specification MUST:

1. Support group text messaging with sender key encryption (Sections 5, 8).
2. Support sender key distribution via pairwise Double Ratchet sessions (Section 5.2).
3. Enforce key rotation on member removal (Section 7.1).
4. Verify Ed25519 signatures on all SenderKeyMessages before decryption (Section 5.5).
5. Verify Ed25519 signatures on all GroupOperations before processing (Section 6.3).
6. Enforce monotonic version ordering for GroupOperations (Section 6.4).
7. Enforce monotonic chain index for replay protection (Section 5.8).
8. Limit out-of-order key storage to MAX_SKIP = 1000 (Section 5.7).
9. Use ChaCha20-Poly1305 for sender key AEAD (Section 5.4).
10. Derive sender key chain using HKDF-SHA-256 with the specified salt and info strings (Section 5.3).
11. Pad all messages per PaddingStrategy before encryption (Section 8.1).
12. Implement Zeroize and ZeroizeOnDrop for all sender key state (Section 11.8).
13. Clear all group state on panic_wipe (Section 11.8).
14. Enforce group size limits: 256 for text/files, 8 for calls (Section 11.9).
15. Use full-mesh pairwise WebRTC for group calls, NOT sender keys (Section 9.1).
16. Use constant-time hash comparison for file integrity verification (Section 10.5).
17. Set the group message flag (0x10) on all group messages (Section 3.2).
18. Route all group traffic through 3-hop onion circuits (PNP-004).

### 13.2 SHOULD Requirements

Implementations conforming to this specification SHOULD:

1. Rotate sender keys every 1000 messages or 24 hours (Section 7.2).
2. Expire stored skipped message keys after 7 days (Section 5.7).
3. Provide progress indication for group file transfers (Section 10).
4. Send GroupCallEnd when the call initiator leaves (Section 9.4).

### 13.3 MAY Requirements

Implementations conforming to this specification MAY:

1. Support late join for group calls (Section 9.5).
2. Support file transfer resume via GroupFileResume (Section 10.6).
3. Implement additional group roles beyond Admin and Member.

## 14. Cross-Protocol References

- **PNP-001** (Wire Protocol): GROUP_TEXT (0x0C), GROUP_CALL_SIGNAL (0x0D), GROUP_FILE_OFFER (0x0E), GROUP_FILE_CHUNK (0x0F), GROUP_FILE_CONTROL (0x10), and SENDER_KEY_DISTRIBUTION (0x11) message types extend PNP-001 Section 3.4. MessageFlags bit 0x10 indicates group messages. All group data is carried in standard PNP-001 envelopes with bucket padding.
- **PNP-002** (Handshake Protocol): Pairwise Double Ratchet sessions established via PNP-002 are used to distribute sender key material (Section 5.2) and to derive SRTP keys for group call media (Section 9.1).
- **PNP-004** (Relay Circuit Protocol): All group traffic flows through 3-hop onion circuits. Group messages are indistinguishable from 1:1 messages at the relay layer.
- **PNP-005** (Gossip Mesh Protocol): GroupOperations are distributed via gossip with GossipPayloadType 0x04 (Section 6.5).
- **PNP-006** (Traffic Shaping Protocol): Group call circuits use MediaCall bandwidth mode (PNP-007 Section 8) for real-time media streams.
- **PNP-007** (Media and File Transfer Protocol): Group calls reuse the SRTP key derivation (PNP-007 Sections 5.2, 6.6) and codec negotiation (PNP-007 Section 5.3) mechanisms for pairwise media streams within the full-mesh topology.
