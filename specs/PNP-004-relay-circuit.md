# PNP-004: ParolNet Relay Circuit Protocol

### Status: DRAFT
### Version: 0.1
### Date: 2026-04-10

---

## Implementation Note

This document is a protocol design target. The `parolnet-relay` crate contains relay cell, onion encryption, and circuit-building primitives, but the current browser chat path does not yet route normal PWA messages through production 3-hop circuits.

## 1. Overview

The ParolNet Relay Circuit Protocol (PRCP) defines how a client constructs an onion-routed circuit through a sequence of volunteer relay nodes, such that no single relay learns both the origin and destination of a data flow. The protocol uses fixed-size cells to prevent size-based traffic correlation, incremental circuit construction with per-hop X25519 key agreement, and layered ChaCha20-Poly1305 encryption. Relay nodes are assumed potentially compromised (zero-trust); the security property emerges from the requirement that an adversary must compromise all hops simultaneously to deanonymize a circuit.

This protocol draws inspiration from Tor's circuit construction but simplifies the design: it uses CBOR (RFC 8949) for structured sub-fields within cells, ChaCha20-Poly1305 (RFC 8439) as the sole AEAD cipher for layer encryption, and a gossip-based relay directory rather than a centralized directory authority.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

- **Originator (OP)**: The client initiating a circuit. The OP knows the full path.
- **Relay**: A volunteer node that forwards cells along a circuit. A relay knows only its predecessor and successor in the circuit.
- **Hop**: A single relay in the circuit path. Hops are numbered 1 (nearest to OP) through N (furthest).
- **Guard Node**: The first hop in a circuit. The OP SHOULD select guard nodes from a small set of long-lived, high-uptime relays and reuse them across circuits.
- **Exit Relay**: The final hop. It decrypts the innermost layer and delivers data to the destination.
- **Circuit**: An ordered sequence of hops with established shared keys. Identified locally by a Circuit ID.
- **Cell**: The fixed-size unit of data transmitted on a circuit. All cells are exactly 512 bytes.
- **Circuit ID (CID)**: A 32-bit random identifier, locally scoped to a single TCP/TLS connection between two nodes.
- **Relay Descriptor**: A signed record advertising a relay's identity, capabilities, and network address.

## 3. Cell Format

All cells MUST be exactly 512 bytes. Shorter payloads MUST be padded with random bytes to fill the cell. A receiver MUST NOT interpret padding bytes.

### 3.1 Cell Header (Fixed, 7 bytes)

```
Offset  Length  Field
------  ------  -----
0       4       Circuit ID (CID), big-endian uint32
4       1       Cell Type (see Section 3.2)
5       2       Payload Length, big-endian uint16 (0..505)
7       505     Payload (type-dependent, padded to 505 bytes)
```

Total: 4 + 1 + 2 + 505 = 512 bytes.

### 3.2 Cell Types

| Value | Name     | Direction          | Description                                    |
|-------|----------|--------------------|------------------------------------------------|
| 0x01  | CREATE   | OP -> Relay        | Initiate key exchange with hop 1               |
| 0x02  | CREATED  | Relay -> OP        | Hop 1 key exchange response                    |
| 0x03  | EXTEND   | OP -> Relay (enc)  | Request current hop to extend circuit           |
| 0x04  | EXTENDED | Relay -> OP (enc)  | Extension key exchange response                 |
| 0x05  | DATA     | Bidirectional      | Application data, layered-encrypted             |
| 0x06  | DESTROY  | Bidirectional      | Graceful circuit teardown                       |
| 0x07  | PADDING  | Bidirectional      | No-op cell for traffic analysis resistance      |
| 0x08  | RELAY_EARLY | OP -> Relay     | Like EXTEND but with hop counter for loop prevention |

Cell type values 0x09-0xFF are reserved for future use.

### 3.3 CREATE Payload (Plaintext on TLS Channel)

```
Offset  Length  Field
------  ------  -----
0       32      Client ephemeral X25519 public key
32      N       CBOR-encoded handshake extensions (optional)
32+N    ...     Random padding to fill 505 bytes
```

The handshake extensions MAY include protocol version negotiation and requested cryptographic parameters. If absent, defaults apply (ChaCha20-Poly1305, protocol version 1).

### 3.4 CREATED Payload

```
Offset  Length  Field
------  ------  -----
0       32      Relay ephemeral X25519 public key
32      32      Key confirmation: HMAC-SHA256(shared_secret, "prcp-created-v1")
64      N       CBOR-encoded handshake extensions (optional)
64+N    ...     Random padding to fill 505 bytes
```

### 3.5 EXTEND Payload (Decrypted by Current Hop)

The EXTEND payload is encrypted under all preceding hop keys (onion layers). When the target relay decrypts its layer, it sees:

```
Offset  Length  Field
------  ------  -----
0       32      PeerId of next relay (SHA-256 of its Ed25519 public key)
32      32      Client ephemeral X25519 public key (for next hop)
64      N       CBOR-encoded handshake extensions (optional)
64+N    ...     Random padding
```

The relay receiving EXTEND MUST look up the specified PeerId in its local relay directory to resolve the network address. This prevents the originator from embedding IP addresses in EXTEND cells, which would leak topology information to intermediate relays if the cell were compromised. The relay MUST open a TLS connection to the resolved address (if not already connected), allocate a new CID on that connection, and send a CREATE cell on behalf of the OP. It MUST NOT log, store, or forward the OP's identity. If the PeerId is not found in the local directory, the relay MUST respond with a DESTROY cell (reason: protocol error).

### 3.6 EXTENDED Payload

Same format as CREATED (Section 3.4), relayed back through the circuit encrypted under each hop's key.

### 3.7 DATA Payload

```
Offset  Length  Field
------  ------  -----
0       4       Stream ID, big-endian uint32 (multiplexing within circuit)
4       1       Data command (0x01=DATA, 0x02=END, 0x03=CONNECTED, 0x04=RESOLVE)
5       2       Data length, big-endian uint16
7       N       Data bytes
7+N     ...     Random padding to fill 505 bytes
```

DATA cells carry application-layer streams multiplexed within a single circuit. The Stream ID is chosen by the OP and MUST be unique per circuit.

### 3.8 DESTROY Payload

```
Offset  Length  Field
------  ------  -----
0       1       Reason code (see below)
1       ...     Random padding to fill 505 bytes
```

Reason codes:
- 0x00: Normal teardown
- 0x01: Protocol error
- 0x02: Resource exhaustion
- 0x03: Circuit timeout
- 0x04: Requested by exit
- 0x05-0xFF: Reserved

### 3.9 PADDING Payload

All 505 payload bytes MUST be cryptographically random. Receivers MUST silently discard PADDING cells after decryption. PADDING cells MUST be indistinguishable from DATA cells to observers (same size, same encryption).

## 4. State Machine

### 4.1 Circuit States (OP Perspective)

```
                    +------------------+
                    |     IDLE         |
                    +--------+---------+
                             |
                        CREATE sent
                             |
                             v
                    +--------+---------+
                    |  CREATING_HOP_1  |
                    +--------+---------+
                             |
                      CREATED received
                        (keys derived)
                             |
                             v
                    +--------+---------+
                    | EXTENDING_HOP_2  |------ EXTEND sent
                    +--------+---------+
                             |
                     EXTENDED received
                        (keys derived)
                             |
                             v
                    +--------+---------+
                    | EXTENDING_HOP_3  |------ EXTEND sent
                    +--------+---------+
                             |
                     EXTENDED received
                        (keys derived)
                             |
                             v
                    +--------+---------+
                    |      OPEN        |<----> DATA cells flow
                    +--------+---------+
                             |
                      DESTROY sent/recv
                        or timeout
                             |
                             v
                    +--------+---------+
                    |     CLOSED       |
                    +------------------+
```

### 4.2 Circuit States (Relay Perspective)

A relay maintains a mapping: (connection_in, CID_in) <-> (connection_out, CID_out).

```
                    +------------------+
                    |     IDLE         |
                    +--------+---------+
                             |
                     CREATE received
                             |
                             v
                    +--------+---------+
                    |   HANDSHAKING    |
                    +--------+---------+
                             |
                      CREATED sent
                             |
                             v
                    +--------+---------+
                    |      OPEN        |<----> Forward cells
                    +--------+---------+
                             |
                      DESTROY or timeout
                             |
                             v
                    +--------+---------+
                    |     CLOSED       |
                    +------------------+
```

## 5. Processing Rules

### 5.1 Key Exchange

1. The OP MUST generate a fresh X25519 ephemeral key pair for each hop.
2. The relay MUST generate a fresh X25519 ephemeral key pair for each CREATE it handles.
3. The shared secret MUST be computed as X25519(client_ephemeral_private, relay_ephemeral_public).
4. From the 32-byte shared secret, both sides MUST derive keys using HKDF-SHA256 (RFC 5869) with info string "prcp-key-expand-v1":
   - Bytes 0-31: Forward key (OP->Exit direction, ChaCha20-Poly1305)
   - Bytes 32-63: Backward key (Exit->OP direction, ChaCha20-Poly1305)
   - Bytes 64-75: Forward nonce seed (12 bytes)
   - Bytes 76-87: Backward nonce seed (12 bytes)
5. Nonces MUST be constructed as: nonce_seed XOR counter (big-endian uint96). The counter starts at 0 and increments by 1 for each cell encrypted in that direction. A node MUST destroy the circuit if the counter reaches 2^32 (approximately 2 TB of cell data).
6. The key confirmation in CREATED MUST be verified before the OP proceeds. Failure to verify MUST result in circuit destruction.

### 5.2 Layer Encryption

1. When the OP sends a DATA cell through a 3-hop circuit, it MUST encrypt the payload three times: first with hop 3's forward key, then hop 2's forward key, then hop 1's forward key.
2. Each hop peels one layer by decrypting with its forward key, then forwards the result.
3. In the reverse direction (exit -> OP), each hop adds one layer by encrypting with its backward key. The OP decrypts all three layers in order (hop 1, hop 2, hop 3).
4. The AEAD tag (16 bytes) for each layer MUST be prepended to the encrypted payload. This reduces the effective payload capacity by 16 bytes per hop. For a 3-hop circuit, the maximum DATA payload data field is 505 - (3 * 16) = 457 bytes.
5. Relay nodes MUST NOT be able to distinguish encrypted DATA from encrypted PADDING. Both MUST use the same encryption path.

### 5.3 Circuit Construction

1. The OP MUST build circuits incrementally: first establish keys with hop 1, then extend to hop 2 through hop 1, then extend to hop 3 through hops 1 and 2.
2. Circuits MUST have exactly 3 hops. Implementations MUST NOT allow fewer than 3 hops. Future protocol versions MAY permit variable-length circuits.
3. The OP SHOULD pre-build circuits before they are needed and keep a pool of 3-5 ready circuits.
4. Circuit construction MUST complete within 30 seconds. If any hop fails to respond within 10 seconds, the OP MUST destroy the partial circuit and retry with a different relay selection.

### 5.4 Circuit IDs

1. CIDs MUST be randomly generated 32-bit unsigned integers.
2. CIDs are scoped to a single TLS connection between two nodes. The same CID value MAY appear on different connections without conflict.
3. When a relay extends a circuit, it MUST choose a new random CID for the outgoing connection that does not collide with any existing CID on that connection.
4. CID 0x00000000 is reserved and MUST NOT be used for circuits.

### 5.5 Relay Cell Processing

1. Upon receiving a cell, a relay MUST look up the (connection, CID) pair in its circuit table.
2. If no matching circuit exists and the cell is CREATE, the relay MUST initiate the handshake.
3. If no matching circuit exists and the cell is not CREATE, the relay MUST silently discard it.
4. For DATA and PADDING cells on an OPEN circuit, the relay MUST decrypt one layer (forward direction) or encrypt one layer (backward direction) and forward to the paired connection/CID.
5. A relay MUST NOT buffer more than 64 cells per circuit. If the outgoing connection is congested, the relay MUST drop the oldest cells and MAY send DESTROY.
6. A relay MUST enforce a maximum of 8192 simultaneous circuits. Exceeding this limit MUST result in rejecting new CREATE cells.

### 5.6 Relay Directory (Gossip-Based)

1. Each relay MUST publish a signed relay descriptor containing:
   - PeerId (32 bytes)
   - Ed25519 identity public key (32 bytes)
   - X25519 long-term public key (32 bytes, used for optional ntor-like optimization)
   - Network addresses (IPv4/IPv6 + port)
   - Capabilities (bandwidth class, exit policy flags)
   - Uptime counter
   - Descriptor timestamp (Unix epoch seconds)
   - Ed25519 signature over all preceding fields
2. Relay descriptors MUST be propagated via the Gossip/Mesh Protocol (PNP-005).
3. A descriptor MUST be refreshed at least every 6 hours. Descriptors older than 24 hours MUST be considered stale and SHOULD NOT be used for new circuits.
4. Nodes MUST verify the Ed25519 signature and confirm PeerId = SHA-256(identity_public_key) before accepting a descriptor.
5. Nodes SHOULD maintain a local cache of at least 100 relay descriptors.

### 5.7 Relay Selection

1. The OP MUST select hop 1 from its guard set. The guard set SHOULD contain 2-3 relays, selected from relays with uptime exceeding 7 days, and SHOULD be stable for at least 30 days.
2. Hops 2 and 3 MUST be selected randomly from the known relay pool, excluding the guard and each other.
3. No two hops in a circuit MUST share the same /16 IPv4 subnet or /48 IPv6 prefix.
4. The OP SHOULD weight relay selection by advertised bandwidth class.

### 5.8 Circuit Teardown

1. **Graceful**: Either endpoint sends a DESTROY cell. Each relay in the path MUST forward DESTROY to the next hop, then deallocate the circuit.
2. **Ungraceful**: If no cell (including PADDING) is received on a circuit for 90 seconds, the relay MUST consider the circuit dead and deallocate it. The relay SHOULD send DESTROY in both directions.
3. Upon receiving DESTROY, a relay MUST deallocate the circuit within 1 second and MUST NOT forward any further cells on that CID.

### 5.9 Padding Between Relays

1. When a circuit is OPEN, each pair of adjacent nodes (OP-hop1, hop1-hop2, hop2-hop3) MUST exchange PADDING cells at a constant rate when no DATA cells are pending. The default rate is 1 cell per 500ms (see PNP-006 for traffic shaping parameters).
2. The padding rate SHOULD be negotiated during circuit construction via handshake extensions.
3. PADDING cells MUST be encrypted identically to DATA cells and MUST be indistinguishable to any observer.

## 6. Security Considerations

1. **Compromised relays**: The protocol assumes any individual relay may be compromised. Security depends on the adversary not controlling all three hops simultaneously. Relay selection rules (Section 5.7) mitigate Sybil attacks by subnet diversity requirements.
2. **Replay attacks**: Each cell is encrypted with a unique nonce derived from a monotonically increasing counter. Replayed cells will have invalid AEAD tags and MUST be rejected.
3. **Forward secrecy**: Ephemeral X25519 keys are used for each circuit. Compromise of a relay's long-term identity key does not reveal past session keys.
4. **Circuit fingerprinting**: Fixed cell sizes and constant-rate padding prevent size and timing analysis on individual links. However, a global passive adversary observing all links simultaneously may still perform traffic confirmation attacks. This is an inherent limitation shared with Tor.
5. **RELAY_EARLY attacks**: The RELAY_EARLY cell type includes a hop counter decremented at each relay. This prevents a malicious relay from extending a circuit to an arbitrary depth to perform tagging attacks. An OP MUST set the counter to 3. Each relay MUST decrement by 1 and MUST NOT forward if counter reaches 0.
6. **Cell counter overflow**: Implementations MUST destroy circuits before the nonce counter reaches 2^32 to prevent nonce reuse.

## 7. Privacy Considerations

1. No relay learns both the OP's identity and the destination. Hop 1 (guard) knows the OP's IP but not the destination. Hop 3 (exit) knows the destination but not the OP.
2. CIDs are locally scoped and randomly chosen, preventing cross-connection correlation.
3. The relay directory is distributed via gossip, preventing a directory server from learning which relays a client is interested in.
4. Guard nodes reduce the probability of an adversary being selected as the first hop over time, compared to random first-hop selection.
5. Implementations MUST NOT include timestamps, sequence numbers, or any OP-identifying information in cell payloads beyond what is specified in this document.
