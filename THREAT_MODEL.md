# ParolNet Threat Model

### Document Status: DRAFT
### Version: 0.1
### Date: 2026-04-10
### Framework: STRIDE (Microsoft)

---

## 1. System Overview

ParolNet is a decentralized, censorship-resistant communication platform designed for users in hostile network environments. It provides end-to-end encrypted messaging with metadata protection, traffic indistinguishability, and offline mesh capabilities.

### 1.1 Crate Architecture

The system is composed of seven Rust crates arranged in a layered dependency hierarchy:

```
+-------------------------------------------------------------------+
|                        parolnet-core                               |
|  Public API: bootstrap, send, recv, panic_wipe, session mgmt      |
+----------+-------------------+--------------------+---------------+
           |                   |                    |
+----------+--+  +-------------+--+  +--------------+--+
| parolnet-   |  | parolnet-      |  | parolnet-       |
| relay       |  | mesh           |  | wasm            |
| Onion       |  | Gossip,        |  | Browser PWA     |
| circuits,   |  | store-forward, |  | bindings via    |
| 3-hop       |  | bloom filters, |  | wasm-bindgen    |
| routing     |  | PoW anti-spam  |  |                 |
+------+------+  +-------+--------+  +--------+--------+
       |                  |                    |
+------+------------------+------+             |
|    parolnet-transport          |             |
|    TLS 1.3, WebSocket,         |             |
|    DPI evasion, traffic shape  |             |
+-------------+------------------+             |
              |                                |
      +-------+--------+              +--------+------+
      | parolnet-       |              | parolnet-     |
      | protocol        +--------------+ crypto        |
      | Wire format,    |              | X3DH, Double  |
      | envelope, CBOR  |              | Ratchet, AEAD |
      +-----------------+              +---------------+
```

**parolnet-crypto** and **parolnet-protocol** are WASM-compatible (no native dependencies). All cryptographic operations use pure-Rust implementations (dalek-cryptography, RustCrypto) with no C bindings.

### 1.2 Protocol Stack

| Layer | Spec | Function |
|-------|------|----------|
| Wire Protocol | PNP-001 | Envelope format, bucket padding (256/1024/4096/16384 bytes), CBOR encoding |
| Handshake | PNP-002 | X3DH key agreement, Double Ratchet initialization, rekeying |
| Bootstrap | PNP-003 | QR code / passphrase peer introduction, SAS verification |
| Relay Circuits | PNP-004 | 3-hop onion routing, 512-byte fixed cells, per-hop X25519 key exchange |
| Gossip/Mesh | PNP-005 | Epidemic propagation, bloom filter deduplication, PoW anti-spam, store-forward |
| Traffic Shaping | PNP-006 | TLS fingerprint mimicry, constant-rate padding, DPI evasion |

### 1.3 Key Design Invariants

- **Identity**: `PeerId = SHA-256(Ed25519_public_key)`. No external identifiers.
- **Encryption**: ChaCha20-Poly1305 default AEAD. No compression before encryption.
- **Key material**: All secret keys derive `Zeroize` and `ZeroizeOnDrop`.
- **Constant-time operations**: `subtle` crate for comparisons.
- **No C crypto dependencies**: Pure Rust only.

---

## 2. Adversary Profiles

### 2.1 Local Network Observer (L-ADV)

**Examples**: ISP, campus/corporate network administrator, Wi-Fi hotspot operator, local law enforcement with lawful intercept capability.

**Capabilities**:
- Full packet capture on the local network segment
- Deep packet inspection (DPI) of TLS ClientHello, packet sizes, timing
- DNS query logging and interception
- IP address logging of all connections
- Ability to inject, drop, or modify packets (active attacker)
- Access to commercial DPI appliances (e.g., Sandvine, Allot)

**Limitations**:
- Cannot observe traffic beyond the local network segment
- Cannot compromise relay nodes or endpoint devices
- Cannot break TLS 1.3 encryption
- Cannot perform global traffic correlation

### 2.2 National Firewall Operator (N-ADV)

**Examples**: China's Great Firewall (GFW), Iran's NIN, Russia's TSPU/SORM, Turkmenistan's national gateway.

**Capabilities**:
- All capabilities of L-ADV, applied at national border gateways
- IP blocklisting at scale (millions of entries)
- DNS poisoning and hijacking for all domains
- TLS fingerprint classification and blocking (e.g., GFW blocks Tor by ClientHello fingerprint)
- Statistical traffic analysis (entropy testing, packet size distribution classification)
- Active probing of suspected circumvention endpoints
- Bandwidth throttling of suspicious connections
- Certificate interception (MITM) on connections where the CA is state-controlled
- Legal authority to compel ISPs to cooperate

**Limitations**:
- Cannot observe traffic inside foreign networks
- Cannot compromise devices outside national jurisdiction (without separate CNE operations)
- Typically cannot maintain state for every flow simultaneously (resource-constrained DPI)
- Cannot break properly implemented TLS 1.3 with certificate pinning

### 2.3 Compromised Relay Operator (R-ADV)

**Examples**: Adversary who operates one or more volunteer relay nodes, or who has compromised relay nodes through software exploitation.

**Capabilities**:
- Full access to all data traversing the compromised relay(s)
- Can log circuit IDs, cell timing, cell counts, and connection metadata
- Can observe cleartext headers of PNP-001 envelopes passing through gossip
- Can correlate inbound and outbound traffic timing on the compromised node
- Can selectively drop, delay, or duplicate cells
- Can inject malformed cells to probe circuit behavior
- Can publish fraudulent relay descriptors (Sybil attack)
- If controlling the guard node: knows the originator's IP address
- If controlling the exit relay: knows the destination PeerId

**Limitations**:
- Cannot decrypt onion-encrypted cell payloads for hops it does not control
- Cannot determine both origin and destination from a single compromised hop (requires controlling all 3 hops)
- Cannot forge Ed25519 signatures of other nodes
- Cannot break the Double Ratchet session encryption (E2EE layer is above the relay layer)

### 2.4 Device Seizure (D-ADV)

**Examples**: Law enforcement with a warrant, border agents conducting device inspection, authoritarian regime security services with physical access.

**Capabilities**:
- Physical possession of the device
- Forensic analysis of storage (including deleted files, swap, hibernation images)
- Cold boot attacks on RAM (extracting key material from powered-on devices)
- Compulsion to reveal passwords/PINs (legal or extralegal)
- Access to any unencrypted data on the device
- Hardware forensic tools (Cellebrite, GrayKey)

**Limitations**:
- Cannot access data that has been securely erased (overwritten with random data)
- Cannot recover key material that was `Zeroize`d before device seizure
- Cannot break ChaCha20-Poly1305 without the key
- Effectiveness depends on whether the user activated panic wipe before seizure

### 2.5 Global Passive Adversary (G-ADV)

**Examples**: A signals intelligence agency (e.g., NSA, GCHQ, FSB) with pervasive network monitoring capability, or a coalition of national ISPs sharing traffic metadata.

**Capabilities**:
- Simultaneous observation of traffic on all (or most) network links
- Long-term traffic storage and retrospective analysis
- Timing correlation across multiple network segments
- Traffic volume correlation (matching input/output flows across relays)
- Statistical analysis of communication patterns over weeks or months
- Ability to enumerate all relay nodes by observing the gossip network
- Netflow/IPFIX data from multiple ISPs simultaneously

**Limitations**:
- Cannot decrypt E2EE message content
- Cannot inject or modify traffic (passive only)
- Correlation attacks are probabilistic, not deterministic, when constant-rate padding is used
- Cannot attribute traffic to a specific user without additional information (e.g., device seizure)

---

## 3. STRIDE Analysis

### 3.1 Transport Layer (parolnet-transport, PNP-006)

| # | Threat | STRIDE Category | Mitigation | Residual Risk |
|---|--------|----------------|------------|---------------|
| T-1 | Adversary identifies ParolNet traffic by TLS ClientHello fingerprint | Information Disclosure | TLS ClientHello mimics latest Chrome/Firefox fingerprint (PNP-006 Section 5.1). Cipher suites, extensions, supported groups, ALPN all match target browser. Multiple fingerprint profiles distributed across node population. | Fingerprints become stale between updates. If all nodes use the same profile, blocking that profile blocks the entire network. Update cadence of at least every 6 months is required (PNP-006 Section 6.1). |
| T-2 | Statistical traffic analysis distinguishes ParolNet from web browsing | Information Disclosure | Constant-rate padding at configurable intervals (PNP-006 Section 4.1). Burst smoothing queues messages and drains at base rate (PNP-006 Section 4.2). Timing jitter from CSPRNG (PNP-006 Section 4.4). Traffic shaped into request-response cadences mimicking HTTP/2 browsing (PNP-006 Section 4.6). | Sufficiently sophisticated statistical classifiers with long observation windows may detect subtle deviations from genuine browser behavior. Uniform jitter distribution is simpler than real browser inter-packet timing. |
| T-3 | Active probing identifies relay nodes | Information Disclosure | Relays respond to non-ParolNet connections with plausible HTTP responses (PNP-006 Section 5.2). Relay does not reveal protocol behavior until valid CREATE cell received. Relays listen on port 443 only. | A determined adversary can enumerate relays by probing all port-443 endpoints and analyzing response behavior heuristics. Response latency and TLS session resumption patterns may differ from genuine web servers. |
| T-4 | MITM attack on TLS connection | Spoofing / Tampering | TLS 1.3 with certificate verification. SNI set to plausible CDN-hosted domain (PNP-006 Section 5.2). All data within TLS is AEAD-encrypted at the application layer (Double Ratchet). | State-controlled CAs could issue fraudulent certificates. Certificate pinning mitigates this but requires out-of-band pin distribution. |
| T-5 | Connection metadata reveals ParolNet usage | Information Disclosure | Long-lived connections (10 min to 4 hours) mimic persistent HTTP/2 connections (PNP-006 Section 4.5). 2-8 simultaneous connections mimic browser behavior. TCP keepalive at 30-second intervals. | Connection duration distribution may differ subtly from genuine browser sessions. Persistent connections to the same IP over days are unusual for browsers. |
| T-6 | TCP RST injection terminates connections | Denial of Service | Graceful TLS close_notify required (PNP-006 Section 4.5). Nodes reconnect after 30-second delay. Circuit pool provides redundancy (PNP-004 Section 5.3). | Persistent RST injection on all connections to known relay IPs is effective DoS. Requires IP-level blocking mitigation (domain fronting, relay rotation). |

### 3.2 Relay Circuit Layer (parolnet-relay, PNP-004)

| # | Threat | STRIDE Category | Mitigation | Residual Risk |
|---|--------|----------------|------------|---------------|
| R-1 | Single compromised relay deanonymizes circuit | Information Disclosure | 3-hop onion routing ensures no single relay knows both origin and destination (PNP-004 Section 7.1). Guard knows OP IP but not destination. Exit knows destination but not OP. | Compromising all 3 hops simultaneously breaks anonymity. Guard node reuse (PNP-004 Section 5.7) limits the probability of adversary selection as first hop but creates a long-term target. |
| R-2 | Sybil attack on relay directory | Spoofing / Elevation of Privilege | Relay descriptors are Ed25519-signed (PNP-004 Section 5.6). PeerId verified as SHA-256(pubkey). No two hops may share same /16 IPv4 or /48 IPv6 prefix (PNP-004 Section 5.7). PoW difficulty 20 for RELAY_DESCRIPTOR messages (PNP-005 Section 5.6). | An adversary with many IP addresses across diverse subnets can still inject Sybil relays. There is no centralized directory authority to vet relays, unlike Tor. Gossip-based directory is more censorship-resistant but more vulnerable to Sybil injection. |
| R-3 | Replay attack on circuit cells | Tampering | Monotonically increasing nonce counter per circuit direction (PNP-004 Section 5.1). AEAD tag validation rejects replayed cells. Circuit destroyed at counter 2^32 to prevent overflow (PNP-004 Section 5.1 step 5, Section 6.6). | None identified for cell replay. |
| R-4 | Tagging attack (malicious relay modifies cell to trace it) | Tampering | AEAD authentication on every layer. Modified cells produce invalid tags at subsequent hops and are dropped. RELAY_EARLY hop counter prevents circuit extension attacks (PNP-004 Section 6.5). | A relay can drop cells selectively (rather than modify them) to perform a selective DoS, which may be detectable by the OP as circuit degradation. |
| R-5 | Timing correlation across circuit hops | Information Disclosure | Constant-rate PADDING cells between all adjacent hop pairs at 1 cell/500ms when idle (PNP-004 Section 5.9). Jitter on all sends (PNP-006 Section 4.4). Fixed 512-byte cell size eliminates size correlation. | A global passive adversary observing all links simultaneously can still perform statistical traffic confirmation. This is an inherent limitation shared with all low-latency anonymity networks including Tor. |
| R-6 | Circuit fingerprinting by cell count or pattern | Information Disclosure | Fixed cell sizes (PNP-004 Section 3). PADDING indistinguishable from DATA after encryption (PNP-004 Section 5.2 step 5). Dummy traffic fills gaps (PNP-006 Section 4.3). | Long-lived circuits with distinctive activity patterns may be fingerprintable over extended observation. |
| R-7 | Resource exhaustion via CREATE flooding | Denial of Service | Maximum 8192 simultaneous circuits per relay (PNP-004 Section 5.5 step 6). Maximum 64 buffered cells per circuit (PNP-004 Section 5.5 step 5). 10-second per-hop timeout, 30-second total construction timeout (PNP-004 Section 5.3 step 4). | Distributed CREATE flooding from many sources can still exhaust relay resources. No PoW is required for CREATE cells (unlike gossip messages). |
| R-8 | Compromised exit relay observes destination PeerId | Information Disclosure | Destination is a PeerId (hash of public key), not a real-world identity. Message content is E2EE under Double Ratchet (PNP-002), invisible to exit relay. | Exit relay learns the destination PeerId and can build a profile of which PeerIds communicate. Combined with guard compromise, full deanonymization is possible. |

### 3.3 Gossip/Mesh Layer (parolnet-mesh, PNP-005)

| # | Threat | STRIDE Category | Mitigation | Residual Risk |
|---|--------|----------------|------------|---------------|
| G-1 | Message forgery in gossip network | Spoofing | All gossip messages signed by originator's Ed25519 key (PNP-005 Section 3.1 "sig" field). Signature verification mandatory (PNP-005 Section 5.1 step 4). | An adversary who compromises a peer's private key can forge messages from that peer. No revocation mechanism is instantaneous; REVOCATION messages (type 0x05) propagate via gossip with delay. |
| G-2 | Spam flooding via bulk gossip injection | Denial of Service | Proof-of-work required on all messages (PNP-005 Section 5.6). Default difficulty 16 (65536 hashes). Per-peer scoring penalizes invalid messages (PNP-005 Section 5.8). Rate limiting of 10 messages/minute/source recommended (PNP-005 Section 6.4). | PoW difficulty 16 is computationally trivial for well-resourced adversaries. Difficulty adjustment relies on median relay advertisement, which can be manipulated by Sybil relays. |
| G-3 | Bloom filter manipulation suppresses message delivery | Tampering | Bloom filter is mutable and unsigned (PNP-005 Section 3.3 -- intentionally excluded from signature). Rate limiting per source PeerId (PNP-005 Section 6.4) mitigates amplification from cleared bloom filters. | A malicious relay can stuff the bloom filter to suppress forwarding to specific peers, or clear it to cause amplification. This is a fundamental design tradeoff for epidemic routing. |
| G-4 | Source PeerId in gossip reveals originator | Information Disclosure | For USER_MESSAGE type, application layer SHOULD use a purpose-specific pseudonymous PeerId (PNP-005 Section 7.1). High-sensitivity messages SHOULD be injected via circuits first (PNP-005 Section 7.2). | Pseudonymous PeerIds can be correlated over time. If a user's gossip PeerId is linked to their identity through other means, all gossip messages from that PeerId are attributable. |
| G-5 | Store-and-forward buffer reveals message metadata | Information Disclosure | Buffered messages are E2EE at the application layer (PNP-005 Section 6.6). Buffers encrypted at rest using node identity key (PNP-005 Section 7.5). Panic wipe erases all buffered data. | Gossip metadata (src PeerId, TTL, timestamps) is visible to the storing node. A compromised node can build a metadata graph from its buffer. |
| G-6 | Message propagation path reconstruction | Information Disclosure | Forwarding jitter 0-200ms (PNP-005 Section 5.2 step 4). Bloom filter obscures exact propagation path. | A global passive adversary observing many peers can reconstruct propagation order by timestamp correlation across nodes. |
| G-7 | Sybil peers manipulate peer scoring | Elevation of Privilege | Peer scoring starts at 100, decays toward 100 (PNP-005 Section 5.8). Peers below score 0 are disconnected for 1 hour. | Sybil peers can artificially inflate each other's scores by delivering valid messages between themselves. No proof-of-identity beyond Ed25519 keys exists. |

### 3.4 Bootstrap/Handshake (PNP-002, PNP-003)

| # | Threat | STRIDE Category | Mitigation | Residual Risk |
|---|--------|----------------|------------|---------------|
| B-1 | QR code photographed by bystander | Information Disclosure | QR displayed briefly with visual expiration indicator (PNP-003 Section 5.1 step 4). Only one bootstrap accepted per seed (PNP-003 Section 6.1). SAS verification detects impersonation (PNP-003 Section 5.5). | If adversary photographs QR before legitimate scanner, they obtain the seed and presenter's identity key. They can race the legitimate scanner to complete the bootstrap. SAS verification is the primary defense. |
| B-2 | Man-in-the-middle during bootstrap | Spoofing | HMAC proof in BootstrapHandshake binds identities to shared secret (PNP-003 Section 5.4). SAS verification detects MITM with probability 1 - 10^-6 (PNP-003 Section 6.3). | If SAS verification is skipped (user convenience), MITM is undetected. The protocol allows skipping SAS (PNP-003 Section 4, state machine). |
| B-3 | Passphrase brute-force | Information Disclosure | Minimum 6 BIP-39 words (66 bits entropy), default 8 words (88 bits). Argon2id strengthening with t=3, m=64MB, p=4 (PNP-003 Section 5.2). | Passphrases chosen by users (rather than generated) may have lower entropy. Social engineering could extract passphrases. |
| B-4 | mDNS/BLE discovery reveals ParolNet presence on local network | Information Disclosure | `bs_hint` (4-byte truncated hash) limits correlation without BS (PNP-003 Section 3.5). mDNS ceases after connection established (PNP-003 Section 5.6 step 6). Nonce rotated each broadcast (PNP-003 Section 5.6 step 4). | Any local network observer can detect `_parolnet._tcp` mDNS service type. This unambiguously identifies a ParolNet user on the local network. High-risk environments should avoid mDNS entirely. |
| B-5 | Replay of bootstrap handshake messages | Tampering / Spoofing | 128-bit random nonce in BootstrapHandshake (PNP-003 Section 6.4). QR timestamp validated within 30 minutes (PNP-003 Section 5.1 step 6). Nonce replay cache for 60 minutes. | None identified beyond the cache window. After 60 minutes, replayed nonces would no longer match a valid BS (which is erased after session establishment). |
| B-6 | Key Compromise Impersonation (KCI) | Spoofing | Inherited from X3DH: compromise of Alice's IK allows impersonating Alice to Bob, but NOT impersonating Bob to Alice (PNP-002 Section 6.2). | KCI is a known property of X3DH. If Alice's long-term key is compromised, the adversary can establish sessions pretending to be Alice with any peer. |
| B-7 | OPK exhaustion weakens forward secrecy | Information Disclosure | Fallback to 3-DH without OPK is supported (PNP-002 Section 6.3). Peers SHOULD maintain 20-100 OPKs and replenish proactively (PNP-002 Section 2). | Without OPK, compromise of both Bob's SPK and IK reveals initial handshake messages. The Double Ratchet restores forward secrecy after the first ratchet step. |
| B-8 | Handshake timing correlation | Information Disclosure | Random delay 100-2000ms before HandshakeResponse (PNP-002 Section 7.3). Handshake sub-type hidden inside encrypted payload (PNP-003 Section 8). | Timing correlation between HandshakeInit and HandshakeResponse remains possible for a network observer, especially with few concurrent sessions. |

### 3.5 Client Application (parolnet-core, parolnet-wasm)

| # | Threat | STRIDE Category | Mitigation | Residual Risk |
|---|--------|----------------|------------|---------------|
| C-1 | Device seizure exposes keys and message history | Information Disclosure | Panic wipe securely erases all keys, messages, contacts. Zeroize/ZeroizeOnDrop on all key material structs. Decoy mode makes app appear as calculator/notepad. | Panic wipe requires user action before seizure. Cold boot attack can extract keys from RAM if device is powered on. Swap/hibernation files may contain key material. |
| C-2 | Malware on device reads messages in plaintext | Information Disclosure | Out of scope for ParolNet (endpoint security is the OS/device responsibility). | ParolNet cannot protect against a compromised endpoint. Messages must be decrypted for display; malware with screen capture or memory access defeats all cryptographic protections. |
| C-3 | Coerced password disclosure (rubber-hose cryptanalysis) | Information Disclosure | Deniable encryption: X3DH does not produce non-repudiable transcripts (PNP-002 Section 6.8). Panic wipe destroys evidence. Decoy mode provides plausible alternative. | Deniability is a cryptographic property, not a practical guarantee. A court or adversary may not accept deniability arguments. Torture renders all cryptographic protections irrelevant. |
| C-4 | Application-level replay of decrypted messages | Repudiation | Double Ratchet sequence numbers and chain indices prevent replay (PNP-001 Section 3.3). Message ID uniqueness check with 60-minute cache (PNP-001 Section 5.3 step 3). | After cache expiration, very old message IDs could theoretically be replayed, but the Double Ratchet state will have advanced, making decryption fail. |
| C-5 | Side-channel leakage from non-constant-time operations | Information Disclosure | `subtle` crate for constant-time comparisons. ChaCha20-Poly1305 is constant-time without hardware acceleration (no AES-NI dependency). Pure Rust crypto (no C FFI timing variability). | WASM execution environment may not guarantee constant-time behavior. JIT compilation and garbage collection in browsers introduce timing variability outside ParolNet's control. |
| C-6 | WASM binary reverse-engineering reveals protocol details | Information Disclosure | Protocol is open-source; security does not depend on obscurity. No secrets are embedded in the binary. | Not a vulnerability. Listed for completeness. |

---

## 4. Data Flow Diagram

```
                          NETWORK OBSERVER (L-ADV / N-ADV)
                          can see: IP addresses, TLS metadata,
                          packet sizes, timing, connection patterns
                          cannot see: message content, routing info
                                         |
                                         | observes
                                         v
+-------------+    TLS 1.3     +----------+----------+
|             |  (Chrome fp)   |                     |
|   User      +===============>  Guard Relay (Hop 1) |
|   Device    |  HTTP/2 DATA   |                     |
|             |  frames with   | Knows: OP's IP addr |
| - E2EE msg  |  512-byte     | Cannot: see dest,   |
|   encrypted  |  onion cells  |   decrypt payload   |
|   under DR   |  + PADDING    |                     |
| - Padded to  |               +----------+----------+
|   bucket sz  |                          |
| - Wrapped in |                   TLS 1.3|
|   onion      |                          v
|   layers     |               +----------+----------+
+-------------+                |                     |
      ^                        |  Middle Relay        |
      |                        |  (Hop 2)            |
      |                        |                     |
      |                        | Knows: nothing      |
      |                        |   useful (only prev |
      |                        |   and next hop CIDs)|
      |                        |                     |
      |                        +----------+----------+
      |                                   |
      |                            TLS 1.3|
      |                                   v
      |                        +----------+----------+
      |                        |                     |
      |                        |  Exit Relay (Hop 3) |
      |                        |                     |
      |                        | Knows: dest PeerId  |
      |                        | Cannot: see origin  |
      |                        |   IP, decrypt E2EE  |
      |                        |   content           |
      |                        +----------+----------+
      |                                   |
      |                            TLS 1.3|
      |                                   v
      |                        +----------+----------+
      |   (reverse path,       |                     |
      +------------------------+ Destination Peer    |
         same 3-hop circuit)   |                     |
                               | Decrypts onion      |
                               | Decrypts DR payload |
                               | Sees plaintext msg  |
                               +---------------------+

  Gossip Layer (parallel path for store-forward / relay directory):

  +--------+     gossip msg      +--------+     gossip msg      +--------+
  | Peer A +-------------------->| Peer B +-------------------->| Peer C |
  +--------+  fanout=3, TTL--   +--------+  fanout=3, TTL--   +--------+
               bloom filter                  bloom filter
               updated                       updated
               PoW verified                  PoW verified
               sig verified                  sig verified

  Each gossip hop sees: src PeerId, TTL, expiry, bloom filter, payload (E2EE)
  Each gossip hop cannot: decrypt E2EE payload, determine full propagation path
```

**Data flow annotations**:

1. User device encrypts message under Double Ratchet session key, pads to bucket size (PNP-001 Section 3.6), wraps in 3 onion layers (PNP-004 Section 5.2).
2. Each TLS connection carries HTTP/2 frames containing 512-byte cells, indistinguishable from HTTPS traffic (PNP-006 Section 5.3).
3. Constant-rate padding fills gaps between real cells on every link (PNP-004 Section 5.9, PNP-006 Section 4.1).
4. Guard relay peels one onion layer, sees CID for next hop, forwards. Middle relay repeats. Exit relay peels final layer, delivers PNP-001 envelope to destination.
5. Gossip layer operates independently for delay-tolerant delivery and relay directory distribution (PNP-005).

---

## 5. Trust Boundaries

### 5.1 Device Boundary

**Crosses when**: Data leaves the user's device (or enters from the network).

**Trust change**: Inside the device, plaintext messages, private keys, and contact lists exist in memory. Outside the device, all data is encrypted (Double Ratchet + onion layers + TLS).

**Controls**:
- Zeroize/ZeroizeOnDrop for all key material
- Panic wipe erases all persistent state
- Decoy mode conceals app identity
- Encrypted storage at rest for store-and-forward buffers (PNP-005 Section 7.5)
- No logs, analytics, or telemetry transmitted (PNP-003 Section 7.4)

**Risk**: Endpoint compromise (malware, physical seizure) defeats all network-layer protections. This is the highest-value attack point.

### 5.2 TLS Boundary

**Crosses when**: Data passes between the TLS session and the raw TCP stream.

**Trust change**: Below TLS, all data is visible to network observers. Above TLS, data is encrypted but the TLS termination point (the immediate peer) can see the TLS-decrypted stream.

**Controls**:
- TLS 1.3 with browser-mimicking ClientHello (PNP-006 Section 5.1)
- HTTP/2 framing wraps all protocol data (PNP-006 Section 5.3)
- Application-layer encryption (onion + DR) ensures TLS termination point only sees encrypted cells
- SNI set to plausible CDN domain (PNP-006 Section 5.2)

**Risk**: A compromised TLS peer (relay) sees encrypted cells but cannot decrypt onion layers for other hops. However, it can perform traffic analysis on cell timing and volume.

### 5.3 Relay Boundary

**Crosses when**: A cell traverses from one relay hop to the next.

**Trust change**: Each relay peels or adds one onion encryption layer. The relay sees the cell after its own decryption but before the next hop's encryption. CIDs change at each hop.

**Controls**:
- Per-hop ephemeral X25519 key exchange (PNP-004 Section 5.1)
- Forward/backward key separation (PNP-004 Section 5.1 step 4)
- CIDs locally scoped and randomly chosen (PNP-004 Section 5.4)
- AEAD authentication prevents tampering (tagging attacks fail)
- Fixed cell sizes prevent size correlation (PNP-004 Section 3)

**Risk**: A relay can observe timing of cells it processes. If the same adversary controls multiple hops, they can correlate timing to link circuit segments. Subnet diversity rules (PNP-004 Section 5.7 step 3) provide partial mitigation.

### 5.4 Network Boundary

**Crosses when**: Traffic passes between network segments (e.g., from user's ISP to relay's ISP, across national borders).

**Trust change**: Traffic crosses from one observer's jurisdiction to another. A national firewall sees all traffic crossing the border.

**Controls**:
- Traffic shaping makes ParolNet indistinguishable from HTTPS browsing (PNP-006)
- Domain fronting optionally available (PNP-006 Section 5.2)
- Relay probing returns plausible web responses (PNP-006 Section 5.2 step 3, Section 6.3)
- Port 443 exclusively (PNP-006 Section 5.2 step 4)

**Risk**: A national firewall with sophisticated classifiers and willingness to block broad categories of traffic (e.g., all TLS connections to unknown IPs) can disrupt connectivity. This is an arms race, not a solved problem.

---

## 6. Known Limitations

The following are limitations that ParolNet does NOT and CANNOT fully protect against. Users whose safety depends on understanding these limitations MUST be informed.

### 6.1 Global Passive Adversary with Relay Compromise

If an adversary simultaneously observes all network links AND controls all three relay hops in a circuit, complete deanonymization is achieved: the adversary knows who is communicating with whom, when, and can decrypt message content at the exit relay (though E2EE content remains protected by the Double Ratchet). Even without controlling all hops, traffic confirmation attacks (correlating entry and exit timing) become feasible for a global passive adversary. Constant-rate padding increases the difficulty but does not eliminate the possibility. This is an inherent limitation of all low-latency anonymity networks, including Tor (documented in PNP-004 Section 6.4).

### 6.2 Endpoint Compromise

Malware with access to the device's memory or screen can read plaintext messages after decryption. ParolNet encrypts data at rest and in transit but cannot protect against a compromised operating system, a malicious browser extension (for the WASM/PWA target), or a hardware implant. Endpoint security is outside ParolNet's threat model.

### 6.3 Rubber-Hose Cryptanalysis

No cryptographic system protects against physical coercion. ParolNet provides deniability (X3DH transcripts are deniable per PNP-002 Section 6.8) and panic wipe capability, but these are mitigations, not solutions. A user who is physically compelled to reveal their passphrase, unlock their device, or explain their communication history cannot be protected by software.

### 6.4 TLS Fingerprint Staleness

Browser TLS fingerprints evolve with every browser release. If ParolNet's mimicked fingerprint falls behind, the fingerprint itself becomes a distinguishing signal. The specification requires updates at least every 6 months (PNP-006 Section 6.1), but this relies on the development community maintaining and distributing updated profiles. In a scenario where ParolNet distribution channels are compromised, users may be unable to receive fingerprint updates.

### 6.5 Timing Correlation by Sophisticated Adversaries

The uniform jitter distribution used in PNP-006 Section 4.4 is a simplification. Real browser inter-packet timing follows complex, non-uniform distributions influenced by page rendering, JavaScript execution, and user behavior. A sufficiently sophisticated classifier trained on real browser traffic could distinguish uniform jitter from genuine browsing patterns. Implementations in high-threat environments are advised to use empirically derived timing distributions (PNP-006 Section 6.4), but no such profiles are currently specified.

### 6.6 Gossip Metadata Exposure

The gossip layer necessarily exposes message metadata (source PeerId, TTL, timestamps) to forwarding nodes (PNP-005 Section 6.6). While application payloads are E2EE, a node that handles a large volume of gossip traffic can build a social graph of which PeerIds communicate via gossip. The recommendation to use pseudonymous PeerIds (PNP-005 Section 7.1) mitigates this but does not eliminate it, particularly if pseudonymous PeerIds can be linked through traffic analysis.

### 6.7 mDNS/BLE Service Discovery

Local network discovery via mDNS uses the service type `_parolnet._tcp` (PNP-005 Section 5.9, PNP-003 Section 5.6), which unambiguously identifies a ParolNet user to any local network observer. In high-threat environments (e.g., monitored office networks, university campuses in authoritarian states), this is a significant risk. Users MUST be able to disable local discovery entirely.

### 6.8 No Centralized Relay Vetting

Unlike Tor's directory authorities, ParolNet's relay directory is distributed via gossip. There is no authority to vet relay operators, flag malicious relays, or coordinate relay bans. PoW requirements (PNP-005 Section 5.6) raise the cost of Sybil attacks but do not prevent them from well-resourced adversaries. The gossip-based directory is more censorship-resistant but more vulnerable to Sybil injection than a centralized directory model.

### 6.9 WASM Execution Environment

The parolnet-wasm crate runs in a browser environment where constant-time guarantees are weakened by JIT compilation, garbage collection, and shared memory. Side-channel attacks (cache timing, speculative execution) are harder to defend against in WASM than in native code. The browser's same-origin policy provides isolation, but browser extensions and compromised web contexts are outside ParolNet's control.

---

## 7. Security Properties

When operating correctly -- with an uncompromised device, a non-globally-observed network, and at least one honest relay hop per circuit -- ParolNet provides the following security properties.

### 7.1 Forward Secrecy

Compromise of long-term identity keys does NOT reveal past message content. This is provided by:
- Ephemeral X25519 keys in X3DH handshake (PNP-002 Section 6.1)
- Double Ratchet generating unique per-message keys (PNP-002 Section 5.4)
- Per-circuit ephemeral X25519 keys at each relay hop (PNP-004 Section 5.1)

Each message uses a key derived through the ratchet, which is deleted after use.

### 7.2 Future Secrecy (Post-Compromise Recovery)

If a session key is compromised, the Double Ratchet restores secrecy after the next DH ratchet step (typically within a few messages). Periodic rekeying every 7 days or 10,000 messages (PNP-002 Section 5.5) provides an additional recovery mechanism.

### 7.3 Metadata Protection

ParolNet protects communication metadata at multiple layers:
- **Who**: No registration, no identifiers beyond cryptographic keys. PeerId = SHA-256(pubkey).
- **To whom**: Onion routing hides destination from all but the exit relay. Exit relay sees PeerId, not real-world identity.
- **When**: Timestamps coarsened to 5-minute buckets (PNP-001 Section 3.2). Constant-rate padding obscures activity timing.
- **How much**: Bucket padding (256/1024/4096/16384 bytes) hides message sizes (PNP-001 Section 3.6). Fixed 512-byte cells on circuits (PNP-004 Section 3).
- **How often**: Cover traffic and dummy messages maintain constant traffic rate regardless of actual communication activity (PNP-006 Section 4).

### 7.4 Traffic Indistinguishability

To a passive network observer, ParolNet traffic is designed to be indistinguishable from HTTPS/2 browsing on CDN-hosted websites. This is achieved through:
- TLS ClientHello fingerprint mimicry (PNP-006 Section 5.1)
- HTTP/2 framing for all protocol data (PNP-006 Section 5.3)
- Port 443 exclusively (PNP-006 Section 5.2)
- Connection behavior matching browser patterns (PNP-006 Section 4.5)
- Burst smoothing and request-response cadences (PNP-006 Sections 4.2, 4.6)

### 7.5 Cryptographic Deniability

The X3DH handshake does not produce a non-repudiable transcript (PNP-002 Section 6.8). Neither party can prove to a third party that the other participated in a conversation. No signatures or MACs over the handshake transcript are added that would break this property.

### 7.6 Relay Zero-Trust

The system assumes any individual relay may be adversary-controlled. Security emerges from the requirement that an adversary must compromise all three hops simultaneously to break anonymity (PNP-004 Section 6.1). The E2EE layer (Double Ratchet) is independent of the relay layer, so even a fully compromised relay path cannot read message content.

### 7.7 Censorship Resistance

The system is designed to resist censorship through:
- No single point of failure or control (decentralized)
- Traffic indistinguishable from normal browsing (resists DPI-based blocking)
- Relay probing returns plausible web content (resists active probing)
- Gossip-based relay directory (no directory authority to censor)
- Offline mesh capability via mDNS/BLE (survives internet shutdowns)
- Domain fronting support where available (PNP-006 Section 5.2)

### 7.8 Panic Wipe / Data Destruction

A single action securely erases all keys, messages, contacts, and session state from the device. Combined with Zeroize/ZeroizeOnDrop on all key material, this ensures that a seized device (after panic wipe) reveals no usable cryptographic material or communication history.

---

## Appendix A: Threat/Adversary Cross-Reference Matrix

Which adversary profiles pose which threats:

| Threat ID | L-ADV | N-ADV | R-ADV | D-ADV | G-ADV |
|-----------|-------|-------|-------|-------|-------|
| T-1 TLS fingerprint | Yes | **Yes** | No | No | Yes |
| T-2 Statistical analysis | Yes | **Yes** | No | No | **Yes** |
| T-3 Active probing | Yes | **Yes** | No | No | No |
| T-4 TLS MITM | Yes | **Yes** | No | No | No |
| T-5 Connection metadata | Yes | **Yes** | No | No | **Yes** |
| T-6 TCP RST injection | Yes | **Yes** | No | No | No |
| R-1 Single relay compromise | No | No | **Yes** | No | No |
| R-2 Sybil relay directory | No | Yes | **Yes** | No | Yes |
| R-5 Timing correlation | No | No | Yes | No | **Yes** |
| R-7 CREATE flooding | Yes | Yes | **Yes** | No | No |
| R-8 Exit observes dest | No | No | **Yes** | No | No |
| G-1 Message forgery | No | No | Yes | **Yes** | No |
| G-2 Spam flooding | Yes | Yes | **Yes** | No | No |
| G-4 Source PeerId exposure | No | No | **Yes** | No | **Yes** |
| B-1 QR interception | **Yes** | No | No | No | No |
| B-2 Bootstrap MITM | **Yes** | No | No | No | No |
| B-4 mDNS discovery | **Yes** | No | No | No | No |
| C-1 Device seizure | No | No | No | **Yes** | No |
| C-2 Endpoint malware | No | No | No | **Yes** | No |
| C-3 Coerced disclosure | No | No | No | **Yes** | No |

**Bold** indicates the primary adversary for that threat.

---

## Appendix B: Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | 2026-04-10 | ParolNet Team | Initial draft |
