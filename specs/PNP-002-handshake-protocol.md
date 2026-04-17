# PNP-002: ParolNet Handshake Protocol

### Status: CANDIDATE
### Version: 0.3
### Date: 2026-04-17

---

## Changelog

**v0.3 (2026-04-17) — Identity rotation (H5)**

- Added §8 "Identity Rotation": specifies the signed key-update message flow that lets a user regenerate their Ed25519 identity (and therefore their PeerId) while preserving established Double Ratchet sessions with existing contacts. New clauses: `PNP-002-MUST-036` through `PNP-002-MUST-039`, `PNP-002-SHOULD-011` and `PNP-002-SHOULD-012`. Existing "Cross-Protocol References" table renumbered from §8 to §9.
- PNP-001 §3.4 cross-referenced: code `0x13 IDENTITY_ROTATE` carries the signed rotation payload.

**v0.2 (2026-04-17) — Harmonization pass**

- Status bumped from DRAFT to CANDIDATE.
- Added clause IDs to every RFC 2119 statement (`PNP-002-MUST-NNN`, `-SHOULD-NNN`, `-MAY-NNN`).
- Clarified that the `init_key` / `init_iv` derivation corresponds to scheme `N-HANDSHAKE` in PNP-001 §9 Nonce Construction Catalog.
- Clarified the `aead_algo` field semantics (§3.2): if the field is absent or set to 0x00, ChaCha20-Poly1305 MUST be used. Only explicit mutual agreement on 0x02 may select AES-256-GCM, and this selection governs only the PNP-001 session-layer AEAD (never the PNP-004 onion-layer AEAD).
- Completed cross-reference table.

**v0.1 (2026-04-10)** — Initial draft.

---

## 1. Overview

The ParolNet Handshake Protocol (PHP) defines how two peers establish an encrypted session. It adapts the Extended Triple Diffie-Hellman (X3DH) key agreement protocol for a fully decentralized environment where no central key server exists. Pre-key bundles are distributed through the relay network, direct exchange, or out-of-band mechanisms (PNP-003).

Upon completion of the handshake, both peers derive a shared secret that initializes a Double Ratchet session for ongoing message encryption. The protocol provides forward secrecy, future secrecy (via rekeying), and cryptographic deniability.

## 2. Terminology

All RFC 2119 keywords apply as defined in PNP-001 Section 2. Additional terms:

- **IK**: Identity Key. A long-term Ed25519 keypair. The public key hashes to the PeerId.
- **SPK**: Signed Pre-Key. A medium-term X25519 keypair, signed by the IK. Rotated periodically (RECOMMENDED: every 7-30 days).
- **OPK**: One-Time Pre-Key. An ephemeral X25519 keypair, used once and discarded. Peers SHOULD maintain a pool of 20-100 OPKs.
- **EK**: Ephemeral Key. A single-use X25519 keypair generated at handshake initiation time.
- **Pre-Key Bundle**: The set {IK_pub, SPK_pub, SPK_sig, [OPK_pub]} published by a peer.
- **KDF**: Key Derivation Function. HKDF-SHA-256 (RFC 5869).

## 3. Message Format

### 3.1 Pre-Key Bundle

The pre-key bundle is CBOR-encoded and distributed via the relay network, direct transfer, or out-of-band (PNP-003). It is wrapped in a PNP-001 envelope with `msg_type = 0x05` (HANDSHAKE).

```
PreKeyBundle = CBOR Map:
  {
    "ik"      : bstr(32),       -- Ed25519 identity public key.
    "spk"     : bstr(32),       -- X25519 signed pre-key public key.
    "spk_id"  : uint32,         -- Signed pre-key identifier.
    "spk_sig" : bstr(64),       -- Ed25519 signature over (spk || spk_id).
    "opks"    : [                -- Array of one-time pre-keys. MAY be empty.
                  {
                    "id"  : uint32,    -- One-time pre-key identifier.
                    "key" : bstr(32)   -- X25519 one-time pre-key public key.
                  }
                ]
  }
```

A peer SHOULD publish a new pre-key bundle whenever its OPK pool is depleted or its SPK is rotated. **PNP-002-SHOULD-001**

### 3.2 Handshake Initiation Message (Alice -> Bob)

```
HandshakeInit = CBOR Map:
  {
    "type"       : uint8,          -- 0x01 (INIT).
    "ik_a"       : bstr(32),       -- Alice's Ed25519 identity public key.
    "ek_a"       : bstr(32),       -- Alice's ephemeral X25519 public key.
    "spk_id_b"   : uint32,         -- ID of Bob's signed pre-key Alice used.
    "opk_id_b"   : uint32 / null,  -- ID of Bob's one-time pre-key Alice used,
                                      or null if none was available.
    "nonce"      : bstr(16),       -- 128-bit cryptographically random nonce.
    "ciphertext" : bstr,           -- Initial message encrypted with derived key.
    "aead_algo"  : uint8           -- 0x01 = ChaCha20-Poly1305 (default),
                                      0x02 = AES-256-GCM,
                                      0x00 / absent = ChaCha20-Poly1305 (implicit).
  }
```

The `aead_algo` field selects the **session-layer AEAD cipher only** (PNP-001 §3.3). It does NOT affect the PNP-004 onion-layer AEAD, which is fixed to ChaCha20-Poly1305. If the field is absent or set to 0x00, ChaCha20-Poly1305 MUST be used. **PNP-002-MUST-001** An implementation MUST refuse to negotiate any value other than 0x01 or 0x02. **PNP-002-MUST-002**

### 3.3 Handshake Response Message (Bob -> Alice)

```
HandshakeResponse = CBOR Map:
  {
    "type"       : uint8,         -- 0x02 (RESPONSE).
    "ik_b"       : bstr(32),      -- Bob's Ed25519 identity public key.
    "ek_b"       : bstr(32),      -- Bob's ephemeral X25519 public key.
    "nonce"      : bstr(16),      -- 128-bit cryptographically random nonce.
    "ciphertext" : bstr,          -- Response encrypted with session key.
    "ratchet_key": bstr(32)       -- Bob's initial Double Ratchet public key.
  }
```

### 3.4 Rekeying Message

```
RekeyMessage = CBOR Map:
  {
    "type"         : uint8,       -- 0x03 (REKEY).
    "new_spk"      : bstr(32),    -- New X25519 signed pre-key public key.
    "new_spk_id"   : uint32,      -- New signed pre-key identifier.
    "new_spk_sig"  : bstr(64),    -- Ed25519 signature over (new_spk || new_spk_id).
    "nonce"        : bstr(16),    -- 128-bit cryptographically random nonce.
    "ciphertext"   : bstr         -- Confirmation, encrypted with current session.
  }
```

### 3.5 Close Message

```
CloseMessage = CBOR Map:
  {
    "type"       : uint8,         -- 0x04 (CLOSE).
    "nonce"      : bstr(16),      -- 128-bit cryptographically random nonce.
    "ciphertext" : bstr           -- Reason/confirmation, encrypted.
  }
```

## 4. State Machine

```
                         publish PreKeyBundle
                                |
                                v
                        +-------+-------+
          (Alice)       |     INIT      |       (Bob)
       generate EK ---->               <---- waiting for contact
                        +-------+-------+
                                |
                  Alice sends HandshakeInit
                                |
                                v
                        +-------+-------+
                        |    OFFERED    |
                        | (Alice waits) |
                        +-------+-------+
                                |
                  Bob validates, sends HandshakeResponse
                                |
                                v
                        +-------+-------+
                        |   ACCEPTED   |
                        | (Bob waits   |
                        |  for first   |
                        |  DR message) |
                        +-------+-------+
                                |
                  Alice validates, sends first DR message
                                |
                                v
                        +-------+-------+
                        |  ESTABLISHED |
                        | (both peers  |
                        |  in Double   |
                        |  Ratchet)    |
                        +-------+-------+
                           |         |
              rekey trigger|         | close trigger
                           v         v
                   +-------+--+  +---+--------+
                   | REKEYING |  |   CLOSED   |
                   +-------+--+  +------------+
                           |
                   rekey complete
                           |
                           v
                   +-------+-------+
                   |  ESTABLISHED  |
                   +---------------+
```

State transition table:

| Current State | Event | Next State | Action |
|--------------|-------|------------|--------|
| INIT | Alice sends HandshakeInit | OFFERED | Start timeout (60s) |
| INIT | Bob receives HandshakeInit | ACCEPTED | Validate, derive keys, send HandshakeResponse |
| OFFERED | Alice receives HandshakeResponse | ESTABLISHED | Validate, derive keys, init Double Ratchet |
| OFFERED | Timeout (60s) | INIT | MAY retry with new EK |
| ACCEPTED | Bob receives first DR message | ESTABLISHED | Confirm session |
| ACCEPTED | Timeout (120s) | INIT | Discard session state |
| ESTABLISHED | Either peer sends RekeyMessage | REKEYING | Begin key rotation |
| REKEYING | Peer confirms rekey | ESTABLISHED | Update session keys |
| REKEYING | Timeout (60s) | ESTABLISHED | Abort rekey, keep old keys |
| ESTABLISHED | Either peer sends CloseMessage | CLOSED | Destroy session state |
| Any | Unrecoverable error | CLOSED | Destroy session state |

## 5. Processing Rules

### 5.1 X3DH Key Agreement (Adapted for Decentralized Use)

The X3DH computation proceeds as follows. Alice has obtained Bob's pre-key bundle through one of:
- The relay network (Bob published it as a HANDSHAKE message).
- Direct exchange (Bluetooth, local network, USB).
- Out-of-band bootstrap (PNP-003).

Alice MUST verify `spk_sig` against `ik` before proceeding. **PNP-002-MUST-003** If verification fails, the handshake MUST be aborted. **PNP-002-MUST-004**

Alice converts her Ed25519 IK to an X25519 key for DH computation (using the birational map defined in RFC 8032, Section 5.1.5). Bob's IK is similarly converted.

Alice computes:

```
DH1 = X25519(IK_a_x25519_private, SPK_b)
DH2 = X25519(EK_a_private, IK_b_x25519)
DH3 = X25519(EK_a_private, SPK_b)
DH4 = X25519(EK_a_private, OPK_b)      -- only if OPK_b is available
```

The shared secret is:

```
If OPK used:
  SK = HKDF-SHA-256(
    salt = 32 zero bytes,
    ikm  = 0xFF repeated 32 bytes || DH1 || DH2 || DH3 || DH4,
    info = "ParolNet_X3DH_v1",
    len  = 32
  )

If no OPK:
  SK = HKDF-SHA-256(
    salt = 32 zero bytes,
    ikm  = 0xFF repeated 32 bytes || DH1 || DH2 || DH3,
    info = "ParolNet_X3DH_v1",
    len  = 32
  )
```

The leading 32 bytes of 0xFF serve as a domain separator (consistent with the Signal X3DH specification).

### 5.2 Handshake Initiation (Alice)

1. Alice MUST generate a fresh ephemeral X25519 keypair (EK_a). **PNP-002-MUST-005**
2. Alice MUST perform the X3DH computation as described in §5.1. **PNP-002-MUST-006**
3. Alice MUST derive the initial encryption key and IV from SK per nonce scheme `N-HANDSHAKE` (PNP-001 §9):
   ```
   init_key = HKDF-SHA-256(salt=SK, ikm="ParolNet_init_key", len=32)
   init_iv  = HKDF-SHA-256(salt=SK, ikm="ParolNet_init_iv",  len=12)
   ```
   **PNP-002-MUST-007**
4. Alice MUST encrypt her initial payload (which MAY include an initial text message, or MAY be empty) using the negotiated AEAD with `init_key` and `init_iv`. **PNP-002-MUST-008**
5. Alice MUST send the HandshakeInit in a PNP-001 envelope with `msg_type = 0x05`. **PNP-002-MUST-009**
6. Alice MUST transition to the OFFERED state and start a 60-second timeout. **PNP-002-MUST-010**
7. Alice MUST retain `EK_a` private key material only until the session is ESTABLISHED. Alice MUST delete it upon ESTABLISHED or on handshake failure, whichever comes first. **PNP-002-MUST-011**

### 5.3 Handshake Response (Bob)

1. Bob MUST verify that `spk_id_b` matches a current or recent SPK. **PNP-002-MUST-012** Bob SHOULD accept SPKs from the previous rotation period (to handle race conditions). **PNP-002-SHOULD-002**
2. If `opk_id_b` is present, Bob MUST verify it matches an unused OPK and MUST delete that OPK after use (one-time property). **PNP-002-MUST-013**
3. Bob MUST perform the X3DH computation (DH operations are symmetric). **PNP-002-MUST-014**
4. Bob MUST derive the same `init_key` and `init_iv` and verify Alice's ciphertext. **PNP-002-MUST-015**
5. Bob MUST generate a fresh ephemeral key (EK_b) and a Double Ratchet initial keypair. **PNP-002-MUST-016**
6. Bob MUST send the HandshakeResponse. **PNP-002-MUST-017**
7. Bob MUST transition to the ACCEPTED state. **PNP-002-MUST-018**

### 5.4 Session Establishment

1. Upon receiving the HandshakeResponse, Alice MUST verify Bob's identity key and derive the session keys. **PNP-002-MUST-019**
2. Both peers MUST initialize the Double Ratchet with:
   - `SK` as the root key.
   - Bob's `ratchet_key` as the initial ratchet public key.
   **PNP-002-MUST-020**
3. Alice MUST send the first Double Ratchet message (which performs the first ratchet step) to confirm the session. **PNP-002-MUST-021**
4. Both peers MUST transition to ESTABLISHED upon successful completion. **PNP-002-MUST-022**

### 5.5 Rekeying

1. Either peer MAY initiate rekeying. **PNP-002-MAY-001** Implementations SHOULD rekey after 7 days or 10,000 messages, whichever comes first. **PNP-002-SHOULD-003**
2. The initiating peer MUST generate a new SPK and sign it with their IK. **PNP-002-MUST-023**
3. The RekeyMessage MUST be encrypted with the current Double Ratchet session. **PNP-002-MUST-024**
4. The receiving peer MUST verify the new SPK signature and acknowledge the rekey. **PNP-002-MUST-025**
5. Both peers MUST derive a new root key:
   ```
   new_root = HKDF-SHA-256(
     salt = current_root_key,
     ikm  = DH(old_ratchet_private, new_spk),
     info = "ParolNet_rekey_v1",
     len  = 32
   )
   ```
   **PNP-002-MUST-026**
6. Both peers MUST continue accepting messages encrypted with the old keys for a grace period of 120 seconds after rekey completion, to handle in-flight messages. **PNP-002-MUST-027**

### 5.6 Session Closure

1. Either peer MAY send a CloseMessage at any time. **PNP-002-MAY-002**
2. Upon sending or receiving a CloseMessage, the peer MUST securely erase all session state: root key, chain keys, message keys, ratchet keypairs. **PNP-002-MUST-028**
3. A peer MUST NOT reuse any key material from a closed session. **PNP-002-MUST-029**
4. After closure, a new handshake (starting from INIT) is REQUIRED to re-establish communication. **PNP-002-MUST-030**

## 6. Security Considerations

1. **Forward Secrecy**: The use of ephemeral keys (EK_a, EK_b) and the Double Ratchet ensures that compromise of long-term identity keys does not reveal past session content. Each message uses a unique key derived through the ratchet.

2. **Key Compromise Impersonation (KCI)**: If Alice's IK is compromised, an attacker can impersonate Alice to Bob but cannot impersonate Bob to Alice (because the attacker does not know Bob's IK private key). This is a property inherited from X3DH.

3. **One-Time Pre-Key Exhaustion**: If Bob's OPK pool is exhausted, the handshake falls back to 3-DH (DH1, DH2, DH3). This provides weaker forward secrecy for the initial handshake (compromise of Bob's SPK and IK would reveal the initial messages). Implementations SHOULD replenish OPK pools proactively. **PNP-002-SHOULD-004**

4. **SPK Rotation**: The SPK SHOULD be rotated every 7-30 days. **PNP-002-SHOULD-005** The previous SPK SHOULD be retained for one additional rotation period to handle in-flight handshakes. **PNP-002-SHOULD-006** SPKs older than two rotation periods MUST be deleted. **PNP-002-MUST-031**

5. **Ed25519 to X25519 Conversion**: The birational map from Ed25519 to X25519 is well-defined and safe. Implementations MUST use a well-audited library for this conversion (e.g., the dalek-cryptography crate). **PNP-002-MUST-032**

6. **Nonce Reuse Prevention**: Every handshake message includes a fresh 128-bit random nonce. Implementations MUST use a cryptographically secure random number generator. **PNP-002-MUST-033**

7. **Timeout Handling**: The 60-second timeout in OFFERED state prevents resource exhaustion from unanswered handshakes. Implementations MUST limit the number of concurrent pending handshakes. **PNP-002-MUST-034** The RECOMMENDED maximum is 32 concurrent pending handshakes per peer. **PNP-002-SHOULD-007**

8. **Deniability**: The handshake does not produce a non-repudiable transcript. The X3DH shared secret can be computed by either party, so neither can prove to a third party that the other participated. The SPK signature proves that Bob published a pre-key bundle, but does not prove that a specific session was established. Implementations MUST NOT add signatures or MACs over the handshake transcript that would break deniability. **PNP-002-MUST-035**

## 7. Privacy Considerations

1. **Identity Key Exposure**: The HandshakeInit message contains Alice's identity public key (`ik_a`) in the cleartext header of the handshake payload. To mitigate this, `ik_a` SHOULD be placed inside the encrypted portion of the envelope payload when possible (i.e., when both peers have an existing session or a shared secret from PNP-003). **PNP-002-SHOULD-008**

2. **Pre-Key Bundle Metadata**: Publishing pre-key bundles through the relay network reveals that a PeerId exists and is active. Implementations SHOULD publish pre-key bundles at regular intervals regardless of activity **PNP-002-SHOULD-009** and MAY publish decoy bundles for non-existent PeerIds. **PNP-002-MAY-003**

3. **Handshake Correlation**: An observer who sees both a HandshakeInit and HandshakeResponse can correlate them by timing and the `spk_id_b` / `opk_id_b` values. These values are inside the encrypted payload and thus protected from relay observers, but the timing correlation remains. Implementations SHOULD add random delay before responding (100-2000ms). **PNP-002-SHOULD-010**

4. **Session Duration**: Long-lived sessions can be correlated by traffic patterns. Periodic rekeying (§5.5) does not change the session's traffic pattern. For stronger privacy, peers MAY close and re-establish sessions periodically through different relay paths. **PNP-002-MAY-004**

## 8. Identity Rotation

### 8.1 Motivation

A ParolNet PeerId is stable: `PeerId = SHA-256(Ed25519_identity_public_key)`. A single one-time correlation (e.g., an observer logging a PeerId alongside an IP address at any point in a user's life) therefore links that user's activity forever under that identity. Identity rotation is an opt-in, user-initiated operation that lets a user discard the correlated PeerId and continue communicating with all existing contacts under a fresh identity without re-running the X3DH handshake.

The mechanism preserves Double Ratchet session state (forward secrecy is not compromised) while unlinking future activity from the old PeerId for any network observer that is not already a contact. Contacts, by construction, learn that the two identities are the same user — this is acceptable because they already know the user through the previous identity.

Identity rotation is orthogonal to SPK rotation (§6.4). SPK rotation happens automatically every 7–30 days and keeps the same IK; identity rotation replaces the IK and is user-initiated (e.g., after a suspected device compromise).

### 8.2 Rotation Message Format

The rotating party (Alice) signs an `IdentityRotationPayload` with her OLD Ed25519 secret key. The payload is serialized (CBOR for the native wire, JSON-with-hex for the PWA/WASM wire — both encode the same six fields) and delivered inside each contact's existing Double Ratchet session as a PNP-001 envelope with `msg_type = 0x13` (IDENTITY_ROTATE, see PNP-001 §3.4).

```
IdentityRotationPayload = CBOR Map:
  {
    "old_peer_id"      : bstr(32),  -- SHA-256(old Ed25519 pub).
    "new_peer_id"      : bstr(32),  -- SHA-256(new Ed25519 pub).
    "new_ed25519_pub"  : bstr(32),  -- New Ed25519 identity public key.
    "rotated_at"       : uint64,    -- Unix seconds at signing time.
    "grace_expires_at" : uint64,    -- rotated_at + 604800 (7 days).
    "signature"        : bstr(64)   -- Ed25519 signature by OLD secret key.
  }
```

### 8.3 Signed Byte Sequence (Domain Separation)

The signature covers the following concatenation (all integers big-endian, matching PNP-001 conventions):

```
signed_bytes =
    "ParolNet-IdentityRotation-v1"
    || old_peer_id           (32 bytes)
    || new_peer_id           (32 bytes)
    || new_ed25519_pub       (32 bytes)
    || rotated_at            (8 bytes, big-endian)
    || grace_expires_at      (8 bytes, big-endian)
```

The fixed ASCII prefix `ParolNet-IdentityRotation-v1` is a domain-separation tag. Its purpose is to guarantee that an Ed25519 signature produced in any other PNP-XXX protocol context (e.g., SPK attestation, authority directory signing, relay challenge-response) cannot be repurposed as a valid identity-rotation attestation. Implementations MUST use exactly this byte sequence for both signing and verification.

### 8.4 Normative Rules

1. A rotation message MUST be signed by the OLD Ed25519 secret key. **PNP-002-MUST-036**
2. A receiver MUST verify the signature with the OLD Ed25519 public key that was stored at original contact-add time (i.e., the pubkey from which the contact's current PeerId was derived). **PNP-002-MUST-037**
3. `grace_expires_at` MUST equal `rotated_at + 604800` (exactly 7 days in seconds). A receiver MUST reject any payload where this invariant does not hold. **PNP-002-MUST-038**
4. After `grace_expires_at` has passed, the rotating party MUST zeroize the old Ed25519 secret key from all client storage. **PNP-002-MUST-039**
5. During the grace window, the rotating party SHOULD accept incoming PNP-001 envelopes addressed to either the old PeerId or the new PeerId. **PNP-002-SHOULD-011**
6. A receiver SHOULD surface the successful rotation in the contact UI (e.g., a "identity rotated <date>" badge, or a prompt to re-verify the safety number) so the user can recognize the change. **PNP-002-SHOULD-012**

### 8.5 Receiver Behavior

Upon receipt of an IDENTITY_ROTATE envelope decrypted successfully against the existing session:

1. Parse the `IdentityRotationPayload`.
2. Look up the OLD Ed25519 pubkey associated with the sender's contact record.
3. Run signature verification per §7.4 clauses 1–3. If any check fails, the frame MUST be treated as malformed and silently discarded (per PNP-001-MUST-008 behavior for unrecognized/invalid content).
4. If all checks pass, auto-remap the contact record's `peer_id` field from `old_peer_id` to `new_peer_id`, retaining the Double Ratchet session (the session is keyed by peer identity, not PeerId, so no ratchet state changes).
5. Store the new Ed25519 pubkey as the contact's "current" key and retain the old one for at least the duration of the grace window to validate any in-flight rotation retransmissions.
6. Surface the rotation to the user (§7.4 clause 6).

The X3DH handshake is NOT re-run. The session's forward/future secrecy guarantees (§6.1) carry over unchanged.

### 8.6 Security Considerations

**Compromise of the OLD secret key**: If Alice's old Ed25519 secret key is compromised before rotation, the attacker can forge a rotation payload to her contacts, binding the attacker's new pubkey to her identity. Implementations SHOULD surface the rotation prominently enough that users can recognize a rotation they did not perform and revert via out-of-band re-verification. This is equivalent to the trust assumption of the original X3DH (§6.1): an attacker who compromises Alice's IK can impersonate Alice to new contacts; §7 extends that to existing contacts only during the rotation window.

**Replay**: The `rotated_at` field is monotonically increasing from the user's perspective. A receiver MAY reject rotation payloads with `rotated_at` older than the already-recorded rotation timestamp for the same contact, though this is not normatively required because the signature is still valid and the payload still nominates a specific `new_peer_id`.

**Linkability to contacts**: Identity rotation unlinks the user's future activity from the old PeerId for network observers only. Existing contacts learn the rotation by design. Users concerned about revealing past identities to specific contacts should instead close the session (§5.6) and re-add them via a new QR code from the new identity.

**Grace window rationale**: The 7-day grace window is chosen to cover common offline intervals (travel, device swap) so that messages in transit to the old PeerId via store-and-forward relays still reach the user. After the window closes, the old PeerId becomes unreachable. This upper bound is a deliberate privacy/availability trade-off.

## 9. Cross-Protocol References

| Spec | Relationship |
|------|-------------|
| PNP-001 (Wire Protocol) | Handshake messages carried in envelopes with `msg_type = 0x05`. Identity rotation messages (§8) carried in envelopes with `msg_type = 0x13`. Nonce scheme `N-HANDSHAKE` defined in PNP-001 §9 governs the `init_iv` derivation in §5.2.3. Session-layer AEAD negotiated here governs PNP-001 §3.3. |
| PNP-003 (Bootstrap) | Out-of-band bootstrap produces a shared secret that MAY seed the initial pre-key bundle exchange, avoiding disclosure over public relays. |
| PNP-004 (Relay Circuit) | Onion-layer AEAD is independent of the session-layer AEAD negotiated here (ChaCha20-Poly1305 only, no negotiation). |
| PNP-005 (Gossip Mesh) | Pre-key bundles MAY be distributed via gossip. |
| PNP-009 (Group Communication) | Group sender-key setup reuses the pairwise session established here. |
