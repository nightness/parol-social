# PNP-003: ParolNet Bootstrap Protocol

### Status: CANDIDATE
### Version: 0.2
### Date: 2026-04-17

---

## Changelog

**v0.2 (2026-04-17) — Harmonization pass**

- Status bumped from DRAFT to CANDIDATE.
- Assigned a normative BLE service UUID for §5.7 Bluetooth bootstrap (previously TBD): `b51e4c00-50ef-4e6c-9a83-d2b4f0ae1c01`. Characteristic UUIDs are derived siblings within the same service.
- Added clause IDs to every RFC 2119 statement (`PNP-003-MUST-NNN`, `-SHOULD-NNN`, `-MAY-NNN`).
- Clarified that the 30-minute QR freshness window (§5.1.6) is scoped to the bootstrap layer and is unrelated to the envelope-level replay/timestamp windows tabulated in PNP-001 §5.4.
- Completed cross-reference table.

**v0.1 (2026-04-10)** — Initial draft.

---

## Implementation Note

This specification describes the bootstrap design target. The current code implements QR bootstrap helpers and WASM bindings, but local discovery is implemented as obfuscated UDP broadcast in `parolnet-mesh`, not as mDNS/BLE. Treat mDNS/BLE requirements below as design text until the spec and implementation are reconciled.

---

## 1. Overview

The ParolNet Bootstrap Protocol (PBP) defines how two peers establish initial contact with zero pre-existing infrastructure. It covers the out-of-band exchange of identity material, the derivation of a shared authentication secret, and the first authenticated handshake. The protocol is designed so that no data is ever stored on any server, and the entire process can occur over local connectivity (LAN, Bluetooth) or through physical proximity (QR code scanning).

PBP produces a shared secret and authenticated identity binding that feeds into PNP-002 (Handshake Protocol) for session establishment.

## 2. Terminology

All RFC 2119 keywords apply. Additional terms:

- **Bootstrap Secret (BS)**: A shared secret established through out-of-band exchange.
- **QR Payload**: The data encoded in a QR code for peer introduction.
- **SAS**: Short Authentication String. A human-readable string derived from key material for voice verification.
- **mDNS**: Multicast DNS (RFC 6762), used for local peer discovery.
- **Contact Binding**: The association between a PeerId and a Bootstrap Secret, stored locally by each peer.
- **Passphrase**: A human-memorable string used as an alternative to QR scanning.

## 3. Message Format

### 3.1 QR Code Payload

The QR payload is CBOR-encoded, then base45-encoded (for efficient QR representation), and presented as a QR code. The total payload MUST fit within a single QR code (maximum 2953 bytes for alphanumeric mode at error correction level M). **PNP-003-MUST-001**

```
QRPayload = CBOR Map:
  {
    "v"    : uint8,           -- Protocol version. MUST be 0x01.
    "ik"   : bstr(32),        -- Ed25519 identity public key of the QR presenter.
    "seed" : bstr(32),        -- 256-bit cryptographically random shared secret seed.
    "relay" : tstr / null,    -- OPTIONAL. Relay hint (hostname:port or onion address).
    "ts"   : uint64,          -- Coarsened timestamp (5-min bucket) of QR generation.
    "net"  : uint8            -- Network hint: 0x01=internet relay, 0x02=LAN, 0x03=BT.
  }
```

The `v` field MUST be set to 0x01 for this version of the protocol. **PNP-003-MUST-002**

CBOR byte-level layout example (approximate):

```
A6                          -- CBOR map(6)
  61 76                     -- key "v" (text, 1 byte)
  01                        -- value 1 (unsigned int)
  62 69 6B                  -- key "ik" (text, 2 bytes)
  58 20 <32 bytes>          -- value: bstr(32)
  64 73 65 65 64            -- key "seed" (text, 4 bytes)
  58 20 <32 bytes>          -- value: bstr(32)
  65 72 65 6C 61 79         -- key "relay" (text, 5 bytes)
  F6                        -- value: null (or tstr if present)
  62 74 73                  -- key "ts" (text, 2 bytes)
  1A XXXXXXXX               -- value: uint32 (coarsened timestamp)
  63 6E 65 74               -- key "net" (text, 3 bytes)
  01                        -- value: 1 (internet relay)
```

Total CBOR size: approximately 82 bytes (without relay hint), well within QR capacity.

### 3.2 Passphrase-Based Bootstrap

When QR scanning is not feasible (e.g., phone call, text message), peers MAY use a passphrase instead:

```
PassphrasePayload = CBOR Map:
  {
    "v"       : uint8,         -- Protocol version. MUST be 0x01.
    "ik"      : bstr(32),      -- Identity public key.
    "phrase"  : tstr           -- Human-readable passphrase (see Section 5.3).
  }
```

The `v` field MUST be set to 0x01. **PNP-003-MUST-003** The passphrase is communicated verbally or through an existing trusted channel. It MUST NOT be transmitted over the ParolNet network. **PNP-003-MUST-004**

### 3.3 Bootstrap Handshake Message

After BS derivation, the first authenticated contact uses this message, wrapped in a PNP-001 envelope with `msg_type = 0x05`:

```
BootstrapHandshake = CBOR Map:
  {
    "type"          : uint8,         -- 0x10 (BOOTSTRAP_INIT) or 0x11 (BOOTSTRAP_RESP).
    "ik"            : bstr(32),      -- Sender's Ed25519 identity public key.
    "ek"            : bstr(32),      -- Ephemeral X25519 public key.
    "proof"         : bstr(32),      -- HMAC-SHA-256(BS, ik || ek || nonce).
    "nonce"         : bstr(16),      -- 128-bit random nonce.
    "prekey_bundle" : PreKeyBundle   -- Sender's pre-key bundle (Section 3.1 of PNP-002).
  }
```

### 3.4 SAS Verification Message

```
SASVerify = CBOR Map:
  {
    "type"       : uint8,       -- 0x12 (SAS_CONFIRM).
    "sas_mac"    : bstr(32),    -- HMAC-SHA-256(session_key, sas_string || "confirm").
    "nonce"      : bstr(16)     -- 128-bit random nonce.
  }
```

### 3.5 Local Discovery Announcement (mDNS/BT)

For LAN or Bluetooth discovery, peers broadcast:

```
DiscoveryAnnouncement = CBOR Map:
  {
    "v"       : uint8,         -- Protocol version. MUST be 0x01.
    "peer_id" : bstr(32),      -- PeerId (SHA-256 of identity public key).
    "port"    : uint16,        -- TCP/UDP port for direct connection.
    "nonce"   : bstr(8),       -- 64-bit random nonce (rotated each broadcast).
    "bs_hint" : bstr(4)        -- First 4 bytes of SHA-256(BS), to help the
                                  matching peer identify the announcement without
                                  revealing BS to observers.
  }
```

The `v` field MUST be set to 0x01. **PNP-003-MUST-005**

## 4. State Machine

```
                  +-------------------+
                  | NO_CONTACT        |
                  | (peers unknown    |
                  |  to each other)   |
                  +---------+---------+
                            |
            QR scan / passphrase exchange / BT tap
                            |
                            v
                  +---------+---------+
                  | SECRET_SHARED     |
                  | (BS derived,      |
                  |  not yet verified)|
                  +---------+---------+
                            |
              BootstrapHandshake exchange
                            |
                            v
                  +---------+---------+
                  | AUTHENTICATED     |
                  | (proof verified,  |
                  |  identities bound)|
                  +---------+---------+
                            |
                   +--------+--------+
                   |                 |
            SAS requested     SAS skipped
                   |                 |
                   v                 |
          +--------+--------+       |
          | SAS_PENDING      |       |
          | (awaiting voice  |       |
          |  confirmation)   |       |
          +--------+---------+       |
                   |                 |
             SAS confirmed           |
                   |                 |
                   v                 v
          +--------+---------+------+--+
          | CONTACT_ESTABLISHED         |
          | (transition to PNP-002      |
          |  full handshake)            |
          +-----------------------------+
```

State transition table:

| Current State | Event | Next State | Action |
|--------------|-------|------------|--------|
| NO_CONTACT | QR scanned (either direction) | SECRET_SHARED | Derive BS from seed |
| NO_CONTACT | Passphrase exchanged | SECRET_SHARED | Derive BS from passphrase |
| NO_CONTACT | BT/NFC tap | SECRET_SHARED | Exchange QR payloads over BT, derive BS |
| SECRET_SHARED | Send/receive BootstrapHandshake | AUTHENTICATED | Verify proof HMAC |
| SECRET_SHARED | Proof verification fails | NO_CONTACT | Abort, erase BS |
| SECRET_SHARED | Timeout (5 minutes) | NO_CONTACT | Erase BS |
| AUTHENTICATED | SAS verification requested | SAS_PENDING | Compute and display SAS |
| AUTHENTICATED | SAS skipped by both peers | CONTACT_ESTABLISHED | Accept risk, proceed |
| SAS_PENDING | SAS confirmed by both peers | CONTACT_ESTABLISHED | Proceed to PNP-002 |
| SAS_PENDING | SAS mismatch / rejection | NO_CONTACT | Abort, erase all state |
| SAS_PENDING | Timeout (10 minutes) | NO_CONTACT | Abort, erase all state |
| CONTACT_ESTABLISHED | Initiate PNP-002 handshake | (PNP-002 INIT) | Use BS-authenticated IK binding |

## 5. Processing Rules

### 5.1 QR Code Bootstrap

1. The QR presenter (Alice) MUST generate a fresh 32-byte `seed` using a CSPRNG. **PNP-003-MUST-006**
2. Alice MUST encode the QRPayload as CBOR, then base45-encode the result. **PNP-003-MUST-007**
3. The QR code MUST use error correction level M or higher. **PNP-003-MUST-008**
4. Alice MUST display the QR code only while actively waiting for contact. **PNP-003-MUST-009** The QR SHOULD include a visual expiration indicator (RECOMMENDED: 10 minutes). **PNP-003-SHOULD-001**
5. The QR scanner (Bob) MUST decode and validate the QR payload. **PNP-003-MUST-010**
6. Bob MUST verify that the timestamp `ts` is within 30 minutes of the current coarsened time. QR codes older than 30 minutes MUST be rejected. **PNP-003-MUST-011**
7. Both peers derive the Bootstrap Secret: **PNP-003-MUST-012**
   ```
   BS = HKDF-SHA-256(
     salt = "ParolNet_bootstrap_v1",
     ikm  = seed,
     info = sorted_concat(IK_alice_pub, IK_bob_pub),
     len  = 32
   )
   ```
   The `info` field uses the lexicographically smaller public key first, ensuring both peers derive the same BS regardless of who presented the QR.

### 5.2 Shared Secret Derivation (Passphrase)

1. The passphrase MUST be at least 6 words from a standardized wordlist (BIP-39 English wordlist, 2048 words, yielding at least 66 bits of entropy). **PNP-003-MUST-013**
2. The passphrase MUST be transmitted out-of-band (voice, existing trusted channel). It MUST NOT be transmitted over the ParolNet network. **PNP-003-MUST-014**
3. Both peers derive BS from the passphrase: **PNP-003-MUST-015**
   ```
   BS = HKDF-SHA-256(
     salt = "ParolNet_passphrase_v1",
     ikm  = Argon2id(passphrase, salt="ParolNet", t=3, m=65536, p=4),
     info = sorted_concat(IK_alice_pub, IK_bob_pub),
     len  = 32
   )
   ```
   Argon2id is used to strengthen the passphrase against brute-force attacks on the BS.
4. After BS derivation, the passphrase MUST be securely erased from memory. **PNP-003-MUST-016**

### 5.3 Passphrase Generation

1. Implementations MUST provide a passphrase generator that selects words uniformly at random from the BIP-39 English wordlist. **PNP-003-MUST-017**
2. The default passphrase length MUST be 8 words (88 bits of entropy). **PNP-003-MUST-018**
3. Implementations MAY support other wordlists for localization, provided the wordlist contains at least 2048 words and the entropy per word is clearly communicated to the user. **PNP-003-MAY-001**
4. Implementations MUST display the entropy of the generated passphrase to the user. **PNP-003-MUST-019**

### 5.4 Bootstrap Handshake

1. The peer who scanned the QR (or both peers simultaneously after passphrase exchange) MUST send a BootstrapHandshake message. **PNP-003-MUST-020**
2. The `proof` field MUST be computed as: **PNP-003-MUST-021**
   ```
   proof = HMAC-SHA-256(BS, ik_sender || ek_sender || nonce)
   ```
3. The receiver MUST verify the `proof` by recomputing the HMAC with the received values and the locally derived BS. If verification fails, the bootstrap MUST be aborted and BS MUST be erased. **PNP-003-MUST-022**
4. After successful proof verification, both peers MUST exchange PreKeyBundles (included in the BootstrapHandshake) and transition to PNP-002 handshake. **PNP-003-MUST-023**
5. Both peers MUST erase the `seed` and BS from memory after the PNP-002 session reaches ESTABLISHED state. The long-term contact binding is maintained through the identity key association, not the bootstrap secret. **PNP-003-MUST-024**

### 5.5 SAS Verification

1. After the AUTHENTICATED state is reached, either peer MAY request SAS verification. **PNP-003-MAY-002**
2. The SAS is computed as: **PNP-003-MUST-025**
   ```
   sas_material = HKDF-SHA-256(
     salt = BS,
     ikm  = IK_alice_pub || IK_bob_pub || EK_alice_pub || EK_bob_pub,
     info = "ParolNet_SAS_v1",
     len  = 5
   )
   sas_string = encode_as_digits(sas_material)  -- 6-digit decimal number
   ```
   The 5 bytes (40 bits) are converted to a 6-digit decimal string by taking `uint40 mod 1000000` and zero-padding.
3. Both peers MUST display the SAS to the user. **PNP-003-MUST-026** Users SHOULD compare the SAS over a voice channel or in person. **PNP-003-SHOULD-002**
4. Implementations MUST also support an emoji-based SAS (for accessibility): the 5 bytes are split into 5 values (0-255), each mapped to one of 256 distinct emoji. **PNP-003-MUST-027**
5. After the user confirms the SAS matches, the confirming peer MUST send a SASVerify message. **PNP-003-MUST-028**
6. Both peers MUST receive the SASVerify message and verify the `sas_mac` before transitioning to CONTACT_ESTABLISHED. **PNP-003-MUST-029**

### 5.6 Local Network Discovery (mDNS)

1. For LAN bootstrap, peers MUST announce their presence using mDNS with service type `_parolnet._tcp`. **PNP-003-MUST-030**
2. The TXT record MUST contain the CBOR-encoded DiscoveryAnnouncement, base64-encoded. **PNP-003-MUST-031**
3. The `bs_hint` field allows a peer who already has a BS (from QR/passphrase) to identify the correct announcement without revealing the BS to network observers.
4. The `nonce` MUST be rotated with each mDNS announcement (RECOMMENDED interval: 30 seconds). **PNP-003-MUST-032**
5. After discovering a matching peer, the peers MUST establish a direct TCP connection and proceed with the BootstrapHandshake over that connection. **PNP-003-MUST-033**
6. All mDNS announcements MUST cease once the connection is established. **PNP-003-MUST-034**

### 5.7 Bluetooth Bootstrap

1. For Bluetooth bootstrap, peers MUST advertise a BLE service with service UUID `b51e4c00-50ef-4e6c-9a83-d2b4f0ae1c01`. **PNP-003-MUST-035** The service exposes two GATT characteristics:
   - QR Exchange Characteristic: `b51e4c00-50ef-4e6c-9a83-d2b4f0ae1c02` (write + notify, carries a QRPayload equivalent in CBOR).
   - BS Confirmation Characteristic: `b51e4c00-50ef-4e6c-9a83-d2b4f0ae1c03` (write + notify, carries the BootstrapHandshake message).
2. The BLE advertisement MUST include the `bs_hint` (4 bytes) in the service data. **PNP-003-MUST-036**
3. Upon BLE connection, peers MUST exchange QRPayload-equivalent data over the QR Exchange Characteristic. **PNP-003-MUST-037**
4. The BLE connection MUST be encrypted at the link layer (BLE Secure Connections, LE Secure Connections pairing with Numeric Comparison or Passkey). **PNP-003-MUST-038**
5. After exchanging identity material, the peers MUST proceed with the BootstrapHandshake either over BLE or by transitioning to a TCP connection using information from the exchange. **PNP-003-MUST-039**

## 6. Security Considerations

1. **QR Code Interception**: An attacker who photographs the QR code obtains the `seed` and the presenter's identity key. This allows them to derive BS and potentially impersonate the scanner. To mitigate this: (a) QR codes SHOULD be displayed briefly **PNP-003-SHOULD-003**, (b) the QR presenter MUST accept only one bootstrap per seed **PNP-003-MUST-040**, (c) SAS verification SHOULD be performed for high-security contacts. **PNP-003-SHOULD-004**

2. **Passphrase Brute-Force**: With 8 BIP-39 words (88 bits of entropy) and Argon2id strengthening, offline brute-force is computationally infeasible. Implementations MUST NOT accept passphrases shorter than 6 words. **PNP-003-MUST-041** The Argon2id parameters (t=3, m=64MB, p=4) SHOULD be tuned for a computation time of 500ms-2s on the target platform. **PNP-003-SHOULD-005**

3. **Man-in-the-Middle**: Without SAS verification or a pre-existing trusted channel, a MITM attacker can intercept the QR scan and substitute their own identity key. SAS verification detects this attack with probability `1 - 10^-6` (for 6-digit SAS). Implementations SHOULD strongly encourage SAS verification for initial contacts **PNP-003-SHOULD-006** and MUST make the verification option prominently visible. **PNP-003-MUST-042**

4. **Replay of Bootstrap Messages**: The 128-bit nonce in BootstrapHandshake prevents replay. The timestamp in the QR payload provides an additional time-bound. Implementations MUST reject bootstrap handshakes with nonces seen in the last 60 minutes. **PNP-003-MUST-043**

5. **BS Erasure**: The bootstrap secret is ephemeral and MUST be erased after PNP-002 session establishment. **PNP-003-MUST-044** If BS is compromised after erasure, it does not affect the ongoing Double Ratchet session (forward secrecy is provided by PNP-002).

6. **Local Network Exposure**: mDNS announcements reveal that a ParolNet peer exists on the local network. The `bs_hint` partially mitigates indiscriminate correlation, but a local network observer can detect ParolNet usage. For high-risk environments, implementations SHOULD prefer Bluetooth or direct QR exchange over mDNS. **PNP-003-SHOULD-007**

7. **Bluetooth Security**: BLE advertisements are inherently public. The `bs_hint` prevents casual observers from associating an advertisement with a specific bootstrap exchange, but an attacker who has the BS can match it. BLE Secure Connections provides link-layer encryption, but implementations MUST NOT rely solely on BLE link-layer security; the BootstrapHandshake HMAC proof provides application-layer authentication. **PNP-003-MUST-045**

## 7. Privacy Considerations

1. **No Server Storage**: At no point during bootstrap is any data stored on any server, relay, or third-party infrastructure. All data exchange occurs directly between the two peers (QR, voice, BLE, LAN) or through existing trusted channels.

2. **Ephemeral Discovery**: mDNS announcements and BLE advertisements MUST cease once the bootstrap is complete. **PNP-003-MUST-046** The `nonce` rotation ensures that passive observers cannot track a peer across announcements.

3. **Identity Key Exposure**: The QR payload and BootstrapHandshake contain the identity public key in cleartext (or base45-encoded). This is acceptable because bootstrap is inherently an identity-revealing operation -- you are introducing yourself to a specific person. However, the identity key MUST NOT be broadcast beyond the intended recipient. **PNP-003-MUST-047**

4. **No Breadcrumbs**: After successful bootstrap:
   - The QR code MUST be cleared from the display and any screenshot buffer. **PNP-003-MUST-048**
   - The passphrase MUST be erased from memory. **PNP-003-MUST-049**
   - The BS MUST be erased after PNP-002 session establishment. **PNP-003-MUST-050**
   - mDNS/BLE advertisements MUST be stopped. **PNP-003-MUST-051**
   - No logs, analytics, or telemetry regarding the bootstrap event MUST be transmitted or stored persistently. Local secure logs MAY be kept if the user explicitly opts in. **PNP-003-MUST-052**

5. **Contact Graph Protection**: The bootstrap process creates a contact binding that is stored only on the two peers' devices. No central directory, social graph, or contact list exists on any server. If a peer's device is compromised, only that peer's contact list is exposed -- there is no server-side graph to seize.

6. **Relay Hint Privacy**: The optional `relay` field in the QR payload reveals a relay that the presenter uses. This relay could be monitored. Implementations SHOULD rotate relay hints **PNP-003-SHOULD-008** and MAY omit the relay hint entirely if the peers are bootstrapping on the same local network. **PNP-003-MAY-003**

## 8. Cross-Protocol References

| Spec | Relationship |
|------|-------------|
| PNP-001 (Wire Protocol) | BootstrapHandshake messages transmitted as PNP-001 envelopes with `msg_type = 0x05`. The 30-minute QR freshness window defined in §5.1.6 is scoped to bootstrap only and is separate from the envelope-level timestamp / replay windows in PNP-001 §5.4. |
| PNP-002 (Handshake) | PBP produces an authenticated IK binding + BS that feeds PNP-002. After PNP-002 ESTABLISHED, BS is erased. |
| PNP-004 (Relay Circuit) | Relay hints in QR payloads may reference PNP-004 relays. |
| PNP-005 (Gossip Mesh) | Pre-key bundles exchanged during bootstrap may subsequently be republished via gossip. |

## 9. Cross-Protocol Dependencies

```
+-------------------+
|     PNP-003       |
|   Bootstrap       |
| (initial contact) |
+--------+----------+
         |
         | produces: authenticated IK binding + BS
         v
+--------+----------+
|     PNP-002       |
|   Handshake       |
| (session setup)   |
+--------+----------+
         |
         | produces: Double Ratchet session
         v
+--------+----------+
|     PNP-001       |
|   Wire Protocol   |
| (message envelope)|
+-------------------+
```

All messages from all three protocols are transmitted as PNP-001 envelopes. PNP-002 and PNP-003 messages use `msg_type = 0x05` (HANDSHAKE) in the PNP-001 cleartext header; the specific handshake sub-type is determined by the `type` field inside the encrypted payload.
