# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — H12 Phase 2 relay peer presence + lookup (PNP-008 v0.3, commit 1 of 2)
- New `parolnet-relay::presence` module: `PresenceAuthority` tracking locally-connected peers + a federation cache (1 hr TTL) of peers seen on other relays. Each `PresenceEntry` is Ed25519-signed by the home relay's identity key over `SHA-256(relay_peer_id || peer_id || last_seen.to_be_bytes())` so the signature is verifiable against the authority-endorsed directory.
- New HTTP endpoints in `parolnet-relay-server`: `GET /peers/presence` (CBOR `Vec<PresenceEntry>` for locally-connected peers) and `GET /peers/lookup?id=<peer_id_hex>` (CBOR `LookupResult` on hit, 404 on miss). Both are rate-limited to 10 req/s per client IP per PNP-008-MUST-066.
- Connect/disconnect and per-message heartbeat hooks now upsert/remove presence state so `/peers/presence` always matches the live WebSocket peer map.
- Background task polls every `PEER_RELAY_URLS` entry every 300 s for `/peers/presence`, verifies each returned signature against the peer relay's Ed25519 identity (resolved via the authority-verified directory), and merges into the federation cache. Entries past the 3600 s TTL are treated as misses and evicted lazily.
- Spec: PNP-008 bumped to v0.3 CANDIDATE. Added §10.5 Presence, §10.6 Peer Lookup, §10.7 Federation Presence Fetch, with clauses `PNP-008-MUST-063` through `PNP-008-MUST-070`. Summary count bumped from 62 → 70 MUSTs.
- Conformance: new `pnp_008_presence.rs` with 8 clause-pinned tests covering local presence signing, canonical signable-bytes layout, local-over-federation priority, federation signature rejection, TTL enforcement, and default rate-limit / poll-interval caps.
- Follow-up (commit 2 of 2): PWA lookup-aware `sendRelay`, per-relay token pools, and outbound WS lifecycle so users on different relays can actually exchange messages.

### Added — Privacy Pass relay-frame auth (PNP-001 §10, H9 commit 1 of 2)
- New `parolnet-relay::tokens` module: epoch-rotating VOPRF (`Ristretto255-SHA512`, RFC 9497) issuer / verifier powering RFC 9578 Privacy Pass tokens for the outer relay frame. 1-hour epochs, 5-minute grace, 8192 tokens/client/epoch. Server secrets zeroize on drop per the security invariants.
- New `POST /tokens/issue` endpoint in `parolnet-relay-server`: Ed25519-authenticated batch blind-evaluation; one batch per identity per epoch.
- Outer relay frame `{type, to, token, payload}` replaces the prior `{type, to, from, payload}`. The `from` field is gone — relays no longer learn per-frame sender identity. Pre-launch: no legacy / dual-path.
- Spec: PNP-001 v0.5 CANDIDATE adds §10 "Outer Relay Frame" + §10.2 "Token Auth (Privacy Pass)" with clauses `PNP-001-MUST-048` through `PNP-001-MUST-052`.
- Conformance: 5 new tests in `pnp_001_outer_frame.rs` covering no-token drop, issue→spend round-trip, double-spend rejection, cross-epoch expiry, nonce tamper, and Ed25519 issuance guard.
- Follow-up (commit 2 of 2): WASM exports + PWA wire-up so the client actually blinds, requests, spends, and re-provisions tokens end-to-end.

### Added — Identity Rotation (PNP-002 §8, H5)
- New `IdentityRotationPayload` in `parolnet-protocol`: old/new PeerId, new Ed25519 pubkey, rotated_at, grace_expires_at, Ed25519 signature over canonical domain-separated byte sequence (`ParolNet-IdentityRotation-v1`).
- `rotate_identity()` generates a new `IdentityKeyPair` and produces a signed rotation payload; `verify_identity_rotation()` checks signature under the old identity's Ed25519 public key.
- New PNP-001 §3.4 wire code `0x13 IDENTITY_ROTATE`; delivered per-contact over existing Double Ratchet sessions so the old identity authenticates the rotation.
- `parolnet-core::rotate_identity_for_peers()` orchestrator: builds one PNP-001 envelope per active session; `ParolNet::replace_identity_preserving_sessions()` swaps identity without tearing down sessions (sessions re-peg to the new PeerId).
- WASM exports `rotate_identity(now_secs)` and `handle_identity_rotation(source_old_ed25519_pub_hex, payload_json)`.
- PWA: Settings → "Regenerate identity" button generates a new identity, signs a rotation notice per contact, and dispatches over existing sessions. Receiver dispatch (`MSG_TYPE_IDENTITY_ROTATE` case) verifies the signature against the contact's stored `identityPubKey` trust anchor and remaps the contact record to the new PeerId.
- 7-day grace window: the retired identity secret is retained so in-flight messages can still decrypt; `zeroizeExpiredRetiredIdentity()` runs at boot and wipes the secret once `grace_expires_at` has passed.
- Contact trust anchor: `identityPubKey` is now captured at contact-add time from both scanner and presenter paths (QR-based handshake) to authenticate future rotations.
- Spec: PNP-001 v0.4 adds code `0x13`; PNP-002 v0.3 adds §8 Identity Rotation with MUST-036..039 and SHOULD-011..012.
- Conformance: 12 tests in `pnp_002_identity_rotation.rs` covering canonical signing bytes, domain separation, PeerId binding, grace window, signature verification, and freshness.
- i18n: 5 new keys (`toast.identityRotated`, `toast.contactRotated`, `settings.regenerateIdentity`, `settings.regenerateIdentityDescription`, `settings.regenerateIdentityConfirm`) natively translated in all 16 languages.
- Relay-side multi-subscription during the grace window (so the retiring node can still pull queued traffic addressed to the old PeerId) is tracked as a follow-up; client-side lifecycle is complete.

### Added — Wire-level cover traffic (PNP-006, H7)
- New `pwa/src/cover-traffic.js`: NORMAL-mode timer (500ms base + ≤100ms jitter) emits `MSG_TYPE_DECOY` (0x04) envelopes to a rotating contact with an established Double Ratchet session.
- Real sends suppress the next decoy tick via `markRealSend()` — PNP-006-MUST-005 (real data has priority over padding).
- `dispatchByMsgType` now drops DECOY silently: no UI, no handler, no log.
- Settings toggle under Network → WebRTC Privacy; default ON; 16-language strings.
- No-op when no contact has a secure session yet (fails safe during bootstrap).
- Decoy plaintext is 8 random bytes → envelope lands in the 256-byte bucket → ~512 B/s idle bandwidth.
- LOW / HIGH modes and burst pacing (PNP-006 Table §3.1, MUST-007/008) deferred to a follow-up.

### Changed — Envelope coverage for all user-facing wire types (PNP-001)
- Every user-facing PWA wire frame now ships as a PNP-001 padded envelope: `call_offer`, `call_reject`, `group_message`, `group_invite`, `sender_key`, `group_call_invite`, `group_file_offer`, `group_file_chunk`, and `file_accept`.
- Removed the legacy plaintext-JSON `_pn_type` string-marker path from send and receive code. `dispatchByMsgType` is the single wire-frame dispatcher, routing on the envelope header's `msg_type` code (PNP-001 §3.4).
- Added `GROUP_ADMIN` (code `0x12`) to PNP-001 §3.4 registry for group membership admin signaling (invite / add / remove).
- `pwa/src/protocol-constants.js` now mirrors the full PNP-001 §3.4 registry; `pwa/tests/unit.test.mjs` asserts 1:1 mapping between exports and spec codes.

### Added — Reproducible Builds
- `Dockerfile.release`: deterministic build environment with pinned Rust 1.92, wasm-pack 0.13.1, and binaryen
- `scripts/reproducible-build.sh`: build script with `--verify` mode that builds twice and compares SHA-256 checksums
- CI job for reproducible build artifact generation with checksum output
- Pinned exact Rust toolchain version (1.92.0) in `rust-toolchain.toml` for build determinism

### Added — PWA UI for Calls, Files & Groups
- Group management UI: create groups, invite members, remove members, leave group
- Group chat with per-group message history stored in IndexedDB (`groups` and `group_messages` stores)
- Group member management modal with add/remove member controls
- Chats/Groups tab switcher in contact list view
- Group calls with participant grid (up to 8 participants), mute toggle, group call invitations
- Group file transfer: send files to all group members with chunked delivery and progress tracking
- 1:1 file receive flow: incoming file offer accept/decline, chunked receive with progress, download link
- Incoming call notifications: slide-down banner with accept/decline for both 1:1 and group calls
- Sender key distribution for encrypted group messaging via `_pn_type: 'sender_key'` messages
- Structured message routing via `_pn_type` field dispatches file, call, group, and sender key messages
- IndexedDB schema v4 with `groups` (keyPath: `groupId`) and `group_messages` (indexed by `groupId`, `timestamp`) stores

### Added — Domain Fronting & Bridge Relays
- `BridgeAddress` type in `parolnet-protocol`: host/port + optional CDN front domain + fingerprint pinning
- QR-encodable bridge address format with `to_qr_string()`/`from_qr_string()` parsing
- Relay server bridge mode (`BRIDGE_MODE=true`): unlisted relay that doesn't join public directory
- X-Forwarded-For trusted proxy support (`TRUSTED_PROXY_IPS`) for rate limiting behind CDN
- `GET /bridge-info` endpoint returns bridge configuration
- PWA bridge relay support: `addBridge()`, IndexedDB persistence, priority connection
- WASM exports: `parse_bridge_address()`, `create_bridge_address()` for QR/text bridge sharing

### Added — WebRTC Privacy Hardening
- Privacy mode (default ON): `iceTransportPolicy: "relay"` prevents IP leakage via WebRTC
- ICE candidate filtering: strips host/srflx candidates in privacy mode
- `GET /turn-credentials` endpoint: time-limited HMAC-SHA1 credentials for TURN relay access
- Auto-fetch TURN credentials from relay server on startup
- Settings toggle for WebRTC privacy mode with privacy warning
- WASM export `get_webrtc_privacy_config()` for privacy-safe WebRTC configuration

### Added — 3-Hop Onion Circuit Support
- WASM-compatible circuit builder (`parolnet-wasm/src/circuit.rs`): 512-byte relay cell format, X25519 handshake, layered ChaCha20-Poly1305 onion encryption, HKDF key derivation, HMAC key confirmation — all using pure-Rust WASM-compatible deps
- Relay server binary WebSocket frame handling: CREATE/EXTEND/DATA/DESTROY cell processing, per-circuit state tracking, single-relay MVP mode for 3-hop simulation
- JS-facing circuit exports: `build_circuit`, `circuit_send`, `circuit_recv`, `circuit_destroy`
- WebSocket accessor methods on `WasmWebSocket` for circuit builder integration

### Added — WASM WebSocket Transport
- `WasmWebSocket` in `parolnet-wasm`: browser WebSocket wrapper using `web_sys::WebSocket` with binary send/recv, async `wait_open`, error/close tracking
- JS exports: `ws_connect`, `ws_wait_open`, `ws_send`, `ws_recv`, `ws_close`, `ws_is_open`
- Added `wasm-bindgen-futures` workspace dependency

### Added — Relay Federation
- `POST /directory/push` endpoint: accepts CBOR-encoded descriptors from peer relays with per-IP rate limiting (10/min)
- Bidirectional directory sync: relays now push their directory to peers after pulling
- Dynamic peer discovery: new relay URLs discovered from directory entries (capped at 50)
- `RelayDirectory::merge_descriptors()` convenience method for bulk descriptor merging
- Push rate limiter with periodic cleanup

### Added — Relay Health & Reputation Scoring
- `RelayHealth` struct tracking latency EMA, success/failure counts, computed score
- `record_success()`, `record_failure()` methods on `RelayDirectory`
- Health-weighted relay selection in `select_random()` and `select_guards()`
- Minimum health threshold (0.1) filters degraded relays

### Security — Phase 1-3 Audit Fixes

#### Cryptographic Safety
- KDF (`hkdf_sha256`) now returns `Zeroizing<Vec<u8>>`; all callers use `Deref` transparently
- Manual `Drop` impls for `SignedPreKey`, `OneTimePreKeyPair`, `DoubleRatchetSession` zeroize skipped fields (public key bytes, `skipped_keys` HashMap)
- X3DH: intermediate `key_bytes` zeroized after `StaticSecret` construction
- Core session manager: drain + explicit drop for session map during panic wipe
- WASM: `Drop` impl zeroizes `PendingBootstrap` secrets

#### Remote DoS Prevention
- TLS stream: `MAX_FRAME_SIZE` (64 KiB) guard on `recv()`
- CBOR codec: `MAX_HEADER_SIZE` (512 B) guard before decode
- Gossip: `MAX_ENVELOPE_SIZE` + `is_valid_structure()` on inbound envelopes
- Relay cells: `payload_len ≤ CELL_PAYLOAD_SIZE` enforced in `from_bytes()`
- Relay server: per-IP connection rate limiting and per-peer message rate limiting
- Relay server: rate limiter cleanup task (every 5 minutes)
- Gossip: per-PeerId rate limiting (10 msgs/60s) with `RateLimited` action
- Gossip: reject messages with future timestamps (>300s clock skew)

#### Protocol Privacy
- Gossip `signable_bytes()` excludes relay-modified fields (`hops`, `seen`) — prevents signature invalidation during forwarding
- Anonymous gossip envelopes supported for `UserMessage` types (omit `src`/`src_pubkey`)
- `CleartextHeader` constructor enforces timestamp coarsening — prevents timing correlation
- Relay CREATED cells include HMAC-SHA256 key confirmation (constant-time verify)
- `PaddingStrategy::pad()` returns `Result` with `MessageTooLarge` error instead of silent truncation

#### Transport Obfuscation
- TLS fingerprint cipher suites applied to `ClientConfig` (was declaration-only)
- SNI configurable per-connection, removed hardcoded `www.example.com`
- `OsRng` used for traffic shaping jitter (was non-cryptographic RNG)
- TLS config option added to WebSocket transport

#### Relay Hardening
- `/16` subnet diversity enforcement in relay path selection
- Bandwidth-weighted random guard selection
- EXTEND cells use `PeerId` instead of `SocketAddr` — prevents IP leakage to intermediate relays
- Counter overflow checks (`u32::MAX`) before encrypt/decrypt operations
- Auth-gated `/peers` and `/bootstrap` admin endpoints with bearer token
- QR code timestamp validation with 30-minute expiry window

#### Mesh & Discovery Hardening
- UDP discovery encrypted with HMAC-SHA256 time-based tags and HKDF XOR-masked PeerIds
- Gossip forwarding jitter (0–200ms) to prevent timing correlation attacks

#### PWA Security
- Removed plaintext message fallback — require encryption or show error
- Replaced `new Function()` calculator eval with safe recursive-descent parser (XSS fix)
- Added strict Content Security Policy header
- Replaced `innerHTML` XSS vector in relay URL display with DOM APIs
- Removed `isHtml` flag from message rendering, use safe DOM construction
- Removed privacy-leaking telemetry events (`message_sent`/`received`, session)
- Removed `decoy_enabled` from localStorage — derive from WASM only
- Service worker: SRI hash verification for cached critical resources (`app.js`, `styles.css`, `crypto-store.js`, `index.html`)
- Service worker: removed `skipWaiting()` from install handler — compromised SW updates no longer immediately take control
- STUN/TURN servers configurable via IndexedDB settings (IP leak warning documented)
- Panic wipe code configurable via IndexedDB settings (was hardcoded)

#### Defense in Depth
- Relay server uses real Ed25519 keypair (env `RELAY_SECRET_KEY` or ephemeral)
- Challenge-response auth for peer registration (nonce + Ed25519 signature)

### Breaking Changes
- `PaddingStrategy::pad()` signature changed from `Vec<u8>` to `Result<Vec<u8>, PaddingError>`
- `hkdf_sha256` return type changed from `Result<Vec<u8>>` to `Result<Zeroizing<Vec<u8>>>`
- EXTEND cell format changed from `SocketAddr` to `PeerId`
- Relay CREATED cell now includes HMAC field (32 bytes)
- Gossip `signable_bytes()` no longer includes `hops` and `seen` fields — existing signatures incompatible

### Added
- Password-encrypted IndexedDB storage using AES-256-GCM with PBKDF2 key derivation (600k iterations)
- Unlock screen for encrypted storage (passphrase or calculator keypad in decoy mode)
- Auto-lock after 5 minutes in background, panic wipe clears in-memory keys
- Settings UI to enable encryption with passphrase setup and automatic data migration
- Configurable relay server URL in PWA settings
- Platform-agnostic time functions for WASM compatibility (`time_compat.rs`)

### Changed
- PWA uses relay-only networking for all peer connectivity
- Connection dot shows green for relay connection (was orange)
- Service worker properly skips POST requests in cache handler
- WASM init uses non-deprecated `{ module_or_path }` form

### Removed
- WebTorrent tracker support — relay server handles all peer connectivity
- Dead tracker URLs (fastcast.nz, most public WSS trackers)

### Fixed
- `SystemTime::now()` panic on wasm32 target (replaced with `js_sys::Date::now()`)
- Service worker crash on POST request caching

### Security
- All local data (private keys, messages, contacts) can now be encrypted at rest
- Decoy mode unlock code doubles as encryption passphrase — no separate prompt
- Protocol specifications (PNP-001 through PNP-009) in `specs/`
- Rust workspace with 9 crates: crypto, protocol, transport, mesh, relay, core, wasm, relay-server, authority-cli
- Trait definitions for all core interfaces (AEAD, Transport, Connection, etc.)
- `IdentityKeyPair` with Ed25519 key generation and PeerId derivation
- `PeerId` type derived from SHA-256 of Ed25519 public key (no phone/email)
- Wire protocol types: Envelope, CleartextHeader, MessageType, MessageFlags
- Bucket padding infrastructure (256/1024/4096/16384 byte sizes)
- Traffic shaping bandwidth modes (LOW/NORMAL/HIGH)
- Relay circuit constants and cell types (512-byte fixed cells)
- Gossip protocol types with peer scoring
- Core client API with `panic_wipe()` and `enter_decoy_mode()`
- WASM bindings crate with wasm-bindgen
- Security-hardened build profile (strip, LTO, panic=abort)
- HKDF-SHA-256 with RFC 5869 test vectors
- ChaCha20-Poly1305 and AES-256-GCM AEAD implementations
- X3DH key agreement with SPK signature verification
- Double Ratchet with bidirectional messaging and out-of-order delivery
- Deniable authentication via HMAC-SHA-256
- CBOR envelope codec and bucket padding (encode/decode roundtrip)
- TLS stream transport with rustls, WebSocket transport
- Traffic shaping: constant-rate padding, burst smoothing, jitter
- TLS fingerprint profiles for Chrome 120+ and Firefox 120+
- Onion routing: 3-layer encrypt/peel, circuit construction, relay node
- Relay directory with guard selection and path building
- Gossip bloom filter, proof-of-work, dedup filter with rotation
- Store-and-forward buffer with eviction policy
- Bootstrap: QR payload (CBOR), HMAC proof, SAS verification
- Session manager with Double Ratchet integration
- Panic wipe: secure file overwrite + delete, session clearing
- PWA shell: offline-first service worker, installable, survives site takedown
- Multilingual README (Chinese, Russian, Persian, Kurdish, Azerbaijani, Arabic, Korean, Turkish)
- STRATEGIES.md: viral adoption playbook
- CONTRIBUTING.md: contributor guide with security requirements
- THREAT_MODEL.md: STRIDE analysis, 5 adversary profiles, 25 threats mapped
- GitHub Actions CI: check, test, clippy, fmt, wasm, msrv
- Dependabot configuration for cargo and GitHub Actions
