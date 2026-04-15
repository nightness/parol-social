# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Protocol specifications (PNP-001 through PNP-006) in `specs/`
- Rust workspace with 7 crates: crypto, protocol, transport, mesh, relay, core, wasm
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
