# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
