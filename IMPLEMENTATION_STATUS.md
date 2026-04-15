# ParolNet Implementation Status

### Document Status: CURRENT CODE SNAPSHOT
### Date: 2026-04-15

This document records what the repository currently implements versus what the protocol specifications describe. The `specs/` directory remains the design target for the protocol suite, but not every specification is fully wired into the browser app or relay server yet.

## Summary

ParolNet currently contains a working Rust workspace, a browser PWA shell, a relay server, and substantial protocol primitives. It should be treated as an active prototype, not as a production-ready safety tool for high-risk users.

The current user-facing PWA sends encrypted messages over a direct WebSocket relay and optional WebRTC data channels. It does not yet route normal PWA chat traffic through completed 3-hop onion circuits with constant-rate cover traffic.

## Workspace

The Cargo workspace currently has 9 members:

| Crate | Current role |
|------|--------------|
| `parolnet-crypto` | AEAD, HKDF, identity keys, X3DH, Double Ratchet, sender keys |
| `parolnet-protocol` | Wire types, CBOR codec, padding, gossip/message/address types |
| `parolnet-transport` | Native TLS and WebSocket transport building blocks |
| `parolnet-mesh` | Gossip, peer manager, store-forward, UDP broadcast discovery |
| `parolnet-relay` | Relay cells, circuit primitives, onion encryption helpers, relay directory |
| `parolnet-core` | Client/session/bootstrap APIs, media/file/group helpers, panic wipe helpers |
| `parolnet-wasm` | Browser bindings for crypto/session/bootstrap/core functions |
| `parolnet-relay-server` | Axum WebSocket relay, store-forward, directory and endorsement endpoints |
| `parolnet-authority-cli` | Authority key and relay endorsement CLI |

## Current User-Facing Path

The current PWA path is:

1. Browser loads `pwa/index.html`, JavaScript, WASM, and service worker assets.
2. Identity keys are generated or restored through WASM.
3. QR bootstrap can establish a Double Ratchet session between contacts.
4. Messages are encrypted in WASM when a session exists.
5. Encrypted payloads are sent through the relay server's `/ws` endpoint or a WebRTC data channel.
6. The relay server forwards or buffers JSON messages keyed by PeerId.

This path provides end-to-end content encryption when a Double Ratchet session exists. It does not provide the full anonymity, traffic-shaping, or relay-path metadata protections described by PNP-004 and PNP-006.

## Implemented Or Mostly Implemented

- Ed25519 identity keys and `PeerId = SHA-256(public_key)`.
- X3DH-style shared secret derivation and Double Ratchet sessions.
- ChaCha20-Poly1305 and AES-256-GCM wrappers.
- Bucket padding utilities in `parolnet-protocol`.
- CBOR header/envelope codec with size guards.
- Sender-key primitives for group messaging.
- QR bootstrap helpers exposed to WASM.
- Relay cell type, 512-byte cell serialization, onion encryption helpers, and partial circuit construction APIs.
- Relay directory descriptors, signature verification, authority endorsement types, and `/endorse` endpoint.
- Gossip envelope types, PoW checks, dedup/rate limiting, and store-forward primitives.
- PWA encrypted IndexedDB mode using AES-GCM and PBKDF2.
- PWA decoy calculator mode and panic wipe flow for browser storage/cache cleanup.

## Partial Or Prototype

- 3-hop relay circuits exist as library primitives, but the normal PWA message path does not use them.
- Relay-to-relay directory sync exists as simple polling of `/directory`; the broader PNP-008 federation plan is not fully implemented.
- TLS camouflage is an approximation using rustls settings. Full browser ClientHello mimicry, HTTP/2 DATA framing, GREASE behavior, and updatable fingerprint profiles are not implemented.
- Traffic shaping exists as constants/helpers and some jitter, but constant-rate padding and dummy traffic are not applied end-to-end to the current PWA relay path.
- Mesh discovery is implemented as obfuscated UDP broadcast, not mDNS/BLE as written in older spec text.
- File, call, group call, and group file APIs exist in core/WASM, but the PWA UI path is incomplete and does not yet send those flows through the full protocol stack.
- WebRTC is used for optional browser data channels and signaling, with public STUN defaults unless the user changes settings.

## Not Yet Implemented

- Production 3-hop onion routing for normal PWA messages.
- Constant-rate cover traffic for browser relay connections.
- HTTP/2 framing for ParolNet cells on the current relay server.
- Browser-side WebSocket transport implemented in Rust/WASM (`crates/parolnet-wasm/src/websocket.rs` is a TODO).
- BLE bootstrap.
- mDNS `_parolnet._tcp` discovery. Current code uses UDP broadcast with an HMAC-derived tag and masked PeerId.
- Domain-fronting transport and bridge relay support.
- Full relay health/reputation scoring from PNP-008.
- Certificate pinning.
- Verified reproducible release process.

## Documentation Rule

When docs say "ParolNet provides" a property, that statement must refer to code exercised by the current application path. When docs describe a protocol target, they should say "the protocol is designed to" or "PNP-00X specifies" unless the feature is wired into the current app.
