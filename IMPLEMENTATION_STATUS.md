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
- Browser-side WebSocket transport: `WasmWebSocket` wrapper over `web_sys::WebSocket` with binary send/recv, async `wait_open`, and JS exports (`ws_connect`, `ws_send`, `ws_recv`, `ws_close`, `ws_is_open`, `ws_wait_open`).
- Relay health/reputation scoring: `RelayHealth` tracks latency EMA, success/failure counts, and computes weighted scores. `select_random()` and `select_guards()` use health-weighted selection.
- Relay federation: gossip-based directory propagation via `POST /directory/push`, bidirectional pull+push sync, dynamic peer discovery from directory entries (capped at 50), push rate limiting, `merge_descriptors()` API.
- 3-hop onion circuit support: WASM circuit builder constructs 3-hop circuits over WebSocket with X25519 handshake, layered ChaCha20-Poly1305 encryption, and HMAC key confirmation. Relay server processes binary relay cells (CREATE/EXTEND/DATA/DESTROY) with single-relay MVP mode. JS exports (`build_circuit`, `circuit_send`, `circuit_recv`, `circuit_destroy`) allow PWA to send messages through onion circuits.
- WebRTC privacy mode: relay-only by default (`iceTransportPolicy: "relay"`), ICE candidate filtering strips host/srflx candidates, `GET /turn-credentials` endpoint generates time-limited HMAC-SHA1 TURN credentials, auto-fetch credentials from relay on startup, settings toggle with privacy warning, WASM `get_webrtc_privacy_config()` export.
- Domain fronting & bridge relays: `BridgeAddress` type with QR encoding, relay server bridge mode (unlisted, X-Forwarded-For proxy support), PWA bridge relay discovery and priority connection, WASM bridge address parsing exports. CDN-side domain fronting is an operational deployment concern (configure CDN to proxy to bridge relay).
- PWA group management UI: create/join/leave groups, group chat with per-group IndexedDB message history, member management modal, Chats/Groups tab switcher.
- PWA file receive flow: incoming file offer accept/decline, chunked receive with progress, download link on completion.
- PWA incoming call notifications: slide-down banner with accept/decline for 1:1 and group calls.
- PWA group calls: participant grid (up to 8), mute toggle, group call invitations via structured messages.
- PWA group file transfer: chunked send to all group members with progress tracking.
- Sender key distribution for group encryption via structured `_pn_type: 'sender_key'` messages.

## Partial Or Prototype

- 3-hop relay circuits: library primitives exist and are now wired into the WASM/relay-server path via single-relay MVP mode; multi-relay path selection with real network hops is not yet used for normal PWA chat.
- Relay-to-relay directory sync uses bidirectional pull+push with dynamic peer discovery; the broader PNP-008 federation plan (consensus, voting) is not fully implemented.
- TLS camouflage is an approximation using rustls settings. Full browser ClientHello mimicry, HTTP/2 DATA framing, GREASE behavior, and updatable fingerprint profiles are not implemented.
- Traffic shaping exists as constants/helpers and some jitter, but constant-rate padding and dummy traffic are not applied end-to-end to the current PWA relay path.
- Mesh discovery is implemented as obfuscated UDP broadcast, not mDNS/BLE as written in older spec text.
- File, call, group call, and group file APIs: core/WASM primitives exist and PWA UI is wired for basic flows; messages are not yet routed through the full onion circuit protocol stack.
- WebRTC data channels use privacy mode by default (relay-only, ICE candidate filtering); TURN credential auto-fetch is implemented but multi-relay TURN infrastructure deployment is left to operators.

## Not Yet Implemented

- Production multi-relay 3-hop onion routing (current MVP simulates 3 hops on a single relay).
- Constant-rate cover traffic for browser relay connections.
- HTTP/2 framing for ParolNet cells on the current relay server.
- BLE bootstrap.
- mDNS `_parolnet._tcp` discovery. Current code uses UDP broadcast with an HMAC-derived tag and masked PeerId.
- Full domain fronting with HTTP/2 DATA frame wrapping (current bridge mode uses standard WebSocket over CDN proxy).
- Certificate pinning.
- Verified reproducible release process.

## Documentation Rule

When docs say "ParolNet provides" a property, that statement must refer to code exercised by the current application path. When docs describe a protocol target, they should say "the protocol is designed to" or "PNP-00X specifies" unless the feature is wired into the current app.
