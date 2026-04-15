# PNP-008: Relay Federation & Network Resilience

## Implementation Note

This document is a phased implementation plan and design target. Current code includes authority keys, endorsed descriptors, `/endorse`, `/directory`, and simple polling-based relay directory sync through configured `PEER_RELAY_URLS`. It does not yet implement the full federation manager, bridge relay design, health/reputation system, or pluggable transports described below.

## Context

ParolNet relay discovery is gossip-based (no centralized authority) — good foundation. But current design has critical gaps for censorship resistance:

1. **No relay-to-relay federation** — separate clusters can't share state
2. **No internet bootstrap** — only LAN UDP broadcast + manual QR/passphrase
3. **Blocking one well-known relay can partition the network**
4. **No bridge relays** for censored environments

Goal: anyone hosts a relay, if one goes down others exist, no single host blocks the network.

---

## Phase 1 — Foundation (no breaking changes)

### 1A. New gossip payload types
**File**: `crates/parolnet-protocol/src/gossip.rs`
- Add `FederationSync = 0x06`, `FederationHeartbeat = 0x07`, `BridgeAnnouncement = 0x08`
- Backward compatible — unknown types already ignored by existing peers

### 1B. Scalable IBLT
**File**: `crates/parolnet-mesh/src/sync.rs`
- Add `Iblt::with_capacity(cells)` — tiered sizes (80/400/2000) for different sync scales
- Current `Iblt::new()` stays as alias for 80-cell default

### 1C. Relay health & reputation
**File**: `crates/parolnet-relay/src/health.rs` (NEW)

```rust
pub struct RelayReputation {
    pub score: f64,              // 0.0-1.0, starts 0.5, EWMA decay 0.9
    pub uptime_ratio: f64,
    pub bandwidth_observed: u64,
    pub latency_ms: u32,
    pub successful_relays: u64,
    pub failed_relays: u64,
    pub first_seen: u64,
    pub last_probe: u64,
    pub flags: RelayFlags,       // bitflags: GUARD_ELIGIBLE, STABLE, BRIDGE, SUSPECT, BANNED
}
```

- Health probes: connect latency, circuit create timing, data integrity checks
- PoW challenge for new relays (22-bit, ~4s on commodity hardware)
- Malicious relay detection: data corruption, selective dropping, timing anomalies
- Integrate with `RelayDirectory` — add `select_by_reputation()` method

### 1D. Config extension
**File**: `crates/parolnet-core/src/config.rs`
- Add optional `federation`, `bootstrap_channels`, `bridge_mode` fields
- All `Option` — existing configs unchanged

---

## Phase 2 — Bootstrap Resilience

### Multi-channel bootstrap with fallback chain
**File**: `crates/parolnet-core/src/network_bootstrap.rs` (NEW)

Channels tried in order (10s timeout each):

| Priority | Channel | How it works | Censor must... |
|----------|---------|-------------|----------------|
| 1 | Seed relays | 5-10 hardcoded addrs, updated each release | Block all IPs |
| 2 | DNS TXT | Query `_parolnet-relay._tcp.<domain>` for signed descriptors | Poison multiple domains |
| 3 | HTTPS relay list | CDN-hosted CBOR list, domain-fronting supported | Block entire CDN |
| 4 | DHT | Mainline BitTorrent DHT, BEP-44 mutable items | Block BitTorrent globally |
| 5 | Manual | Existing QR/passphrase (PNP-003) | Physical presence |

**File**: `crates/parolnet-core/src/seed_relays.rs` (NEW)
- Hardcoded seed relay addresses, compile-time configurable
- Seeds only used for initial descriptor fetch — not trusted for routing

**Security**: All relay descriptors verified via Ed25519 signature regardless of channel. DNS poisoning or CDN compromise can't inject unsigned relays.

**New deps**: `hickory-resolver` (DNS), `mainline` (DHT). `reqwest` likely already transitive via server crate.

---

## Phase 3 — Relay Federation

### Relay-to-relay gossip layer
**File**: `crates/parolnet-mesh/src/federation.rs` (NEW)

```rust
pub struct FederationManager {
    config: FederationConfig,           // max 8 peers, 60s heartbeat, 300s descriptor exchange
    peers: RwLock<HashMap<PeerId, FederationPeerState>>,
    directory: Arc<RwLock<RelayDirectory>>,
}
```

**How it works**:
1. Relay connects to federation peers via persistent TLS
2. On connect: exchange IBLTs of relay descriptor IDs (reuses `sync.rs`)
3. IBLT diff identifies missing descriptors — fetch only those
4. Periodic re-sync every 5 minutes catches drift
5. Heartbeats every 60s confirm liveness

**Conflict resolution**: Newer timestamp wins. Same-timestamp tie-break: lexicographic PeerId.

**Rate limiting**: Per-peer token bucket — 100 descriptors/min, 10 sync requests/hr. Exceeding penalizes via existing `PeerScore`.

**Eclipse attack mitigation**: Min 3 federation peers from distinct /16 subnets (extends existing subnet diversity logic).

### Partition healing
**File**: `crates/parolnet-mesh/src/partition.rs` (NEW)

When two clusters reconnect:
- IBLT-based set reconciliation (tiered sizing from Phase 1B)
- Sync scope: descriptors only (default) or descriptors + recent gossip IDs
- Replay prevention: timestamp + signature on sync messages, 5-minute window
- Each fetched descriptor individually verified via Ed25519 — corrupted data rejected

### Relay server changes
**File**: `crates/parolnet-relay-server/src/main.rs`
- Add federation peering endpoint
- Initialize `FederationManager` alongside existing `PeerManager`
- Probe-resistant: serve plausible HTTPS page when non-ParolNet connection arrives

---

## Phase 4 — Anti-Censorship

### Pluggable transports
**File**: `crates/parolnet-transport/src/pluggable.rs` (replace stub)

```rust
#[async_trait]
pub trait PluggableTransport: Send + Sync {
    fn name(&self) -> &'static str;
    async fn connect(&self, target: &TransportTarget) -> Result<Box<dyn Connection>>;
    async fn listen(&self, addr: SocketAddr) -> Result<Box<dyn Listener>>;
}
```

**File**: `crates/parolnet-transport/src/domain_front.rs` (NEW)
- TLS SNI shows innocent domain, HTTP Host header targets real backend
- Leverages existing `tls_camouflage.rs` fingerprint profiles

**File**: `crates/parolnet-transport/src/obfs.rs` (NEW)
- Traffic obfuscation with IAT modes (none/constant/adaptive)

### Bridge relays
**File**: `crates/parolnet-relay/src/bridge.rs` (NEW)
- `BridgeDescriptor`: like `RelayDescriptor` but NOT published in main directory
- Distributed only via direct sharing (QR, email, out-of-band)
- Optional steganographic address encoding (email headers, image EXIF, DNS CNAME chains)
- Probe resistant: serve plausible HTTPS on unrecognized connections

---

## Crate Change Summary

| Crate | New Files | Modified Files |
|-------|-----------|----------------|
| parolnet-protocol | — | `src/gossip.rs` (3 payload types) |
| parolnet-core | `network_bootstrap.rs`, `seed_relays.rs` | `src/config.rs` |
| parolnet-mesh | `federation.rs`, `partition.rs` | `src/sync.rs`, `src/lib.rs` |
| parolnet-relay | `health.rs`, `bridge.rs` | `src/directory.rs` |
| parolnet-transport | `obfs.rs`, `domain_front.rs` | `src/pluggable.rs` |
| parolnet-relay-server | — | `src/main.rs` |

## New Spec Document

`specs/PNP-008-relay-federation.md` — covers federation protocol, bootstrap channels, health/reputation, partition healing, anti-censorship measures.

---

## Verification

- **Phase 1**: `cargo check --workspace` + `cargo test --workspace` — all additive, nothing breaks
- **Phase 2**: Integration test with 2 relay instances — fresh node bootstraps from seed, discovers relays
- **Phase 3**: Integration test with 3+ relays — partition one, reconnect, verify descriptor convergence via IBLT sync
- **Phase 4**: Test domain-fronting transport against local nginx proxy; test bridge descriptor sharing via QR flow

## Security Properties Maintained

- All descriptors Ed25519-signed — no unsigned data enters directory
- PoW on descriptor publication prevents descriptor flooding
- Federation peers scored — bad behavior isolated automatically
- Bridge addresses never in public directory — enumeration-resistant
- No new identifying information introduced — PeerId still = SHA-256(pubkey)
- All existing invariants from CLAUDE.md preserved (zeroize, padding, no compression before encryption, constant-time crypto, pure Rust)
