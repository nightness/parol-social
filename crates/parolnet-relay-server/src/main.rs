use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{
        Query,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use futures_util::{SinkExt, StreamExt};
use parolnet_mesh::peer_manager::PeerManager;
use parolnet_protocol::address::PeerId;
use parolnet_relay::authority::EndorsedDescriptor;
use parolnet_relay::directory::{RelayDescriptor, RelayDirectory};
use parolnet_relay::bridge::{
    DisclosureLimiter, DisclosureScope, IpAuditLog, COVER_CONTENT_TYPE, COVER_PAGE_HTML,
    IP_LOG_SCRUBBER_INTERVAL_SECS,
};
use parolnet_relay::federation_codec::{
    CLOSE_OVERSIZE, CLOSE_UNKNOWN_TYPE, FEDERATION_LINK_PATH,
};
use parolnet_relay::presence::{PresenceAuthority, PresenceConfig, PresenceEntry};
use parolnet_relay::tokens::{Suite, Token, TokenAuthority, TokenConfig};
use parolnet_transport::{Connection, TransportError};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tracing::info;

type PeerMap = Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Message>>>>;

/// Per-IP WebSocket connection rate limiter.
/// Max 10 new connections per minute per IP address.
const WS_CONN_RATE_LIMIT: u32 = 10;
const WS_CONN_RATE_WINDOW_SECS: u64 = 60;

/// Per-peer message rate limiter.
/// Max 100 messages per minute per connected peer.
const MSG_RATE_LIMIT: u32 = 100;
const MSG_RATE_WINDOW_SECS: u64 = 60;

/// In-memory rate limiter tracking (window_start, count) per key.
struct RateLimiter<K: std::hash::Hash + Eq> {
    limits: std::sync::Mutex<HashMap<K, (std::time::Instant, u32)>>,
    max_count: u32,
    window: Duration,
}

impl<K: std::hash::Hash + Eq + Clone> RateLimiter<K> {
    fn new(max_count: u32, window_secs: u64) -> Self {
        Self {
            limits: std::sync::Mutex::new(HashMap::new()),
            max_count,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Check if a key is rate-limited. Increments the counter.
    /// Returns true if the request should be rejected.
    fn is_limited(&self, key: &K) -> bool {
        let mut limits = self.limits.lock().unwrap();
        let now = std::time::Instant::now();
        let entry = limits.entry(key.clone()).or_insert((now, 0));

        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 1);
            return false;
        }

        entry.1 += 1;
        entry.1 > self.max_count
    }

    /// Periodically clean up expired entries.
    fn cleanup(&self) {
        let mut limits = self.limits.lock().unwrap();
        let now = std::time::Instant::now();
        limits.retain(|_, (start, _)| now.duration_since(*start) < self.window);
    }
}

type ConnRateLimiter = Arc<RateLimiter<std::net::IpAddr>>;
type MsgRateLimiter = Arc<RateLimiter<String>>;
/// Per-IP rate limiter for POST /directory/push requests.
/// Max 10 pushes per minute per source IP.
type PushRateLimiter = Arc<RateLimiter<std::net::IpAddr>>;
const PUSH_RATE_LIMIT: u32 = 10;
const PUSH_RATE_WINDOW_SECS: u64 = 60;

/// Maximum number of dynamically discovered peer relay URLs.
const MAX_DISCOVERED_PEERS: usize = 50;

/// Maximum number of buffered messages per offline peer.
const MAX_STORED_MESSAGES_PER_PEER: usize = 256;
/// Maximum total size of buffered messages per peer (4 MB).
const MAX_STORED_BUFFER_SIZE: usize = 4 * 1024 * 1024;
/// Time-to-live for buffered messages (24 hours).
const MESSAGE_TTL: Duration = Duration::from_secs(86400);

/// A JSON message buffered for an offline peer, with metadata for TTL / eviction.
struct BufferedRelayMessage {
    json: String,
    stored_at: std::time::Instant,
    size: usize,
}

/// Store-and-forward buffer for relay messages destined to offline peers.
///
/// Keys are typed `PeerId` values; stored payloads remain JSON strings
/// because they are forwarded verbatim to browser WebSocket clients.
struct RelayMessageStore {
    buffers: HashMap<PeerId, Vec<BufferedRelayMessage>>,
}

impl RelayMessageStore {
    fn new() -> Self {
        Self {
            buffers: HashMap::new(),
        }
    }

    /// Buffer a JSON message for `peer`. Evicts oldest messages when the
    /// per-peer count or size limit is exceeded.
    fn store(&mut self, peer: PeerId, msg: String) {
        let size = msg.len();
        let buffer = self.buffers.entry(peer).or_default();

        // Evict oldest messages until under count limit
        while buffer.len() >= MAX_STORED_MESSAGES_PER_PEER {
            buffer.remove(0);
        }

        // Evict oldest messages until under size limit
        let mut total_size: usize = buffer.iter().map(|m| m.size).sum();
        while total_size + size > MAX_STORED_BUFFER_SIZE && !buffer.is_empty() {
            total_size -= buffer.remove(0).size;
        }

        buffer.push(BufferedRelayMessage {
            json: msg,
            stored_at: std::time::Instant::now(),
            size,
        });
    }

    /// Retrieve and drain all buffered messages for `peer`.
    fn retrieve(&mut self, peer: &PeerId) -> Vec<String> {
        self.buffers
            .remove(peer)
            .unwrap_or_default()
            .into_iter()
            .map(|m| m.json)
            .collect()
    }

    /// Remove messages older than [`MESSAGE_TTL`]. Returns the number of
    /// expired messages removed.
    fn expire(&mut self) -> usize {
        let now = std::time::Instant::now();
        let mut expired = 0;

        for buffer in self.buffers.values_mut() {
            let before = buffer.len();
            buffer.retain(|m| now.duration_since(m.stored_at) < MESSAGE_TTL);
            expired += before - buffer.len();
        }

        // Remove empty peer entries
        self.buffers.retain(|_, v| !v.is_empty());

        expired
    }
}

/// Adapter bridging a WebSocket peer's mpsc sender to the `Connection` trait,
/// so that the PeerManager/gossip protocol can push CBOR gossip messages out
/// over the existing relay WebSocket channels.
struct WsConnection {
    tx: mpsc::UnboundedSender<Message>,
}

#[async_trait]
impl Connection for WsConnection {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        // Encode raw bytes as a hex string wrapped in a gossip JSON message
        let hex_data = hex::encode(data);
        let msg = serde_json::json!({
            "type": "gossip",
            "payload": hex_data,
            "from": ""
        })
        .to_string();
        self.tx
            .send(Message::Text(msg.into()))
            .map_err(|_| TransportError::ConnectionClosed)
    }

    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        // The relay server is push-based, not pull-based.
        // Gossip messages arrive via handle_socket, not via recv().
        Err(TransportError::NotAvailable(
            "relay uses push-based messaging".into(),
        ))
    }

    async fn close(&self) -> Result<(), TransportError> {
        Ok(())
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        None
    }
}

// --- Analytics module (real implementation when feature enabled) ---
#[cfg(feature = "analytics")]
mod analytics {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    pub struct Stats {
        pub start_time: Instant,
        pub total_connections: AtomicU64,
        pub total_messages_routed: AtomicU64,
        pub total_messages_queued: AtomicU64,
        pub total_disconnections: AtomicU64,
    }

    impl Stats {
        pub fn new() -> Self {
            Self {
                start_time: Instant::now(),
                total_connections: AtomicU64::new(0),
                total_messages_routed: AtomicU64::new(0),
                total_messages_queued: AtomicU64::new(0),
                total_disconnections: AtomicU64::new(0),
            }
        }

        pub fn record_connection(&self) {
            self.total_connections.fetch_add(1, Ordering::Relaxed);
        }

        pub fn record_message_routed(&self) {
            self.total_messages_routed.fetch_add(1, Ordering::Relaxed);
        }

        pub fn record_message_queued(&self) {
            self.total_messages_queued.fetch_add(1, Ordering::Relaxed);
        }

        pub fn record_disconnection(&self) {
            self.total_disconnections.fetch_add(1, Ordering::Relaxed);
        }

        pub fn to_json(&self, online_peers: usize) -> String {
            let uptime = self.start_time.elapsed();
            let total_routed = self.total_messages_routed.load(Ordering::Relaxed);
            let uptime_secs = uptime.as_secs();
            let messages_per_minute = if uptime_secs > 0 {
                (total_routed as f64 / uptime_secs as f64) * 60.0
            } else {
                0.0
            };
            format!(
                r#"{{"uptime_secs":{},"online_peers":{},"total_connections":{},"total_messages_routed":{},"total_messages_queued":{},"total_disconnections":{},"messages_per_minute":{:.2}}}"#,
                uptime_secs,
                online_peers,
                self.total_connections.load(Ordering::Relaxed),
                total_routed,
                self.total_messages_queued.load(Ordering::Relaxed),
                self.total_disconnections.load(Ordering::Relaxed),
                messages_per_minute,
            )
        }
    }
}

// --- Analytics module (no-op when feature disabled — zero cost) ---
#[cfg(not(feature = "analytics"))]
mod analytics {
    pub struct Stats;

    impl Stats {
        pub fn new() -> Self {
            Self
        }

        pub fn record_connection(&self) {}
        pub fn record_message_routed(&self) {}
        pub fn record_message_queued(&self) {}
        pub fn record_disconnection(&self) {}
    }
}

#[derive(Deserialize)]
struct IncomingMessage {
    #[serde(rename = "type")]
    msg_type: String,
    peer_id: Option<String>,
    to: Option<String>,
    payload: Option<String>,
    /// Peer IDs to exclude from gossip forwarding.
    #[serde(default)]
    exclude: Vec<String>,
    /// Ed25519 public key (hex) for registration challenge-response.
    pubkey: Option<String>,
    /// Hex-encoded Ed25519 signature over the challenge nonce.
    signature: Option<String>,
    /// Hex-encoded challenge nonce being responded to.
    nonce: Option<String>,
    /// H9 Privacy Pass token (hex CBOR). REQUIRED on "message" frames —
    /// replaces the outer `from` field (see PNP-001 §"Outer Relay Frame",
    /// clause PNP-001-MUST-048).
    token: Option<String>,
}

#[derive(Default, Serialize)]
struct OutgoingMessage {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    online_peers: Option<usize>,
}

// --- Client telemetry ---

#[derive(Deserialize)]
struct TelemetryEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[allow(dead_code)]
    ts: u64,
    #[allow(dead_code)]
    meta: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct TelemetryBatch {
    #[allow(dead_code)]
    ts: u64,
    events: Vec<TelemetryEvent>,
}

struct ClientStats {
    wasm_load_success: AtomicU64,
    wasm_load_fail: AtomicU64,
    relay_connects: AtomicU64,
    relay_disconnects: AtomicU64,
    webrtc_success: AtomicU64,
    webrtc_fail: AtomicU64,
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    sessions_established: AtomicU64,
    errors: AtomicU64,
    total_batches: AtomicU64,
}

impl ClientStats {
    fn new() -> Self {
        Self {
            wasm_load_success: AtomicU64::new(0),
            wasm_load_fail: AtomicU64::new(0),
            relay_connects: AtomicU64::new(0),
            relay_disconnects: AtomicU64::new(0),
            webrtc_success: AtomicU64::new(0),
            webrtc_fail: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            sessions_established: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            total_batches: AtomicU64::new(0),
        }
    }

    #[cfg(feature = "analytics")]
    fn to_json(&self) -> String {
        format!(
            r#"{{"wasm_load_success":{},"wasm_load_fail":{},"relay_connects":{},"relay_disconnects":{},"webrtc_success":{},"webrtc_fail":{},"messages_sent":{},"messages_received":{},"sessions_established":{},"errors":{},"total_batches":{}}}"#,
            self.wasm_load_success.load(Ordering::Relaxed),
            self.wasm_load_fail.load(Ordering::Relaxed),
            self.relay_connects.load(Ordering::Relaxed),
            self.relay_disconnects.load(Ordering::Relaxed),
            self.webrtc_success.load(Ordering::Relaxed),
            self.webrtc_fail.load(Ordering::Relaxed),
            self.messages_sent.load(Ordering::Relaxed),
            self.messages_received.load(Ordering::Relaxed),
            self.sessions_established.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
            self.total_batches.load(Ordering::Relaxed),
        )
    }
}

async fn handle_telemetry(
    client_stats: Arc<ClientStats>,
    Json(batch): Json<TelemetryBatch>,
) -> impl IntoResponse {
    // Validate
    if batch.events.len() > 500 {
        return StatusCode::BAD_REQUEST;
    }

    client_stats.total_batches.fetch_add(1, Ordering::Relaxed);

    for event in &batch.events {
        match event.event_type.as_str() {
            "wasm_load_success" => {
                client_stats
                    .wasm_load_success
                    .fetch_add(1, Ordering::Relaxed);
            }
            "wasm_load_fail" => {
                client_stats.wasm_load_fail.fetch_add(1, Ordering::Relaxed);
            }
            "relay_connect" => {
                client_stats.relay_connects.fetch_add(1, Ordering::Relaxed);
            }
            "relay_disconnect" => {
                client_stats
                    .relay_disconnects
                    .fetch_add(1, Ordering::Relaxed);
            }
            "webrtc_connect_success" => {
                client_stats.webrtc_success.fetch_add(1, Ordering::Relaxed);
            }
            "webrtc_connect_fail" => {
                client_stats.webrtc_fail.fetch_add(1, Ordering::Relaxed);
            }
            "message_sent" => {
                client_stats.messages_sent.fetch_add(1, Ordering::Relaxed);
            }
            "message_received" => {
                client_stats
                    .messages_received
                    .fetch_add(1, Ordering::Relaxed);
            }
            "session_established" => {
                client_stats
                    .sessions_established
                    .fetch_add(1, Ordering::Relaxed);
            }
            "error" => {
                client_stats.errors.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    StatusCode::OK
}

/// Validate the admin token from the Authorization header.
/// Returns true if the ADMIN_TOKEN env var is set and the request
/// includes a matching `Authorization: Bearer <token>` header.
fn check_admin_token(headers: &axum::http::HeaderMap) -> bool {
    let Some(expected) = std::env::var("ADMIN_TOKEN").ok().filter(|s| !s.is_empty()) else {
        return false;
    };
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|token| token == expected)
        .unwrap_or(false)
}

/// Extract the real client IP, respecting X-Forwarded-For when the connecting
/// IP is in the set of trusted proxy IPs (e.g., CDN edge servers).
fn get_client_ip(
    connecting_ip: IpAddr,
    headers: &axum::http::HeaderMap,
    trusted_proxies: &HashSet<IpAddr>,
) -> IpAddr {
    if trusted_proxies.contains(&connecting_ip)
        && let Some(xff) = headers.get("x-forwarded-for")
        && let Ok(xff_str) = xff.to_str()
        && let Some(first_ip) = xff_str.split(',').next()
        && let Ok(ip) = first_ip.trim().parse::<IpAddr>()
    {
        return ip;
    }
    connecting_ip
}

/// GET /bridge-info — returns bridge configuration JSON, rate-limited per
/// (scope_kind, scope_value) by an ephemeral in-memory disclosure counter
/// (PNP-008-MUST-089). Only active when BRIDGE_MODE=true.
///
/// Query string: `?scope=email&id=<email>` or `?scope=qr&id=<session_id>`.
async fn handle_bridge_info(
    params: HashMap<String, String>,
    bridge_front_domain: Option<String>,
    relay_fingerprint: String,
    limiter: Arc<Mutex<DisclosureLimiter>>,
) -> impl IntoResponse {
    let scope_kind = params.get("scope").map(|s| s.as_str()).unwrap_or("");
    let scope_id = params.get("id").cloned().unwrap_or_default();
    let scope = match (scope_kind, scope_id.as_str()) {
        ("email", id) if !id.is_empty() => DisclosureScope::Email(id.to_string()),
        ("qr", id) if !id.is_empty() => DisclosureScope::QrSession(id.to_string()),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "scope and id required\n".to_string(),
            );
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    {
        let mut lim = limiter.lock().await;
        if !lim.try_disclose(scope, now) {
            // MUST-089: per-window cap reached — reject without leaking count.
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                "{\"error\":\"disclosure limit reached\"}".to_string(),
            );
        }
    }
    let json = serde_json::json!({
        "bridge": true,
        "front_domain": bridge_front_domain,
        "fingerprint": relay_fingerprint,
    });
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        json.to_string(),
    )
}

/// Fallback route for bridge-mode relays (PNP-008-MUST-085..088).
///
/// Any request that does not hit a known ParolNet endpoint is served the
/// generic cover page — plain HTTP 200, `text/html`, body ≥ 256 B, no
/// `ParolNet`/`bridge` tokens. Served without inspecting the request IP, so
/// no per-source state is retained (MUST-088).
async fn handle_cover_page() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, COVER_CONTENT_TYPE)],
        COVER_PAGE_HTML,
    )
}

/// GET /directory — serve the current relay directory as CBOR-encoded endorsed descriptors.
///
/// Returns a CBOR-serialized `Vec<RelayDescriptor>` of all known descriptors.
/// This is a public endpoint (no auth required) so any relay or client can
/// discover the full network.
async fn handle_directory(directory: Arc<Mutex<RelayDirectory>>) -> impl IntoResponse {
    let dir = directory.lock().await;
    let descriptors: Vec<&RelayDescriptor> = dir.descriptors().values().collect();
    let mut cbor_buf = Vec::new();
    if let Err(e) = ciborium::into_writer(&descriptors, &mut cbor_buf) {
        tracing::error!(error = %e, "Failed to serialize directory to CBOR");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(axum::http::header::CONTENT_TYPE, "application/cbor")],
            Vec::new(),
        );
    }
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/cbor")],
        cbor_buf,
    )
}

/// POST /endorse — accept a CBOR-encoded `EndorsedDescriptor`, verify authority
/// endorsements meet threshold, then add to directory.
async fn handle_endorse(
    directory: Arc<Mutex<RelayDirectory>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let endorsed: EndorsedDescriptor = match ciborium::from_reader(body.as_ref()) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid CBOR in /endorse request");
            return StatusCode::BAD_REQUEST;
        }
    };
    let mut dir = directory.lock().await;
    match dir.handle_endorsed_descriptor(endorsed) {
        Ok(()) => {
            tracing::info!("Accepted endorsed descriptor via /endorse");
            StatusCode::OK
        }
        Err(e) => {
            tracing::warn!(error = %e, "Rejected endorsed descriptor");
            StatusCode::FORBIDDEN
        }
    }
}

/// POST /directory/push — accept CBOR-encoded `Vec<RelayDescriptor>` pushed from peer relays.
///
/// Merges the descriptors into our local directory via gossip validation
/// (timestamp, Ed25519 signature, freshness). Rate-limited to 10 pushes per
/// minute per source IP.
async fn handle_directory_push(
    directory: Arc<Mutex<RelayDirectory>>,
    our_peer_id: PeerId,
    push_rl: PushRateLimiter,
    client_ip: IpAddr,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if push_rl.is_limited(&client_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "rate limited"})),
        )
            .into_response();
    }

    let descriptors: Vec<RelayDescriptor> = match ciborium::from_reader(body.as_ref()) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid CBOR in /directory/push request");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid CBOR"})),
            )
                .into_response();
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut dir = directory.lock().await;
    let merged = dir.merge_descriptors(descriptors, &our_peer_id, now);
    drop(dir);

    if merged > 0 {
        tracing::info!(merged, source = %client_ip, "Merged descriptors from /directory/push");
    }

    (StatusCode::OK, Json(serde_json::json!({"merged": merged}))).into_response()
}

// ---- H12 Phase 2 presence + peer lookup ----------------------------------

/// Per-IP rate limiter for `/peers/presence` and `/peers/lookup`
/// (PNP-008-MUST-066 — 10 req/s per client). Implemented as 10 req per 1 s
/// window of the shared [`RateLimiter`].
type LookupRateLimiter = Arc<RateLimiter<std::net::IpAddr>>;
const LOOKUP_RATE_LIMIT: u32 = 10;
const LOOKUP_RATE_WINDOW_SECS: u64 = 1;

/// GET /peers/presence — return the locally-connected peers of this relay,
/// CBOR-encoded as `Vec<PresenceEntry>`. Rate-limited per client IP.
///
/// Clauses: PNP-008-MUST-063 (endpoint shape), PNP-008-MUST-064 (signatures),
/// PNP-008-MUST-066 (rate limit).
async fn handle_peers_presence(
    presence: Arc<Mutex<PresenceAuthority>>,
    rl: LookupRateLimiter,
    client_ip: IpAddr,
) -> axum::response::Response {
    if rl.is_limited(&client_ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    let rows: Vec<PresenceEntry> = presence.lock().await.local_presence();
    let mut cbor_buf = Vec::new();
    if let Err(e) = ciborium::into_writer(&rows, &mut cbor_buf) {
        tracing::error!(error = %e, "Failed to serialize presence to CBOR");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/cbor")],
        cbor_buf,
    )
        .into_response()
}

/// GET /peers/lookup?id=<peer_id_hex> — resolve the home relay of `peer_id`.
///
/// Returns 200 + CBOR `LookupResult` on hit; 404 on miss; 400 on malformed id;
/// 429 on rate limit.
///
/// Clauses: PNP-008-MUST-065 (local-first, federation-second), PNP-008-MUST-066
/// (rate limit).
async fn handle_peers_lookup(
    presence: Arc<Mutex<PresenceAuthority>>,
    rl: LookupRateLimiter,
    client_ip: IpAddr,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    if rl.is_limited(&client_ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    let Some(id_hex) = params.get("id") else {
        return (StatusCode::BAD_REQUEST, "missing id").into_response();
    };
    let Some(peer_id) = parse_peer_id(id_hex) else {
        return (StatusCode::BAD_REQUEST, "invalid id").into_response();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let Some(res) = presence.lock().await.lookup(&peer_id, now) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut cbor_buf = Vec::new();
    if let Err(e) = ciborium::into_writer(&res, &mut cbor_buf) {
        tracing::error!(error = %e, "Failed to serialize LookupResult to CBOR");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/cbor")],
        cbor_buf,
    )
        .into_response()
}

/// Background task: every `poll_interval_secs` (default 300 s, PNP-008-MUST-069),
/// fetch `/peers/presence` from every `PEER_RELAY_URLS` entry, resolve each
/// peer relay's Ed25519 pubkey via the authority-verified directory, verify
/// each `PresenceEntry` signature, and merge into the local federation cache.
/// Expired entries are evicted on every tick (PNP-008-MUST-070).
async fn federation_presence_fetch(
    presence: Arc<Mutex<PresenceAuthority>>,
    directory: Arc<Mutex<RelayDirectory>>,
    peer_relay_urls: Arc<Mutex<Vec<String>>>,
    poll_interval_secs: u64,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "presence: HTTP client init failed");
            return;
        }
    };

    let mut interval = tokio::time::interval(Duration::from_secs(poll_interval_secs));
    loop {
        interval.tick().await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Evict expired federation entries opportunistically.
        presence.lock().await.tick_evict(now);

        let urls: Vec<String> = {
            let known = peer_relay_urls.lock().await;
            known.clone()
        };
        if urls.is_empty() {
            continue;
        }

        // Snapshot the directory so we can resolve each peer relay's pubkey
        // without holding the lock across HTTP I/O.
        let directory_snapshot: HashMap<std::net::SocketAddr, ([u8; 32], parolnet_protocol::address::PeerId)> = {
            let dir = directory.lock().await;
            dir.descriptors()
                .values()
                .map(|d| (d.addr, (d.identity_key, d.peer_id)))
                .collect()
        };

        for url in &urls {
            let presence_url = format!("{}/peers/presence", url.trim_end_matches('/'));

            // Resolve the home relay's Ed25519 pubkey by matching the URL's
            // host:port against the directory's `addr` field. Without a
            // trusted directory entry for the peer relay we refuse to merge,
            // because the presence signature must be verifiable (MUST-064).
            let Some((pubkey, home_peer_id)) =
                resolve_peer_relay_identity(url, &directory_snapshot)
            else {
                tracing::debug!(
                    url = %presence_url,
                    "presence fetch skipped: peer relay identity not yet in authority-verified directory"
                );
                continue;
            };
            let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&pubkey) else {
                tracing::debug!(url = %presence_url, "presence fetch skipped: invalid pubkey bytes");
                continue;
            };

            match client.get(&presence_url).send().await {
                Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                    Ok(body) => {
                        let entries: Vec<PresenceEntry> =
                            match ciborium::from_reader(body.as_ref()) {
                                Ok(v) => v,
                                Err(e) => {
                                    tracing::warn!(
                                        url = %presence_url,
                                        error = %e,
                                        "invalid CBOR in /peers/presence response"
                                    );
                                    continue;
                                }
                            };
                        let stats = presence.lock().await.merge_federation_presence(
                            url,
                            home_peer_id,
                            &verifying_key,
                            entries,
                            now,
                        );
                        if stats.accepted > 0 || stats.rejected > 0 {
                            tracing::debug!(
                                url = %presence_url,
                                accepted = stats.accepted,
                                rejected = stats.rejected,
                                "merged federation presence"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::debug!(url = %presence_url, error = %e, "presence read failed");
                    }
                },
                Ok(resp) => {
                    tracing::debug!(
                        url = %presence_url,
                        status = %resp.status(),
                        "peer relay non-success for /peers/presence"
                    );
                }
                Err(e) => {
                    tracing::debug!(url = %presence_url, error = %e, "presence fetch error");
                }
            }
        }
    }
}

/// Resolve a peer relay URL (e.g. `http://1.2.3.4:9000`) to its Ed25519
/// verifying key + PeerId by matching the URL's `host:port` against the
/// directory's `addr` field. Returns `None` if no matching descriptor exists
/// (which means the authority-verified directory hasn't converged yet — we
/// wait rather than accept unverified presence entries).
fn resolve_peer_relay_identity(
    url: &str,
    directory_snapshot: &HashMap<std::net::SocketAddr, ([u8; 32], parolnet_protocol::address::PeerId)>,
) -> Option<([u8; 32], parolnet_protocol::address::PeerId)> {
    // Strip scheme, then expect host:port.
    let without_scheme = url
        .trim_end_matches('/')
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let addr: std::net::SocketAddr = without_scheme.parse().ok()?;
    directory_snapshot.get(&addr).copied()
}

// ---- H9 Privacy Pass token issuance --------------------------------------

/// Per-identity issuance accounting: (current_epoch_id, tokens_issued_this_epoch).
/// Enforces the PNP-001 §10.2 budget of `budget_per_epoch` tokens per identity
/// per epoch. Multiple batches are fine as long as the running total stays
/// under the cap — the previous "one batch per epoch" rule was stricter than
/// the spec requires and starved the PWA after a single refill.
type IssueLimiter = Arc<Mutex<HashMap<[u8; 32], (u32, u32)>>>;

/// CBOR shape of an inbound `POST /tokens/issue` request body.
#[derive(Deserialize)]
struct TokenIssueRequest {
    /// Hex-encoded Ed25519 public key (32 bytes).
    ed25519_pubkey_hex: String,
    /// Hex-encoded Ed25519 signature (64 bytes) over the challenge nonce.
    ed25519_sig_hex: String,
    /// Hex-encoded challenge nonce (32 bytes) the client just signed.
    challenge_nonce_hex: String,
    /// Raw VOPRF `BlindedElement` bytes, one per requested token.
    /// Each element is 32 bytes (compressed Ristretto255).
    blinded_bytes_list: Vec<serde_bytes::ByteBuf>,
}

/// CBOR shape of a `POST /tokens/issue` response.
#[derive(Serialize)]
struct TokenIssueResponse {
    /// 4-byte epoch identifier.
    #[serde(with = "serde_bytes")]
    epoch_id: Vec<u8>,
    /// Unix seconds at which the active epoch started.
    activated_at: u64,
    /// Unix seconds at which the active epoch fully expires (past grace).
    expires_at: u64,
    /// Ciphersuite name, per RFC 9497 §4.1 ("ristretto255-SHA512").
    ciphersuite: &'static str,
    /// Per-epoch budget the client is authorized to claim.
    budget: u32,
    /// VOPRF `EvaluationElement` bytes, one per request entry.
    evaluated: Vec<serde_bytes::ByteBuf>,
}

/// `POST /tokens/issue` — mint a batch of blind-evaluated Privacy Pass tokens.
///
/// Flow:
///   1. Decode CBOR body.
///   2. Verify Ed25519(challenge_nonce) under the supplied pubkey
///      (PNP-001-MUST-052 — authenticated issuance).
///   3. Cap one batch per identity per epoch.
///   4. Deserialize each `BlindedElement` (32-byte Ristretto255).
///   5. Call `TokenAuthority::issue` and return evaluated elements.
async fn handle_tokens_issue(
    authority: Arc<Mutex<TokenAuthority>>,
    issue_limiter: IssueLimiter,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let req: TokenIssueRequest = match ciborium::from_reader(body.as_ref()) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid CBOR in /tokens/issue request");
            return (StatusCode::BAD_REQUEST, "invalid CBOR").into_response();
        }
    };

    // 1. Decode Ed25519 material.
    let pubkey_bytes = match hex::decode(&req.ed25519_pubkey_hex) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid pubkey hex").into_response(),
    };
    let sig_bytes = match hex::decode(&req.ed25519_sig_hex) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid signature hex").into_response(),
    };
    let nonce_bytes = match hex::decode(&req.challenge_nonce_hex) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid nonce hex").into_response(),
    };

    let vk_arr: [u8; 32] = match pubkey_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, "pubkey must be 32 bytes").into_response(),
    };
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&vk_arr) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid Ed25519 key").into_response(),
    };
    let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, "sig must be 64 bytes").into_response(),
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

    // 2. Verify signature. PNP-001-MUST-052.
    use ed25519_dalek::Verifier;
    if verifying_key.verify(&nonce_bytes, &signature).is_err() {
        tracing::warn!("Rejected /tokens/issue — signature verify failed");
        return (StatusCode::UNAUTHORIZED, "signature verify failed").into_response();
    }

    // Advance and snapshot epoch state under the authority mutex.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // 3. Rate-limit: up to `budget_per_epoch` tokens per identity per epoch
    //    (PNP-001 §10.2). Allows multiple batches as long as the running
    //    total stays under the cap.
    let (current_epoch, budget): ([u8; 4], u32) = {
        let mut a = authority.lock().await;
        a.tick(now);
        (a.current_epoch(), a.budget_per_epoch())
    };
    let epoch_id_u32 = u32::from_be_bytes(current_epoch);
    let requested = req.blinded_bytes_list.len() as u32;
    {
        let mut lim = issue_limiter.lock().await;
        let entry = lim.entry(vk_arr).or_insert((epoch_id_u32, 0));
        // Epoch changed → reset the counter for this identity.
        if entry.0 != epoch_id_u32 {
            *entry = (epoch_id_u32, 0);
        }
        if entry.1.saturating_add(requested) > budget {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "budget exhausted for this epoch",
            )
                .into_response();
        }
        entry.1 = entry.1.saturating_add(requested);
    }

    // 4. Deserialize blinded elements and 5. issue.
    let mut blinded_vec = Vec::with_capacity(req.blinded_bytes_list.len());
    for (i, bb) in req.blinded_bytes_list.iter().enumerate() {
        match voprf::BlindedElement::<Suite>::deserialize(bb.as_ref()) {
            Ok(b) => blinded_vec.push(b),
            Err(e) => {
                tracing::warn!(idx = i, error = %e, "bad BlindedElement");
                return (
                    StatusCode::BAD_REQUEST,
                    format!("bad BlindedElement at index {i}"),
                )
                    .into_response();
            }
        }
    }

    let (evaluated, activated_at, expires_at) = {
        let a = authority.lock().await;
        let eval = a.issue(&blinded_vec);
        (eval, a.current_activated_at(), a.current_expires_at())
    };

    let evaluated_bytes: Vec<serde_bytes::ByteBuf> = evaluated
        .iter()
        .map(|e| serde_bytes::ByteBuf::from(e.serialize().to_vec()))
        .collect();

    let resp = TokenIssueResponse {
        epoch_id: current_epoch.to_vec(),
        activated_at,
        expires_at,
        ciphersuite: "ristretto255-SHA512",
        budget: {
            let a = authority.lock().await;
            a.budget_per_epoch()
        },
        evaluated: evaluated_bytes,
    };

    let mut cbor = Vec::new();
    if ciborium::into_writer(&resp, &mut cbor).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "encode failed").into_response();
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/cbor")],
        cbor,
    )
        .into_response()
}

/// Parse a hex-encoded CBOR-serialized [`Token`] (what rides in the outer
/// frame's `token` field).
fn parse_outer_token(hex_str: &str) -> Option<Token> {
    let bytes = hex::decode(hex_str).ok()?;
    ciborium::from_reader(bytes.as_slice()).ok()
}

/// Generate time-limited TURN credentials using HMAC-SHA1 (RFC 7635-adjacent).
/// Requires `TURN_SECRET` env var. Returns 404 if TURN is not configured.
async fn handle_turn_credentials() -> impl IntoResponse {
    let secret = match std::env::var("TURN_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "TURN not configured"})),
            )
                .into_response();
        }
    };

    let ttl: u64 = 86400; // 24 hours
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expiry = now + ttl;

    // Generate a random component for the username
    let random_id: u64 = rand::random();
    let username = format!("{expiry}:{random_id:016x}");

    // HMAC-SHA1(secret, username) — standard TURN REST API pattern
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;

    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    let result = mac.finalize();
    let credential = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        result.into_bytes(),
    );

    // TURN URIs: explicit env var, or auto-generate from TURN_DOMAIN/TURN_EXTERNAL_IP
    let uris: Vec<String> = {
        let explicit = std::env::var("TURN_URIS").unwrap_or_default();
        if !explicit.trim().is_empty() {
            explicit
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            let host = std::env::var("TURN_DOMAIN")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    std::env::var("TURN_EXTERNAL_IP")
                        .ok()
                        .filter(|s| !s.is_empty())
                })
                .unwrap_or_default();
            if host.is_empty() {
                vec![]
            } else {
                vec![
                    format!("stun:{host}:3478"),
                    format!("turn:{host}:3478"),
                    format!("turn:{host}:3478?transport=tcp"),
                    format!("turns:{host}:5349"),
                ]
            }
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "username": username,
            "credential": credential,
            "ttl": ttl,
            "uris": uris
        })),
    )
        .into_response()
}

/// Background task: periodically pull `/directory` from peer relays, merge,
/// then push our directory to peers for bidirectional gossip propagation.
///
/// Also performs dynamic peer discovery: when merging descriptors, newly
/// discovered relay addresses are added to the peer URL list (capped at
/// `MAX_DISCOVERED_PEERS`).
async fn relay_directory_sync(
    directory: Arc<Mutex<RelayDirectory>>,
    our_peer_id: PeerId,
    peer_relay_urls: Arc<Mutex<Vec<String>>>,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create HTTP client for directory sync");
            return;
        }
    };

    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;

        // Collect peer relay URLs to sync from
        let urls: Vec<String> = {
            let known_urls = peer_relay_urls.lock().await;
            known_urls.clone()
        };

        if urls.is_empty() {
            tracing::debug!("No peer relay URLs configured for directory sync");
            continue;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // --- Phase 1: Pull from peers ---
        for url in &urls {
            let directory_url = format!("{}/directory", url.trim_end_matches('/'));
            match client.get(&directory_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.bytes().await {
                        Ok(body) => {
                            let descriptors: Vec<RelayDescriptor> =
                                match ciborium::from_reader(body.as_ref()) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        tracing::warn!(
                                            url = %directory_url,
                                            error = %e,
                                            "Failed to parse CBOR from peer relay"
                                        );
                                        continue;
                                    }
                                };

                            // Dynamic peer discovery: collect new relay addresses
                            // before merging (we need the addrs from descriptors).
                            let mut new_peer_urls: Vec<String> = Vec::new();
                            {
                                let known_urls = peer_relay_urls.lock().await;
                                for desc in &descriptors {
                                    if desc.peer_id == our_peer_id {
                                        continue;
                                    }
                                    let candidate_url = format!("http://{}", desc.addr);
                                    if known_urls.len() + new_peer_urls.len() < MAX_DISCOVERED_PEERS
                                        && !known_urls.contains(&candidate_url)
                                        && !new_peer_urls.contains(&candidate_url)
                                    {
                                        new_peer_urls.push(candidate_url);
                                    }
                                }
                            }

                            // Merge descriptors
                            let mut dir = directory.lock().await;
                            let merged = dir.merge_descriptors(descriptors, &our_peer_id, now);
                            drop(dir);

                            if merged > 0 {
                                tracing::info!(
                                    url = %directory_url,
                                    merged,
                                    "Merged descriptors from peer relay"
                                );
                            }

                            // Add discovered peers
                            if !new_peer_urls.is_empty() {
                                let mut known_urls = peer_relay_urls.lock().await;
                                for new_url in new_peer_urls {
                                    if known_urls.len() < MAX_DISCOVERED_PEERS
                                        && !known_urls.contains(&new_url)
                                    {
                                        tracing::info!(
                                            url = %new_url,
                                            "Discovered new peer relay from directory"
                                        );
                                        known_urls.push(new_url);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                url = %directory_url,
                                error = %e,
                                "Failed to read response body from peer relay"
                            );
                        }
                    }
                }
                Ok(resp) => {
                    tracing::debug!(
                        url = %directory_url,
                        status = %resp.status(),
                        "Peer relay returned non-success status"
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        url = %directory_url,
                        error = %e,
                        "Failed to reach peer relay"
                    );
                }
            }
        }

        // --- Phase 2: Push our directory to peers ---
        let our_descriptors: Vec<RelayDescriptor> = {
            let dir = directory.lock().await;
            dir.descriptors().values().cloned().collect()
        };

        if our_descriptors.is_empty() {
            continue;
        }

        let mut cbor_buf = Vec::new();
        if let Err(e) = ciborium::into_writer(&our_descriptors, &mut cbor_buf) {
            tracing::error!(error = %e, "Failed to serialize directory for push");
            continue;
        }

        // Re-read URLs in case new peers were discovered during pull phase
        let push_urls: Vec<String> = {
            let known_urls = peer_relay_urls.lock().await;
            known_urls.clone()
        };

        for url in &push_urls {
            let push_url = format!("{}/directory/push", url.trim_end_matches('/'));
            match client
                .post(&push_url)
                .header("Content-Type", "application/cbor")
                .body(cbor_buf.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!(url = %push_url, "Pushed directory to peer relay");
                }
                Ok(resp) => {
                    tracing::debug!(
                        url = %push_url,
                        status = %resp.status(),
                        "Peer relay rejected directory push"
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        url = %push_url,
                        error = %e,
                        "Failed to push directory to peer relay"
                    );
                }
            }
        }
    }
}

/// WSS `/federation/v1` — accepts inbound federation links (PNP-008 §5.5).
///
/// Enforces MUST-077/078/079/080 on the wire: WSS path, `len_be32 || cbor`
/// framing, 2 MiB cap, unknown-type close (4002). Peer-identity admission
/// (MUST-018: PNP-002 handshake inside PNP-006 TLS camouflage) is not yet
/// wired — the handler currently accepts the upgrade and runs the frame
/// decode loop without admitting any peer into [`FederationManager`]. Dedup
/// (MUST-083) and reputation accounting therefore do NOT fire on this path
/// until the handshake commit lands; unit tests on `FederationLink::admit_inbound`
/// continue to exercise that code path directly.
///
/// No admission-by-header: a header-claimed peer_id has no cryptographic
/// proof, and admitting on it would let any prober dedup-kick a legitimate
/// peer's link (claim their id, get kicked, repeat).
async fn handle_federation_link(mut socket: WebSocket, peer_addr: std::net::SocketAddr) {
    info!("federation link upgrade accepted from {peer_addr}");

    while let Some(msg) = socket.recv().await {
        let data = match msg {
            Ok(Message::Binary(b)) => b,
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => continue,
        };
        match parolnet_relay::federation_codec::decode_frame(&data) {
            Ok(_frame) => {
                // Frame ingestion into FederationManager lands alongside the
                // PNP-002 handshake wiring (MUST-018): verify Ed25519 sig on
                // the first FederationSync, extract peer_id from the signed
                // descriptor, THEN admit through FederationManager.
            }
            Err(err) => {
                let code = err.close_code();
                let reason = match code {
                    CLOSE_OVERSIZE => "frame exceeds 2 MiB cap".into(),
                    CLOSE_UNKNOWN_TYPE => "unknown federation payload type".into(),
                    _ => "federation codec error".into(),
                };
                let _ = socket
                    .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                        code,
                        reason,
                    })))
                    .await;
                break;
            }
        }
    }
}

/// GET /peers — returns JSON list of currently connected peer IDs.
/// Requires ADMIN_TOKEN authentication. Returns 404 if ADMIN_TOKEN is not set,
/// 403 if the token is missing or invalid.
async fn handle_peers(
    headers: axum::http::HeaderMap,
    peers: PeerMap,
) -> Result<Json<Vec<String>>, StatusCode> {
    if std::env::var("ADMIN_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
        .is_none()
    {
        return Err(StatusCode::NOT_FOUND);
    }
    if !check_admin_token(&headers) {
        return Err(StatusCode::FORBIDDEN);
    }
    let peer_list = peers.lock().await;
    let peer_ids: Vec<String> = peer_list.keys().cloned().collect();
    Ok(Json(peer_ids))
}

/// GET /bootstrap?exclude=<peer_id> — returns up to 20 known peer IDs,
/// excluding the optionally specified peer. Used by clients for peer discovery
/// to establish direct WebRTC connections.
async fn handle_bootstrap(
    Query(params): Query<HashMap<String, String>>,
    peers: PeerMap,
) -> Json<Vec<String>> {
    let peer_list = peers.lock().await;
    let exclude = params.get("exclude").cloned().unwrap_or_default();
    let known: Vec<String> = peer_list
        .keys()
        .filter(|p| **p != exclude)
        .take(20)
        .cloned()
        .collect();
    Json(known)
}

#[tokio::main]
async fn main() {
    // Install rustls crypto provider for reqwest TLS support
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt::init();

    let port: u16 = std::env::var("RELAY_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9000);

    // Bridge mode configuration
    let bridge_mode = std::env::var("BRIDGE_MODE").unwrap_or_default() == "true";
    let bridge_front_domain: Option<String> = std::env::var("BRIDGE_FRONT_DOMAIN")
        .ok()
        .filter(|s| !s.is_empty());
    let trusted_proxies: Arc<HashSet<IpAddr>> = {
        let ips: HashSet<IpAddr> = std::env::var("TRUSTED_PROXY_IPS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .collect();
        if !ips.is_empty() {
            info!(
                "Configured {} trusted proxy IPs for X-Forwarded-For",
                ips.len()
            );
        }
        Arc::new(ips)
    };
    if bridge_mode {
        info!("Bridge mode enabled — relay will NOT join public directory");
        if let Some(ref fd) = bridge_front_domain {
            info!("Bridge front domain: {fd}");
        }
    }

    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
    let store = Arc::new(Mutex::new(RelayMessageStore::new()));
    let stats = Arc::new(analytics::Stats::new());
    let client_stats = Arc::new(ClientStats::new());
    let directory: Arc<Mutex<RelayDirectory>> = Arc::new(Mutex::new(RelayDirectory::new()));

    // Bridge disclosure counter (PNP-008-MUST-089). In-memory only — a
    // process restart zeroes it, which is the whole point: a seized bridge
    // yields no disclosure history.
    let bridge_disclosure_limiter: Arc<Mutex<DisclosureLimiter>> =
        Arc::new(Mutex::new(DisclosureLimiter::new()));

    // Bridge IP audit log (PNP-008-MUST-054 / MUST-090). Scheduled scrubber
    // runs independently of request traffic.
    let bridge_ip_audit: Arc<Mutex<IpAuditLog>> = Arc::new(Mutex::new(IpAuditLog::new()));
    if bridge_mode {
        let audit = bridge_ip_audit.clone();
        let limiter = bridge_disclosure_limiter.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(IP_LOG_SCRUBBER_INTERVAL_SECS));
            interval.tick().await;
            loop {
                interval.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let evicted = audit.lock().await.purge(now);
                limiter.lock().await.gc();
                if evicted > 0 {
                    info!("bridge IP audit log purged {evicted} stale entries");
                }
            }
        });
    }

    // H9 Privacy Pass token authority. The VOPRF secret is generated once on
    // boot and rotated on every 1-hour epoch boundary (PNP-001-MUST-051).
    let startup_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let token_authority: Arc<Mutex<TokenAuthority>> = Arc::new(Mutex::new(TokenAuthority::new(
        TokenConfig::default(),
        startup_secs,
    )));
    let issue_limiter: IssueLimiter = Arc::new(Mutex::new(HashMap::new()));
    // Spawn a ticker so rotation happens even when there's no /tokens/issue
    // traffic to drive it.
    {
        let ta = token_authority.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                ta.lock().await.tick(now);
            }
        });
    }

    // Parse peer relay URLs from PEER_RELAY_URLS env var (comma-separated)
    let peer_relay_urls: Arc<Mutex<Vec<String>>> = {
        let urls: Vec<String> = std::env::var("PEER_RELAY_URLS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !urls.is_empty() {
            info!(
                "Configured {} peer relay URLs for directory sync",
                urls.len()
            );
        }
        Arc::new(Mutex::new(urls))
    };

    let conn_rate_limiter: ConnRateLimiter = Arc::new(RateLimiter::new(
        WS_CONN_RATE_LIMIT,
        WS_CONN_RATE_WINDOW_SECS,
    ));
    let msg_rate_limiter: MsgRateLimiter =
        Arc::new(RateLimiter::new(MSG_RATE_LIMIT, MSG_RATE_WINDOW_SECS));
    let push_rate_limiter: PushRateLimiter =
        Arc::new(RateLimiter::new(PUSH_RATE_LIMIT, PUSH_RATE_WINDOW_SECS));

    // Spawn periodic rate limiter cleanup (every 5 minutes)
    {
        let conn_rl = conn_rate_limiter.clone();
        let msg_rl = msg_rate_limiter.clone();
        let push_rl = push_rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                conn_rl.cleanup();
                msg_rl.cleanup();
                push_rl.cleanup();
            }
        });
    }


    // Initialize mesh PeerManager as a gossip supernode.
    //
    // Identity priority (see `parolnet_relay_server::identity`):
    //   1. RELAY_SECRET_KEY env var (hex) — never touches disk.
    //   2. File at RELAY_KEY_FILE (default /data/relay.key).
    //   3. Generate fresh + persist to that file (mode 0600).
    let key_file = parolnet_relay_server::identity::key_file_path();
    let (key_bytes, identity_source) =
        parolnet_relay_server::identity::load_or_generate_relay_identity(&key_file)
            .expect("failed to load or generate relay identity");
    let relay_signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
    match identity_source {
        parolnet_relay_server::identity::IdentitySource::EnvVar => {
            info!("Loaded relay identity from RELAY_SECRET_KEY env var (not persisted to disk)");
        }
        parolnet_relay_server::identity::IdentitySource::ExistingFile => {
            info!(
                "Loaded persistent relay identity from {}",
                key_file.display()
            );
        }
        parolnet_relay_server::identity::IdentitySource::GeneratedAndPersisted => {
            info!(
                "Generated new persistent relay identity and wrote it to {} (mode 0600)",
                key_file.display()
            );
        }
    }
    let pubkey_bytes = relay_signing_key.verifying_key().to_bytes();
    info!(
        "Relay Ed25519 public key (authority-verification identity): {}",
        hex::encode(pubkey_bytes)
    );
    let our_peer_id = {
        use sha2::{Digest, Sha256};
        PeerId(Sha256::digest(pubkey_bytes).into())
    };
    info!("Relay PeerId: {}", hex::encode(our_peer_id.0));

    // H12 Phase 2 presence authority. Clones the signing key bytes into a
    // zeroizing wrapper so the long-lived relay identity can be re-used here
    // without widening the lifetime of the original SigningKey.
    let presence_authority: Arc<Mutex<PresenceAuthority>> = Arc::new(Mutex::new({
        let mut pa = PresenceAuthority::new(
            our_peer_id,
            relay_signing_key.clone(),
            PresenceConfig::default(),
        );
        // Resolve the public URL this relay advertises as its `home_relay_url`.
        // Falls back to "http://<bind>:<port>" which matches the descriptor
        // addr format used by the federation directory sync task.
        let public_url = std::env::var("RELAY_PUBLIC_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("http://0.0.0.0:{port}"));
        pa.set_own_public_url(public_url);
        pa
    }));

    let peer_manager = Arc::new(PeerManager::new(our_peer_id, relay_signing_key));

    // Spawn periodic maintenance (dedup rotation, stored-message expiry)
    {
        let pm = peer_manager.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(43200)); // 12 hours
            loop {
                interval.tick().await;
                if let Err(e) = pm.run_maintenance().await {
                    tracing::warn!(error = %e, "PeerManager maintenance failed");
                } else {
                    tracing::info!("PeerManager maintenance completed");
                }
            }
        });
    }

    // Spawn periodic message store expiry (every hour)
    {
        let store = store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let expired = store.lock().await.expire();
                if expired > 0 {
                    tracing::info!(expired, "Expired stale buffered relay messages");
                }
            }
        });
    }

    // Spawn relay-to-relay directory sync (every 60s)
    // In bridge mode, skip sync — bridge relays must not appear in or push to the public directory.
    if !bridge_mode {
        let dir = directory.clone();
        let urls = peer_relay_urls.clone();
        tokio::spawn(relay_directory_sync(dir, our_peer_id, urls));
    } else {
        info!("Directory sync disabled in bridge mode");
    }

    // Spawn federation presence fetch (every 300 s, PNP-008-MUST-069).
    // Also skipped in bridge mode so bridges don't leak their federation peers.
    if !bridge_mode {
        let pa = presence_authority.clone();
        let dir = directory.clone();
        let urls = peer_relay_urls.clone();
        let poll = presence_authority
            .lock()
            .await
            .config()
            .federation_poll_interval_secs;
        tokio::spawn(federation_presence_fetch(pa, dir, urls, poll));
    }

    // Rate limiter for presence + lookup endpoints (10 req/s per IP,
    // PNP-008-MUST-066). A 1-second window of 10 events is the policy.
    let lookup_rate_limiter: LookupRateLimiter = Arc::new(RateLimiter::new(
        LOOKUP_RATE_LIMIT,
        LOOKUP_RATE_WINDOW_SECS,
    ));
    {
        let rl = lookup_rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                rl.cleanup();
            }
        });
    }

    // Determine whether the /stats endpoint should be active
    #[cfg(feature = "analytics")]
    let analytics_enabled = std::env::var("PAROLNET_ANALYTICS").unwrap_or_default() == "1";

    #[cfg(feature = "analytics")]
    if analytics_enabled {
        info!("Analytics enabled");
    } else {
        info!("Analytics compiled in but disabled (set PAROLNET_ANALYTICS=1 to enable)");
    }

    #[allow(unused_mut)]
    let mut app = Router::new()
        .route(
            "/ws",
            get({
                let peers = peers.clone();
                let store = store.clone();
                let stats = stats.clone();
                let peer_manager = peer_manager.clone();
                let conn_rl = conn_rate_limiter.clone();
                let msg_rl = msg_rate_limiter.clone();
                let tp = trusted_proxies.clone();
                let ta = token_authority.clone();
                let pa = presence_authority.clone();
                move |ws: WebSocketUpgrade,
                      headers: axum::http::HeaderMap,
                      connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>| async move {
                    // Per-IP connection rate limiting (respecting trusted proxies)
                    let client_ip = get_client_ip(connect_info.0.ip(), &headers, &tp);
                    if conn_rl.is_limited(&client_ip) {
                        return StatusCode::TOO_MANY_REQUESTS.into_response();
                    }
                    ws.on_upgrade(move |socket| {
                        handle_socket(socket, peers, store, stats, peer_manager, msg_rl, ta, pa)
                    })
                    .into_response()
                }
            }),
        )
        .route(
            FEDERATION_LINK_PATH,
            get({
                move |ws: WebSocketUpgrade,
                      connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>| async move {
                    let peer_addr = connect_info.0;
                    ws.on_upgrade(move |socket| handle_federation_link(socket, peer_addr))
                        .into_response()
                }
            }),
        )
        .route("/health", get(|| async { "OK" }))
        .route(
            "/turn-credentials",
            get(|| async { handle_turn_credentials().await }),
        )
        .route(
            "/peers",
            get({
                let peers = peers.clone();
                move |headers: axum::http::HeaderMap| {
                    let peers = peers.clone();
                    async move { handle_peers(headers, peers).await }
                }
            }),
        )
        .route(
            "/bootstrap",
            get({
                let peers = peers.clone();
                move |query: Query<HashMap<String, String>>| {
                    let peers = peers.clone();
                    async move { handle_bootstrap(query, peers).await }
                }
            }),
        )
        .route(
            "/telemetry",
            post({
                let client_stats = client_stats.clone();
                move |body: Json<TelemetryBatch>| {
                    let client_stats = client_stats.clone();
                    async move { handle_telemetry(client_stats, body).await }
                }
            }),
        )
        .route(
            "/directory",
            get({
                let directory = directory.clone();
                move || {
                    let directory = directory.clone();
                    async move { handle_directory(directory).await }
                }
            }),
        )
        .route(
            "/endorse",
            post({
                let directory = directory.clone();
                move |body: axum::body::Bytes| {
                    let directory = directory.clone();
                    async move { handle_endorse(directory, body).await }
                }
            }),
        )
        .route(
            "/directory/push",
            post({
                let directory = directory.clone();
                let push_rl = push_rate_limiter.clone();
                let tp = trusted_proxies.clone();
                move |headers: axum::http::HeaderMap,
                      connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
                      body: axum::body::Bytes| {
                    let directory = directory.clone();
                    let push_rl = push_rl.clone();
                    let client_ip = get_client_ip(connect_info.0.ip(), &headers, &tp);
                    async move {
                        handle_directory_push(directory, our_peer_id, push_rl, client_ip, body)
                            .await
                    }
                }
            }),
        )
        .route(
            "/tokens/issue",
            post({
                let ta = token_authority.clone();
                let il = issue_limiter.clone();
                move |body: axum::body::Bytes| {
                    let ta = ta.clone();
                    let il = il.clone();
                    async move { handle_tokens_issue(ta, il, body).await }
                }
            }),
        )
        .route(
            "/peers/presence",
            get({
                let pa = presence_authority.clone();
                let rl = lookup_rate_limiter.clone();
                let tp = trusted_proxies.clone();
                move |headers: axum::http::HeaderMap,
                      connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>| {
                    let pa = pa.clone();
                    let rl = rl.clone();
                    let client_ip = get_client_ip(connect_info.0.ip(), &headers, &tp);
                    async move { handle_peers_presence(pa, rl, client_ip).await }
                }
            }),
        )
        .route(
            "/peers/lookup",
            get({
                let pa = presence_authority.clone();
                let rl = lookup_rate_limiter.clone();
                let tp = trusted_proxies.clone();
                move |headers: axum::http::HeaderMap,
                      connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
                      query: Query<HashMap<String, String>>| {
                    let pa = pa.clone();
                    let rl = rl.clone();
                    let client_ip = get_client_ip(connect_info.0.ip(), &headers, &tp);
                    async move { handle_peers_lookup(pa, rl, client_ip, query).await }
                }
            }),
        )
        .layer({
            let cors_origins = std::env::var("CORS_ORIGINS").unwrap_or_default();
            if cors_origins.is_empty() {
                tower_http::cors::CorsLayer::permissive()
            } else {
                use tower_http::cors::{AllowOrigin, CorsLayer};
                let origins: Vec<axum::http::HeaderValue> = cors_origins
                    .split(',')
                    .filter_map(|o| o.trim().parse().ok())
                    .collect();
                CorsLayer::new()
                    .allow_origin(AllowOrigin::list(origins))
                    .allow_methods(tower_http::cors::Any)
                    .allow_headers(tower_http::cors::Any)
            }
        });

    // Add /bridge-info endpoint when bridge mode is enabled
    if bridge_mode {
        let bfd = bridge_front_domain.clone();
        let relay_fp = hex::encode(pubkey_bytes);
        let limiter = bridge_disclosure_limiter.clone();
        app = app.route(
            "/bridge-info",
            get(move |Query(params): Query<HashMap<String, String>>| {
                let bfd = bfd.clone();
                let fp = relay_fp.clone();
                let limiter = limiter.clone();
                async move { handle_bridge_info(params, bfd, fp, limiter).await }
            }),
        );
        // MUST-085..088: serve the generic cover page for every other path.
        app = app.fallback(get(handle_cover_page));
    }

    // Add /stats endpoint only when feature is enabled AND env var is set
    #[cfg(feature = "analytics")]
    {
        if analytics_enabled {
            let stats_clone = stats.clone();
            let peers_clone = peers.clone();
            let client_stats_clone = client_stats.clone();
            let pm_clone = peer_manager.clone();
            app = app.route(
                "/stats",
                get(move || {
                    let s = stats_clone.clone();
                    let p = peers_clone.clone();
                    let cs = client_stats_clone.clone();
                    let pm = pm_clone.clone();
                    async move {
                        let online = p.lock().await.len();
                        let server_json = s.to_json(online);
                        let client_json = cs.to_json();
                        let mesh_peers = pm.peer_count().await;
                        let combined = format!(
                            r#"{{"server":{},"client":{},"mesh":{{"connected_peers":{}}}}}"#,
                            server_json, client_json, mesh_peers
                        );
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            combined,
                        )
                    }
                }),
            );
        }
    }

    let addr = format!("0.0.0.0:{port}");
    info!("ParolNet relay listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    axum::serve(listener, app).await.unwrap();
}

/// Forward a gossip message to up to `fanout` random connected peers,
/// excluding the sender and any peers in the exclude list.
async fn forward_gossip(
    peers: &PeerMap,
    sender: &str,
    exclude: &[String],
    payload: &str,
    fanout: usize,
) {
    let peers_lock = peers.lock().await;

    // Collect eligible peers (not sender, not in exclude list)
    let eligible: Vec<(&String, &mpsc::UnboundedSender<Message>)> = peers_lock
        .iter()
        .filter(|(id, _)| *id != sender && !exclude.contains(id))
        .collect();

    // Pick up to `fanout` random peers
    let mut rng = rand::thread_rng();
    let selected: Vec<_> = if eligible.len() <= fanout {
        eligible
    } else {
        eligible
            .choose_multiple(&mut rng, fanout)
            .cloned()
            .collect()
    };

    let gossip_msg = serde_json::to_string(&OutgoingMessage {
        msg_type: "gossip".into(),
        from: Some(sender.to_string()),
        payload: Some(payload.to_string()),
        ..Default::default()
    })
    .unwrap();

    for (_id, tx) in selected {
        let _ = tx.send(Message::Text(gossip_msg.clone().into()));
    }
}

/// Try to parse a hex-encoded peer ID string into a `PeerId`.
/// Returns `None` if the string is not valid 64-char hex (32 bytes).
fn parse_peer_id(hex_str: &str) -> Option<PeerId> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(PeerId(arr))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Circuit routing state for onion relay cells
// ---------------------------------------------------------------------------

/// Per-circuit state held by the relay server.
struct CircuitState {
    /// Keys derived from the CREATE/EXTEND handshake.
    keys: parolnet_relay::onion::HopKeys,
    /// Forward (client -> relay) counter for onion nonce derivation.
    forward_counter: u32,
    /// Backward (relay -> client) counter for onion nonce derivation.
    /// Currently unused in single-relay MVP; reserved for reverse-direction routing.
    #[allow(dead_code)]
    backward_counter: u32,
}

type CircuitTable = Arc<std::sync::Mutex<HashMap<u32, CircuitState>>>;

/// Handle a binary relay cell received from a WebSocket client.
///
/// Processes CREATE, EXTEND, DATA, and DESTROY cells. In single-relay MVP
/// mode, EXTEND is handled internally (the relay creates a new sub-circuit
/// for each hop rather than forwarding to another relay).
fn handle_relay_cell(
    cell: parolnet_relay::RelayCell,
    tx: &mpsc::UnboundedSender<Message>,
    circuit_table: &CircuitTable,
    peers: &PeerMap,
    _my_peer_id: &Option<String>,
) {
    use parolnet_relay::CellType;
    use parolnet_relay::handshake::CircuitHandshake;
    use parolnet_relay::onion::HopKeys;

    match cell.cell_type {
        CellType::Create => {
            // Generate ephemeral X25519 key, do DH, derive keys, respond CREATED
            let relay_secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
            match CircuitHandshake::handle_create(&cell, &relay_secret) {
                Ok((created_cell, keys)) => {
                    let mut table = circuit_table.lock().unwrap();
                    table.insert(
                        cell.circuit_id,
                        CircuitState {
                            keys,
                            forward_counter: 0,
                            backward_counter: 0,
                        },
                    );
                    let _ = tx.send(Message::Binary(created_cell.to_bytes().to_vec().into()));
                    tracing::debug!(circuit_id = cell.circuit_id, "circuit CREATE handled");
                }
                Err(e) => {
                    tracing::warn!(circuit_id = cell.circuit_id, error = %e, "CREATE failed");
                }
            }
        }

        CellType::Extend => {
            // In single-relay MVP mode: handle EXTEND internally.
            // Peel the onion layer from the EXTEND payload, then create a new
            // sub-circuit with fresh DH keys.
            let mut table = circuit_table.lock().unwrap();
            if let Some(state) = table.get_mut(&cell.circuit_id) {
                // Peel the onion layer from the EXTEND payload
                let payload_data = &cell.payload[..cell.payload_len as usize];
                let peeled = parolnet_relay::onion::onion_peel(
                    payload_data,
                    &state.keys.forward_key,
                    &state.keys.forward_nonce_seed,
                    state.forward_counter,
                );
                state.forward_counter += 1;

                match peeled {
                    Ok(inner) => {
                        // Parse the inner EXTEND payload: peer_id[32] + client_pubkey[32]
                        if inner.len() >= 64 {
                            let mut client_pub = [0u8; 32];
                            client_pub.copy_from_slice(&inner[32..64]);
                            let client_public = x25519_dalek::PublicKey::from(client_pub);

                            // Generate new DH keys for this sub-hop
                            let hop_secret =
                                x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
                            let hop_public = x25519_dalek::PublicKey::from(&hop_secret);
                            let shared = hop_secret.diffie_hellman(&client_public);

                            if let Ok(hop_keys) = HopKeys::from_shared_secret(shared.as_bytes()) {
                                // Register the new sub-circuit hop — use a derived circuit_id
                                // to avoid collision. We use circuit_id + hop_index.
                                let sub_id =
                                    cell.circuit_id.wrapping_add(table.len() as u32 + 1000);
                                table.insert(
                                    sub_id,
                                    CircuitState {
                                        keys: hop_keys,
                                        forward_counter: 0,
                                        backward_counter: 0,
                                    },
                                );

                                // Respond with EXTENDED containing the hop's public key
                                let extended = CircuitHandshake::extended_cell(
                                    cell.circuit_id,
                                    hop_public.as_bytes(),
                                );
                                let _ =
                                    tx.send(Message::Binary(extended.to_bytes().to_vec().into()));
                                tracing::debug!(
                                    circuit_id = cell.circuit_id,
                                    "circuit EXTEND handled (single-relay MVP)"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            circuit_id = cell.circuit_id,
                            error = %e,
                            "EXTEND onion peel failed"
                        );
                    }
                }
            } else {
                tracing::warn!(circuit_id = cell.circuit_id, "EXTEND for unknown circuit");
            }
        }

        CellType::Data => {
            // Peel one onion layer and deliver the payload
            let mut table = circuit_table.lock().unwrap();
            if let Some(state) = table.get_mut(&cell.circuit_id) {
                let payload_data = &cell.payload[..cell.payload_len as usize];
                let peeled = parolnet_relay::onion::onion_peel(
                    payload_data,
                    &state.keys.forward_key,
                    &state.keys.forward_nonce_seed,
                    state.forward_counter,
                );
                state.forward_counter += 1;

                match peeled {
                    Ok(plaintext) => {
                        // Convert the decrypted payload to a JSON message and route
                        // to the target peer using the existing PeerMap routing.
                        // The plaintext is expected to be a UTF-8 JSON message.
                        if let Ok(text) = String::from_utf8(plaintext) {
                            // Try to route via PeerMap
                            if let Ok(incoming) = serde_json::from_str::<serde_json::Value>(&text)
                                && let Some(to) = incoming.get("to").and_then(|v| v.as_str())
                            {
                                let peers_guard = peers.blocking_lock();
                                if let Some(recipient_tx) = peers_guard.get(to) {
                                    let _ = recipient_tx.send(Message::Text(text.into()));
                                }
                            }
                        }
                        tracing::debug!(circuit_id = cell.circuit_id, "DATA cell routed");
                    }
                    Err(e) => {
                        tracing::warn!(
                            circuit_id = cell.circuit_id,
                            error = %e,
                            "DATA onion peel failed"
                        );
                    }
                }
            }
        }

        CellType::Destroy => {
            let mut table = circuit_table.lock().unwrap();
            table.remove(&cell.circuit_id);
            tracing::debug!(circuit_id = cell.circuit_id, "circuit destroyed");
        }

        _ => {
            tracing::debug!(
                circuit_id = cell.circuit_id,
                cell_type = ?cell.cell_type,
                "ignoring unhandled cell type"
            );
        }
    }
}

async fn handle_socket(
    socket: WebSocket,
    peers: PeerMap,
    store: Arc<Mutex<RelayMessageStore>>,
    stats: Arc<analytics::Stats>,
    peer_manager: Arc<PeerManager>,
    msg_rate_limiter: MsgRateLimiter,
    token_authority: Arc<Mutex<TokenAuthority>>,
    presence_authority: Arc<Mutex<PresenceAuthority>>,
) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    let mut my_peer_id: Option<String> = None;

    // Circuit routing state for onion relay cells
    let circuit_table: Arc<std::sync::Mutex<HashMap<u32, CircuitState>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Spawn task to forward messages from channel to WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Ping interval to keep the WebSocket connection alive
    let mut ping_interval = tokio::time::interval(Duration::from_secs(30));
    ping_interval.tick().await; // consume the immediate first tick

    // Read messages from WebSocket, multiplexed with ping keepalive
    loop {
        let ws_msg = tokio::select! {
            msg_opt = receiver.next() => {
                match msg_opt {
                    Some(Ok(msg @ Message::Text(_))) => msg,
                    Some(Ok(msg @ Message::Binary(_))) => msg,
                    Some(Ok(Message::Pong(_))) => continue,
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => break,
                }
            }
            _ = ping_interval.tick() => {
                // Send a ping through the channel to the send task
                if tx.send(Message::Ping(vec![].into())).is_err() {
                    break; // send task died, connection is dead
                }
                continue;
            }
        };

        // Handle binary frames (relay cells)
        if let Message::Binary(ref bin) = ws_msg {
            if bin.len() == parolnet_relay::CELL_SIZE {
                let mut buf = [0u8; parolnet_relay::CELL_SIZE];
                buf.copy_from_slice(bin);
                if let Ok(cell) = parolnet_relay::RelayCell::from_bytes(&buf) {
                    handle_relay_cell(cell, &tx, &circuit_table, &peers, &my_peer_id);
                }
            }
            continue;
        }

        let text = match ws_msg {
            Message::Text(t) => t.to_string(),
            _ => continue,
        };

        let Ok(incoming) = serde_json::from_str::<IncomingMessage>(&text) else {
            let _ = tx.send(Message::Text(
                serde_json::to_string(&OutgoingMessage {
                    msg_type: "error".into(),
                    message: Some("invalid JSON".into()),
                    ..Default::default()
                })
                .unwrap()
                .into(),
            ));
            continue;
        };

        // Per-peer message rate limiting
        if let Some(ref pid) = my_peer_id
            && msg_rate_limiter.is_limited(pid)
        {
            let _ = tx.send(Message::Text(
                serde_json::to_string(&OutgoingMessage {
                    msg_type: "error".into(),
                    message: Some("rate limited".into()),
                    ..Default::default()
                })
                .unwrap()
                .into(),
            ));
            continue;
        }

        match incoming.msg_type.as_str() {
            "register" => {
                if let Some(peer_id) = incoming.peer_id {
                    // Challenge-response: if peer provides pubkey + signature + nonce,
                    // verify identity. Otherwise issue a challenge nonce.
                    if let (Some(pubkey_hex), Some(sig_hex), Some(nonce_hex)) =
                        (&incoming.pubkey, &incoming.signature, &incoming.nonce)
                    {
                        // Verify challenge-response
                        let valid = (|| -> Result<bool, String> {
                            let pubkey_bytes = hex::decode(pubkey_hex)
                                .map_err(|e| format!("invalid pubkey hex: {e}"))?;
                            let sig_bytes = hex::decode(sig_hex)
                                .map_err(|e| format!("invalid signature hex: {e}"))?;
                            let nonce_bytes = hex::decode(nonce_hex)
                                .map_err(|e| format!("invalid nonce hex: {e}"))?;

                            // Verify PeerId = SHA-256(pubkey)
                            use sha2::{Digest, Sha256};
                            let expected_pid = hex::encode(Sha256::digest(&pubkey_bytes));
                            if expected_pid != peer_id {
                                return Err("peer_id does not match pubkey".into());
                            }

                            let vk_bytes: [u8; 32] = pubkey_bytes
                                .try_into()
                                .map_err(|_| "pubkey must be 32 bytes".to_string())?;
                            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes)
                                .map_err(|e| format!("invalid Ed25519 key: {e}"))?;

                            let sig_arr: [u8; 64] = sig_bytes
                                .try_into()
                                .map_err(|_| "signature must be 64 bytes".to_string())?;
                            let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

                            use ed25519_dalek::Verifier;
                            verifying_key
                                .verify(&nonce_bytes, &signature)
                                .map_err(|_| "signature verification failed".to_string())?;

                            Ok(true)
                        })();

                        match valid {
                            Ok(true) => {
                                // Authenticated — complete registration
                                peers.lock().await.insert(peer_id.clone(), tx.clone());
                                my_peer_id = Some(peer_id.clone());
                                stats.record_connection();

                                if let Some(mesh_pid) = parse_peer_id(&peer_id) {
                                    let ws_conn = Arc::new(WsConnection { tx: tx.clone() });
                                    if let Err(e) = peer_manager.add_peer(mesh_pid, ws_conn).await {
                                        tracing::warn!(
                                            peer = %peer_id, error = %e,
                                            "failed to add peer to mesh PeerManager"
                                        );
                                    }
                                }

                                let online = peers.lock().await.len();
                                let _ = tx.send(Message::Text(
                                    serde_json::to_string(&OutgoingMessage {
                                        msg_type: "registered".into(),
                                        peer_id: Some(peer_id.clone()),
                                        online_peers: Some(online),
                                        ..Default::default()
                                    })
                                    .unwrap()
                                    .into(),
                                ));

                                info!(
                                    "Peer registered (authenticated): {}...  ({} online)",
                                    &peer_id[..16.min(peer_id.len())],
                                    online
                                );

                                // Publish presence (PNP-008-MUST-063): this
                                // peer is now authoritatively connected here,
                                // so `/peers/presence` must advertise it.
                                if let Some(mesh_pid) = parse_peer_id(&peer_id) {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    presence_authority
                                        .lock()
                                        .await
                                        .upsert_local(mesh_pid, now);
                                }

                                // Deliver stored messages
                                if let Some(mesh_pid) = parse_peer_id(&peer_id) {
                                    let pending = store.lock().await.retrieve(&mesh_pid);
                                    for msg in pending {
                                        let _ = tx.send(Message::Text(msg.into()));
                                    }
                                }
                            }
                            Ok(false) | Err(_) => {
                                let err_msg = match valid {
                                    Err(e) => e,
                                    _ => "authentication failed".into(),
                                };
                                let _ = tx.send(Message::Text(
                                    serde_json::to_string(&OutgoingMessage {
                                        msg_type: "error".into(),
                                        message: Some(format!("register auth failed: {err_msg}")),
                                        ..Default::default()
                                    })
                                    .unwrap()
                                    .into(),
                                ));
                            }
                        }
                    } else {
                        // No auth provided — issue a challenge nonce
                        let mut nonce = [0u8; 32];
                        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
                        let nonce_hex = hex::encode(nonce);
                        let _ = tx.send(Message::Text(
                            serde_json::json!({
                                "type": "challenge",
                                "nonce": nonce_hex,
                                "peer_id": peer_id
                            })
                            .to_string()
                            .into(),
                        ));
                    }
                }
            }

            "message" => {
                // PNP-001 "Outer Relay Frame" (§ Token Auth): the frame carries
                // a `token` field *instead of* a `from` field. The relay MUST
                // VOPRF-verify the token and MUST reject duplicates.
                //
                // Clauses:
                //   - PNP-001-MUST-048 — `token` field is mandatory.
                //   - PNP-001-MUST-049 — VOPRF verify under current / prior
                //     epoch key; drop otherwise (silent — no leak).
                //   - PNP-001-MUST-050 — spent-set enforcement.
                let (Some(to), Some(payload), Some(token_hex)) =
                    (incoming.to, incoming.payload, incoming.token)
                else {
                    tracing::warn!(
                        peer = %my_peer_id.clone().unwrap_or_default(),
                        "dropping outer message frame missing token / to / payload"
                    );
                    continue;
                };

                let Some(token) = parse_outer_token(&token_hex) else {
                    tracing::warn!("dropping outer message frame with malformed token");
                    continue;
                };

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let verified = {
                    let mut a = token_authority.lock().await;
                    a.tick(now);
                    a.verify_and_spend(&token, now)
                };
                if let Err(e) = verified {
                    tracing::warn!(error = %e, "dropping outer message frame — token rejected");
                    continue;
                }

                // Refresh presence for the authenticated sender; every message
                // doubles as a liveness heartbeat so `/peers/presence` stays
                // current without a dedicated keepalive frame.
                if let Some(ref pid_hex) = my_peer_id
                    && let Some(mesh_pid) = parse_peer_id(pid_hex)
                {
                    presence_authority
                        .lock()
                        .await
                        .upsert_local(mesh_pid, now);
                }

                // Token passed — route the payload to `to`. The outbound frame
                // does NOT carry a `from` field; the relay is intentionally
                // blind to sender identity on the wire.
                let outgoing = serde_json::to_string(&OutgoingMessage {
                    msg_type: "message".into(),
                    payload: Some(payload),
                    ..Default::default()
                })
                .unwrap();

                let peers_lock = peers.lock().await;
                if let Some(recipient_tx) = peers_lock.get(&to) {
                    let _ = recipient_tx.send(Message::Text(outgoing.into()));
                    stats.record_message_routed();
                } else {
                    drop(peers_lock);
                    if let Some(dest_pid) = parse_peer_id(&to) {
                        store.lock().await.store(dest_pid, outgoing);
                        stats.record_message_queued();
                    }
                    let _ = tx.send(Message::Text(
                        serde_json::to_string(&OutgoingMessage {
                            msg_type: "queued".into(),
                            message: Some("peer offline, message stored".into()),
                            ..Default::default()
                        })
                        .unwrap()
                        .into(),
                    ));
                }
            }

            "gossip" => {
                // Forward gossip payload to up to 3 random peers (excluding sender + exclude list)
                let from = my_peer_id.clone().unwrap_or_default();
                if let Some(payload) = incoming.payload {
                    // Forward via existing relay mechanism (JSON, for browser clients)
                    forward_gossip(&peers, &from, &incoming.exclude, &payload, 3).await;
                    stats.record_message_routed();

                    // Also feed into PeerManager for proper gossip protocol processing
                    // (CBOR-based dedup, bloom filters, PoW validation, score tracking)
                    if let Ok(bytes) = hex::decode(&payload) {
                        let pm = peer_manager.clone();
                        tokio::spawn(async move {
                            match pm.handle_incoming(&bytes).await {
                                Ok(Some(_delivered)) => {
                                    tracing::debug!("Gossip message delivered to relay");
                                }
                                Ok(None) => {} // forwarded or dropped by gossip protocol
                                Err(e) => {
                                    tracing::debug!(
                                        error = %e,
                                        "PeerManager gossip processing error (expected for non-CBOR payloads)"
                                    );
                                }
                            }
                        });
                    }
                }
            }

            "rtc_offer" | "rtc_answer" | "rtc_ice" => {
                // WebRTC signaling — forward directly to target peer
                let peer_id_clone = my_peer_id.clone().unwrap_or_default();
                if let (Some(to), Some(payload)) = (&incoming.to, &incoming.payload) {
                    let outgoing = OutgoingMessage {
                        msg_type: incoming.msg_type.clone(),
                        from: Some(peer_id_clone),
                        payload: Some(payload.clone()),
                        ..Default::default()
                    };
                    let json = serde_json::to_string(&outgoing).unwrap_or_default();
                    let peers_lock = peers.lock().await;
                    if let Some(recipient_tx) = peers_lock.get(to) {
                        let _ = recipient_tx.send(Message::Text(json.into()));
                        stats.record_message_routed();
                    }
                }
            }

            _ => {
                let _ = tx.send(Message::Text(
                    serde_json::to_string(&OutgoingMessage {
                        msg_type: "error".into(),
                        message: Some(format!("unknown type: {}", incoming.msg_type)),
                        ..Default::default()
                    })
                    .unwrap()
                    .into(),
                ));
            }
        }
    }

    // Cleanup on disconnect
    if let Some(peer_id) = &my_peer_id {
        peers.lock().await.remove(peer_id);
        stats.record_disconnection();

        // Remove from mesh PeerManager
        if let Some(mesh_pid) = parse_peer_id(peer_id) {
            peer_manager.remove_peer(&mesh_pid).await;
            // Drop from presence so `/peers/presence` no longer claims this
            // peer is locally connected.
            presence_authority.lock().await.remove_local(&mesh_pid);
        }

        info!(
            "Peer disconnected: {}...",
            &peer_id[..16.min(peer_id.len())]
        );
    }

    send_task.abort();
}
