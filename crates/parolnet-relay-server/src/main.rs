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
use parolnet_transport::{Connection, TransportError};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tracing::info;

type PeerMap = Arc<Mutex<HashMap<String, mpsc::UnboundedSender<String>>>>;

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
    tx: mpsc::UnboundedSender<String>,
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
            .send(msg)
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
    sid: String,
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
    if batch.events.len() > 500 || batch.sid.is_empty() {
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
/// excluding the optionally specified peer.
/// Requires ADMIN_TOKEN authentication. Returns 404 if ADMIN_TOKEN is not set,
/// 403 if the token is missing or invalid.
async fn handle_bootstrap(
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
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
    let exclude = params.get("exclude").cloned().unwrap_or_default();
    let known: Vec<String> = peer_list
        .keys()
        .filter(|p| **p != exclude)
        .take(20)
        .cloned()
        .collect();
    Ok(Json(known))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let port: u16 = std::env::var("RELAY_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9000);

    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
    let store = Arc::new(Mutex::new(RelayMessageStore::new()));
    let stats = Arc::new(analytics::Stats::new());
    let client_stats = Arc::new(ClientStats::new());

    let conn_rate_limiter: ConnRateLimiter = Arc::new(RateLimiter::new(
        WS_CONN_RATE_LIMIT,
        WS_CONN_RATE_WINDOW_SECS,
    ));
    let msg_rate_limiter: MsgRateLimiter =
        Arc::new(RateLimiter::new(MSG_RATE_LIMIT, MSG_RATE_WINDOW_SECS));

    // Spawn periodic rate limiter cleanup (every 5 minutes)
    {
        let conn_rl = conn_rate_limiter.clone();
        let msg_rl = msg_rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                conn_rl.cleanup();
                msg_rl.cleanup();
            }
        });
    }

    // Initialize mesh PeerManager as a gossip supernode
    let our_peer_id = PeerId([0u8; 32]); // Relay's own peer ID (could generate a real one)
    let relay_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
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
                move |ws: WebSocketUpgrade,
                      connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>| async move {
                    // Per-IP connection rate limiting
                    let client_ip = connect_info.0.ip();
                    if conn_rl.is_limited(&client_ip) {
                        return StatusCode::TOO_MANY_REQUESTS.into_response();
                    }
                    ws.on_upgrade(move |socket| {
                        handle_socket(socket, peers, store, stats, peer_manager, msg_rl)
                    })
                    .into_response()
                }
            }),
        )
        .route("/health", get(|| async { "OK" }))
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
                move |headers: axum::http::HeaderMap, query: Query<HashMap<String, String>>| {
                    let peers = peers.clone();
                    async move { handle_bootstrap(headers, query, peers).await }
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
        .layer(tower_http::cors::CorsLayer::permissive());

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
    let eligible: Vec<(&String, &mpsc::UnboundedSender<String>)> = peers_lock
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
        let _ = tx.send(gossip_msg.clone());
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

async fn handle_socket(
    socket: WebSocket,
    peers: PeerMap,
    store: Arc<Mutex<RelayMessageStore>>,
    stats: Arc<analytics::Stats>,
    peer_manager: Arc<PeerManager>,
    msg_rate_limiter: MsgRateLimiter,
) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    let mut my_peer_id: Option<String> = None;

    // Spawn task to forward messages from channel to WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            // Sentinel value: send a WebSocket ping frame instead of text
            if msg == "__ping__" {
                if sender.send(Message::Ping(vec![].into())).await.is_err() {
                    break;
                }
            } else if sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    // Ping interval to keep the WebSocket connection alive
    let mut ping_interval = tokio::time::interval(Duration::from_secs(30));
    ping_interval.tick().await; // consume the immediate first tick

    // Read messages from WebSocket, multiplexed with ping keepalive
    loop {
        let text = tokio::select! {
            msg_opt = receiver.next() => {
                match msg_opt {
                    Some(Ok(Message::Text(t))) => t.to_string(),
                    Some(Ok(Message::Pong(_))) => continue,
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => break,
                }
            }
            _ = ping_interval.tick() => {
                // Send a ping through the channel to the send task
                if tx.send("__ping__".to_string()).is_err() {
                    break; // send task died, connection is dead
                }
                continue;
            }
        };

        let Ok(incoming) = serde_json::from_str::<IncomingMessage>(&text) else {
            let _ = tx.send(
                serde_json::to_string(&OutgoingMessage {
                    msg_type: "error".into(),
                    message: Some("invalid JSON".into()),
                    ..Default::default()
                })
                .unwrap(),
            );
            continue;
        };

        // Per-peer message rate limiting
        if let Some(ref pid) = my_peer_id
            && msg_rate_limiter.is_limited(pid)
        {
            let _ = tx.send(
                serde_json::to_string(&OutgoingMessage {
                    msg_type: "error".into(),
                    message: Some("rate limited".into()),
                    ..Default::default()
                })
                .unwrap(),
            );
            continue;
        }

        match incoming.msg_type.as_str() {
            "register" => {
                if let Some(peer_id) = incoming.peer_id {
                    // Register this peer in the relay's peer map
                    peers.lock().await.insert(peer_id.clone(), tx.clone());
                    my_peer_id = Some(peer_id.clone());

                    stats.record_connection();

                    // Register with PeerManager for gossip protocol routing
                    if let Some(mesh_pid) = parse_peer_id(&peer_id) {
                        let ws_conn = Arc::new(WsConnection { tx: tx.clone() });
                        if let Err(e) = peer_manager.add_peer(mesh_pid, ws_conn).await {
                            tracing::warn!(
                                peer = %peer_id,
                                error = %e,
                                "failed to add peer to mesh PeerManager"
                            );
                        }
                    }

                    let online = peers.lock().await.len();
                    let _ = tx.send(
                        serde_json::to_string(&OutgoingMessage {
                            msg_type: "registered".into(),
                            peer_id: Some(peer_id.clone()),
                            online_peers: Some(online),
                            ..Default::default()
                        })
                        .unwrap(),
                    );

                    info!(
                        "Peer registered: {}...  ({} online)",
                        &peer_id[..16.min(peer_id.len())],
                        online
                    );

                    // Deliver any stored messages
                    if let Some(mesh_pid) = parse_peer_id(&peer_id) {
                        let pending = store.lock().await.retrieve(&mesh_pid);
                        for msg in pending {
                            let _ = tx.send(msg);
                        }
                    }
                }
            }

            "message" => {
                let from = my_peer_id.clone().unwrap_or_default();
                if let (Some(to), Some(payload)) = (incoming.to, incoming.payload) {
                    let outgoing = serde_json::to_string(&OutgoingMessage {
                        msg_type: "message".into(),
                        from: Some(from.clone()),
                        payload: Some(payload),
                        ..Default::default()
                    })
                    .unwrap();

                    let peers_lock = peers.lock().await;
                    if let Some(recipient_tx) = peers_lock.get(&to) {
                        // Recipient online -- forward directly
                        let _ = recipient_tx.send(outgoing);
                        stats.record_message_routed();
                    } else {
                        // Recipient offline -- buffer for later delivery
                        drop(peers_lock);
                        if let Some(dest_pid) = parse_peer_id(&to) {
                            store.lock().await.store(dest_pid, outgoing);
                            stats.record_message_queued();
                        }
                        let _ = tx.send(
                            serde_json::to_string(&OutgoingMessage {
                                msg_type: "queued".into(),
                                message: Some("peer offline, message stored".into()),
                                ..Default::default()
                            })
                            .unwrap(),
                        );
                    }
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
                        let _ = recipient_tx.send(json);
                        stats.record_message_routed();
                    }
                }
            }

            _ => {
                let _ = tx.send(
                    serde_json::to_string(&OutgoingMessage {
                        msg_type: "error".into(),
                        message: Some(format!("unknown type: {}", incoming.msg_type)),
                        ..Default::default()
                    })
                    .unwrap(),
                );
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
        }

        info!(
            "Peer disconnected: {}...",
            &peer_id[..16.min(peer_id.len())]
        );
    }

    send_task.abort();
}
