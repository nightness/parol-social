use axum::{
    Json, Router,
    extract::{
        Query,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tracing::info;

type PeerMap = Arc<Mutex<HashMap<String, mpsc::UnboundedSender<String>>>>;
type MessageStore = Arc<Mutex<HashMap<String, Vec<String>>>>;
// TODO: Replace MessageStore with parolnet_mesh::store_forward::InMemoryStore once
// the relay server's message handling is refactored to use protocol Envelope types
// instead of raw JSON strings. The InMemoryStore operates on Envelope + PeerId,
// which requires deeper integration than a drop-in replacement.

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

/// GET /peers — returns JSON list of currently connected peer IDs.
async fn handle_peers(peers: PeerMap) -> Json<Vec<String>> {
    let peer_list = peers.lock().await;
    let peer_ids: Vec<String> = peer_list.keys().cloned().collect();
    Json(peer_ids)
}

/// GET /bootstrap?exclude=<peer_id> — returns up to 20 known peer IDs,
/// excluding the optionally specified peer.
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
    tracing_subscriber::fmt::init();

    let port: u16 = std::env::var("RELAY_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9000);

    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
    let store: MessageStore = Arc::new(Mutex::new(HashMap::new()));
    let stats = Arc::new(analytics::Stats::new());

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
                move |ws: WebSocketUpgrade| async move {
                    ws.on_upgrade(move |socket| handle_socket(socket, peers, store, stats))
                }
            }),
        )
        .route("/health", get(|| async { "OK" }))
        .route(
            "/peers",
            get({
                let peers = peers.clone();
                move || {
                    let peers = peers.clone();
                    async move { handle_peers(peers).await }
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
        .layer(tower_http::cors::CorsLayer::permissive());

    // Add /stats endpoint only when feature is enabled AND env var is set
    #[cfg(feature = "analytics")]
    {
        if analytics_enabled {
            let stats_clone = stats.clone();
            let peers_clone = peers.clone();
            app = app.route(
                "/stats",
                get(move || {
                    let s = stats_clone.clone();
                    let p = peers_clone.clone();
                    async move {
                        let online = p.lock().await.len();
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            s.to_json(online),
                        )
                    }
                }),
            );
        }
    }

    let addr = format!("0.0.0.0:{port}");
    info!("ParolNet relay listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
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

async fn handle_socket(
    socket: WebSocket,
    peers: PeerMap,
    store: MessageStore,
    stats: Arc<analytics::Stats>,
) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    let mut my_peer_id: Option<String> = None;

    // Spawn task to forward messages from channel to WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    // Read messages from WebSocket
    while let Some(Ok(msg)) = receiver.next().await {
        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Close(_) => break,
            _ => continue,
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

        match incoming.msg_type.as_str() {
            "register" => {
                if let Some(peer_id) = incoming.peer_id {
                    // Register this peer
                    peers.lock().await.insert(peer_id.clone(), tx.clone());
                    my_peer_id = Some(peer_id.clone());

                    stats.record_connection();

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
                    let pending = store.lock().await.remove(&peer_id).unwrap_or_default();
                    for msg in pending {
                        let _ = tx.send(msg);
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
                        // Recipient offline -- store for later (max 1000 per peer)
                        drop(peers_lock);
                        let mut store_lock = store.lock().await;
                        let pending = store_lock.entry(to).or_default();
                        if pending.len() < 1000 {
                            pending.push(outgoing);
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
                    forward_gossip(&peers, &from, &incoming.exclude, &payload, 3).await;
                    stats.record_message_routed();
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
        info!(
            "Peer disconnected: {}...",
            &peer_id[..16.min(peer_id.len())]
        );
    }

    send_task.abort();
}
