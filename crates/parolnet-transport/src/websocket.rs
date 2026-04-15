//! WebSocket-over-TLS transport.
//!
//! WSS traffic looks like normal HTTPS to DPI systems.

use crate::{Connection, TransportError};
use async_trait::async_trait;
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

/// Configuration for WebSocket transport.
#[derive(Clone, Debug, Default)]
pub struct WebSocketConfig {
    /// Whether to use TLS (wss://) instead of plain WebSocket (ws://).
    ///
    /// When true, connections use `wss://` URLs and the listener should be
    /// wrapped with TLS. This is critical for DPI evasion — plain WebSocket
    /// frames are trivially detectable by network observers.
    ///
    /// TODO: Wire up TLS for the listener side. Currently `tokio-tungstenite`'s
    /// `connect_async` supports `wss://` URLs for client connections (via the
    /// `MaybeTlsStream` type), but the server listener needs to wrap the TCP
    /// acceptor with `tokio-rustls` before upgrading to WebSocket. This requires:
    /// 1. Accept TLS on the TCP socket using `TlsAcceptor`
    /// 2. Pass the `TlsStream<TcpStream>` to `tokio_tungstenite::accept_async`
    /// 3. Update the `ServerWebSocketStream` type alias accordingly
    pub use_tls: bool,
}

/// A WebSocket connection wrapping a tokio_tungstenite stream.
///
/// Supports both client connections (via `connect`) and server-side
/// accepted connections (via `from_server_stream`).
pub struct WebSocketConnection {
    sink: Arc<Mutex<WsSink>>,
    stream: Arc<Mutex<WsRecv>>,
    peer_addr: Option<SocketAddr>,
}

type ClientWebSocketStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

type ServerWebSocketStream = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// Unified sink type supporting both client and server WebSocket streams.
enum WsSink {
    Client(SplitSink<ClientWebSocketStream, Message>),
    Server(SplitSink<ServerWebSocketStream, Message>),
}

/// Unified receive type supporting both client and server WebSocket streams.
enum WsRecv {
    Client(SplitStream<ClientWebSocketStream>),
    Server(SplitStream<ServerWebSocketStream>),
}

impl WebSocketConnection {
    /// Connect to a WebSocket server at the given URL.
    pub async fn connect(url: &str) -> Result<Self, TransportError> {
        let (ws_stream, _response) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let (sink, stream) = ws_stream.split();
        Ok(Self {
            sink: Arc::new(Mutex::new(WsSink::Client(sink))),
            stream: Arc::new(Mutex::new(WsRecv::Client(stream))),
            peer_addr: None,
        })
    }

    /// Wrap an already-upgraded server-side WebSocket stream.
    pub fn from_server_stream(ws_stream: ServerWebSocketStream, peer_addr: SocketAddr) -> Self {
        let (sink, stream) = ws_stream.split();
        Self {
            sink: Arc::new(Mutex::new(WsSink::Server(sink))),
            stream: Arc::new(Mutex::new(WsRecv::Server(stream))),
            peer_addr: Some(peer_addr),
        }
    }
}

#[async_trait]
impl Connection for WebSocketConnection {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        let msg = Message::Binary(data.to_vec().into());
        let mut sink = self.sink.lock().await;
        match &mut *sink {
            WsSink::Client(s) => s.send(msg).await,
            WsSink::Server(s) => s.send(msg).await,
        }
        .map_err(|e| TransportError::SendFailed(e.to_string()))
    }

    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        let mut stream = self.stream.lock().await;
        loop {
            let next = match &mut *stream {
                WsRecv::Client(s) => s.next().await,
                WsRecv::Server(s) => s.next().await,
            };
            match next {
                Some(Ok(Message::Binary(data))) => return Ok(data.to_vec()),
                Some(Ok(Message::Close(_))) | None => return Err(TransportError::ConnectionClosed),
                Some(Ok(_)) => continue, // skip ping/pong/text
                Some(Err(e)) => return Err(TransportError::ReceiveFailed(e.to_string())),
            }
        }
    }

    async fn close(&self) -> Result<(), TransportError> {
        let mut sink = self.sink.lock().await;
        match &mut *sink {
            WsSink::Client(s) => s.close().await,
            WsSink::Server(s) => s.close().await,
        }
        .map_err(|e| TransportError::SendFailed(e.to_string()))
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }
}
