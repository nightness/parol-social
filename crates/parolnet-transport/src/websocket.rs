//! WebSocket-over-TLS transport.
//!
//! WSS traffic looks like normal HTTPS to DPI systems.

use crate::{Connection, TransportError};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

/// A WebSocket connection wrapping a tokio_tungstenite stream.
pub struct WebSocketConnection {
    stream: Arc<Mutex<WebSocketStream>>,
    peer_addr: Option<SocketAddr>,
}

type WebSocketStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

impl WebSocketConnection {
    /// Connect to a WebSocket server at the given URL.
    pub async fn connect(url: &str) -> Result<Self, TransportError> {
        let (ws_stream, _response) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        Ok(Self {
            stream: Arc::new(Mutex::new(ws_stream)),
            peer_addr: None,
        })
    }
}

#[async_trait]
impl Connection for WebSocketConnection {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        use futures_util::SinkExt;
        let mut stream = self.stream.lock().await;
        stream
            .send(Message::Binary(data.to_vec().into()))
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))
    }

    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        use futures_util::StreamExt;
        let mut stream = self.stream.lock().await;
        loop {
            match stream.next().await {
                Some(Ok(Message::Binary(data))) => return Ok(data.to_vec()),
                Some(Ok(Message::Close(_))) | None => {
                    return Err(TransportError::ConnectionClosed)
                }
                Some(Ok(_)) => continue, // skip ping/pong/text
                Some(Err(e)) => return Err(TransportError::ReceiveFailed(e.to_string())),
            }
        }
    }

    async fn close(&self) -> Result<(), TransportError> {
        use futures_util::SinkExt;
        let mut stream = self.stream.lock().await;
        stream
            .close(None)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }
}
