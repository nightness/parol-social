//! WebSocket listener — accepts incoming WebSocket connections.
//!
//! Binds a TCP socket and upgrades accepted connections to WebSocket,
//! producing `WebSocketConnection` instances usable with the `Listener` trait.

use crate::websocket::WebSocketConnection;
use crate::{Listener, TransportError};
use async_trait::async_trait;
use std::net::SocketAddr;
use tracing::debug;

/// Listens for incoming WebSocket connections on a TCP socket.
pub struct WebSocketListener {
    tcp_listener: tokio::net::TcpListener,
    local_addr: SocketAddr,
}

impl WebSocketListener {
    /// Bind a new WebSocket listener to the given address.
    pub async fn bind(addr: SocketAddr) -> Result<Self, TransportError> {
        let tcp_listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| TransportError::ConnectionFailed(format!("bind failed: {e}")))?;
        let local_addr = tcp_listener
            .local_addr()
            .map_err(|e| TransportError::ConnectionFailed(format!("local_addr failed: {e}")))?;
        debug!("WebSocket listener bound to {local_addr}");
        Ok(Self {
            tcp_listener,
            local_addr,
        })
    }
}

#[async_trait]
impl Listener for WebSocketListener {
    type Conn = WebSocketConnection;

    async fn accept(&self) -> Result<Self::Conn, TransportError> {
        let (tcp_stream, peer_addr) = self
            .tcp_listener
            .accept()
            .await
            .map_err(|e| TransportError::ConnectionFailed(format!("TCP accept failed: {e}")))?;
        debug!("Accepted TCP connection from {peer_addr}, upgrading to WebSocket");

        let ws_stream = tokio_tungstenite::accept_async(tcp_stream)
            .await
            .map_err(|e| {
                TransportError::ConnectionFailed(format!("WebSocket upgrade failed: {e}"))
            })?;

        Ok(WebSocketConnection::from_server_stream(
            ws_stream, peer_addr,
        ))
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Connection;

    #[tokio::test]
    async fn listener_accept_send_recv() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = WebSocketListener::bind(addr).await.unwrap();
        let listen_addr = listener.local_addr();

        // Spawn the listener side
        let server = tokio::spawn(async move {
            let conn = listener.accept().await.unwrap();
            // Receive a message from the client
            let data = conn.recv().await.unwrap();
            assert_eq!(data, b"hello from client");
            // Send a response
            conn.send(b"hello from server").await.unwrap();
            conn.close().await.unwrap();
        });

        // Client side: connect via the existing WebSocketConnection::connect
        let url = format!("ws://{listen_addr}");
        let client = WebSocketConnection::connect(&url).await.unwrap();
        client.send(b"hello from client").await.unwrap();
        let response = client.recv().await.unwrap();
        assert_eq!(response, b"hello from server");

        server.await.unwrap();
    }
}
