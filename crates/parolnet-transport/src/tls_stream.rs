//! Custom TLS stream transport.
//!
//! Direct rustls + tokio TCP streams. No QUIC library — we control
//! every byte on the wire for maximum fingerprint control.
//! Traffic can be shaped to look like standard HTTPS to any CDN.

use crate::tls_camouflage::FingerprintProfile;
use crate::{Connection, Listener, Transport, TransportError};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};

/// TLS stream transport using rustls directly over TCP.
pub struct TlsTransport {
    client_config: Arc<rustls::ClientConfig>,
    server_config: Option<Arc<rustls::ServerConfig>>,
}

impl TlsTransport {
    /// Create a client-only TLS transport with the given fingerprint profile.
    pub fn client(profile: &FingerprintProfile) -> Result<Self, TransportError> {
        let config = profile
            .build_client_config()
            .map_err(|e| TransportError::TlsHandshakeFailed(e.to_string()))?;
        Ok(Self {
            client_config: Arc::new(config),
            server_config: None,
        })
    }

    /// Create a TLS transport with both client and server capabilities.
    pub fn with_server_config(
        profile: &FingerprintProfile,
        server_config: rustls::ServerConfig,
    ) -> Result<Self, TransportError> {
        let client_config = profile
            .build_client_config()
            .map_err(|e| TransportError::TlsHandshakeFailed(e.to_string()))?;
        Ok(Self {
            client_config: Arc::new(client_config),
            server_config: Some(Arc::new(server_config)),
        })
    }
}

/// A TLS connection wrapping a tokio TCP stream.
pub struct TlsConnection {
    stream: Mutex<TlsStream>,
    peer_addr: Option<SocketAddr>,
}

enum TlsStream {
    Client(client::TlsStream<TcpStream>),
    Server(server::TlsStream<TcpStream>),
}

#[async_trait]
impl Connection for TlsConnection {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        let mut stream = self.stream.lock().await;
        // Length-prefixed framing: 4-byte BE length + data
        let len = (data.len() as u32).to_be_bytes();
        match &mut *stream {
            TlsStream::Client(s) => {
                s.write_all(&len).await?;
                s.write_all(data).await?;
                s.flush().await?;
            }
            TlsStream::Server(s) => {
                s.write_all(&len).await?;
                s.write_all(data).await?;
                s.flush().await?;
            }
        }
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        let mut stream = self.stream.lock().await;
        let mut len_buf = [0u8; 4];
        match &mut *stream {
            TlsStream::Client(s) => {
                s.read_exact(&mut len_buf).await.map_err(|e| {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        TransportError::ConnectionClosed
                    } else {
                        TransportError::from(e)
                    }
                })?;
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                s.read_exact(&mut buf).await?;
                Ok(buf)
            }
            TlsStream::Server(s) => {
                s.read_exact(&mut len_buf).await.map_err(|e| {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        TransportError::ConnectionClosed
                    } else {
                        TransportError::from(e)
                    }
                })?;
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                s.read_exact(&mut buf).await?;
                Ok(buf)
            }
        }
    }

    async fn close(&self) -> Result<(), TransportError> {
        let mut stream = self.stream.lock().await;
        match &mut *stream {
            TlsStream::Client(s) => s.shutdown().await?,
            TlsStream::Server(s) => s.shutdown().await?,
        }
        Ok(())
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }
}

/// TLS listener accepting incoming connections.
pub struct TlsListener {
    tcp_listener: TcpListener,
    acceptor: TlsAcceptor,
    local_addr: SocketAddr,
}

#[async_trait]
impl Listener for TlsListener {
    type Conn = TlsConnection;

    async fn accept(&self) -> Result<Self::Conn, TransportError> {
        let (tcp_stream, peer_addr) = self.tcp_listener.accept().await?;
        let tls_stream = self
            .acceptor
            .accept(tcp_stream)
            .await
            .map_err(|e| TransportError::TlsHandshakeFailed(e.to_string()))?;

        Ok(TlsConnection {
            stream: Mutex::new(TlsStream::Server(tls_stream)),
            peer_addr: Some(peer_addr),
        })
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

#[async_trait]
impl Transport for TlsTransport {
    type Conn = TlsConnection;
    type Listen = TlsListener;

    fn name(&self) -> &'static str {
        "tls"
    }

    async fn connect(&self, addr: SocketAddr) -> Result<Self::Conn, TransportError> {
        let tcp_stream = TcpStream::connect(addr).await?;
        let connector = TlsConnector::from(self.client_config.clone());

        // Use a plausible SNI hostname
        let server_name = rustls::pki_types::ServerName::try_from("www.example.com")
            .map_err(|e| TransportError::TlsHandshakeFailed(e.to_string()))?
            .to_owned();

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| TransportError::TlsHandshakeFailed(e.to_string()))?;

        Ok(TlsConnection {
            stream: Mutex::new(TlsStream::Client(tls_stream)),
            peer_addr: Some(addr),
        })
    }

    async fn listen(&self, addr: SocketAddr) -> Result<Self::Listen, TransportError> {
        let server_config = self
            .server_config
            .as_ref()
            .ok_or_else(|| TransportError::NotAvailable("no server config".into()))?;

        let tcp_listener = TcpListener::bind(addr).await?;
        let local_addr = tcp_listener.local_addr()?;
        let acceptor = TlsAcceptor::from(server_config.clone());

        Ok(TlsListener {
            tcp_listener,
            acceptor,
            local_addr,
        })
    }
}
