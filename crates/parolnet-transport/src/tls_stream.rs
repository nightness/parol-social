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

/// Default SNI hostname used when none is configured.
pub const DEFAULT_SNI: &str = "cdn.jsdelivr.net";

/// TLS stream transport using rustls directly over TCP.
pub struct TlsTransport {
    client_config: Arc<rustls::ClientConfig>,
    server_config: Option<Arc<rustls::ServerConfig>>,
    /// SNI hostname sent in the TLS ClientHello. Should look like a plausible
    /// CDN or popular website to avoid DPI fingerprinting. Each deployment
    /// should configure a unique, plausible SNI rather than sharing a default.
    sni: String,
}

impl TlsTransport {
    /// Create a client-only TLS transport with the given fingerprint profile.
    pub fn client(profile: &FingerprintProfile) -> Result<Self, TransportError> {
        Self::client_with_sni(profile, DEFAULT_SNI.to_string())
    }

    /// Create a client-only TLS transport with a custom SNI hostname.
    pub fn client_with_sni(
        profile: &FingerprintProfile,
        sni: String,
    ) -> Result<Self, TransportError> {
        let config = profile
            .build_client_config()
            .map_err(|e| TransportError::TlsHandshakeFailed(e.to_string()))?;
        Ok(Self {
            client_config: Arc::new(config),
            server_config: None,
            sni,
        })
    }

    /// Create a TLS transport with both client and server capabilities.
    pub fn with_server_config(
        profile: &FingerprintProfile,
        server_config: rustls::ServerConfig,
    ) -> Result<Self, TransportError> {
        Self::with_server_config_and_sni(profile, server_config, DEFAULT_SNI.to_string())
    }

    /// Create a TLS transport with both client and server capabilities and a custom SNI.
    pub fn with_server_config_and_sni(
        profile: &FingerprintProfile,
        server_config: rustls::ServerConfig,
        sni: String,
    ) -> Result<Self, TransportError> {
        let client_config = profile
            .build_client_config()
            .map_err(|e| TransportError::TlsHandshakeFailed(e.to_string()))?;
        Ok(Self {
            client_config: Arc::new(client_config),
            server_config: Some(Arc::new(server_config)),
            sni,
        })
    }

    /// Create a TLS transport with explicit client and server configs.
    ///
    /// Useful for testing with self-signed certificates where the default
    /// client config (which trusts only webpki roots) would reject the cert.
    pub fn with_configs(
        client_config: rustls::ClientConfig,
        server_config: rustls::ServerConfig,
    ) -> Self {
        Self::with_configs_and_sni(client_config, server_config, DEFAULT_SNI.to_string())
    }

    /// Create a TLS transport with explicit client and server configs and a custom SNI.
    pub fn with_configs_and_sni(
        client_config: rustls::ClientConfig,
        server_config: rustls::ServerConfig,
        sni: String,
    ) -> Self {
        Self {
            client_config: Arc::new(client_config),
            server_config: Some(Arc::new(server_config)),
            sni,
        }
    }

    /// Get the configured SNI hostname.
    pub fn sni(&self) -> &str {
        &self.sni
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
        /// Maximum allowed frame size (64 KiB) to prevent remote DoS via
        /// unbounded allocation from a malicious length prefix.
        const MAX_FRAME_SIZE: u32 = 65536;

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
                let len = u32::from_be_bytes(len_buf);
                if len > MAX_FRAME_SIZE {
                    return Err(TransportError::ReceiveFailed(
                        "frame exceeds maximum size".into(),
                    ));
                }
                let mut buf = vec![0u8; len as usize];
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
                let len = u32::from_be_bytes(len_buf);
                if len > MAX_FRAME_SIZE {
                    return Err(TransportError::ReceiveFailed(
                        "frame exceeds maximum size".into(),
                    ));
                }
                let mut buf = vec![0u8; len as usize];
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

        // Use the configured SNI hostname (should look like a plausible CDN)
        let server_name = rustls::pki_types::ServerName::try_from(self.sni.as_str())
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
