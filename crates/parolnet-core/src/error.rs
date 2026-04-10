use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("bootstrap failed: {0}")]
    BootstrapFailed(String),

    #[error("session error: {0}")]
    SessionError(String),

    #[error("no active session with peer")]
    NoSession,

    #[error("panic wipe failed: {0}")]
    WipeFailed(String),

    #[error("crypto error: {0}")]
    Crypto(#[from] parolnet_crypto::CryptoError),

    #[error("protocol error: {0}")]
    Protocol(#[from] parolnet_protocol::ProtocolError),

    #[cfg(feature = "native")]
    #[error("transport error: {0}")]
    Transport(#[from] parolnet_transport::TransportError),

    #[cfg(feature = "native")]
    #[error("relay error: {0}")]
    Relay(#[from] parolnet_relay::RelayError),

    #[cfg(feature = "native")]
    #[error("mesh error: {0}")]
    Mesh(#[from] parolnet_mesh::MeshError),
}
