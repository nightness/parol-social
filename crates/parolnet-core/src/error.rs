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

    #[error("group error: {0}")]
    GroupError(String),

    #[error("not a group admin")]
    NotGroupAdmin,

    #[error("group not found")]
    GroupNotFound,

    #[error("group is full")]
    GroupFull,

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

impl CoreError {
    /// Return an opaque error message safe for external consumers.
    ///
    /// Internal details (paths, keys, peer IDs) are never leaked.
    pub fn to_external(&self) -> &str {
        match self {
            CoreError::BootstrapFailed(_) => "bootstrap failed",
            CoreError::SessionError(_) => "session error",
            CoreError::NoSession => "no session",
            CoreError::WipeFailed(_) => "wipe failed",
            CoreError::Crypto(_) => "crypto error",
            CoreError::Protocol(_) => "protocol error",
            CoreError::GroupError(_) => "group error",
            CoreError::NotGroupAdmin => "not group admin",
            CoreError::GroupNotFound => "group not found",
            CoreError::GroupFull => "group full",
            #[cfg(feature = "native")]
            CoreError::Transport(_) => "transport error",
            #[cfg(feature = "native")]
            CoreError::Relay(_) => "relay error",
            #[cfg(feature = "native")]
            CoreError::Mesh(_) => "mesh error",
        }
    }
}
