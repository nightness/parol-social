use thiserror::Error;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("circuit construction failed: {0}")]
    CircuitBuildFailed(String),

    #[error("cell processing error: {0}")]
    CellError(String),

    #[error("invalid cell type: 0x{0:02x}")]
    InvalidCellType(u8),

    #[error("circuit not found: CID {0}")]
    CircuitNotFound(u32),

    #[error("circuit limit exceeded")]
    CircuitLimitExceeded,

    #[error("nonce counter overflow — circuit must be destroyed")]
    NonceOverflow,

    #[error("key exchange failed: {0}")]
    KeyExchangeFailed(String),

    #[error("AEAD verification failed")]
    AeadFailed,

    #[error("RELAY_EARLY limit exceeded")]
    RelayEarlyLimitExceeded,

    #[error("circuit timeout")]
    Timeout,

    #[error("transport error: {0}")]
    Transport(#[from] parolnet_transport::TransportError),

    #[error("federation sync error: {0}")]
    FederationSync(String),
}
