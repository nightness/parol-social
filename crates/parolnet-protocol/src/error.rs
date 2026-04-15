use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid envelope length: {0} is not a valid bucket size")]
    InvalidEnvelopeLength(usize),

    #[error("CBOR encoding error: {0}")]
    CborEncode(String),

    #[error("CBOR decoding error: {0}")]
    CborDecode(String),

    #[error("invalid message type: 0x{0:02x}")]
    InvalidMessageType(u8),

    #[error("padding error: {0}")]
    PaddingError(String),

    #[error("message too large: {size} bytes exceeds maximum bucket size {max}")]
    MessageTooLarge { size: usize, max: usize },

    #[error("invalid protocol version: expected {expected}, got {got}")]
    InvalidVersion { expected: u8, got: u8 },

    #[error("duplicate map key in CBOR payload")]
    DuplicateMapKey,

    #[error("replay detected: message ID already seen")]
    ReplayDetected,

    #[error("timestamp out of range")]
    TimestampOutOfRange,

    #[error("invalid state transition: {0}")]
    InvalidTransition(String),

    #[error("invalid bridge address: {0}")]
    InvalidBridgeAddress(String),

    #[error("crypto error: {0}")]
    Crypto(#[from] parolnet_crypto::CryptoError),
}
