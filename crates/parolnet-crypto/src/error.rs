use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AEAD encryption failed")]
    EncryptionFailed,

    #[error("AEAD decryption failed: invalid ciphertext or authentication tag")]
    DecryptionFailed,

    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },

    #[error("key derivation failed")]
    KdfFailed,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid pre-key bundle: {reason}")]
    InvalidPreKeyBundle { reason: String },

    #[error("X3DH key agreement failed: {reason}")]
    KeyAgreementFailed { reason: String },

    #[error("Double Ratchet error: {reason}")]
    RatchetError { reason: String },

    #[error("message from unknown ratchet chain")]
    UnknownChain,

    #[error("message key exhausted or already used")]
    MessageKeyExhausted,

    #[error("sender key error: {reason}")]
    SenderKeyError { reason: String },

    #[error("not implemented: {feature}")]
    NotImplemented { feature: String },
}
