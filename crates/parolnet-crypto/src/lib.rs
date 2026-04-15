//! # parolnet-crypto
//!
//! Cryptographic primitives for the ParolNet protocol suite.
//!
//! This crate provides:
//! - AEAD encryption (ChaCha20-Poly1305 and AES-256-GCM)
//! - X3DH key agreement for decentralized session establishment
//! - Double Ratchet for forward-secret message encryption
//! - Identity key management (Ed25519 + X25519)
//! - Key derivation (HKDF-SHA-256)
//! - Deniable authentication primitives
//! - Secure memory wiping utilities
//!
//! All types holding secret key material implement `Zeroize` and `ZeroizeOnDrop`.
//! This crate has no async runtime dependency and compiles to WASM.

pub mod aead;
pub mod deniable;
pub mod double_ratchet;
pub mod error;
pub mod identity;
pub mod kdf;
pub mod sender_key;
pub mod wipe;
pub mod x3dh;

pub use error::CryptoError;

use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Core AEAD abstraction ──────────────────────────────────────────

/// Authenticated encryption with associated data.
///
/// Allows swapping ChaCha20-Poly1305 (internal, constant-time without AES-NI)
/// vs AES-256-GCM (transport disguise, matches TLS cipher) without changing
/// protocol code.
pub trait Aead: Send + Sync {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn key_len(&self) -> usize;
    fn nonce_len(&self) -> usize;
}

// ── Key Derivation Chain ───────────────────────────────────────────

/// A key derivation function chain for the Double Ratchet.
///
/// Each ratchet step produces a new chain key and a message key.
/// Implements `Zeroize` to ensure chain keys are wiped from memory.
pub trait KdfChain: Zeroize + Send {
    fn ratchet(&mut self) -> (ChainKey, MessageKey);
}

// ── Double Ratchet Session ─────────────────────────────────────────

/// Manages a Double Ratchet session between two peers.
///
/// Provides forward secrecy and future secrecy: compromise of current
/// keys does not reveal past or future message content.
pub trait RatchetSession: Send {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<(RatchetHeader, Vec<u8>), CryptoError>;

    fn decrypt(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

// ── X3DH Key Agreement ────────────────────────────────────────────

/// X3DH handshake: produces a shared secret from identity + ephemeral keys.
///
/// Adapted for decentralized use — no central key server required.
/// Pre-key bundles are distributed via relay network or direct exchange.
pub trait KeyAgreement {
    fn initiate(
        &self,
        recipient_bundle: &PreKeyBundle,
    ) -> Result<(SharedSecret, X3dhHeader), CryptoError>;

    fn respond(
        &self,
        header: &X3dhHeader,
        spk_secret: &x25519_dalek::StaticSecret,
        opk_secret: Option<&x25519_dalek::StaticSecret>,
    ) -> Result<SharedSecret, CryptoError>;
}

// ── Key material types ─────────────────────────────────────────────
// All types holding secret material derive Zeroize and ZeroizeOnDrop.

/// A 32-byte chain key used in the Double Ratchet KDF chain.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChainKey(pub [u8; 32]);

/// A 32-byte message key derived from a chain key, used for one message.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MessageKey(pub [u8; 32]);

/// A 32-byte shared secret produced by X3DH key agreement.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; 32]);

/// Header sent with each Double Ratchet message.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RatchetHeader {
    /// The sender's current ratchet public key (X25519).
    pub ratchet_key: [u8; 32],
    /// Number of messages in the previous sending chain.
    pub previous_chain_length: u32,
    /// Message number in the current sending chain.
    pub message_number: u32,
}

/// Header sent during X3DH initiation (Alice -> Bob).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct X3dhHeader {
    /// Alice's Ed25519 identity public key.
    pub identity_key: [u8; 32],
    /// Alice's ephemeral X25519 public key.
    pub ephemeral_key: [u8; 32],
    /// ID of Bob's signed pre-key that Alice used.
    pub signed_prekey_id: u32,
    /// ID of Bob's one-time pre-key that Alice used (if any).
    pub one_time_prekey_id: Option<u32>,
}

/// A pre-key bundle published by a peer for X3DH handshakes.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PreKeyBundle {
    /// Ed25519 identity public key.
    pub identity_key: [u8; 32],
    /// X25519 signed pre-key public key.
    pub signed_prekey: [u8; 32],
    /// Signed pre-key identifier.
    pub signed_prekey_id: u32,
    /// Ed25519 signature over (signed_prekey || signed_prekey_id). 64 bytes.
    pub signed_prekey_sig: Vec<u8>,
    /// One-time pre-keys (may be empty if exhausted).
    pub one_time_prekeys: Vec<OneTimePreKey>,
}

/// A single one-time pre-key in a pre-key bundle.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OneTimePreKey {
    pub id: u32,
    pub key: [u8; 32],
}

/// An Ed25519 identity keypair with its derived X25519 key.
///
/// The identity key is long-lived and its SHA-256 hash forms the PeerId.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityKeyPair {
    /// Ed25519 signing key (secret).
    #[zeroize(skip)] // ed25519_dalek handles its own zeroization
    pub signing_key: ed25519_dalek::SigningKey,
}

impl IdentityKeyPair {
    /// Generate a new random identity keypair.
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Get the Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }

    /// Restore an identity keypair from a saved 32-byte secret key.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(secret);
        Self { signing_key }
    }

    /// Export the secret key bytes for persistence.
    /// SECURITY: These bytes must be stored encrypted.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Compute the PeerId: SHA-256 of the Ed25519 public key.
    pub fn peer_id(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.public_key_bytes());
        hasher.finalize().into()
    }
}
