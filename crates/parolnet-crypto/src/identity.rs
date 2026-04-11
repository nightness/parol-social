//! Identity key management.
//!
//! Ed25519 identity keypairs and their X25519 counterparts for DH operations.
//! The PeerId is derived as SHA-256(Ed25519_public_key).

use crate::CryptoError;
use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A signed pre-key (medium-term X25519 keypair, signed by the identity key).
///
/// Rotated every 7-30 days. The previous SPK should be retained for one
/// additional rotation period to handle in-flight handshakes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKey {
    pub id: u32,
    #[zeroize(skip)]
    pub private_key: x25519_dalek::StaticSecret,
    #[zeroize(skip)]
    pub public_key: x25519_dalek::PublicKey,
    pub signature: [u8; 64],
}

impl SignedPreKey {
    /// Generate a new signed pre-key and sign it with the identity key.
    pub fn generate(id: u32, identity_key: &crate::IdentityKeyPair) -> Result<Self, CryptoError> {
        let private_key = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let public_key = x25519_dalek::PublicKey::from(&private_key);

        // Sign (spk_public_bytes || id) with the Ed25519 identity key
        let mut sign_data = Vec::with_capacity(36);
        sign_data.extend_from_slice(public_key.as_bytes());
        sign_data.extend_from_slice(&id.to_be_bytes());

        let sig = identity_key.signing_key.sign(&sign_data);

        Ok(Self {
            id,
            private_key,
            public_key,
            signature: sig.to_bytes(),
        })
    }

    /// Verify the signature against an identity public key.
    pub fn verify(&self, identity_pubkey: &ed25519_dalek::VerifyingKey) -> Result<(), CryptoError> {
        use ed25519_dalek::Verifier;
        let mut sign_data = Vec::with_capacity(36);
        sign_data.extend_from_slice(self.public_key.as_bytes());
        sign_data.extend_from_slice(&self.id.to_be_bytes());

        let sig = ed25519_dalek::Signature::from_bytes(&self.signature);
        identity_pubkey
            .verify(&sign_data, &sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

/// A one-time pre-key (ephemeral X25519 keypair, used exactly once).
///
/// Peers should maintain a pool of 20-100 OPKs and replenish proactively.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OneTimePreKeyPair {
    pub id: u32,
    #[zeroize(skip)]
    pub private_key: x25519_dalek::StaticSecret,
    #[zeroize(skip)]
    pub public_key: x25519_dalek::PublicKey,
}

impl OneTimePreKeyPair {
    /// Generate a new one-time pre-key.
    pub fn generate(id: u32) -> Self {
        let private_key = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let public_key = x25519_dalek::PublicKey::from(&private_key);
        Self {
            id,
            private_key,
            public_key,
        }
    }
}
