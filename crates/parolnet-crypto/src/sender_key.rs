//! Sender Key protocol for group messaging encryption.
//!
//! Each group member generates a sender key chain and distributes it to other
//! members via pairwise Double Ratchet sessions. This achieves O(1) encrypt
//! per send — the sender encrypts once, and all N-1 members can decrypt.
//!
//! Follows the Signal Sender Keys design:
//! - Each member maintains a symmetric chain key per sender
//! - Messages are signed with Ed25519 for authenticity
//! - Encrypted with ChaCha20-Poly1305 using keys derived via HKDF-SHA-256

use crate::aead::ChaCha20Poly1305Cipher;
use crate::kdf::hkdf_sha256;
use crate::{Aead, CryptoError};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum number of skipped message keys to store.
const MAX_SKIP: u32 = 1000;

/// State for one sender in a group's sender key chain.
///
/// The sender holds `signing_key = Some(...)` and can encrypt.
/// Receivers hold `signing_key = None` and can only decrypt/verify.
/// All secret key material is zeroized on drop.
#[derive(Zeroize)]
pub struct SenderKeyState {
    /// Current symmetric chain key.
    chain_key: [u8; 32],
    /// Sender's signing key (Some for our own state, None for received states).
    #[zeroize(skip)]
    signing_key: Option<SigningKey>,
    /// Sender's public key bytes — always set, used for verification and nonce derivation.
    signing_public_key: [u8; 32],
    /// Monotonically increasing message counter.
    chain_index: u32,
    /// Skipped message keys for out-of-order delivery.
    #[zeroize(skip)]
    skipped_keys: HashMap<u32, [u8; 32]>,
}

/// Wire format for a sender-key encrypted message.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SenderKeyMessage {
    /// Chain index at which this message was encrypted.
    pub chain_index: u32,
    /// The encrypted message payload.
    pub ciphertext: Vec<u8>,
    /// Ed25519 signature over (chain_index || ciphertext). 64 bytes.
    pub signature: Vec<u8>,
}

/// Distribution message sent via pairwise Double Ratchet to share sender keys.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SenderKeyDistribution {
    /// PeerId of the sender.
    pub sender_peer_id: [u8; 32],
    /// Current chain key.
    pub chain_key: [u8; 32],
    /// Current chain index.
    pub chain_index: u32,
    /// Sender's Ed25519 public key.
    pub signing_public_key: [u8; 32],
}

impl Default for SenderKeyState {
    fn default() -> Self {
        Self::new()
    }
}

impl SenderKeyState {
    /// Generate a fresh sender key state with a new signing key and random chain key.
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let signing_public_key = signing_key.verifying_key().to_bytes();

        let mut chain_key = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut chain_key);

        Self {
            chain_key,
            signing_key: Some(signing_key),
            signing_public_key,
            chain_index: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Create a receiver-only state from a distribution message.
    ///
    /// The resulting state can decrypt and verify messages but cannot encrypt.
    pub fn from_distribution(dist: &SenderKeyDistribution) -> Result<Self, CryptoError> {
        // Validate the public key is a valid Ed25519 point
        VerifyingKey::from_bytes(&dist.signing_public_key).map_err(|_| {
            CryptoError::SenderKeyError {
                reason: "invalid signing public key in distribution".into(),
            }
        })?;

        Ok(Self {
            chain_key: dist.chain_key,
            signing_key: None,
            signing_public_key: dist.signing_public_key,
            chain_index: dist.chain_index,
            skipped_keys: HashMap::new(),
        })
    }

    /// Export current state as a distribution message for sharing with group members.
    pub fn create_distribution(&self, sender_peer_id: [u8; 32]) -> SenderKeyDistribution {
        SenderKeyDistribution {
            sender_peer_id,
            chain_key: self.chain_key,
            chain_index: self.chain_index,
            signing_public_key: self.signing_public_key,
        }
    }

    /// Encrypt a message using the sender key chain.
    ///
    /// Only the sender (who holds the signing key) can encrypt.
    /// Returns a `SenderKeyMessage` containing the ciphertext and signature.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<SenderKeyMessage, CryptoError> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or(CryptoError::SenderKeyError {
                reason: "receiver-only state cannot encrypt".into(),
            })?;

        // Derive message key from chain_key
        let mk_bytes = hkdf_sha256(&self.chain_key, &[0x01], b"ParolNet_sender_key_v1", 32)?;
        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&mk_bytes);

        // Derive next chain key
        let ck_bytes = hkdf_sha256(&self.chain_key, &[0x02], b"ParolNet_sender_chain_v1", 32)?;
        self.chain_key.copy_from_slice(&ck_bytes);

        // Build nonce: SHA-256(signing_public_key)[0..8] || chain_index.to_be_bytes()
        let nonce = Self::build_nonce(&self.signing_public_key, self.chain_index);

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305Cipher::new(&message_key)?;
        let ciphertext = cipher.encrypt(&nonce, plaintext, &[])?;

        // Zeroize message key after use
        message_key.zeroize();

        // Sign (chain_index || ciphertext)
        let mut signed_data = Vec::with_capacity(4 + ciphertext.len());
        signed_data.extend_from_slice(&self.chain_index.to_be_bytes());
        signed_data.extend_from_slice(&ciphertext);
        let signature = signing_key.sign(&signed_data);

        let old_index = self.chain_index;
        self.chain_index += 1;

        Ok(SenderKeyMessage {
            chain_index: old_index,
            ciphertext,
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Decrypt a sender key message.
    ///
    /// Handles out-of-order delivery by storing skipped message keys.
    pub fn decrypt(&mut self, msg: &SenderKeyMessage) -> Result<Vec<u8>, CryptoError> {
        // Verify Ed25519 signature
        let verifying_key = VerifyingKey::from_bytes(&self.signing_public_key).map_err(|_| {
            CryptoError::SenderKeyError {
                reason: "invalid signing public key".into(),
            }
        })?;

        let mut signed_data = Vec::with_capacity(4 + msg.ciphertext.len());
        signed_data.extend_from_slice(&msg.chain_index.to_be_bytes());
        signed_data.extend_from_slice(&msg.ciphertext);

        let sig_bytes: [u8; 64] =
            msg.signature
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::SenderKeyError {
                    reason: "invalid signature length".into(),
                })?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&signed_data, &signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        // Handle message ordering
        if msg.chain_index < self.chain_index {
            // Look up in skipped keys
            let mk = self
                .skipped_keys
                .remove(&msg.chain_index)
                .ok_or(CryptoError::MessageKeyExhausted)?;
            let nonce = Self::build_nonce(&self.signing_public_key, msg.chain_index);
            let cipher = ChaCha20Poly1305Cipher::new(&mk)?;
            return cipher.decrypt(&nonce, &msg.ciphertext, &[]);
        }

        if msg.chain_index > self.chain_index {
            // Ratchet forward, storing skipped keys
            let skip_count = msg.chain_index - self.chain_index;
            if skip_count > MAX_SKIP {
                return Err(CryptoError::SenderKeyError {
                    reason: "too many skipped message keys".into(),
                });
            }
            for idx in self.chain_index..msg.chain_index {
                if self.skipped_keys.len() >= MAX_SKIP as usize {
                    return Err(CryptoError::SenderKeyError {
                        reason: "too many skipped message keys".into(),
                    });
                }
                let mk_bytes =
                    hkdf_sha256(&self.chain_key, &[0x01], b"ParolNet_sender_key_v1", 32)?;
                let mut mk = [0u8; 32];
                mk.copy_from_slice(&mk_bytes);
                self.skipped_keys.insert(idx, mk);

                let ck_bytes =
                    hkdf_sha256(&self.chain_key, &[0x02], b"ParolNet_sender_chain_v1", 32)?;
                self.chain_key.copy_from_slice(&ck_bytes);
            }
            self.chain_index = msg.chain_index;
        }

        // msg.chain_index == self.chain_index: derive message key and decrypt
        let mk_bytes = hkdf_sha256(&self.chain_key, &[0x01], b"ParolNet_sender_key_v1", 32)?;
        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&mk_bytes);

        // Advance chain key
        let ck_bytes = hkdf_sha256(&self.chain_key, &[0x02], b"ParolNet_sender_chain_v1", 32)?;
        self.chain_key.copy_from_slice(&ck_bytes);
        self.chain_index += 1;

        let nonce = Self::build_nonce(&self.signing_public_key, msg.chain_index);
        let cipher = ChaCha20Poly1305Cipher::new(&message_key)?;
        let plaintext = cipher.decrypt(&nonce, &msg.ciphertext, &[])?;

        // Zeroize message key after use
        message_key.zeroize();

        Ok(plaintext)
    }

    /// Rotate the sender key chain. Generates a new random chain key and resets the index.
    ///
    /// Used for periodic rotation (e.g., every 1000 messages or 24 hours).
    /// After rotation, a new distribution message must be sent to all group members.
    pub fn rotate(&mut self) {
        use rand::RngCore;
        OsRng.fill_bytes(&mut self.chain_key);
        self.chain_index = 0;
        // Clear skipped keys from old chain — they are no longer valid
        for value in self.skipped_keys.values_mut() {
            value.zeroize();
        }
        self.skipped_keys.clear();
    }

    /// Build a 12-byte nonce from the signing public key and chain index.
    ///
    /// Nonce = SHA-256(signing_public_key)[0..8] || chain_index.to_be_bytes()
    /// This guarantees uniqueness: different senders have different public keys,
    /// and within a sender's chain the index is monotonic.
    fn build_nonce(signing_public_key: &[u8; 32], chain_index: u32) -> [u8; 12] {
        let hash = Sha256::digest(signing_public_key);
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&hash[..8]);
        nonce[8..12].copy_from_slice(&chain_index.to_be_bytes());
        nonce
    }
}

/// Manual `Drop` to zeroize key material that `#[zeroize(skip)]` excludes:
/// - `skipped_keys`: HashMap values contain message keys (secret material).
/// - `signing_key`: `SigningKey` handles its own zeroization.
impl Drop for SenderKeyState {
    fn drop(&mut self) {
        // Zeroize the derive-Zeroize fields (chain_key, etc.)
        self.zeroize();

        // Zeroize all skipped message keys (HashMap is #[zeroize(skip)])
        for value in self.skipped_keys.values_mut() {
            value.zeroize();
        }
        self.skipped_keys.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sender_key_encrypt_decrypt() {
        let mut sender = SenderKeyState::new();
        let peer_id = [0x42u8; 32];
        let dist = sender.create_distribution(peer_id);

        let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

        let msg = sender.encrypt(b"hello group").unwrap();
        let plaintext = receiver.decrypt(&msg).unwrap();
        assert_eq!(plaintext, b"hello group");
    }

    #[test]
    fn test_sender_key_out_of_order() {
        let mut sender = SenderKeyState::new();
        let peer_id = [0x42u8; 32];
        let dist = sender.create_distribution(peer_id);
        let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

        let msg1 = sender.encrypt(b"msg1").unwrap();
        let msg2 = sender.encrypt(b"msg2").unwrap();
        let msg3 = sender.encrypt(b"msg3").unwrap();

        // Decrypt out of order: 3, 1, 2
        let pt3 = receiver.decrypt(&msg3).unwrap();
        assert_eq!(pt3, b"msg3");

        let pt1 = receiver.decrypt(&msg1).unwrap();
        assert_eq!(pt1, b"msg1");

        let pt2 = receiver.decrypt(&msg2).unwrap();
        assert_eq!(pt2, b"msg2");
    }

    #[test]
    fn test_sender_key_tampered_ciphertext() {
        let mut sender = SenderKeyState::new();
        let peer_id = [0x42u8; 32];
        let dist = sender.create_distribution(peer_id);
        let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

        let mut msg = sender.encrypt(b"secret data").unwrap();
        // Tamper with ciphertext
        if !msg.ciphertext.is_empty() {
            msg.ciphertext[0] ^= 0xFF;
        }

        // Should fail — signature won't match tampered ciphertext
        assert!(receiver.decrypt(&msg).is_err());
    }

    #[test]
    fn test_sender_key_tampered_signature() {
        let mut sender = SenderKeyState::new();
        let peer_id = [0x42u8; 32];
        let dist = sender.create_distribution(peer_id);
        let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

        let mut msg = sender.encrypt(b"secret data").unwrap();
        // Tamper with signature
        msg.signature[0] ^= 0xFF;

        assert!(receiver.decrypt(&msg).is_err());
    }

    #[test]
    fn test_sender_key_rotation() {
        let mut sender = SenderKeyState::new();
        let peer_id = [0x42u8; 32];
        let dist = sender.create_distribution(peer_id);
        let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

        // Send a message before rotation
        let msg1 = sender.encrypt(b"before rotation").unwrap();

        // Rotate sender keys
        sender.rotate();

        // Distribute new keys
        let new_dist = sender.create_distribution(peer_id);
        let mut receiver2 = SenderKeyState::from_distribution(&new_dist).unwrap();

        // New messages use new chain
        let msg2 = sender.encrypt(b"after rotation").unwrap();
        let pt2 = receiver2.decrypt(&msg2).unwrap();
        assert_eq!(pt2, b"after rotation");

        // Old receiver can still decrypt old message
        let pt1 = receiver.decrypt(&msg1).unwrap();
        assert_eq!(pt1, b"before rotation");
    }

    #[test]
    fn test_receiver_cannot_encrypt() {
        let sender = SenderKeyState::new();
        let peer_id = [0x42u8; 32];
        let dist = sender.create_distribution(peer_id);
        let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

        let result = receiver.encrypt(b"should fail");
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::SenderKeyError { reason } => {
                assert!(reason.contains("receiver-only"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
