//! AEAD cipher implementations.
//!
//! Provides ChaCha20-Poly1305 (primary, constant-time without AES-NI)
//! and AES-256-GCM (secondary, for transport-layer TLS disguise).

use crate::{Aead, CryptoError};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ChaCha20-Poly1305 AEAD cipher.
///
/// Primary cipher for all internal encryption. Constant-time on all
/// platforms including mobile ARM without AES-NI hardware support.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20Poly1305Cipher {
    key: [u8; 32],
}

impl ChaCha20Poly1305Cipher {
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: key.len(),
            });
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }
}

impl Aead for ChaCha20Poly1305Cipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::ChaCha20Poly1305;
        use chacha20poly1305::aead::{Aead as AeadTrait, KeyInit, Payload};

        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceLength {
                expected: 12,
                got: nonce.len(),
            });
        }

        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::ChaCha20Poly1305;
        use chacha20poly1305::aead::{Aead as AeadTrait, KeyInit, Payload};

        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceLength {
                expected: 12,
                got: nonce.len(),
            });
        }

        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    fn key_len(&self) -> usize {
        32
    }
    fn nonce_len(&self) -> usize {
        12
    }
}

/// AES-256-GCM AEAD cipher.
///
/// Secondary cipher used at the transport layer to match TLS cipher suites.
/// Provides hardware acceleration on platforms with AES-NI.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes256GcmCipher {
    key: [u8; 32],
}

impl Aes256GcmCipher {
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: key.len(),
            });
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }
}

impl Aead for Aes256GcmCipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use aes_gcm::Aes256Gcm;
        use aes_gcm::aead::{Aead as AeadTrait, KeyInit, Payload};

        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceLength {
                expected: 12,
                got: nonce.len(),
            });
        }

        let cipher = Aes256Gcm::new((&self.key).into());
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use aes_gcm::Aes256Gcm;
        use aes_gcm::aead::{Aead as AeadTrait, KeyInit, Payload};

        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceLength {
                expected: 12,
                got: nonce.len(),
            });
        }

        let cipher = Aes256Gcm::new((&self.key).into());
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    fn key_len(&self) -> usize {
        32
    }
    fn nonce_len(&self) -> usize {
        12
    }
}
