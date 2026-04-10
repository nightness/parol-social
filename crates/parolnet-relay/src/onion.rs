//! Onion routing: layer encryption/decryption (PNP-004 Section 5.2).
//!
//! For a 3-hop circuit:
//! - OP encrypts 3 layers: first with hop 3's key, then hop 2's, then hop 1's
//! - Each relay peels one layer by decrypting with its forward key
//! - Reverse direction: each relay adds one layer by encrypting with backward key

use crate::{RelayError, AEAD_TAG_SIZE};
use parolnet_crypto::aead::ChaCha20Poly1305Cipher;
use parolnet_crypto::Aead;

/// A single hop's encryption keys and nonce state.
#[derive(Clone)]
pub struct HopKeys {
    /// Forward key (OP -> Exit direction).
    pub forward_key: [u8; 32],
    /// Backward key (Exit -> OP direction).
    pub backward_key: [u8; 32],
    /// Forward nonce seed (12 bytes).
    pub forward_nonce_seed: [u8; 12],
    /// Backward nonce seed (12 bytes).
    pub backward_nonce_seed: [u8; 12],
}

impl HopKeys {
    /// Derive hop keys from a shared secret using HKDF (PNP-004 Section 5.1).
    pub fn from_shared_secret(shared_secret: &[u8; 32]) -> Result<Self, RelayError> {
        let material = parolnet_crypto::kdf::hkdf_sha256(
            &[0u8; 32],
            shared_secret,
            b"prcp-key-expand-v1",
            88, // 32 + 32 + 12 + 12
        )
        .map_err(|e| RelayError::KeyExchangeFailed(e.to_string()))?;

        let mut forward_key = [0u8; 32];
        let mut backward_key = [0u8; 32];
        let mut forward_nonce_seed = [0u8; 12];
        let mut backward_nonce_seed = [0u8; 12];

        forward_key.copy_from_slice(&material[0..32]);
        backward_key.copy_from_slice(&material[32..64]);
        forward_nonce_seed.copy_from_slice(&material[64..76]);
        backward_nonce_seed.copy_from_slice(&material[76..88]);

        Ok(Self {
            forward_key,
            backward_key,
            forward_nonce_seed,
            backward_nonce_seed,
        })
    }

    /// Compute the nonce for a given counter by XORing with the seed.
    fn make_nonce(seed: &[u8; 12], counter: u32) -> [u8; 12] {
        let mut nonce = *seed;
        let counter_bytes = counter.to_be_bytes();
        // XOR counter into the last 4 bytes of the nonce
        for i in 0..4 {
            nonce[8 + i] ^= counter_bytes[i];
        }
        nonce
    }
}

/// Encrypt a payload with one onion layer (forward direction, OP side).
///
/// Returns ciphertext with AEAD tag prepended.
pub fn onion_wrap(
    payload: &[u8],
    key: &[u8; 32],
    nonce_seed: &[u8; 12],
    counter: u32,
) -> Result<Vec<u8>, RelayError> {
    let cipher = ChaCha20Poly1305Cipher::new(key)
        .map_err(|e| RelayError::KeyExchangeFailed(e.to_string()))?;
    let nonce = HopKeys::make_nonce(nonce_seed, counter);
    cipher
        .encrypt(&nonce, payload, &[])
        .map_err(|_| RelayError::AeadFailed)
}

/// Decrypt (peel) one onion layer (forward direction, relay side).
///
/// Expects ciphertext with AEAD tag appended (as produced by ChaCha20-Poly1305).
pub fn onion_peel(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce_seed: &[u8; 12],
    counter: u32,
) -> Result<Vec<u8>, RelayError> {
    let cipher = ChaCha20Poly1305Cipher::new(key)
        .map_err(|e| RelayError::KeyExchangeFailed(e.to_string()))?;
    let nonce = HopKeys::make_nonce(nonce_seed, counter);
    cipher
        .decrypt(&nonce, ciphertext, &[])
        .map_err(|_| RelayError::AeadFailed)
}

/// Encrypt a payload with multiple onion layers (OP side).
///
/// Layers are applied innermost-first: encrypt with hop N's key first,
/// then hop N-1, ..., then hop 1.
pub fn onion_encrypt(
    payload: &[u8],
    hop_keys: &[HopKeys],
    counters: &[u32],
) -> Result<Vec<u8>, RelayError> {
    if hop_keys.len() != counters.len() {
        return Err(RelayError::CellError("key/counter length mismatch".into()));
    }

    let mut data = payload.to_vec();

    // Encrypt from innermost (last hop) to outermost (first hop)
    for i in (0..hop_keys.len()).rev() {
        data = onion_wrap(
            &data,
            &hop_keys[i].forward_key,
            &hop_keys[i].forward_nonce_seed,
            counters[i],
        )?;
    }

    Ok(data)
}

/// Decrypt all onion layers (OP side, reverse direction).
///
/// Layers are peeled outermost-first: decrypt with hop 1's backward key,
/// then hop 2, ..., then hop N.
pub fn onion_decrypt(
    ciphertext: &[u8],
    hop_keys: &[HopKeys],
    counters: &[u32],
) -> Result<Vec<u8>, RelayError> {
    if hop_keys.len() != counters.len() {
        return Err(RelayError::CellError("key/counter length mismatch".into()));
    }

    let mut data = ciphertext.to_vec();

    for i in 0..hop_keys.len() {
        data = onion_peel(
            &data,
            &hop_keys[i].backward_key,
            &hop_keys[i].backward_nonce_seed,
            counters[i],
        )?;
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hop_keys(seed: u8) -> HopKeys {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        HopKeys::from_shared_secret(&secret).unwrap()
    }

    #[test]
    fn test_single_layer_roundtrip() {
        let keys = test_hop_keys(1);
        let plaintext = b"hello from the originator";

        let encrypted = onion_wrap(plaintext, &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap();
        assert_ne!(encrypted, plaintext);
        assert_eq!(encrypted.len(), plaintext.len() + AEAD_TAG_SIZE);

        let decrypted = onion_peel(&encrypted, &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_three_layer_roundtrip() {
        let hop1 = test_hop_keys(1);
        let hop2 = test_hop_keys(2);
        let hop3 = test_hop_keys(3);
        let hops = [hop1.clone(), hop2.clone(), hop3.clone()];
        let counters = [0u32, 0, 0];

        let plaintext = b"secret message through 3 relays";

        // OP encrypts with 3 layers
        let encrypted = onion_encrypt(plaintext, &hops, &counters).unwrap();

        // Each relay peels one layer
        let after_hop1 = onion_peel(&encrypted, &hop1.forward_key, &hop1.forward_nonce_seed, 0).unwrap();
        let after_hop2 = onion_peel(&after_hop1, &hop2.forward_key, &hop2.forward_nonce_seed, 0).unwrap();
        let after_hop3 = onion_peel(&after_hop2, &hop3.forward_key, &hop3.forward_nonce_seed, 0).unwrap();

        assert_eq!(after_hop3, plaintext);
    }

    #[test]
    fn test_backward_direction() {
        let hop1 = test_hop_keys(1);
        let hop2 = test_hop_keys(2);
        let hop3 = test_hop_keys(3);

        let plaintext = b"response from exit relay";

        // Exit relay (hop3) encrypts with backward key
        let from_hop3 = onion_wrap(plaintext, &hop3.backward_key, &hop3.backward_nonce_seed, 0).unwrap();
        // Hop2 adds a layer
        let from_hop2 = onion_wrap(&from_hop3, &hop2.backward_key, &hop2.backward_nonce_seed, 0).unwrap();
        // Hop1 adds a layer
        let from_hop1 = onion_wrap(&from_hop2, &hop1.backward_key, &hop1.backward_nonce_seed, 0).unwrap();

        // OP decrypts all layers
        let hops = [hop1, hop2, hop3];
        let counters = [0u32, 0, 0];
        let decrypted = onion_decrypt(&from_hop1, &hops, &counters).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_counter_increments() {
        let keys = test_hop_keys(1);

        let ct0 = onion_wrap(b"msg0", &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap();
        let ct1 = onion_wrap(b"msg0", &keys.forward_key, &keys.forward_nonce_seed, 1).unwrap();

        // Same plaintext, different counter → different ciphertext
        assert_ne!(ct0, ct1);

        // Decrypt with correct counter
        assert_eq!(onion_peel(&ct0, &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap(), b"msg0");
        assert_eq!(onion_peel(&ct1, &keys.forward_key, &keys.forward_nonce_seed, 1).unwrap(), b"msg0");

        // Wrong counter fails
        assert!(onion_peel(&ct0, &keys.forward_key, &keys.forward_nonce_seed, 1).is_err());
    }

    #[test]
    fn test_tampered_onion_layer_fails() {
        let keys = test_hop_keys(1);
        let mut encrypted = onion_wrap(b"secret", &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap();
        encrypted[0] ^= 0xFF;
        assert!(onion_peel(&encrypted, &keys.forward_key, &keys.forward_nonce_seed, 0).is_err());
    }

    #[test]
    fn test_hop_keys_derivation_deterministic() {
        let secret = [42u8; 32];
        let k1 = HopKeys::from_shared_secret(&secret).unwrap();
        let k2 = HopKeys::from_shared_secret(&secret).unwrap();
        assert_eq!(k1.forward_key, k2.forward_key);
        assert_eq!(k1.backward_key, k2.backward_key);
    }

    #[test]
    fn test_different_secrets_different_keys() {
        let k1 = HopKeys::from_shared_secret(&[1u8; 32]).unwrap();
        let k2 = HopKeys::from_shared_secret(&[2u8; 32]).unwrap();
        assert_ne!(k1.forward_key, k2.forward_key);
    }
}
