//! wasm-bindgen bindings exposing crypto + protocol to JS/TS.
//!
//! These functions use the global STATE from lib.rs to encrypt/decrypt
//! messages via the Double Ratchet session established with `create_session`.

use wasm_bindgen::prelude::*;

use crate::STATE;

/// Encrypt a message using the Double Ratchet session for the given peer.
///
/// `peer_id_hex` — 32-byte peer id, hex-encoded.
/// `plaintext` — raw bytes to encrypt.
///
/// Returns the ciphertext bytes (header + ciphertext concatenated).
#[wasm_bindgen]
pub fn encrypt_message(peer_id_hex: &str, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    let peer_id_bytes = crate::decode_32(peer_id_hex)?;
    let peer_id = parolnet_protocol::address::PeerId(peer_id_bytes);

    let state = STATE.lock().unwrap();
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized — call initialize() first"))?;

    let (header, ciphertext) = client
        .send(&peer_id, plaintext)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    // Serialize header + ciphertext into a single byte vector.
    // Format: [32 bytes public_key][4 bytes previous_chain_length BE][4 bytes message_number BE][ciphertext]
    let mut out = Vec::with_capacity(40 + ciphertext.len());
    out.extend_from_slice(&header.ratchet_key);
    out.extend_from_slice(&header.previous_chain_length.to_be_bytes());
    out.extend_from_slice(&header.message_number.to_be_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a message using the Double Ratchet session for the given peer.
///
/// `peer_id_hex` — 32-byte peer id, hex-encoded.
/// `ciphertext` — bytes previously produced by `encrypt_message` (header + ciphertext).
///
/// Returns the decrypted plaintext bytes.
#[wasm_bindgen]
pub fn decrypt_message(peer_id_hex: &str, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    if ciphertext.len() < 40 {
        return Err(JsError::new(
            "ciphertext too short — must contain header (40 bytes) + data",
        ));
    }

    let peer_id_bytes = crate::decode_32(peer_id_hex)?;
    let peer_id = parolnet_protocol::address::PeerId(peer_id_bytes);

    // Parse header from the first 40 bytes.
    let mut ratchet_key = [0u8; 32];
    ratchet_key.copy_from_slice(&ciphertext[..32]);
    let previous_chain_length = u32::from_be_bytes(ciphertext[32..36].try_into().unwrap());
    let message_number = u32::from_be_bytes(ciphertext[36..40].try_into().unwrap());

    let header = parolnet_crypto::RatchetHeader {
        ratchet_key,
        previous_chain_length,
        message_number,
    };

    let state = STATE.lock().unwrap();
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized — call initialize() first"))?;

    client
        .recv(&peer_id, &header, &ciphertext[40..])
        .map_err(|e| JsError::new(&format!("{e}")))
}
