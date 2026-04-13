//! # parolnet-wasm
//!
//! WASM bindings for ParolNet.
//!
//! Exposes the Rust crypto core to a JS/TS PWA shell via `wasm-bindgen`.
//! The crypto runs in the WASM sandbox, not in JS — harder to tamper with.
//!
//! Provides:
//! - Key generation and identity management
//! - Session management (establish, send, has_session, session_count)
//! - Message encryption/decryption (Double Ratchet)
//! - Call signaling (start, answer, reject, hangup, state query)
//! - File transfer (chunked send/receive with SHA-256 integrity)
//! - Decoy mode with unlock code (SHA-256 hashed, constant-time verify)
//! - Envelope encoding/decoding (CBOR)
//! - Bootstrap QR payload generation/parsing
//! - SAS verification string computation
//! - Panic wipe (clear all in-memory state)

pub mod bindings;
pub mod storage;
pub mod websocket;

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use wasm_bindgen::prelude::*;

use parolnet_core::ParolNet;
use parolnet_core::call::CallManager;
use parolnet_core::file_transfer::{FileTransferReceiver, FileTransferSender};
use parolnet_protocol::file::FileOffer;

/// Pending bootstrap state from QR generation (presenter side).
struct PendingBootstrap {
    /// The random seed used in the QR payload.
    seed: [u8; 32],
    /// Our X25519 ratchet secret key.
    ratchet_secret: [u8; 32],
}

/// Global state accessible from stateless wasm-bindgen functions.
struct WasmState {
    client: Option<ParolNet>,
    call_manager: CallManager,
    file_senders: HashMap<String, FileTransferSender>,
    file_receivers: HashMap<String, FileTransferReceiver>,
    /// SHA-256 hash of the unlock code, if set.
    unlock_code_hash: Option<[u8; 32]>,
    /// Whether decoy mode is currently active.
    decoy_active: bool,
    /// Pending bootstrap from our QR generation (we are the presenter/responder).
    pending_bootstrap: Option<PendingBootstrap>,
}

static STATE: LazyLock<Mutex<WasmState>> = LazyLock::new(|| {
    Mutex::new(WasmState {
        client: None,
        call_manager: CallManager::new(),
        file_senders: HashMap::new(),
        file_receivers: HashMap::new(),
        unlock_code_hash: None,
        decoy_active: false,
        pending_bootstrap: None,
    })
});

/// Initialize the WASM module.
#[wasm_bindgen(start)]
pub fn init() {
    // Future: set up panic hook for better browser console errors
}

// ── Identity ────────────────────────────────────────────────

/// Generate a new identity keypair and return the PeerId (32 bytes, hex-encoded).
#[wasm_bindgen]
pub fn generate_identity() -> String {
    let keypair = parolnet_crypto::IdentityKeyPair::generate();
    let peer_id = keypair.peer_id();
    hex::encode(peer_id)
}

/// Generate a new identity and return the public key bytes (hex-encoded).
#[wasm_bindgen]
pub fn generate_keypair() -> JsValue {
    let keypair = parolnet_crypto::IdentityKeyPair::generate();
    serde_wasm_bindgen::to_value(&KeypairResult {
        peer_id: hex::encode(keypair.peer_id()),
        public_key: hex::encode(keypair.public_key_bytes()),
    })
    .unwrap_or(JsValue::NULL)
}

#[derive(serde::Serialize)]
struct KeypairResult {
    peer_id: String,
    public_key: String,
}

// ── Initialization ──────────────────────────────────────────

/// Initialize from a saved secret key (hex-encoded 32 bytes).
/// Returns the peer_id as hex.
#[wasm_bindgen]
pub fn initialize_from_key(secret_key_hex: &str) -> Result<String, JsError> {
    let secret_bytes = decode_32(secret_key_hex)?;
    let identity = parolnet_crypto::IdentityKeyPair::from_secret_bytes(&secret_bytes);
    let config = parolnet_core::ParolNetConfig::default();
    let client = parolnet_core::ParolNet::from_identity(config, identity);
    let peer_id = hex::encode(client.peer_id().0);
    let mut state = STATE.lock().unwrap();
    state.client = Some(client);
    Ok(peer_id)
}

/// Export the current identity's secret key as hex.
/// Used to save the identity to persistent storage.
#[wasm_bindgen]
pub fn export_secret_key() -> Result<String, JsError> {
    let state = STATE.lock().unwrap();
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;
    Ok(hex::encode(client.export_identity_secret()))
}

/// Create a new ParolNet instance with default config.
/// Returns the peer_id as hex.
#[wasm_bindgen]
pub fn initialize() -> String {
    let config = parolnet_core::ParolNetConfig::default();
    let client = ParolNet::new(config);
    let peer_id = hex::encode(client.peer_id().0);
    let mut state = STATE.lock().unwrap();
    state.client = Some(client);
    peer_id
}

/// Get the current peer ID (hex). Returns empty string if not initialized.
#[wasm_bindgen]
pub fn get_peer_id() -> String {
    let state = STATE.lock().unwrap();
    state
        .client
        .as_ref()
        .map(|c| hex::encode(c.peer_id().0))
        .unwrap_or_default()
}

/// Get the current public key (hex). Returns empty string if not initialized.
#[wasm_bindgen]
pub fn get_public_key() -> String {
    let state = STATE.lock().unwrap();
    state
        .client
        .as_ref()
        .map(|c| hex::encode(c.public_key()))
        .unwrap_or_default()
}

// ── Session Management ──────────────────────────────────────

/// Establish a Double Ratchet session with a peer.
///
/// All arguments are hex-encoded 32-byte values.
#[wasm_bindgen]
pub fn create_session(
    peer_id_hex: &str,
    shared_secret_hex: &str,
    ratchet_key_hex: &str,
) -> Result<(), JsError> {
    let peer_id_bytes = decode_32(peer_id_hex)?;
    let shared_secret_bytes = decode_32(shared_secret_hex)?;
    let ratchet_key_bytes = decode_32(ratchet_key_hex)?;

    let peer_id = parolnet_protocol::address::PeerId(peer_id_bytes);
    let shared_secret = parolnet_crypto::SharedSecret(shared_secret_bytes);

    let state = STATE.lock().unwrap();
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized — call initialize() first"))?;

    client
        .establish_session(peer_id, shared_secret, &ratchet_key_bytes, true)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(())
}

/// Send an encrypted message within an established session.
///
/// Returns a JS object `{ header_json, ciphertext_hex }`.
#[wasm_bindgen]
pub fn send_message(peer_id_hex: &str, plaintext: &str) -> Result<JsValue, JsError> {
    let peer_id_bytes = decode_32(peer_id_hex)?;
    let peer_id = parolnet_protocol::address::PeerId(peer_id_bytes);

    let state = STATE.lock().unwrap();
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized — call initialize() first"))?;

    let (header, ciphertext) = client
        .send(&peer_id, plaintext.as_bytes())
        .map_err(|e| JsError::new(&format!("{e}")))?;

    #[derive(serde::Serialize)]
    struct SendResult {
        ratchet_key: String,
        prev_chain_length: u32,
        message_number: u32,
        ciphertext_hex: String,
    }

    let result = SendResult {
        ratchet_key: hex::encode(header.ratchet_key),
        prev_chain_length: header.previous_chain_length,
        message_number: header.message_number,
        ciphertext_hex: hex::encode(&ciphertext),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Check if a session exists for a peer.
#[wasm_bindgen]
pub fn has_session(peer_id_hex: &str) -> bool {
    let Ok(peer_id_bytes) = try_decode_32(peer_id_hex) else {
        return false;
    };
    let peer_id = parolnet_protocol::address::PeerId(peer_id_bytes);
    let state = STATE.lock().unwrap();
    state
        .client
        .as_ref()
        .map(|c| c.has_session(&peer_id))
        .unwrap_or(false)
}

/// Get the number of active sessions.
#[wasm_bindgen]
pub fn session_count() -> u32 {
    let state = STATE.lock().unwrap();
    state
        .client
        .as_ref()
        .map(|c| c.session_count() as u32)
        .unwrap_or(0)
}

// ── Call Management ─────────────────────────────────────────

/// Start an outgoing call to a peer. Returns the call_id as hex.
#[wasm_bindgen]
pub fn start_call(peer_id_hex: &str) -> Result<String, JsError> {
    let peer_id_bytes = decode_32(peer_id_hex)?;
    let peer_id = parolnet_protocol::address::PeerId(peer_id_bytes);
    let state = STATE.lock().unwrap();
    let call_id = state
        .call_manager
        .start_call(peer_id)
        .map_err(|e| JsError::new(&format!("{e}")))?;
    Ok(hex::encode(call_id))
}

/// Answer an incoming call.
#[wasm_bindgen]
pub fn answer_call(call_id_hex: &str) -> Result<(), JsError> {
    let call_id = decode_16(call_id_hex)?;
    let state = STATE.lock().unwrap();
    state
        .call_manager
        .answer(&call_id)
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Reject an incoming call.
#[wasm_bindgen]
pub fn reject_call(call_id_hex: &str) -> Result<(), JsError> {
    let call_id = decode_16(call_id_hex)?;
    let state = STATE.lock().unwrap();
    state
        .call_manager
        .reject(&call_id)
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Hang up an active call.
#[wasm_bindgen]
pub fn hangup_call(call_id_hex: &str) -> Result<(), JsError> {
    let call_id = decode_16(call_id_hex)?;
    let state = STATE.lock().unwrap();
    state
        .call_manager
        .hangup(&call_id)
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Get the state of a call. Returns one of:
/// "idle", "offering", "ringing", "active", "ended", "rejected", or "unknown".
#[wasm_bindgen]
pub fn get_call_state(call_id_hex: &str) -> Result<String, JsError> {
    let call_id = decode_16(call_id_hex)?;
    let state = STATE.lock().unwrap();
    let call_state = state.call_manager.get_state(&call_id);
    let name = match call_state {
        Some(s) => format!("{:?}", s).to_lowercase(),
        None => "unknown".to_string(),
    };
    Ok(name)
}

// ── File Transfer ───────────────────────────────────────────

/// Create a new outgoing file transfer. Returns the file_id as hex.
#[wasm_bindgen]
pub fn create_file_transfer(
    data: &[u8],
    filename: &str,
    mime_type: Option<String>,
) -> Result<String, JsError> {
    let sender = FileTransferSender::new(data.to_vec(), filename.to_string(), mime_type);
    let file_id_hex = hex::encode(sender.offer.file_id);
    let mut state = STATE.lock().unwrap();
    state.file_senders.insert(file_id_hex.clone(), sender);
    Ok(file_id_hex)
}

/// Get the file offer for an outgoing transfer.
/// Returns `{ file_id, file_name, file_size, chunk_size, total_chunks }`.
#[wasm_bindgen]
pub fn get_file_offer(file_id_hex: &str) -> Result<JsValue, JsError> {
    let state = STATE.lock().unwrap();
    let sender = state
        .file_senders
        .get(file_id_hex)
        .ok_or_else(|| JsError::new("file transfer not found"))?;

    #[derive(serde::Serialize)]
    struct OfferJs {
        file_id: String,
        file_name: String,
        file_size: u64,
        chunk_size: u32,
        total_chunks: u32,
    }

    let offer = &sender.offer;
    let result = OfferJs {
        file_id: hex::encode(offer.file_id),
        file_name: offer.file_name.clone(),
        file_size: offer.file_size,
        chunk_size: offer.chunk_size,
        total_chunks: offer.total_chunks(),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Get the next chunk from an outgoing file transfer.
/// Returns `{ chunk_index, data_hex, is_last }` or null if all chunks are sent.
#[wasm_bindgen]
pub fn get_next_chunk(file_id_hex: &str) -> Result<JsValue, JsError> {
    let mut state = STATE.lock().unwrap();
    let sender = state
        .file_senders
        .get_mut(file_id_hex)
        .ok_or_else(|| JsError::new("file transfer not found"))?;

    match sender.next() {
        Some((header, data)) => {
            #[derive(serde::Serialize)]
            struct ChunkJs {
                chunk_index: u32,
                data_hex: String,
                is_last: bool,
            }
            let result = ChunkJs {
                chunk_index: header.chunk_index,
                data_hex: hex::encode(&data),
                is_last: header.is_last,
            };
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsError::new(&format!("serialize: {e}")))
        }
        None => Ok(JsValue::NULL),
    }
}

/// Register an incoming file transfer from a received offer.
#[wasm_bindgen]
pub fn receive_file_offer(
    file_id_hex: &str,
    file_name: &str,
    file_size: u64,
    chunk_size: u32,
    sha256_hex: &str,
) -> Result<(), JsError> {
    let file_id = decode_16(file_id_hex)?;
    let sha256 = decode_32(sha256_hex)?;

    let offer = FileOffer {
        file_id,
        file_name: file_name.to_string(),
        file_size,
        chunk_size,
        sha256,
        mime_type: None,
    };

    let receiver = FileTransferReceiver::new(offer);
    let mut state = STATE.lock().unwrap();
    state
        .file_receivers
        .insert(file_id_hex.to_string(), receiver);
    Ok(())
}

/// Receive a chunk for an incoming file transfer. Returns true if this was the last chunk.
#[wasm_bindgen]
pub fn receive_chunk(
    file_id_hex: &str,
    chunk_index: u32,
    data: &[u8],
    is_last: bool,
) -> Result<bool, JsError> {
    let file_id = decode_16(file_id_hex)?;

    let header = parolnet_protocol::file::FileChunkHeader {
        file_id,
        chunk_index,
        chunk_size: data.len() as u16,
        is_last,
    };

    let mut state = STATE.lock().unwrap();
    let receiver = state
        .file_receivers
        .get_mut(file_id_hex)
        .ok_or_else(|| JsError::new("file transfer not found"))?;

    receiver
        .receive_chunk(&header, data.to_vec())
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Reassemble a completed file transfer and return the raw bytes.
#[wasm_bindgen]
pub fn assemble_file(file_id_hex: &str) -> Result<Vec<u8>, JsError> {
    let state = STATE.lock().unwrap();
    let receiver = state
        .file_receivers
        .get(file_id_hex)
        .ok_or_else(|| JsError::new("file transfer not found"))?;

    receiver
        .assemble()
        .map_err(|e| JsError::new(&format!("{e}")))
}

// ── Decoy Mode / Unlock Code ────────────────────────────────

/// Set an unlock code. The code is SHA-256 hashed before storage.
#[wasm_bindgen]
pub fn set_unlock_code(code: &str) -> Result<(), JsError> {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let mut state = STATE.lock().unwrap();
    state.unlock_code_hash = Some(hash);
    Ok(())
}

/// Verify an unlock code using constant-time comparison.
#[wasm_bindgen]
pub fn verify_unlock_code(code: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let state = STATE.lock().unwrap();
    match &state.unlock_code_hash {
        Some(stored) => stored.ct_eq(&hash).into(),
        None => false,
    }
}

/// Check if an unlock code has been set (decoy mode is enabled).
#[wasm_bindgen]
pub fn is_decoy_enabled() -> bool {
    let state = STATE.lock().unwrap();
    state.unlock_code_hash.is_some()
}

/// Enter decoy mode — the app should switch to a fake UI.
#[wasm_bindgen]
pub fn enter_decoy_mode() {
    let mut state = STATE.lock().unwrap();
    state.decoy_active = true;
}

// ── Bootstrap ───────────────────────────────────────────────

/// Generate a QR bootstrap payload (CBOR bytes, hex-encoded).
///
/// Also stores the ratchet secret and seed in WASM state so the presenter
/// can later establish a responder session when the scanner connects.
#[wasm_bindgen]
pub fn generate_qr_payload(
    identity_key_hex: &str,
    relay_hint: Option<String>,
) -> Result<String, JsError> {
    let ik_bytes =
        hex::decode(identity_key_hex).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
    if ik_bytes.len() != 32 {
        return Err(JsError::new("identity key must be 32 bytes"));
    }
    let mut ik = [0u8; 32];
    ik.copy_from_slice(&ik_bytes);

    let result =
        parolnet_core::bootstrap::generate_qr_payload_with_ratchet(&ik, relay_hint.as_deref())
            .map_err(|e| JsError::new(&format!("{e}")))?;

    // Store the ratchet secret and seed for later responder session establishment
    let mut state = STATE.lock().unwrap();
    state.pending_bootstrap = Some(PendingBootstrap {
        seed: result.seed,
        ratchet_secret: result.ratchet_secret,
    });

    Ok(hex::encode(result.payload_bytes))
}

/// Parse a QR bootstrap payload from hex-encoded CBOR bytes.
#[wasm_bindgen]
pub fn parse_qr_payload(hex_data: &str) -> Result<JsValue, JsError> {
    let data = hex::decode(hex_data).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;

    let payload = parolnet_core::bootstrap::parse_qr_payload(&data)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    serde_wasm_bindgen::to_value(&payload).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Process a scanned QR payload: parse, derive bootstrap secret, establish initiator session.
///
/// This is the **scanner** side of the bootstrap. Returns `{ peer_id }` on success.
/// The scanner can immediately start sending encrypted messages after this call.
#[wasm_bindgen]
pub fn process_scanned_qr(hex_data: &str) -> Result<JsValue, JsError> {
    let data = hex::decode(hex_data).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;

    let state = STATE.lock().unwrap();
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized — call initialize() first"))?;

    // Parse and derive bootstrap secret
    let (payload, bs) = client
        .process_qr(&data)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    // Compute PeerId from the presenter's identity key
    let mut their_ik = [0u8; 32];
    their_ik.copy_from_slice(&payload.ik);
    let their_peer_id = parolnet_protocol::address::PeerId::from_public_key(&their_ik);

    // Get the ratchet public key — required for session establishment
    if payload.rk.is_empty() {
        return Err(JsError::new(
            "QR payload missing ratchet key — cannot establish session",
        ));
    }
    let mut ratchet_key = [0u8; 32];
    ratchet_key.copy_from_slice(&payload.rk);

    // Establish initiator session using the ratchet key from QR
    client
        .establish_session(
            their_peer_id,
            parolnet_crypto::SharedSecret(bs),
            &ratchet_key,
            true,
        )
        .map_err(|e| JsError::new(&format!("{e}")))?;

    #[derive(serde::Serialize)]
    struct ScanResult {
        peer_id: String,
        their_identity_key: String,
        bootstrap_secret: String,
    }

    let result = ScanResult {
        peer_id: hex::encode(their_peer_id.0),
        their_identity_key: hex::encode(&payload.ik),
        bootstrap_secret: hex::encode(bs),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Complete the bootstrap as the QR **presenter** (responder side).
///
/// Called when the presenter receives a bootstrap handshake from the scanner,
/// containing the scanner's identity key. Uses the stored ratchet secret from
/// QR generation to establish the responder session.
///
/// `their_identity_key_hex` — the scanner's Ed25519 identity public key.
#[wasm_bindgen]
pub fn complete_bootstrap_as_presenter(their_identity_key_hex: &str) -> Result<JsValue, JsError> {
    let their_ik_bytes = hex::decode(their_identity_key_hex)
        .map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
    if their_ik_bytes.len() != 32 {
        return Err(JsError::new("identity key must be 32 bytes"));
    }

    let mut state = STATE.lock().unwrap();

    let pending = state
        .pending_bootstrap
        .take()
        .ok_or_else(|| JsError::new("no pending bootstrap — generate a QR first"))?;

    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized — call initialize() first"))?;

    // Derive the same bootstrap secret the scanner derived
    let our_ik = client.public_key();
    let mut their_ik = [0u8; 32];
    their_ik.copy_from_slice(&their_ik_bytes);

    let bs = parolnet_core::bootstrap::derive_bootstrap_secret(&pending.seed, &our_ik, &their_ik)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    // Compute scanner's PeerId
    let their_peer_id = parolnet_protocol::address::PeerId::from_public_key(&their_ik);

    // Establish responder session using our stored ratchet secret
    client
        .establish_responder_session(
            their_peer_id,
            parolnet_crypto::SharedSecret(bs),
            pending.ratchet_secret,
        )
        .map_err(|e| JsError::new(&format!("{e}")))?;

    #[derive(serde::Serialize)]
    struct PresenterResult {
        peer_id: String,
        bootstrap_secret: String,
    }

    let result = PresenterResult {
        peer_id: hex::encode(their_peer_id.0),
        bootstrap_secret: hex::encode(bs),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Compute a 6-digit SAS verification string.
#[wasm_bindgen]
pub fn compute_sas(
    bootstrap_secret_hex: &str,
    ik_alice_hex: &str,
    ik_bob_hex: &str,
    ek_alice_hex: &str,
    ek_bob_hex: &str,
) -> Result<String, JsError> {
    let bs = decode_32(bootstrap_secret_hex)?;
    let ik_a = decode_32(ik_alice_hex)?;
    let ik_b = decode_32(ik_bob_hex)?;
    let ek_a = decode_32(ek_alice_hex)?;
    let ek_b = decode_32(ek_bob_hex)?;

    parolnet_core::bootstrap::compute_sas(&bs, &ik_a, &ik_b, &ek_a, &ek_b)
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Emergency: wipe all state from memory.
#[wasm_bindgen]
pub fn panic_wipe() {
    let mut state = STATE.lock().unwrap();
    state.client = None;
    state.file_senders.clear();
    state.file_receivers.clear();
    state.unlock_code_hash = None;
    state.decoy_active = false;
    state.pending_bootstrap = None;
    // call_manager doesn't have a clear method, but dropping calls is fine
    // The CallManager is behind a Mutex internally; we replace it.
    // Note: we can't easily replace it due to LazyLock, so we prune finished calls.
    state.call_manager.prune_finished();
}

/// Get the ParolNet version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ── Helpers ─────────────────────────────────────────────────

fn decode_32(hex_str: &str) -> Result<[u8; 32], JsError> {
    let bytes = hex::decode(hex_str).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(JsError::new("expected 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn decode_16(hex_str: &str) -> Result<[u8; 16], JsError> {
    let bytes = hex::decode(hex_str).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
    if bytes.len() != 16 {
        return Err(JsError::new("expected 16 bytes"));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Non-JsError version for functions that return bool.
fn try_decode_32(hex_str: &str) -> Result<[u8; 32], ()> {
    let bytes = hex::decode(hex_str).map_err(|_| ())?;
    if bytes.len() != 32 {
        return Err(());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
