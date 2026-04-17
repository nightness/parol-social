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

pub mod circuit;
pub mod federation;
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
use zeroize::Zeroize;

/// Pending bootstrap state from QR generation (presenter side).
struct PendingBootstrap {
    /// The random seed used in the QR payload.
    seed: [u8; 32],
    /// Our X25519 ratchet secret key.
    ratchet_secret: [u8; 32],
}

impl Drop for PendingBootstrap {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.ratchet_secret.zeroize();
    }
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
    console_error_panic_hook::set_once();
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
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.client = Some(client);
    Ok(peer_id)
}

/// Export the current identity's secret key as hex.
/// Used to save the identity to persistent storage.
#[wasm_bindgen]
pub fn export_secret_key() -> Result<String, JsError> {
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
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
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.client = Some(client);
    peer_id
}

/// Get the current peer ID (hex). Returns empty string if not initialized.
#[wasm_bindgen]
pub fn get_peer_id() -> String {
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state
        .client
        .as_ref()
        .map(|c| hex::encode(c.peer_id().0))
        .unwrap_or_default()
}

/// Get the current public key (hex). Returns empty string if not initialized.
#[wasm_bindgen]
pub fn get_public_key() -> String {
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state
        .client
        .as_ref()
        .map(|c| hex::encode(c.public_key()))
        .unwrap_or_default()
}

/// Sign arbitrary bytes (hex-encoded) with our Ed25519 identity key.
/// Returns the 64-byte signature as hex.
#[wasm_bindgen]
pub fn sign_bytes(data_hex: &str) -> Result<String, JsError> {
    use ed25519_dalek::Signer;
    let data = hex::decode(data_hex).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;
    let secret = client.export_identity_secret();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let sig = signing_key.sign(&data);
    Ok(hex::encode(sig.to_bytes()))
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

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
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

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
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

/// Encode a PNP-001 envelope: encrypt `plaintext` for `dest_peer_id_hex`,
/// serialize to CBOR, and pad the final frame to one of the bucket sizes
/// (256 / 1024 / 4096 / 16384 bytes).
///
/// Returns the on-wire envelope as a hex string.
#[wasm_bindgen]
pub fn envelope_encode(
    dest_peer_id_hex: &str,
    msg_type: u8,
    plaintext: &[u8],
    now_secs: u64,
) -> Result<String, JsError> {
    let peer_id_bytes = decode_32(dest_peer_id_hex)?;
    let dest_peer_id = parolnet_protocol::address::PeerId(peer_id_bytes);

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized — call initialize() first"))?;

    let bytes = parolnet_core::envelope::encrypt_for_peer(
        client.sessions(),
        &dest_peer_id,
        msg_type,
        plaintext,
        now_secs,
    )
    .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(hex::encode(bytes))
}

/// Decode a PNP-001 envelope: unpad, CBOR-decode, and decrypt the payload
/// using the Double Ratchet session keyed by `source_peer_id_hex`.
///
/// Returns an object `{ source_hint, msg_type, plaintext_hex, timestamp }`.
/// `source_hint` is either the hex-encoded 32-byte sender hint or `null`.
#[wasm_bindgen]
pub fn envelope_decode(source_peer_id_hex: &str, envelope_hex: &str) -> Result<JsValue, JsError> {
    let peer_id_bytes = decode_32(source_peer_id_hex)?;
    let source_peer_id = parolnet_protocol::address::PeerId(peer_id_bytes);

    let envelope_bytes =
        hex::decode(envelope_hex).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized — call initialize() first"))?;

    let decoded = parolnet_core::envelope::decrypt_for_peer(
        client.sessions(),
        &source_peer_id,
        &envelope_bytes,
    )
    .map_err(|e| JsError::new(&format!("{e}")))?;

    #[derive(serde::Serialize)]
    struct DecodedJs {
        source_hint: Option<String>,
        msg_type: u8,
        plaintext_hex: String,
        timestamp: u64,
    }

    let result = DecodedJs {
        source_hint: decoded.source_hint.map(|p| hex::encode(p.0)),
        msg_type: decoded.msg_type,
        plaintext_hex: hex::encode(&decoded.plaintext),
        timestamp: decoded.timestamp,
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
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state
        .client
        .as_ref()
        .map(|c| c.has_session(&peer_id))
        .unwrap_or(false)
}

/// Get the number of active sessions.
#[wasm_bindgen]
pub fn session_count() -> u32 {
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state
        .client
        .as_ref()
        .map(|c| c.session_count() as u32)
        .unwrap_or(0)
}

/// Export all Double Ratchet sessions as a JSON string.
///
/// Returns `{"<peer_id_hex>": "<session_bytes_hex>", ...}` or empty string if no sessions.
#[wasm_bindgen]
pub fn export_sessions() -> Result<String, JsError> {
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let pairs = client.export_sessions();
    if pairs.is_empty() {
        return Ok(String::new());
    }

    let map: std::collections::HashMap<String, String> = pairs
        .into_iter()
        .map(|(pid, data)| (hex::encode(pid), hex::encode(data)))
        .collect();

    serde_json::to_string(&map).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Import sessions from a JSON string previously produced by `export_sessions`.
///
/// Returns the number of sessions restored.
#[wasm_bindgen]
pub fn import_sessions(json_data: &str) -> Result<u32, JsError> {
    if json_data.is_empty() {
        return Ok(0);
    }

    let map: std::collections::HashMap<String, String> =
        serde_json::from_str(json_data).map_err(|e| JsError::new(&format!("parse: {e}")))?;

    let mut pairs = Vec::with_capacity(map.len());
    for (pid_hex, data_hex) in &map {
        let pid = decode_32(pid_hex)?;
        let data = hex::decode(data_hex).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
        pairs.push((pid, data));
    }

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let count = client
        .import_sessions(pairs)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(count as u32)
}

// ── Call Management ─────────────────────────────────────────

/// Start an outgoing call to a peer. Returns the call_id as hex.
#[wasm_bindgen]
pub fn start_call(peer_id_hex: &str) -> Result<String, JsError> {
    let peer_id_bytes = decode_32(peer_id_hex)?;
    let peer_id = parolnet_protocol::address::PeerId(peer_id_bytes);
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
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
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state
        .call_manager
        .answer(&call_id)
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Reject an incoming call.
#[wasm_bindgen]
pub fn reject_call(call_id_hex: &str) -> Result<(), JsError> {
    let call_id = decode_16(call_id_hex)?;
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state
        .call_manager
        .reject(&call_id)
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Hang up an active call.
#[wasm_bindgen]
pub fn hangup_call(call_id_hex: &str) -> Result<(), JsError> {
    let call_id = decode_16(call_id_hex)?;
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
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
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let call_state = state.call_manager.get_state(&call_id);
    let name = match call_state {
        Some(s) => format!("{:?}", s).to_lowercase(),
        None => "unknown".to_string(),
    };
    Ok(name)
}

// ── Screen Sharing ─────────────────────────────────────────

/// Start screen sharing on an active 1:1 call (pauses camera).
#[wasm_bindgen]
pub fn start_screen_share(call_id_hex: &str) -> Result<(), JsError> {
    let call_id = decode_16(call_id_hex)?;
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state
        .call_manager
        .start_screen_share(&call_id)
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Stop screen sharing on an active 1:1 call (resumes camera).
#[wasm_bindgen]
pub fn stop_screen_share(call_id_hex: &str) -> Result<(), JsError> {
    let call_id = decode_16(call_id_hex)?;
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state
        .call_manager
        .stop_screen_share(&call_id)
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Check if local user is screen sharing on a call.
#[wasm_bindgen]
pub fn is_screen_sharing(call_id_hex: &str) -> Result<bool, JsError> {
    let call_id = decode_16(call_id_hex)?;
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state
        .call_manager
        .is_screen_sharing(&call_id)
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Check if the remote peer is screen sharing on a call.
#[wasm_bindgen]
pub fn is_peer_screen_sharing(call_id_hex: &str) -> Result<bool, JsError> {
    let call_id = decode_16(call_id_hex)?;
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state
        .call_manager
        .is_peer_screen_sharing(&call_id)
        .map_err(|e| JsError::new(&format!("{e}")))
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
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.file_senders.insert(file_id_hex.clone(), sender);
    Ok(file_id_hex)
}

/// Get the file offer for an outgoing transfer.
/// Returns `{ file_id, file_name, file_size, chunk_size, total_chunks }`.
#[wasm_bindgen]
pub fn get_file_offer(file_id_hex: &str) -> Result<JsValue, JsError> {
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
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
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
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
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
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

    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
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
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let receiver = state
        .file_receivers
        .get(file_id_hex)
        .ok_or_else(|| JsError::new("file transfer not found"))?;

    receiver
        .assemble()
        .map_err(|e| JsError::new(&format!("{e}")))
}

// ── Group Management ───────────────────────────────────────

/// Create a new group. Returns the group_id as hex.
///
/// The caller becomes the admin. `now_secs` is the current Unix timestamp.
#[wasm_bindgen]
pub fn create_group(name: &str, now_secs: u64) -> Result<String, JsError> {
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let peer_id = client.peer_id();
    let (group_id, _dist) = client
        .group_manager()
        .create_group(name.to_string(), peer_id, now_secs)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(hex::encode(group_id.0))
}

/// Join an existing group.
#[wasm_bindgen]
pub fn join_group(
    group_id_hex: &str,
    name: &str,
    creator_peer_id_hex: &str,
    created_at: u64,
) -> Result<(), JsError> {
    let group_id_bytes = decode_32(group_id_hex)?;
    let creator_bytes = decode_32(creator_peer_id_hex)?;

    let group_id = parolnet_protocol::group::GroupId(group_id_bytes);
    let creator_peer_id = parolnet_protocol::address::PeerId(creator_bytes);

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let our_peer_id = client.peer_id();

    // Build metadata with creator as admin and us as member
    let metadata = parolnet_protocol::group::GroupMetadataPayload {
        group_id,
        version: 1,
        name: name.to_string(),
        members: vec![
            parolnet_protocol::group::GroupMember {
                peer_id: creator_peer_id,
                role: parolnet_protocol::group::GroupRole::Admin,
                joined_at: created_at,
            },
            parolnet_protocol::group::GroupMember {
                peer_id: our_peer_id,
                role: parolnet_protocol::group::GroupRole::Member,
                joined_at: created_at,
            },
        ],
        created_by: creator_peer_id,
        created_at,
        max_members: parolnet_protocol::group::MAX_GROUP_MEMBERS,
    };

    client
        .group_manager()
        .join_group(group_id, metadata, our_peer_id)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(())
}

/// Leave a group.
#[wasm_bindgen]
pub fn leave_group(group_id_hex: &str) -> Result<(), JsError> {
    let group_id_bytes = decode_32(group_id_hex)?;
    let group_id = parolnet_protocol::group::GroupId(group_id_bytes);

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    client
        .group_manager()
        .leave_group(&group_id)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(())
}

/// Get the members of a group. Returns a JSON array of `{peer_id, role, joined_at}`.
#[wasm_bindgen]
pub fn get_group_members(group_id_hex: &str) -> Result<JsValue, JsError> {
    let group_id_bytes = decode_32(group_id_hex)?;
    let group_id = parolnet_protocol::group::GroupId(group_id_bytes);

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let members = client
        .group_manager()
        .get_members(&group_id)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    #[derive(serde::Serialize)]
    struct MemberJs {
        peer_id: String,
        role: String,
        joined_at: u64,
    }

    let result: Vec<MemberJs> = members
        .iter()
        .map(|m| MemberJs {
            peer_id: hex::encode(m.peer_id.0),
            role: format!("{:?}", m.role).to_lowercase(),
            joined_at: m.joined_at,
        })
        .collect();

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Add a member to a group (admin only).
#[wasm_bindgen]
pub fn add_group_member(
    group_id_hex: &str,
    peer_id_hex: &str,
    now_secs: u64,
) -> Result<(), JsError> {
    let group_id_bytes = decode_32(group_id_hex)?;
    let peer_id_bytes = decode_32(peer_id_hex)?;

    let group_id = parolnet_protocol::group::GroupId(group_id_bytes);
    let new_member = parolnet_protocol::address::PeerId(peer_id_bytes);

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let admin_peer_id = client.peer_id();

    client
        .group_manager()
        .add_member(&group_id, &admin_peer_id, new_member, now_secs)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(())
}

/// Remove a member from a group (admin only). Rotates sender key.
#[wasm_bindgen]
pub fn remove_group_member(
    group_id_hex: &str,
    peer_id_hex: &str,
    now_secs: u64,
) -> Result<(), JsError> {
    let group_id_bytes = decode_32(group_id_hex)?;
    let peer_id_bytes = decode_32(peer_id_hex)?;

    let group_id = parolnet_protocol::group::GroupId(group_id_bytes);
    let target = parolnet_protocol::address::PeerId(peer_id_bytes);

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let admin_peer_id = client.peer_id();

    client
        .group_manager()
        .remove_member(&group_id, &admin_peer_id, &target, now_secs)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(())
}

// ── Group Text ─────────────────────────────────────────────

/// Encrypt a text message for a group using sender keys.
///
/// Returns `{ chain_index, ciphertext_hex, signature_hex }`.
#[wasm_bindgen]
pub fn send_group_text(group_id_hex: &str, plaintext: &str) -> Result<JsValue, JsError> {
    let group_id_bytes = decode_32(group_id_hex)?;
    let group_id = parolnet_protocol::group::GroupId(group_id_bytes);

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let (_peer_id, msg) = client
        .group_manager()
        .encrypt_group_text(&group_id, plaintext.as_bytes())
        .map_err(|e| JsError::new(&format!("{e}")))?;

    #[derive(serde::Serialize)]
    struct GroupTextResult {
        chain_index: u32,
        ciphertext_hex: String,
        signature_hex: String,
    }

    let result = GroupTextResult {
        chain_index: msg.chain_index,
        ciphertext_hex: hex::encode(&msg.ciphertext),
        signature_hex: hex::encode(&msg.signature),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Decrypt a group text message from another member.
///
/// Returns the plaintext string.
#[wasm_bindgen]
pub fn recv_group_text(
    group_id_hex: &str,
    sender_peer_id_hex: &str,
    chain_index: u32,
    ciphertext_hex: &str,
    signature_hex: &str,
) -> Result<String, JsError> {
    let group_id_bytes = decode_32(group_id_hex)?;
    let sender_bytes = decode_32(sender_peer_id_hex)?;

    let group_id = parolnet_protocol::group::GroupId(group_id_bytes);
    let sender_peer_id = parolnet_protocol::address::PeerId(sender_bytes);

    let ciphertext =
        hex::decode(ciphertext_hex).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;
    let signature =
        hex::decode(signature_hex).map_err(|e| JsError::new(&format!("invalid hex: {e}")))?;

    let msg = parolnet_crypto::sender_key::SenderKeyMessage {
        chain_index,
        ciphertext,
        signature,
    };

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let plaintext = client
        .group_manager()
        .decrypt_group_text(&group_id, &sender_peer_id, &msg)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    String::from_utf8(plaintext).map_err(|e| JsError::new(&format!("invalid UTF-8: {e}")))
}

/// Process a sender key distribution from another group member.
///
/// This must be called before decrypting messages from that member.
#[wasm_bindgen]
pub fn process_sender_key(
    group_id_hex: &str,
    sender_peer_id_hex: &str,
    chain_key_hex: &str,
    chain_index: u32,
    signing_public_key_hex: &str,
) -> Result<(), JsError> {
    let group_id_bytes = decode_32(group_id_hex)?;
    let sender_bytes = decode_32(sender_peer_id_hex)?;
    let chain_key = decode_32(chain_key_hex)?;
    let signing_public_key = decode_32(signing_public_key_hex)?;

    let group_id = parolnet_protocol::group::GroupId(group_id_bytes);
    let sender_peer_id = parolnet_protocol::address::PeerId(sender_bytes);

    let dist = parolnet_crypto::sender_key::SenderKeyDistribution {
        sender_peer_id: sender_bytes,
        chain_key,
        chain_index,
        signing_public_key,
    };

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    client
        .group_manager()
        .process_sender_key_distribution(&group_id, sender_peer_id, &dist)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(())
}

/// Get our sender key distribution for a group.
///
/// Returns `{ chain_key_hex, chain_index, signing_public_key_hex }`.
#[wasm_bindgen]
pub fn get_sender_key_distribution(group_id_hex: &str) -> Result<JsValue, JsError> {
    let group_id_bytes = decode_32(group_id_hex)?;
    let group_id = parolnet_protocol::group::GroupId(group_id_bytes);

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let dist = client
        .group_manager()
        .get_our_distribution(&group_id)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    #[derive(serde::Serialize)]
    struct DistJs {
        chain_key_hex: String,
        chain_index: u32,
        signing_public_key_hex: String,
    }

    let result = DistJs {
        chain_key_hex: hex::encode(dist.chain_key),
        chain_index: dist.chain_index,
        signing_public_key_hex: hex::encode(dist.signing_public_key),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

// ── Group Calls ────────────────────────────────────────────

/// Start a new group call. Returns the call_id as hex.
#[wasm_bindgen]
pub fn start_group_call(group_id_hex: &str) -> Result<String, JsError> {
    let group_id_bytes = decode_32(group_id_hex)?;
    let group_id = parolnet_protocol::group::GroupId(group_id_bytes);

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let our_peer_id = client.peer_id();

    let call_id = client
        .group_call_manager()
        .start_call(group_id, our_peer_id)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(hex::encode(call_id))
}

/// Join an existing group call.
#[wasm_bindgen]
pub fn join_group_call(call_id_hex: &str, peer_id_hex: &str) -> Result<(), JsError> {
    let call_id = decode_16(call_id_hex)?;
    let peer_id_bytes = decode_32(peer_id_hex)?;
    let peer_id = parolnet_protocol::address::PeerId(peer_id_bytes);

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    client
        .group_call_manager()
        .join_call(&call_id, peer_id)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(())
}

/// Leave an existing group call.
#[wasm_bindgen]
pub fn leave_group_call(call_id_hex: &str, peer_id_hex: &str) -> Result<(), JsError> {
    let call_id = decode_16(call_id_hex)?;
    let peer_id_bytes = decode_32(peer_id_hex)?;
    let peer_id = parolnet_protocol::address::PeerId(peer_id_bytes);

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    client
        .group_call_manager()
        .leave_call(&call_id, &peer_id)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(())
}

/// Get participants in a group call. Returns a JSON array of peer_id hex strings.
#[wasm_bindgen]
pub fn get_group_call_participants(call_id_hex: &str) -> Result<JsValue, JsError> {
    let call_id = decode_16(call_id_hex)?;

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let participants = client
        .group_call_manager()
        .get_participants(&call_id)
        .map_err(|e| JsError::new(&format!("{e}")))?;

    let result: Vec<String> = participants.iter().map(|p| hex::encode(p.0)).collect();

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Get the state of a group call. Returns "idle", "active", or "ended".
#[wasm_bindgen]
pub fn get_group_call_state(call_id_hex: &str) -> Result<String, JsError> {
    let call_id = decode_16(call_id_hex)?;

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let call_state = client.group_call_manager().get_state(&call_id);
    let name = match call_state {
        Some(s) => format!("{:?}", s).to_lowercase(),
        None => "unknown".to_string(),
    };
    Ok(name)
}

// ── Group File Transfer ────────────────────────────────────

/// Create a new group file transfer. Returns `{ file_id_hex, total_chunks, file_size }`.
#[wasm_bindgen]
pub fn create_group_file_transfer(
    group_id_hex: &str,
    data: &[u8],
    filename: &str,
) -> Result<JsValue, JsError> {
    let group_id_bytes = decode_32(group_id_hex)?;
    let group_id = parolnet_protocol::group::GroupId(group_id_bytes);

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    let (file_id, offer) =
        client
            .group_file_manager()
            .create_send(group_id, filename.to_string(), data.to_vec());

    #[derive(serde::Serialize)]
    struct CreateResult {
        file_id_hex: String,
        total_chunks: u32,
        file_size: u64,
    }

    let result = CreateResult {
        file_id_hex: hex::encode(file_id),
        total_chunks: offer.offer.total_chunks(),
        file_size: offer.offer.file_size,
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Get the next chunk from an outgoing group file transfer.
///
/// Returns `{ chunk_index, data_hex }` or null if all chunks are sent.
#[wasm_bindgen]
pub fn get_group_file_next_chunk(file_id_hex: &str) -> Result<JsValue, JsError> {
    let file_id = decode_16(file_id_hex)?;

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    match client.group_file_manager().get_next_chunk(&file_id) {
        Some(chunk) => {
            #[derive(serde::Serialize)]
            struct ChunkJs {
                chunk_index: u32,
                data_hex: String,
            }
            let result = ChunkJs {
                chunk_index: chunk.chunk_index,
                data_hex: hex::encode(&chunk.data),
            };
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsError::new(&format!("serialize: {e}")))
        }
        None => Ok(JsValue::NULL),
    }
}

/// Register an incoming group file transfer from a received offer.
#[wasm_bindgen]
pub fn receive_group_file_offer(
    file_id_hex: &str,
    group_id_hex: &str,
    file_name: &str,
    file_size: u64,
    chunk_size: u32,
    sha256_hex: &str,
) -> Result<(), JsError> {
    let file_id = decode_16(file_id_hex)?;
    let group_id_bytes = decode_32(group_id_hex)?;
    let sha256 = decode_32(sha256_hex)?;

    let group_id = parolnet_protocol::group::GroupId(group_id_bytes);

    let offer = parolnet_protocol::group::GroupFileOffer {
        group_id,
        offer: parolnet_protocol::file::FileOffer {
            file_id,
            file_name: file_name.to_string(),
            file_size,
            chunk_size,
            sha256,
            mime_type: None,
        },
    };

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    client.group_file_manager().receive_offer(&offer);
    Ok(())
}

/// Receive a chunk for an incoming group file transfer. Returns true if complete.
#[wasm_bindgen]
pub fn receive_group_file_chunk(
    file_id_hex: &str,
    chunk_index: u32,
    data: &[u8],
) -> Result<bool, JsError> {
    let file_id = decode_16(file_id_hex)?;

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    client
        .group_file_manager()
        .receive_chunk(&file_id, chunk_index, data.to_vec())
        .map_err(|e| JsError::new(&format!("{e}")))?;

    Ok(client.group_file_manager().is_recv_complete(&file_id))
}

/// Reassemble a completed group file transfer and return the raw bytes.
#[wasm_bindgen]
pub fn assemble_group_file(file_id_hex: &str) -> Result<Vec<u8>, JsError> {
    let file_id = decode_16(file_id_hex)?;

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let client = state
        .client
        .as_ref()
        .ok_or_else(|| JsError::new("not initialized"))?;

    client
        .group_file_manager()
        .assemble_file(&file_id)
        .map_err(|e| JsError::new(&format!("{e}")))
}

// ── Decoy Mode / Unlock Code ────────────────────────────────

/// Set an unlock code. The code is SHA-256 hashed before storage.
#[wasm_bindgen]
pub fn set_unlock_code(code: &str) -> Result<(), JsError> {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.unlock_code_hash = Some(hash);
    Ok(())
}

/// Verify an unlock code using constant-time comparison.
#[wasm_bindgen]
pub fn verify_unlock_code(code: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    match &state.unlock_code_hash {
        Some(stored) => stored.ct_eq(&hash).into(),
        None => false,
    }
}

/// Check if an unlock code has been set (decoy mode is enabled).
#[wasm_bindgen]
pub fn is_decoy_enabled() -> bool {
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.unlock_code_hash.is_some()
}

/// Enter decoy mode — the app should switch to a fake UI.
#[wasm_bindgen]
pub fn enter_decoy_mode() {
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
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
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
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

    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
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

    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());

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

// ── Federation / Directory Verification ────────────────────

/// Verify a CBOR-encoded SignedDirectory against hardcoded authority pubkeys.
/// Returns a JSON object with `{ valid: true, relay_count: N, timestamp: T }` on success,
/// or throws on deserialization/verification error.
#[wasm_bindgen]
pub fn verify_directory(cbor_bytes: &[u8]) -> Result<JsValue, JsError> {
    let dir: federation::SignedDirectory = ciborium::from_reader(cbor_bytes)
        .map_err(|e| JsError::new(&format!("CBOR decode failed: {e}")))?;

    let valid = dir
        .verify(federation::AUTHORITY_PUBKEYS)
        .map_err(|e| JsError::new(&format!("verification error: {e}")))?;

    #[derive(serde::Serialize)]
    struct DirectoryResult {
        valid: bool,
        relay_count: usize,
        timestamp: u64,
    }

    let result = DirectoryResult {
        valid,
        relay_count: dir.descriptors.len(),
        timestamp: dir.timestamp,
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Verify a single CBOR-encoded EndorsedDescriptor meets the authority threshold.
/// `now_secs` is the current Unix timestamp (use `Date.now() / 1000` in JS).
/// Returns true if enough valid authority endorsements exist.
#[wasm_bindgen]
pub fn verify_endorsed_descriptor(cbor_bytes: &[u8], now_secs: u64) -> Result<bool, JsError> {
    let desc: federation::EndorsedDescriptor = ciborium::from_reader(cbor_bytes)
        .map_err(|e| JsError::new(&format!("CBOR decode failed: {e}")))?;

    desc.verify_threshold(
        federation::AUTHORITY_PUBKEYS,
        federation::AUTHORITY_THRESHOLD,
        now_secs,
    )
    .map_err(|e| JsError::new(&format!("verification error: {e}")))
}

/// Get the network identity as a hex string.
/// network_id = SHA-256(sorted authority pubkeys).
#[wasm_bindgen]
pub fn get_network_id() -> String {
    hex::encode(federation::network_id())
}

/// Get authority public keys as a JSON array of hex strings.
#[wasm_bindgen]
pub fn get_authority_pubkeys() -> JsValue {
    let keys: Vec<String> = federation::AUTHORITY_PUBKEYS
        .iter()
        .map(hex::encode)
        .collect();
    serde_wasm_bindgen::to_value(&keys).unwrap_or(JsValue::NULL)
}

/// Get the authority endorsement threshold.
#[wasm_bindgen]
pub fn get_authority_threshold() -> usize {
    federation::AUTHORITY_THRESHOLD
}

/// Emergency: wipe all state from memory.
#[wasm_bindgen]
pub fn panic_wipe() {
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.client = None;
    state.file_senders.clear();
    state.file_receivers.clear();
    if let Some(ref mut hash) = state.unlock_code_hash {
        hash.zeroize();
    }
    state.unlock_code_hash = None;
    state.decoy_active = false;
    state.pending_bootstrap = None; // Drop impl zeroizes seed + ratchet_secret
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

// ── WebRTC Privacy Config ──────────────────────────────────

/// Returns a JSON string with privacy-safe WebRTC configuration.
/// When `privacy_mode` is true, only relay candidates are permitted.
#[wasm_bindgen]
pub fn get_webrtc_privacy_config(privacy_mode: bool) -> String {
    if privacy_mode {
        r#"{"iceTransportPolicy":"relay"}"#.to_string()
    } else {
        r#"{"iceTransportPolicy":"all"}"#.to_string()
    }
}

// ── Bridge Address Exports ───────────────────────────────────

/// Parse a bridge address from QR/text format.
/// Returns JSON: {"host":"...", "port":N, "front_domain":"...", "fingerprint":"...", "ws_url":"...", "http_url":"..."}
#[wasm_bindgen]
pub fn parse_bridge_address(bridge_str: &str) -> Result<String, JsValue> {
    use parolnet_protocol::BridgeAddress;
    let addr =
        BridgeAddress::from_qr_string(bridge_str).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let json = serde_json::json!({
        "host": addr.host,
        "port": addr.port,
        "front_domain": addr.front_domain,
        "fingerprint": addr.fingerprint.map(hex::encode),
        "ws_url": addr.ws_url(),
        "http_url": addr.http_url(),
    });
    Ok(json.to_string())
}

/// Create a bridge address string for QR encoding.
#[wasm_bindgen]
pub fn create_bridge_address(
    host: &str,
    port: u16,
    front_domain: Option<String>,
    fingerprint: Option<String>,
) -> Result<String, JsValue> {
    use parolnet_protocol::BridgeAddress;
    let mut addr = BridgeAddress::new(host.to_string(), port);
    if let Some(fd) = front_domain {
        addr = addr.with_front_domain(fd);
    }
    if let Some(fp_hex) = fingerprint {
        let fp_bytes: [u8; 32] = hex::decode(&fp_hex)
            .map_err(|e| JsValue::from_str(&e.to_string()))?
            .try_into()
            .map_err(|_| JsValue::from_str("fingerprint must be 32 bytes"))?;
        addr = addr.with_fingerprint(fp_bytes);
    }
    Ok(addr.to_qr_string())
}
