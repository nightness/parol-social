//! WASM-compatible 3-hop onion circuit builder.
//!
//! Re-implements the relay cell format, handshake, and onion crypto from
//! `parolnet-relay` using only WASM-compatible dependencies (`parolnet-crypto`,
//! `x25519-dalek`, `hmac`, `sha2`, `subtle`).  The `parolnet-relay` crate
//! depends on tokio via `parolnet-transport` and therefore cannot be used
//! from WASM.

use std::cell::RefCell;
use std::collections::HashMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use parolnet_crypto::Aead;
use parolnet_crypto::aead::ChaCha20Poly1305Cipher;
use parolnet_crypto::kdf::hkdf_sha256;

use crate::websocket::WasmWebSocket;

// ---------------------------------------------------------------------------
// Constants — mirrors parolnet-relay
// ---------------------------------------------------------------------------

/// Fixed cell size on the wire.
pub const CELL_SIZE: usize = 512;
/// Header: circuit_id(4) + cell_type(1) + payload_len(2).
pub const CELL_HEADER_SIZE: usize = 7;
/// Payload capacity.
pub const CELL_PAYLOAD_SIZE: usize = CELL_SIZE - CELL_HEADER_SIZE; // 505
/// AEAD tag added by ChaCha20-Poly1305.
pub const AEAD_TAG_SIZE: usize = 16;
/// Required hops in a circuit.
pub const REQUIRED_HOPS: usize = 3;
/// Maximum user-data per DATA cell through a 3-hop circuit.
pub const MAX_DATA_PAYLOAD: usize = CELL_PAYLOAD_SIZE - (REQUIRED_HOPS * AEAD_TAG_SIZE); // 457

/// HMAC label used in the CREATE/CREATED handshake.
const CREATED_HMAC_LABEL: &[u8] = b"prcp-created-v1";
/// HKDF info used for key expansion.
const KEY_EXPAND_INFO: &[u8] = b"prcp-key-expand-v1";

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// WasmCellType
// ---------------------------------------------------------------------------

/// Cell type tags — identical to `parolnet_relay::CellType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WasmCellType {
    Create = 0x01,
    Created = 0x02,
    Extend = 0x03,
    Extended = 0x04,
    Data = 0x05,
    Destroy = 0x06,
    Padding = 0x07,
}

impl WasmCellType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Create),
            0x02 => Some(Self::Created),
            0x03 => Some(Self::Extend),
            0x04 => Some(Self::Extended),
            0x05 => Some(Self::Data),
            0x06 => Some(Self::Destroy),
            0x07 => Some(Self::Padding),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// WasmRelayCell
// ---------------------------------------------------------------------------

/// A relay cell — exactly 512 bytes on the wire.
#[derive(Clone)]
pub struct WasmRelayCell {
    pub circuit_id: u32,
    pub cell_type: WasmCellType,
    pub payload: [u8; CELL_PAYLOAD_SIZE],
    pub payload_len: u16,
}

impl WasmRelayCell {
    /// Serialize to exactly 512 bytes.
    pub fn to_bytes(&self) -> [u8; CELL_SIZE] {
        let mut buf = [0u8; CELL_SIZE];
        buf[0..4].copy_from_slice(&self.circuit_id.to_be_bytes());
        buf[4] = self.cell_type as u8;
        buf[5..7].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[7..].copy_from_slice(&self.payload);
        buf
    }

    /// Deserialize from exactly 512 bytes.
    pub fn from_bytes(buf: &[u8; CELL_SIZE]) -> Result<Self, String> {
        let circuit_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let cell_type =
            WasmCellType::from_u8(buf[4]).ok_or_else(|| format!("unknown cell type 0x{:02x}", buf[4]))?;
        let payload_len = u16::from_be_bytes([buf[5], buf[6]]);
        if payload_len as usize > CELL_PAYLOAD_SIZE {
            return Err(format!(
                "payload_len {} exceeds max {}",
                payload_len, CELL_PAYLOAD_SIZE
            ));
        }
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        payload.copy_from_slice(&buf[7..]);
        Ok(Self {
            circuit_id,
            cell_type,
            payload,
            payload_len,
        })
    }
}

// ---------------------------------------------------------------------------
// HopKeys
// ---------------------------------------------------------------------------

/// Encryption keys and nonce seeds for a single circuit hop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WasmHopKeys {
    pub forward_key: [u8; 32],
    pub backward_key: [u8; 32],
    pub forward_nonce_seed: [u8; 12],
    pub backward_nonce_seed: [u8; 12],
}

impl WasmHopKeys {
    /// Derive hop keys from a 32-byte shared secret via HKDF-SHA-256.
    pub fn from_shared_secret(shared_secret: &[u8; 32]) -> Result<Self, String> {
        let material = hkdf_sha256(&[0u8; 32], shared_secret, KEY_EXPAND_INFO, 88)
            .map_err(|e| format!("HKDF failed: {e}"))?;

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
}

// ---------------------------------------------------------------------------
// Onion helpers
// ---------------------------------------------------------------------------

/// Compute the nonce for a given counter by XORing into the last 4 seed bytes.
fn make_nonce(seed: &[u8; 12], counter: u32) -> [u8; 12] {
    let mut nonce = *seed;
    let counter_bytes = counter.to_be_bytes();
    for i in 0..4 {
        nonce[8 + i] ^= counter_bytes[i];
    }
    nonce
}

/// Encrypt one onion layer (forward direction, OP side).
pub fn onion_wrap(
    payload: &[u8],
    key: &[u8; 32],
    nonce_seed: &[u8; 12],
    counter: u32,
) -> Result<Vec<u8>, String> {
    let cipher =
        ChaCha20Poly1305Cipher::new(key).map_err(|e| format!("cipher init: {e}"))?;
    let nonce = make_nonce(nonce_seed, counter);
    cipher
        .encrypt(&nonce, payload, &[])
        .map_err(|e| format!("encrypt: {e}"))
}

/// Decrypt (peel) one onion layer.
pub fn onion_peel(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce_seed: &[u8; 12],
    counter: u32,
) -> Result<Vec<u8>, String> {
    let cipher =
        ChaCha20Poly1305Cipher::new(key).map_err(|e| format!("cipher init: {e}"))?;
    let nonce = make_nonce(nonce_seed, counter);
    cipher
        .decrypt(&nonce, ciphertext, &[])
        .map_err(|e| format!("decrypt: {e}"))
}

/// Encrypt with multiple onion layers (innermost first: hop N, ..., hop 1).
pub fn onion_encrypt(
    payload: &[u8],
    hop_keys: &[WasmHopKeys],
    counters: &[u32],
) -> Result<Vec<u8>, String> {
    if hop_keys.len() != counters.len() {
        return Err("key/counter length mismatch".into());
    }
    let mut data = payload.to_vec();
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

/// Decrypt all onion layers (outermost first: hop 1, ..., hop N).
pub fn onion_decrypt(
    ciphertext: &[u8],
    hop_keys: &[WasmHopKeys],
    counters: &[u32],
) -> Result<Vec<u8>, String> {
    if hop_keys.len() != counters.len() {
        return Err("key/counter length mismatch".into());
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

// ---------------------------------------------------------------------------
// Handshake helpers
// ---------------------------------------------------------------------------

/// Build a CREATE cell carrying our ephemeral X25519 public key.
/// Returns `(cell, our_secret)`.
pub fn create_cell(circuit_id: u32) -> (WasmRelayCell, StaticSecret) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);

    let mut payload = [0u8; CELL_PAYLOAD_SIZE];
    payload[..32].copy_from_slice(public.as_bytes());

    let cell = WasmRelayCell {
        circuit_id,
        cell_type: WasmCellType::Create,
        payload,
        payload_len: 32,
    };
    (cell, secret)
}

/// Process a CREATED cell: verify HMAC, derive hop keys.
pub fn process_created(
    cell: &WasmRelayCell,
    our_secret: &StaticSecret,
) -> Result<WasmHopKeys, String> {
    if cell.cell_type != WasmCellType::Created {
        return Err("expected CREATED cell".into());
    }

    let mut relay_pub = [0u8; 32];
    relay_pub.copy_from_slice(&cell.payload[..32]);
    let relay_public = PublicKey::from(relay_pub);

    let shared = our_secret.diffie_hellman(&relay_public);

    // Verify HMAC key confirmation
    let mut mac = HmacSha256::new_from_slice(shared.as_bytes())
        .map_err(|e| format!("HMAC init: {e}"))?;
    mac.update(CREATED_HMAC_LABEL);
    let expected_hmac = mac.finalize().into_bytes();

    let received_hmac = &cell.payload[32..64];
    let hmac_ok: bool = received_hmac.ct_eq(expected_hmac.as_slice()).into();
    if !hmac_ok {
        return Err("CREATED HMAC key confirmation failed".into());
    }

    WasmHopKeys::from_shared_secret(shared.as_bytes())
}

/// Build an EXTEND cell carrying target PeerId + our ephemeral X25519 pubkey.
/// Returns `(cell, our_secret)`.
pub fn extend_cell(circuit_id: u32, target_peer_id: &[u8; 32]) -> (WasmRelayCell, StaticSecret) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);

    let mut payload = [0u8; CELL_PAYLOAD_SIZE];
    payload[..32].copy_from_slice(target_peer_id);
    payload[32..64].copy_from_slice(public.as_bytes());

    let cell = WasmRelayCell {
        circuit_id,
        cell_type: WasmCellType::Extend,
        payload,
        payload_len: 64,
    };
    (cell, secret)
}

/// Process an EXTENDED cell: derive hop keys (no HMAC in EXTENDED).
pub fn process_extended(
    cell: &WasmRelayCell,
    our_secret: &StaticSecret,
) -> Result<WasmHopKeys, String> {
    if cell.cell_type != WasmCellType::Extended {
        return Err("expected EXTENDED cell".into());
    }

    let mut relay_pub = [0u8; 32];
    relay_pub.copy_from_slice(&cell.payload[..32]);
    let relay_public = PublicKey::from(relay_pub);

    let shared = our_secret.diffie_hellman(&relay_public);
    WasmHopKeys::from_shared_secret(shared.as_bytes())
}

// ---------------------------------------------------------------------------
// WasmCircuit
// ---------------------------------------------------------------------------

/// An established onion circuit with hop keys and counters.
pub struct WasmCircuit {
    pub hop_keys: Vec<WasmHopKeys>,
    pub forward_counters: Vec<u32>,
    pub backward_counters: Vec<u32>,
    pub circuit_id: u32,
    /// WebSocket ID (index into the SOCKETS thread_local).
    pub ws_id: u32,
}

impl WasmCircuit {
    /// Encrypt data with all onion layers for sending through the circuit.
    pub fn wrap_data(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        for c in &self.forward_counters {
            if *c == u32::MAX {
                return Err("nonce counter overflow".into());
            }
        }
        let result = onion_encrypt(data, &self.hop_keys, &self.forward_counters)?;
        for c in &mut self.forward_counters {
            *c += 1;
        }
        Ok(result)
    }

    /// Decrypt data received through the circuit (reverse direction).
    pub fn unwrap_data(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        for c in &self.backward_counters {
            if *c == u32::MAX {
                return Err("nonce counter overflow".into());
            }
        }
        let result = onion_decrypt(data, &self.hop_keys, &self.backward_counters)?;
        for c in &mut self.backward_counters {
            *c += 1;
        }
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Thread-local circuit storage (mirrors SOCKETS pattern in websocket.rs)
// ---------------------------------------------------------------------------

thread_local! {
    static CIRCUITS: RefCell<HashMap<u32, WasmCircuit>> = RefCell::new(HashMap::new());
    static NEXT_CIRCUIT_ID: RefCell<u32> = const { RefCell::new(1) };
}

/// Helper: yield to the browser event loop so WebSocket callbacks can fire.
async fn yield_to_browser() {
    wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&JsValue::NULL))
        .await
        .ok();
}

/// Poll the WebSocket for a binary message, yielding between polls.
/// Times out after ~10 seconds.
async fn ws_recv_async(ws: &WasmWebSocket) -> Result<Vec<u8>, String> {
    for _ in 0..1000 {
        match ws.recv() {
            Ok(Some(data)) => return Ok(data),
            Ok(None) => {}
            Err(e) => return Err(format!("ws recv error: {e}")),
        }
        if ws.is_closed() {
            return Err("WebSocket closed while waiting for response".into());
        }
        yield_to_browser().await;
    }
    Err("timeout waiting for relay response".into())
}

// ---------------------------------------------------------------------------
// WasmCircuitBuilder
// ---------------------------------------------------------------------------

/// Build a 3-hop onion circuit over a WebSocket.
///
/// In the MVP single-relay mode, all three hops are handled by the same relay
/// server. The circuit builder sends CREATE + 2x EXTEND and processes the
/// responses to derive per-hop keys.
pub async fn build_circuit_impl(ws: &WasmWebSocket, ws_id: u32) -> Result<u32, String> {
    let circuit_id: u32 = {
        let val: u32 = (js_sys::Math::random() * f64::from(u32::MAX)) as u32;
        val | 1 // ensure non-zero
    };

    let mut hop_keys: Vec<WasmHopKeys> = Vec::with_capacity(REQUIRED_HOPS);
    let mut secrets: Vec<StaticSecret> = Vec::new();

    // --- Step 1: CREATE (guard hop) ---
    let (cell, secret) = create_cell(circuit_id);
    ws.send(&cell.to_bytes())
        .map_err(|e| format!("send CREATE: {e}"))?;
    secrets.push(secret);

    let raw = ws_recv_async(ws).await?;
    if raw.len() != CELL_SIZE {
        return Err(format!("CREATED: expected {} bytes, got {}", CELL_SIZE, raw.len()));
    }
    let mut buf = [0u8; CELL_SIZE];
    buf.copy_from_slice(&raw);
    let created = WasmRelayCell::from_bytes(&buf)?;
    let guard_keys = process_created(&created, &secrets[0])?;
    hop_keys.push(guard_keys);

    // --- Steps 2-3: EXTEND for middle and exit hops ---
    // In single-relay MVP mode we use a dummy PeerId for each hop.
    for hop_idx in 1..REQUIRED_HOPS {
        // Use a deterministic dummy PeerId — the single relay handles all hops internally
        let mut target_peer_id = [0u8; 32];
        target_peer_id[0] = hop_idx as u8;

        let (ext_cell, ext_secret) = extend_cell(circuit_id, &target_peer_id);

        // Onion-wrap the EXTEND payload through existing hops
        let payload_data = &ext_cell.payload[..ext_cell.payload_len as usize];
        // Wrap from innermost (last existing hop) to outermost (first hop)
        let wrap_counters: Vec<u32> = (0..hop_keys.len()).map(|i| i as u32 + (hop_idx as u32 - 1)).collect();
        let encrypted = onion_encrypt(payload_data, &hop_keys, &wrap_counters)?;

        let mut wire_payload = [0u8; CELL_PAYLOAD_SIZE];
        let copy_len = encrypted.len().min(CELL_PAYLOAD_SIZE);
        wire_payload[..copy_len].copy_from_slice(&encrypted[..copy_len]);

        let wire_cell = WasmRelayCell {
            circuit_id,
            cell_type: WasmCellType::Extend,
            payload: wire_payload,
            payload_len: copy_len as u16,
        };

        ws.send(&wire_cell.to_bytes())
            .map_err(|e| format!("send EXTEND: {e}"))?;

        let raw = ws_recv_async(ws).await?;
        if raw.len() != CELL_SIZE {
            return Err(format!("EXTENDED: expected {} bytes, got {}", CELL_SIZE, raw.len()));
        }
        let mut buf = [0u8; CELL_SIZE];
        buf.copy_from_slice(&raw);
        let extended = WasmRelayCell::from_bytes(&buf)?;
        let new_keys = process_extended(&extended, &ext_secret)?;
        hop_keys.push(new_keys);
    }

    let n = hop_keys.len();
    let circuit = WasmCircuit {
        hop_keys,
        forward_counters: vec![0; n],
        backward_counters: vec![0; n],
        circuit_id,
        ws_id,
    };

    // Store the circuit in the thread-local map and return the circuit_id
    CIRCUITS.with(|circuits| {
        circuits.borrow_mut().insert(circuit_id, circuit);
    });

    Ok(circuit_id)
}

// ---------------------------------------------------------------------------
// JS-facing exports
// ---------------------------------------------------------------------------

/// Build a 3-hop onion circuit over an existing WebSocket.
///
/// `ws_id` is the opaque handle returned by `ws_connect`.
/// Returns a Promise that resolves to the circuit ID (u32).
#[wasm_bindgen]
pub async fn build_circuit(ws_id: u32) -> Result<u32, JsValue> {
    // Extract the WasmWebSocket temporarily — we need it for async operations
    // but thread_local RefCell cannot be held across await points.
    // Instead, clone the Rc state we need.
    use crate::websocket::SOCKETS;

    let ws_state = SOCKETS.with(|sockets| {
        let map = sockets.borrow();
        let ws = map
            .get(&ws_id)
            .ok_or_else(|| JsValue::from_str("invalid socket id"))?;
        // Clone the shared Rc state for async use
        Ok::<_, JsValue>((
            ws.ws_handle().clone(),
            ws.recv_queue_handle().clone(),
            ws.error_queue_handle().clone(),
            ws.opened_handle().clone(),
            ws.closed_handle().clone(),
        ))
    })?;

    // Create a temporary WasmWebSocket proxy for the async builder
    let proxy = WasmWebSocketProxy {
        ws: ws_state.0,
        recv_queue: ws_state.1,
        error_queue: ws_state.2,
        _opened: ws_state.3,
        closed: ws_state.4,
    };

    build_circuit_proxy(&proxy, ws_id)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Lightweight proxy to a WasmWebSocket that can be used across await points.
/// Holds only the Rc-shared state (no Closure references).
struct WasmWebSocketProxy {
    ws: web_sys::WebSocket,
    recv_queue: std::rc::Rc<RefCell<std::collections::VecDeque<Vec<u8>>>>,
    error_queue: std::rc::Rc<RefCell<std::collections::VecDeque<String>>>,
    _opened: std::rc::Rc<RefCell<bool>>,
    closed: std::rc::Rc<RefCell<bool>>,
}

impl WasmWebSocketProxy {
    fn send(&self, data: &[u8]) -> Result<(), String> {
        if self.ws.ready_state() != web_sys::WebSocket::OPEN {
            return Err("WebSocket is not open".into());
        }
        self.ws
            .send_with_u8_array(data)
            .map_err(|e| format!("{e:?}"))
    }

    fn recv(&self) -> Result<Option<Vec<u8>>, String> {
        if let Some(err) = self.error_queue.borrow_mut().pop_front() {
            return Err(err);
        }
        Ok(self.recv_queue.borrow_mut().pop_front())
    }

    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }
}

async fn proxy_recv_async(proxy: &WasmWebSocketProxy) -> Result<Vec<u8>, String> {
    for _ in 0..1000 {
        match proxy.recv() {
            Ok(Some(data)) => return Ok(data),
            Ok(None) => {}
            Err(e) => return Err(format!("ws recv error: {e}")),
        }
        if proxy.is_closed() {
            return Err("WebSocket closed while waiting for response".into());
        }
        yield_to_browser().await;
    }
    Err("timeout waiting for relay response".into())
}

async fn build_circuit_proxy(proxy: &WasmWebSocketProxy, ws_id: u32) -> Result<u32, String> {
    let circuit_id: u32 = {
        let val: u32 = (js_sys::Math::random() * f64::from(u32::MAX)) as u32;
        val | 1
    };

    let mut hop_keys: Vec<WasmHopKeys> = Vec::with_capacity(REQUIRED_HOPS);

    // --- Step 1: CREATE (guard hop) ---
    let (cell, secret) = create_cell(circuit_id);
    proxy
        .send(&cell.to_bytes())
        .map_err(|e| format!("send CREATE: {e}"))?;

    let raw = proxy_recv_async(proxy).await?;
    if raw.len() != CELL_SIZE {
        return Err(format!(
            "CREATED: expected {} bytes, got {}",
            CELL_SIZE,
            raw.len()
        ));
    }
    let mut buf = [0u8; CELL_SIZE];
    buf.copy_from_slice(&raw);
    let created = WasmRelayCell::from_bytes(&buf)?;
    let guard_keys = process_created(&created, &secret)?;
    hop_keys.push(guard_keys);

    // --- Steps 2-3: EXTEND for middle and exit hops ---
    for hop_idx in 1..REQUIRED_HOPS {
        let mut target_peer_id = [0u8; 32];
        target_peer_id[0] = hop_idx as u8;

        let (ext_cell, ext_secret) = extend_cell(circuit_id, &target_peer_id);

        let payload_data = &ext_cell.payload[..ext_cell.payload_len as usize];
        let wrap_counters: Vec<u32> = (0..hop_keys.len())
            .map(|i| i as u32 + (hop_idx as u32 - 1))
            .collect();
        let encrypted = onion_encrypt(payload_data, &hop_keys, &wrap_counters)?;

        let mut wire_payload = [0u8; CELL_PAYLOAD_SIZE];
        let copy_len = encrypted.len().min(CELL_PAYLOAD_SIZE);
        wire_payload[..copy_len].copy_from_slice(&encrypted[..copy_len]);

        let wire_cell = WasmRelayCell {
            circuit_id,
            cell_type: WasmCellType::Extend,
            payload: wire_payload,
            payload_len: copy_len as u16,
        };

        proxy
            .send(&wire_cell.to_bytes())
            .map_err(|e| format!("send EXTEND: {e}"))?;

        let raw = proxy_recv_async(proxy).await?;
        if raw.len() != CELL_SIZE {
            return Err(format!(
                "EXTENDED: expected {} bytes, got {}",
                CELL_SIZE,
                raw.len()
            ));
        }
        let mut buf = [0u8; CELL_SIZE];
        buf.copy_from_slice(&raw);
        let extended = WasmRelayCell::from_bytes(&buf)?;
        let new_keys = process_extended(&extended, &ext_secret)?;
        hop_keys.push(new_keys);
    }

    let n = hop_keys.len();
    let circuit = WasmCircuit {
        hop_keys,
        forward_counters: vec![0; n],
        backward_counters: vec![0; n],
        circuit_id,
        ws_id,
    };

    CIRCUITS.with(|circuits| {
        circuits.borrow_mut().insert(circuit_id, circuit);
    });

    Ok(circuit_id)
}

/// Send data through an established onion circuit.
///
/// Wraps `data` in onion encryption layers, builds a DATA cell, and sends it
/// over the circuit's WebSocket.
#[wasm_bindgen]
pub fn circuit_send(circuit_id: u32, data: &[u8]) -> Result<(), JsValue> {
    if data.len() > MAX_DATA_PAYLOAD {
        return Err(JsValue::from_str(&format!(
            "data too large: {} bytes, max {}",
            data.len(),
            MAX_DATA_PAYLOAD
        )));
    }

    CIRCUITS.with(|circuits| {
        let mut map = circuits.borrow_mut();
        let circuit = map
            .get_mut(&circuit_id)
            .ok_or_else(|| JsValue::from_str("invalid circuit id"))?;

        let encrypted = circuit
            .wrap_data(data)
            .map_err(|e| JsValue::from_str(&e))?;

        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        let copy_len = encrypted.len().min(CELL_PAYLOAD_SIZE);
        payload[..copy_len].copy_from_slice(&encrypted[..copy_len]);

        let cell = WasmRelayCell {
            circuit_id: circuit.circuit_id,
            cell_type: WasmCellType::Data,
            payload,
            payload_len: copy_len as u16,
        };

        let ws_id = circuit.ws_id;
        let bytes = cell.to_bytes();

        // Send via the WebSocket
        crate::websocket::SOCKETS.with(|sockets| {
            let sockets_map = sockets.borrow();
            let ws = sockets_map
                .get(&ws_id)
                .ok_or_else(|| JsValue::from_str("invalid socket id"))?;
            ws.send(&bytes)
                .map_err(|e| JsValue::from_str(&e.to_string()))
        })
    })
}

/// Poll the receive queue for a DATA cell on the given circuit.
///
/// Returns a `Uint8Array` with the decrypted payload, or `null` if no
/// DATA cell is available.
#[wasm_bindgen]
pub fn circuit_recv(circuit_id: u32) -> Result<JsValue, JsValue> {
    CIRCUITS.with(|circuits| {
        let mut map = circuits.borrow_mut();
        let circuit = map
            .get_mut(&circuit_id)
            .ok_or_else(|| JsValue::from_str("invalid circuit id"))?;

        let ws_id = circuit.ws_id;

        // Try to receive from the WebSocket
        let raw = crate::websocket::SOCKETS.with(|sockets| {
            let sockets_map = sockets.borrow();
            let ws = sockets_map
                .get(&ws_id)
                .ok_or_else(|| JsValue::from_str("invalid socket id"))?;
            ws.recv()
                .map_err(|e| JsValue::from_str(&e.to_string()))
        })?;

        let Some(data) = raw else {
            return Ok(JsValue::NULL);
        };

        // Must be exactly 512 bytes to be a relay cell
        if data.len() != CELL_SIZE {
            // Not a cell — put it back? No, the queue is consumed. Return null.
            return Ok(JsValue::NULL);
        }

        let mut buf = [0u8; CELL_SIZE];
        buf.copy_from_slice(&data);
        let cell = WasmRelayCell::from_bytes(&buf)
            .map_err(|e| JsValue::from_str(&e))?;

        if cell.cell_type != WasmCellType::Data {
            return Ok(JsValue::NULL);
        }
        if cell.circuit_id != circuit.circuit_id {
            return Ok(JsValue::NULL);
        }

        let payload = &cell.payload[..cell.payload_len as usize];
        let decrypted = circuit
            .unwrap_data(payload)
            .map_err(|e| JsValue::from_str(&e))?;

        let arr = js_sys::Uint8Array::new_with_length(decrypted.len() as u32);
        arr.copy_from(&decrypted);
        Ok(arr.into())
    })
}

/// Destroy a circuit: send a DESTROY cell and remove from the circuit table.
#[wasm_bindgen]
pub fn circuit_destroy(circuit_id: u32) -> Result<(), JsValue> {
    CIRCUITS.with(|circuits| {
        let mut map = circuits.borrow_mut();
        let circuit = map
            .remove(&circuit_id)
            .ok_or_else(|| JsValue::from_str("invalid circuit id"))?;

        // Build DESTROY cell
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        payload[0] = 0x01; // reason: normal
        let cell = WasmRelayCell {
            circuit_id: circuit.circuit_id,
            cell_type: WasmCellType::Destroy,
            payload,
            payload_len: 1,
        };

        let bytes = cell.to_bytes();

        crate::websocket::SOCKETS.with(|sockets| {
            let sockets_map = sockets.borrow();
            if let Some(ws) = sockets_map.get(&circuit.ws_id) {
                let _ = ws.send(&bytes);
            }
            Ok::<(), JsValue>(())
        })?;

        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_serialization_roundtrip() {
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        payload[0] = 0xAA;
        payload[1] = 0xBB;

        let cell = WasmRelayCell {
            circuit_id: 12345,
            cell_type: WasmCellType::Create,
            payload,
            payload_len: 32,
        };

        let bytes = cell.to_bytes();
        assert_eq!(bytes.len(), CELL_SIZE);

        let recovered = WasmRelayCell::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.circuit_id, 12345);
        assert_eq!(recovered.cell_type, WasmCellType::Create);
        assert_eq!(recovered.payload_len, 32);
        assert_eq!(recovered.payload[0], 0xAA);
        assert_eq!(recovered.payload[1], 0xBB);
    }

    #[test]
    fn test_cell_type_from_u8() {
        assert_eq!(WasmCellType::from_u8(0x01), Some(WasmCellType::Create));
        assert_eq!(WasmCellType::from_u8(0x05), Some(WasmCellType::Data));
        assert_eq!(WasmCellType::from_u8(0x07), Some(WasmCellType::Padding));
        assert_eq!(WasmCellType::from_u8(0xFF), None);
    }

    #[test]
    fn test_hop_keys_derivation() {
        let secret = [42u8; 32];
        let k1 = WasmHopKeys::from_shared_secret(&secret).unwrap();
        let k2 = WasmHopKeys::from_shared_secret(&secret).unwrap();

        // Deterministic
        assert_eq!(k1.forward_key, k2.forward_key);
        assert_eq!(k1.backward_key, k2.backward_key);
        assert_eq!(k1.forward_nonce_seed, k2.forward_nonce_seed);
        assert_eq!(k1.backward_nonce_seed, k2.backward_nonce_seed);

        // Forward and backward are different
        assert_ne!(k1.forward_key, k1.backward_key);
    }

    #[test]
    fn test_different_secrets_different_keys() {
        let k1 = WasmHopKeys::from_shared_secret(&[1u8; 32]).unwrap();
        let k2 = WasmHopKeys::from_shared_secret(&[2u8; 32]).unwrap();
        assert_ne!(k1.forward_key, k2.forward_key);
    }

    #[test]
    fn test_single_layer_onion_roundtrip() {
        let keys = WasmHopKeys::from_shared_secret(&[1u8; 32]).unwrap();
        let plaintext = b"hello from the originator";

        let encrypted =
            onion_wrap(plaintext, &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap();
        assert_ne!(encrypted, plaintext.to_vec());
        assert_eq!(encrypted.len(), plaintext.len() + AEAD_TAG_SIZE);

        let decrypted =
            onion_peel(&encrypted, &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_three_layer_onion_roundtrip() {
        let hop1 = WasmHopKeys::from_shared_secret(&[1u8; 32]).unwrap();
        let hop2 = WasmHopKeys::from_shared_secret(&[2u8; 32]).unwrap();
        let hop3 = WasmHopKeys::from_shared_secret(&[3u8; 32]).unwrap();
        let hops = [hop1.clone(), hop2.clone(), hop3.clone()];
        let counters = [0u32, 0, 0];

        let plaintext = b"secret message through 3 relays";

        // OP encrypts with 3 layers
        let encrypted = onion_encrypt(plaintext, &hops, &counters).unwrap();

        // Each relay peels one layer (forward direction)
        let after_hop1 =
            onion_peel(&encrypted, &hop1.forward_key, &hop1.forward_nonce_seed, 0).unwrap();
        let after_hop2 =
            onion_peel(&after_hop1, &hop2.forward_key, &hop2.forward_nonce_seed, 0).unwrap();
        let after_hop3 =
            onion_peel(&after_hop2, &hop3.forward_key, &hop3.forward_nonce_seed, 0).unwrap();

        assert_eq!(after_hop3, plaintext);
    }

    #[test]
    fn test_backward_direction() {
        let hop1 = WasmHopKeys::from_shared_secret(&[1u8; 32]).unwrap();
        let hop2 = WasmHopKeys::from_shared_secret(&[2u8; 32]).unwrap();
        let hop3 = WasmHopKeys::from_shared_secret(&[3u8; 32]).unwrap();

        let plaintext = b"response from exit relay";

        // Exit relay (hop3) encrypts with backward key
        let from_hop3 =
            onion_wrap(plaintext, &hop3.backward_key, &hop3.backward_nonce_seed, 0).unwrap();
        let from_hop2 =
            onion_wrap(&from_hop3, &hop2.backward_key, &hop2.backward_nonce_seed, 0).unwrap();
        let from_hop1 =
            onion_wrap(&from_hop2, &hop1.backward_key, &hop1.backward_nonce_seed, 0).unwrap();

        // OP decrypts all layers
        let hops = [hop1, hop2, hop3];
        let counters = [0u32, 0, 0];
        let decrypted = onion_decrypt(&from_hop1, &hops, &counters).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_counter_increments() {
        let keys = WasmHopKeys::from_shared_secret(&[1u8; 32]).unwrap();

        let ct0 = onion_wrap(b"msg0", &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap();
        let ct1 = onion_wrap(b"msg0", &keys.forward_key, &keys.forward_nonce_seed, 1).unwrap();

        // Same plaintext, different counter -> different ciphertext
        assert_ne!(ct0, ct1);

        // Decrypt with correct counter
        assert_eq!(
            onion_peel(&ct0, &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap(),
            b"msg0"
        );
        assert_eq!(
            onion_peel(&ct1, &keys.forward_key, &keys.forward_nonce_seed, 1).unwrap(),
            b"msg0"
        );

        // Wrong counter fails
        assert!(onion_peel(&ct0, &keys.forward_key, &keys.forward_nonce_seed, 1).is_err());
    }

    #[test]
    fn test_tampered_layer_fails() {
        let keys = WasmHopKeys::from_shared_secret(&[1u8; 32]).unwrap();
        let mut encrypted =
            onion_wrap(b"secret", &keys.forward_key, &keys.forward_nonce_seed, 0).unwrap();
        encrypted[0] ^= 0xFF;
        assert!(onion_peel(&encrypted, &keys.forward_key, &keys.forward_nonce_seed, 0).is_err());
    }

    #[test]
    fn test_handshake_create_process_created() {
        // Simulate the full CREATE/CREATED handshake
        let circuit_id = 42;

        // Client side: create
        let (create_cell_val, client_secret) = create_cell(circuit_id);
        assert_eq!(create_cell_val.cell_type, WasmCellType::Create);
        assert_eq!(create_cell_val.circuit_id, circuit_id);

        // Relay side: handle CREATE — generate ephemeral key, do DH, build CREATED
        let relay_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let relay_public = PublicKey::from(&relay_secret);

        // Extract client pubkey from CREATE cell
        let mut client_pub_bytes = [0u8; 32];
        client_pub_bytes.copy_from_slice(&create_cell_val.payload[..32]);
        let client_public = PublicKey::from(client_pub_bytes);

        let shared = relay_secret.diffie_hellman(&client_public);

        // Build CREATED response
        let mut created_payload = [0u8; CELL_PAYLOAD_SIZE];
        created_payload[..32].copy_from_slice(relay_public.as_bytes());
        // HMAC
        let mut mac =
            HmacSha256::new_from_slice(shared.as_bytes()).unwrap();
        mac.update(CREATED_HMAC_LABEL);
        let hmac_result = mac.finalize().into_bytes();
        created_payload[32..64].copy_from_slice(&hmac_result);

        let created_cell = WasmRelayCell {
            circuit_id,
            cell_type: WasmCellType::Created,
            payload: created_payload,
            payload_len: 64,
        };

        // Client processes CREATED
        let client_keys = process_created(&created_cell, &client_secret).unwrap();

        // Relay derives keys from same shared secret
        let relay_keys =
            WasmHopKeys::from_shared_secret(shared.as_bytes()).unwrap();

        assert_eq!(client_keys.forward_key, relay_keys.forward_key);
        assert_eq!(client_keys.backward_key, relay_keys.backward_key);
    }

    #[test]
    fn test_handshake_extend_process_extended() {
        let circuit_id = 55;
        let target = [0xCD; 32];

        // Client creates EXTEND
        let (ext_cell, client_secret) = extend_cell(circuit_id, &target);
        assert_eq!(ext_cell.cell_type, WasmCellType::Extend);
        assert_eq!(&ext_cell.payload[..32], &target);

        // Next-hop relay generates key, does DH
        let relay_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let relay_public = PublicKey::from(&relay_secret);

        // Build EXTENDED response
        let mut extended_payload = [0u8; CELL_PAYLOAD_SIZE];
        extended_payload[..32].copy_from_slice(relay_public.as_bytes());
        let extended_cell = WasmRelayCell {
            circuit_id,
            cell_type: WasmCellType::Extended,
            payload: extended_payload,
            payload_len: 32,
        };

        // Client processes EXTENDED
        let client_keys = process_extended(&extended_cell, &client_secret).unwrap();

        // Relay derives the same keys
        let client_public = PublicKey::from(&client_secret);
        let shared = relay_secret.diffie_hellman(&client_public);
        let relay_keys =
            WasmHopKeys::from_shared_secret(shared.as_bytes()).unwrap();

        assert_eq!(client_keys.forward_key, relay_keys.forward_key);
        assert_eq!(client_keys.backward_key, relay_keys.backward_key);
    }

    #[test]
    fn test_wrap_unwrap_data() {
        let hop1 = WasmHopKeys::from_shared_secret(&[1u8; 32]).unwrap();
        let hop2 = WasmHopKeys::from_shared_secret(&[2u8; 32]).unwrap();
        let hop3 = WasmHopKeys::from_shared_secret(&[3u8; 32]).unwrap();

        let mut circuit = WasmCircuit {
            hop_keys: vec![hop1, hop2, hop3],
            forward_counters: vec![0, 0, 0],
            backward_counters: vec![0, 0, 0],
            circuit_id: 100,
            ws_id: 0,
        };

        let plaintext = b"test data payload";
        let encrypted = circuit.wrap_data(plaintext).unwrap();

        // Counters should have incremented
        assert_eq!(circuit.forward_counters, vec![1, 1, 1]);

        // Simulate relay side: peel layers with forward keys
        let hop1_keys = WasmHopKeys::from_shared_secret(&[1u8; 32]).unwrap();
        let hop2_keys = WasmHopKeys::from_shared_secret(&[2u8; 32]).unwrap();
        let hop3_keys = WasmHopKeys::from_shared_secret(&[3u8; 32]).unwrap();

        let after1 = onion_peel(
            &encrypted,
            &hop1_keys.forward_key,
            &hop1_keys.forward_nonce_seed,
            0,
        )
        .unwrap();
        let after2 = onion_peel(
            &after1,
            &hop2_keys.forward_key,
            &hop2_keys.forward_nonce_seed,
            0,
        )
        .unwrap();
        let after3 = onion_peel(
            &after2,
            &hop3_keys.forward_key,
            &hop3_keys.forward_nonce_seed,
            0,
        )
        .unwrap();

        assert_eq!(after3, plaintext);

        // Now test reverse direction: relays wrap with backward keys
        let response = b"response data";
        let from3 = onion_wrap(
            response,
            &hop3_keys.backward_key,
            &hop3_keys.backward_nonce_seed,
            0,
        )
        .unwrap();
        let from2 = onion_wrap(
            &from3,
            &hop2_keys.backward_key,
            &hop2_keys.backward_nonce_seed,
            0,
        )
        .unwrap();
        let from1 = onion_wrap(
            &from2,
            &hop1_keys.backward_key,
            &hop1_keys.backward_nonce_seed,
            0,
        )
        .unwrap();

        let decrypted = circuit.unwrap_data(&from1).unwrap();
        assert_eq!(decrypted, response);
        assert_eq!(circuit.backward_counters, vec![1, 1, 1]);
    }

    #[test]
    fn test_make_nonce() {
        let seed = [0u8; 12];
        let nonce = make_nonce(&seed, 1);
        assert_eq!(nonce[8..], [0, 0, 0, 1]);

        let nonce2 = make_nonce(&seed, 256);
        assert_eq!(nonce2[8..], [0, 0, 1, 0]);

        // XOR property: same seed + different counter = different nonce
        assert_ne!(make_nonce(&seed, 0), make_nonce(&seed, 1));
    }

    #[test]
    fn test_max_data_payload_constant() {
        // 505 - 3*16 = 457
        assert_eq!(MAX_DATA_PAYLOAD, 457);
    }

    #[test]
    fn test_cell_payload_size_constant() {
        assert_eq!(CELL_SIZE, 512);
        assert_eq!(CELL_HEADER_SIZE, 7);
        assert_eq!(CELL_PAYLOAD_SIZE, 505);
    }

    #[test]
    fn test_hop_keys_compatibility_with_relay() {
        // Ensure our WASM HopKeys derivation matches the relay crate's derivation
        // by using the same HKDF parameters
        let secret = [99u8; 32];
        let wasm_keys = WasmHopKeys::from_shared_secret(&secret).unwrap();

        // Manually derive using the same HKDF call
        let material = hkdf_sha256(&[0u8; 32], &secret, KEY_EXPAND_INFO, 88).unwrap();
        assert_eq!(&wasm_keys.forward_key, &material[0..32]);
        assert_eq!(&wasm_keys.backward_key, &material[32..64]);
        assert_eq!(&wasm_keys.forward_nonce_seed, &material[64..76]);
        assert_eq!(&wasm_keys.backward_nonce_seed, &material[76..88]);
    }
}
