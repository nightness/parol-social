//! Native-mode tests for parolnet-wasm public API.
//!
//! These tests exercise the wasm-bindgen functions as regular Rust functions.
//! The `#[wasm_bindgen]` attribute is ignored in native compilation.
//!
//! Functions returning `JsValue` or constructing `JsError` on the error path
//! are gated with `#[cfg(target_arch = "wasm32")]` since those types panic
//! on non-wasm targets.

// ── Identity tests ──────────────────────────────────────────

/// generate_identity() should return a 64-character hex string (32 bytes).
#[test]
fn test_wasm_generate_identity_returns_hex() {
    let id = parolnet_wasm::generate_identity();
    assert_eq!(
        id.len(),
        64,
        "PeerId hex should be 64 chars, got {}",
        id.len()
    );
    assert!(
        id.chars().all(|c| c.is_ascii_hexdigit()),
        "PeerId should contain only hex characters, got: {}",
        id
    );
}

/// version() should return a non-empty string.
#[test]
fn test_wasm_version_not_empty() {
    let v = parolnet_wasm::version();
    assert!(!v.is_empty(), "version() must not be empty");
}

/// panic_wipe() should not panic.
#[test]
fn test_wasm_panic_wipe_does_not_panic() {
    parolnet_wasm::panic_wipe();
}

// ── Initialization tests ────────────────────────────────────

/// initialize() should return a 64-char hex peer_id.
#[test]
fn test_wasm_initialize_returns_peer_id() {
    let peer_id = parolnet_wasm::initialize();
    assert_eq!(
        peer_id.len(),
        64,
        "initialize() should return 64-char hex, got {} chars",
        peer_id.len()
    );
    assert!(
        peer_id.chars().all(|c| c.is_ascii_hexdigit()),
        "peer_id should be hex, got: {}",
        peer_id
    );
}

// ── Session tests ───────────────────────────────────────────

/// After initialization, session_count() should be 0.
#[test]
fn test_wasm_session_count_starts_zero() {
    parolnet_wasm::initialize();
    let count = parolnet_wasm::session_count();
    assert_eq!(count, 0, "session_count should be 0, got {count}");
}

/// has_session for a random peer_id should return false before any session is created.
#[test]
fn test_wasm_has_session_false_before_create() {
    parolnet_wasm::initialize();
    let random_peer = "aa".repeat(32);
    assert!(
        !parolnet_wasm::has_session(&random_peer),
        "has_session should be false for a random peer before create_session"
    );
}

// ── File transfer tests ─────────────────────────────────────

/// create_file_transfer should return a 32-char hex file_id (16 bytes).
///
/// Gated to wasm32 because create_file_transfer returns Result<String, JsError>
/// and JsError construction may panic on non-wasm targets when the error path
/// is taken. However, the success path does not construct JsError, so we test it
/// natively by accepting that JsError::new would panic only if we hit the error
/// path.
#[test]
fn test_wasm_file_transfer_create() {
    let data = b"hello parolnet file transfer";
    let result = parolnet_wasm::create_file_transfer(data, "test.txt", None);
    // On native targets, JsError in the Ok path is fine (it's only constructed in Err)
    // The Result type still works, we just can't unwrap an Err.
    let file_id = result.expect("create_file_transfer should succeed");
    assert_eq!(
        file_id.len(),
        32,
        "file_id hex should be 32 chars (16 bytes), got {} chars",
        file_id.len()
    );
    assert!(
        file_id.chars().all(|c| c.is_ascii_hexdigit()),
        "file_id should be hex, got: {}",
        file_id
    );
}

// ── Unlock code / decoy tests ───────────────────────────────

/// Setting and verifying an unlock code with the correct code should return true.
#[test]
fn test_wasm_unlock_code_default() {
    // Reset state first
    parolnet_wasm::panic_wipe();

    parolnet_wasm::set_unlock_code("00000").expect("set_unlock_code should succeed");
    assert!(
        parolnet_wasm::verify_unlock_code("00000"),
        "verify_unlock_code should return true for the correct code"
    );
}

/// Verifying with the wrong code should return false.
#[test]
fn test_wasm_unlock_code_wrong() {
    // Reset state first
    parolnet_wasm::panic_wipe();

    parolnet_wasm::set_unlock_code("12345").expect("set_unlock_code should succeed");
    assert!(
        !parolnet_wasm::verify_unlock_code("99999"),
        "verify_unlock_code should return false for the wrong code"
    );
}

/// is_decoy_enabled() should return false when no unlock code has been set.
#[test]
fn test_wasm_decoy_not_enabled_by_default() {
    // Reset state to ensure no unlock code is set
    parolnet_wasm::panic_wipe();
    assert!(
        !parolnet_wasm::is_decoy_enabled(),
        "is_decoy_enabled should be false by default"
    );
}

// ── Bootstrap tests (kept from original) ────────────────────

/// QR payload round-trip: generate then parse should both succeed.
///
/// Gated to wasm32 only because `parse_qr_payload` returns `JsValue`.
#[test]
#[cfg(target_arch = "wasm32")]
fn test_wasm_qr_payload_roundtrip() {
    let key_hex = "aa".repeat(32);
    let encoded = parolnet_wasm::generate_qr_payload(&key_hex, None)
        .expect("generate_qr_payload should succeed");

    let parsed = parolnet_wasm::parse_qr_payload(&encoded);
    assert!(
        parsed.is_ok(),
        "parse_qr_payload should succeed: {:?}",
        parsed.err()
    );
}

/// compute_sas with valid 64-char hex strings should return Ok with a 6-char string.
#[test]
fn test_wasm_decode_32_valid() {
    let hex_a = "aa".repeat(32);
    let hex_b = "bb".repeat(32);
    let hex_c = "cc".repeat(32);
    let hex_d = "dd".repeat(32);
    let hex_e = "ee".repeat(32);

    let result = parolnet_wasm::compute_sas(&hex_a, &hex_b, &hex_c, &hex_d, &hex_e);
    assert!(
        result.is_ok(),
        "compute_sas should succeed: {:?}",
        result.err()
    );
    let sas = result.unwrap();
    assert_eq!(sas.len(), 6, "SAS should be 6 chars, got {}", sas.len());
    assert!(
        sas.chars().all(|c| c.is_ascii_digit()),
        "SAS should be all digits, got: {}",
        sas
    );
}

/// compute_sas with a short hex string should return Err.
///
/// Gated to wasm32 because the error path constructs JsError.
#[test]
#[cfg(target_arch = "wasm32")]
fn test_wasm_decode_32_invalid_length() {
    let valid = "aa".repeat(32);
    let short = "abcd";

    let result = parolnet_wasm::compute_sas(short, &valid, &valid, &valid, &valid);
    assert!(result.is_err(), "compute_sas should fail with short input");
}
