//! Native-mode tests for parolnet-wasm public API.
//!
//! These tests exercise the wasm-bindgen functions as regular Rust functions.
//! The `#[wasm_bindgen]` attribute is ignored in native compilation.
//!
//! Some functions return `JsValue` or construct `JsError` on the error path,
//! which panics on non-wasm targets. Those tests are gated with
//! `#[cfg(target_arch = "wasm32")]`.

/// generate_identity() should return a 64-character hex string (32 bytes).
#[test]
fn test_wasm_generate_identity_returns_hex() {
    let id = parolnet_wasm::generate_identity();
    assert_eq!(id.len(), 64, "PeerId hex should be 64 chars, got {}", id.len());
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

/// panic_wipe() is currently a no-op but must not panic.
#[test]
fn test_wasm_panic_wipe_does_not_panic() {
    // Should complete without panicking.
    parolnet_wasm::panic_wipe();
}

/// QR payload round-trip: generate then parse should both succeed.
///
/// Gated to wasm32 only because `parse_qr_payload` returns `JsValue`,
/// which requires wasm-bindgen imported functions unavailable on native targets.
#[test]
#[cfg(target_arch = "wasm32")]
fn test_wasm_qr_payload_roundtrip() {
    let key_hex = "aa".repeat(32);
    let encoded = parolnet_wasm::generate_qr_payload(&key_hex, None)
        .expect("generate_qr_payload should succeed");

    let parsed = parolnet_wasm::parse_qr_payload(&encoded);
    assert!(parsed.is_ok(), "parse_qr_payload should succeed: {:?}", parsed.err());
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
    assert!(result.is_ok(), "compute_sas should succeed: {:?}", result.err());
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
/// Gated to wasm32 only because `JsError::new()` panics on non-wasm targets
/// when the error path is taken.
#[test]
#[cfg(target_arch = "wasm32")]
fn test_wasm_decode_32_invalid_length() {
    let valid = "aa".repeat(32);
    let short = "abcd"; // only 2 bytes, not 32

    let result = parolnet_wasm::compute_sas(short, &valid, &valid, &valid, &valid);
    assert!(result.is_err(), "compute_sas should fail with short input");
}
