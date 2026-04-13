//! Bootstrap protocol implementation (PNP-003).
//!
//! QR code / shared secret key exchange with zero registration breadcrumbs.

use crate::CoreError;
use parolnet_crypto::kdf::hkdf_sha256_fixed;
use serde::{Deserialize, Serialize};

/// QR code payload (PNP-003 Section 3.1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QrPayload {
    /// Protocol version (must be 1).
    pub v: u8,
    /// Ed25519 identity public key of the QR presenter.
    #[serde(with = "serde_bytes")]
    pub ik: Vec<u8>,
    /// 256-bit cryptographically random shared secret seed.
    #[serde(with = "serde_bytes")]
    pub seed: Vec<u8>,
    /// X25519 ratchet public key for Double Ratchet initialization.
    #[serde(with = "serde_bytes", default, skip_serializing_if = "Vec::is_empty")]
    pub rk: Vec<u8>,
    /// Optional relay hint (hostname:port).
    pub relay: Option<String>,
    /// Coarsened timestamp (5-minute bucket).
    pub ts: u64,
    /// Network hint: 1=internet relay, 2=LAN, 3=BT.
    pub net: u8,
}

/// Result of QR payload generation, including the ratchet secret for session setup.
pub struct QrGenerationResult {
    /// CBOR-encoded QR payload bytes.
    pub payload_bytes: Vec<u8>,
    /// X25519 ratchet secret key (caller must store for responder session init).
    pub ratchet_secret: [u8; 32],
    /// The random seed used (caller must store to derive bootstrap secret later).
    pub seed: [u8; 32],
}

/// Generate a QR code payload for peer introduction.
///
/// Returns CBOR-encoded bytes plus the ratchet secret key that the presenter
/// must store to later initialize the responder side of the Double Ratchet.
pub fn generate_qr_payload_with_ratchet(
    identity_key: &[u8; 32],
    relay_hint: Option<&str>,
) -> Result<QrGenerationResult, CoreError> {
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);

    // Generate X25519 ratchet keypair for Double Ratchet initialization
    let ratchet_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let ratchet_public = PublicKey::from(&ratchet_secret);

    let now_secs = crate::now_epoch_secs();
    let coarsened = (now_secs / 300) * 300;

    let payload = QrPayload {
        v: 1,
        ik: identity_key.to_vec(),
        seed: seed.to_vec(),
        rk: ratchet_public.as_bytes().to_vec(),
        relay: relay_hint.map(|s| s.to_string()),
        ts: coarsened,
        net: if relay_hint.is_some() { 1 } else { 2 },
    };

    let mut buf = Vec::new();
    ciborium::into_writer(&payload, &mut buf)
        .map_err(|e| CoreError::BootstrapFailed(format!("CBOR encode: {e}")))?;

    Ok(QrGenerationResult {
        payload_bytes: buf,
        ratchet_secret: ratchet_secret.to_bytes(),
        seed,
    })
}

/// Generate a QR code payload for peer introduction (legacy, without ratchet key).
///
/// Returns CBOR-encoded bytes (base45 encoding for actual QR rendering
/// would be applied by the UI layer).
pub fn generate_qr_payload(
    identity_key: &[u8; 32],
    relay_hint: Option<&str>,
) -> Result<Vec<u8>, CoreError> {
    Ok(generate_qr_payload_with_ratchet(identity_key, relay_hint)?.payload_bytes)
}

/// Parse a scanned QR code payload from CBOR bytes.
pub fn parse_qr_payload(data: &[u8]) -> Result<QrPayload, CoreError> {
    let payload: QrPayload = ciborium::from_reader(data)
        .map_err(|e| CoreError::BootstrapFailed(format!("CBOR decode: {e}")))?;

    if payload.v != 1 {
        return Err(CoreError::BootstrapFailed(format!(
            "unsupported version: {}",
            payload.v
        )));
    }
    if payload.ik.len() != 32 {
        return Err(CoreError::BootstrapFailed(
            "identity key must be 32 bytes".into(),
        ));
    }
    if payload.seed.len() != 32 {
        return Err(CoreError::BootstrapFailed("seed must be 32 bytes".into()));
    }
    if !payload.rk.is_empty() && payload.rk.len() != 32 {
        return Err(CoreError::BootstrapFailed(
            "ratchet key must be 32 bytes".into(),
        ));
    }

    Ok(payload)
}

/// Derive the Bootstrap Secret from a seed and both peers' identity keys.
///
/// BS = HKDF-SHA-256(
///   salt = "ParolNet_bootstrap_v1",
///   ikm  = seed,
///   info = sorted_concat(IK_alice, IK_bob),
///   len  = 32
/// )
pub fn derive_bootstrap_secret(
    seed: &[u8; 32],
    our_ik: &[u8; 32],
    their_ik: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    // Sort keys so both peers derive the same secret regardless of who scanned
    let mut info = Vec::with_capacity(64);
    if our_ik < their_ik {
        info.extend_from_slice(our_ik);
        info.extend_from_slice(their_ik);
    } else {
        info.extend_from_slice(their_ik);
        info.extend_from_slice(our_ik);
    }

    hkdf_sha256_fixed::<32>(b"ParolNet_bootstrap_v1", seed, &info)
        .map_err(|e| CoreError::BootstrapFailed(format!("HKDF: {e}")))
}

/// Compute the HMAC proof for bootstrap authentication (PNP-003 Section 5.4).
///
/// proof = HMAC-SHA-256(BS, ik || ek || nonce)
pub fn compute_bootstrap_proof(
    bootstrap_secret: &[u8; 32],
    identity_key: &[u8; 32],
    ephemeral_key: &[u8; 32],
    nonce: &[u8; 16],
) -> Result<[u8; 32], CoreError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(bootstrap_secret)
        .map_err(|_| CoreError::BootstrapFailed("HMAC init failed".into()))?;
    mac.update(identity_key);
    mac.update(ephemeral_key);
    mac.update(nonce);
    Ok(mac.finalize().into_bytes().into())
}

/// Verify a bootstrap proof.
pub fn verify_bootstrap_proof(
    bootstrap_secret: &[u8; 32],
    identity_key: &[u8; 32],
    ephemeral_key: &[u8; 32],
    nonce: &[u8; 16],
    proof: &[u8; 32],
) -> Result<bool, CoreError> {
    use subtle::ConstantTimeEq;
    let expected = compute_bootstrap_proof(bootstrap_secret, identity_key, ephemeral_key, nonce)?;
    Ok(expected.ct_eq(proof).into())
}

/// Compute a Short Authentication String (SAS) for voice verification.
///
/// Returns a 6-digit decimal string.
pub fn compute_sas(
    bootstrap_secret: &[u8; 32],
    ik_alice: &[u8; 32],
    ik_bob: &[u8; 32],
    ek_alice: &[u8; 32],
    ek_bob: &[u8; 32],
) -> Result<String, CoreError> {
    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(ik_alice);
    ikm.extend_from_slice(ik_bob);
    ikm.extend_from_slice(ek_alice);
    ikm.extend_from_slice(ek_bob);

    let material = hkdf_sha256_fixed::<5>(bootstrap_secret, &ikm, b"ParolNet_SAS_v1")
        .map_err(|e| CoreError::BootstrapFailed(format!("SAS HKDF: {e}")))?;

    // Convert 5 bytes (40 bits) to 6-digit decimal: uint40 mod 1000000
    let val = (material[0] as u64) << 32
        | (material[1] as u64) << 24
        | (material[2] as u64) << 16
        | (material[3] as u64) << 8
        | (material[4] as u64);
    let sas = val % 1_000_000;

    Ok(format!("{sas:06}"))
}
