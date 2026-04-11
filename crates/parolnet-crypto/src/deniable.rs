//! Deniable authentication primitives.
//!
//! Provides mechanisms for deniable communication where neither party
//! can prove to a third party that a conversation took place.
//!
//! Uses HMAC-SHA-256 over a shared secret — the verifier can compute
//! the same tag, so the tag cannot serve as proof of authorship to
//! a third party.

use crate::CryptoError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Generate a deniable authentication tag.
///
/// Unlike a signature, this tag can be forged by the verifier,
/// preventing non-repudiation.
pub fn deniable_auth_tag(
    shared_secret: &[u8; 32],
    message: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let mut mac = HmacSha256::new_from_slice(shared_secret).map_err(|_| CryptoError::KdfFailed)?;
    mac.update(message);
    let result = mac.finalize();
    Ok(result.into_bytes().into())
}

/// Verify a deniable authentication tag in constant time.
pub fn verify_deniable_auth(
    shared_secret: &[u8; 32],
    message: &[u8],
    tag: &[u8; 32],
) -> Result<bool, CryptoError> {
    let expected = deniable_auth_tag(shared_secret, message)?;
    Ok(expected.ct_eq(tag).into())
}
