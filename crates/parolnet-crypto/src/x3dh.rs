//! X3DH (Extended Triple Diffie-Hellman) key agreement.
//!
//! Adapted for decentralized use — no central key server required.
//! Pre-key bundles are distributed via the relay network, direct exchange,
//! or the bootstrap protocol (PNP-003).
//!
//! See PNP-002 Section 5.1 for the full specification.

use crate::{
    CryptoError, IdentityKeyPair, KeyAgreement, PreKeyBundle, SharedSecret, X3dhHeader,
    kdf::hkdf_sha256_fixed,
};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X3DH key agreement implementation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X3dhKeyAgreement {
    pub identity: IdentityKeyPair,
}

/// Convert an Ed25519 signing key to an X25519 static secret.
///
/// Uses the clamped scalar from the Ed25519 secret key as the X25519 private key.
/// This is the standard birational map (RFC 8032 Section 5.1.5).
fn ed25519_signing_to_x25519(signing_key: &ed25519_dalek::SigningKey) -> StaticSecret {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::digest(signing_key.as_bytes());
    // Clamp per X25519 spec
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&h[..32]);
    h.zeroize();
    StaticSecret::from(key_bytes)
}

/// Convert an Ed25519 verifying key to an X25519 public key.
fn ed25519_verify_to_x25519(
    verify_key: &ed25519_dalek::VerifyingKey,
) -> Result<X25519Public, CryptoError> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let compressed = CompressedEdwardsY(verify_key.to_bytes());
    let edwards = compressed
        .decompress()
        .ok_or(CryptoError::InvalidPreKeyBundle {
            reason: "failed to decompress Ed25519 public key to Edwards point".into(),
        })?;
    let montgomery = edwards.to_montgomery();
    Ok(X25519Public::from(montgomery.to_bytes()))
}

impl KeyAgreement for X3dhKeyAgreement {
    /// Initiate a handshake with a recipient using their pre-key bundle.
    ///
    /// Computes per PNP-002 Section 5.1:
    /// - DH1 = X25519(IK_a_x25519, SPK_b)
    /// - DH2 = X25519(EK_a, IK_b_x25519)
    /// - DH3 = X25519(EK_a, SPK_b)
    /// - DH4 = X25519(EK_a, OPK_b) — if OPK available
    fn initiate(
        &self,
        recipient_bundle: &PreKeyBundle,
    ) -> Result<(SharedSecret, X3dhHeader), CryptoError> {
        // Verify the signed pre-key signature
        let bob_ik = ed25519_dalek::VerifyingKey::from_bytes(&recipient_bundle.identity_key)
            .map_err(|_| CryptoError::InvalidPreKeyBundle {
                reason: "invalid identity key".into(),
            })?;

        if recipient_bundle.signed_prekey_sig.len() != 64 {
            return Err(CryptoError::InvalidPreKeyBundle {
                reason: "signature must be 64 bytes".into(),
            });
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&recipient_bundle.signed_prekey_sig);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        let mut sign_data = Vec::with_capacity(36);
        sign_data.extend_from_slice(&recipient_bundle.signed_prekey);
        sign_data.extend_from_slice(&recipient_bundle.signed_prekey_id.to_be_bytes());

        use ed25519_dalek::Verifier;
        bob_ik
            .verify(&sign_data, &sig)
            .map_err(|_| CryptoError::InvalidPreKeyBundle {
                reason: "SPK signature verification failed".into(),
            })?;

        // Convert identity keys to X25519
        let ik_a_x25519 = ed25519_signing_to_x25519(&self.identity.signing_key);
        let ik_b_x25519 = ed25519_verify_to_x25519(&bob_ik)?;
        let spk_b = X25519Public::from(recipient_bundle.signed_prekey);

        // Generate ephemeral key
        let ek_a = StaticSecret::random_from_rng(OsRng);
        let ek_a_public = X25519Public::from(&ek_a);

        // Compute DH values
        let dh1 = ik_a_x25519.diffie_hellman(&spk_b);
        let dh2 = ek_a.diffie_hellman(&ik_b_x25519);
        let dh3 = ek_a.diffie_hellman(&spk_b);

        // Build IKM: 0xFF * 32 || DH1 || DH2 || DH3 [|| DH4]
        let mut ikm = Vec::with_capacity(32 + 32 * 4);
        ikm.extend_from_slice(&[0xFF; 32]); // domain separator
        ikm.extend_from_slice(dh1.as_bytes());
        ikm.extend_from_slice(dh2.as_bytes());
        ikm.extend_from_slice(dh3.as_bytes());

        let mut opk_id_used = None;

        if let Some(opk) = recipient_bundle.one_time_prekeys.first() {
            let opk_pub = X25519Public::from(opk.key);
            let dh4 = ek_a.diffie_hellman(&opk_pub);
            ikm.extend_from_slice(dh4.as_bytes());
            opk_id_used = Some(opk.id);
        }

        // Derive shared secret via HKDF
        let sk = hkdf_sha256_fixed::<32>(&[0u8; 32], &ikm, b"ParolNet_X3DH_v1")?;
        ikm.zeroize();

        let header = X3dhHeader {
            identity_key: self.identity.public_key_bytes(),
            ephemeral_key: *ek_a_public.as_bytes(),
            signed_prekey_id: recipient_bundle.signed_prekey_id,
            one_time_prekey_id: opk_id_used,
        };

        Ok((SharedSecret(sk), header))
    }

    /// Respond to an incoming X3DH handshake.
    ///
    /// Bob performs the symmetric DH computation using his private keys.
    fn respond(&self, _header: &X3dhHeader) -> Result<SharedSecret, CryptoError> {
        // This requires Bob's SPK private key and optionally OPK private key,
        // which are stored in the identity/key management layer.
        // The full implementation needs access to the key store.
        Err(CryptoError::NotImplemented {
            feature: "X3DH response (requires key store integration)".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SignedPreKey;
    use crate::{IdentityKeyPair, OneTimePreKey, PreKeyBundle};

    /// Helper to build Bob's pre-key bundle for testing.
    fn make_bob_bundle(
        bob: &IdentityKeyPair,
    ) -> (
        PreKeyBundle,
        SignedPreKey,
        crate::identity::OneTimePreKeyPair,
    ) {
        let spk = SignedPreKey::generate(1, bob).unwrap();
        let opk = crate::identity::OneTimePreKeyPair::generate(100);

        let bundle = PreKeyBundle {
            identity_key: bob.public_key_bytes(),
            signed_prekey: *spk.public_key.as_bytes(),
            signed_prekey_id: spk.id,
            signed_prekey_sig: spk.signature.to_vec(),
            one_time_prekeys: vec![OneTimePreKey {
                id: opk.id,
                key: *opk.public_key.as_bytes(),
            }],
        };
        (bundle, spk, opk)
    }

    #[test]
    fn test_x3dh_initiate_produces_shared_secret() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (bundle, _spk, _opk) = make_bob_bundle(&bob);

        let agreement = X3dhKeyAgreement { identity: alice };
        let (secret, header) = agreement.initiate(&bundle).unwrap();

        assert_eq!(secret.0.len(), 32);
        assert_ne!(secret.0, [0u8; 32]); // should not be all zeros
        assert_eq!(header.signed_prekey_id, 1);
        assert_eq!(header.one_time_prekey_id, Some(100));
    }

    #[test]
    fn test_x3dh_without_opk() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(1, &bob).unwrap();

        let bundle = PreKeyBundle {
            identity_key: bob.public_key_bytes(),
            signed_prekey: *spk.public_key.as_bytes(),
            signed_prekey_id: spk.id,
            signed_prekey_sig: spk.signature.to_vec(),
            one_time_prekeys: vec![], // no OPKs
        };

        let agreement = X3dhKeyAgreement { identity: alice };
        let (secret, header) = agreement.initiate(&bundle).unwrap();

        assert_eq!(secret.0.len(), 32);
        assert_eq!(header.one_time_prekey_id, None);
    }

    #[test]
    fn test_x3dh_rejects_invalid_spk_signature() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (mut bundle, _spk, _opk) = make_bob_bundle(&bob);

        // Corrupt the signature
        bundle.signed_prekey_sig[0] ^= 0xFF;

        let agreement = X3dhKeyAgreement { identity: alice };
        assert!(agreement.initiate(&bundle).is_err());
    }
}
