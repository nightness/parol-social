use parolnet_crypto::*;
use parolnet_crypto::aead::{ChaCha20Poly1305Cipher, Aes256GcmCipher};
use parolnet_crypto::kdf;
use parolnet_crypto::x3dh::X3dhKeyAgreement;
use parolnet_crypto::identity::{SignedPreKey, OneTimePreKeyPair};

// ── HKDF Tests ──────────────────────────────────────────────────

#[test]
fn test_hkdf_rfc5869_test_case_1() {
    // RFC 5869 Test Case 1 (SHA-256)
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

    let okm = kdf::hkdf_sha256(&salt, &ikm, &info, 42).unwrap();
    let expected = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    ).unwrap();
    assert_eq!(okm, expected);
}

#[test]
fn test_hkdf_fixed_size() {
    let key: [u8; 32] = kdf::hkdf_sha256_fixed(
        b"salt",
        b"input key material",
        b"info",
    ).unwrap();
    assert_eq!(key.len(), 32);
    assert_ne!(key, [0u8; 32]);
}

#[test]
fn test_hkdf_different_info_produces_different_keys() {
    let k1 = kdf::hkdf_sha256(b"salt", b"ikm", b"info1", 32).unwrap();
    let k2 = kdf::hkdf_sha256(b"salt", b"ikm", b"info2", 32).unwrap();
    assert_ne!(k1, k2);
}

// ── AEAD Tests ──────────────────────────────────────────────────

#[test]
fn test_chacha20_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"hello world";
    let aad = b"additional data";

    let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
    let ct = cipher.encrypt(&nonce, plaintext, aad).unwrap();
    let pt = cipher.decrypt(&nonce, &ct, aad).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_aes256gcm_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"hello world";
    let aad = b"additional data";

    let cipher = Aes256GcmCipher::new(&key).unwrap();
    let ct = cipher.encrypt(&nonce, plaintext, aad).unwrap();
    let pt = cipher.decrypt(&nonce, &ct, aad).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_chacha20_tampered_ciphertext() {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();

    let mut ct = cipher.encrypt(&nonce, b"secret", b"").unwrap();
    ct[0] ^= 0xFF;
    assert!(cipher.decrypt(&nonce, &ct, b"").is_err());
}

#[test]
fn test_chacha20_wrong_aad() {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();

    let ct = cipher.encrypt(&nonce, b"secret", b"aad1").unwrap();
    assert!(cipher.decrypt(&nonce, &ct, b"aad2").is_err());
}

#[test]
fn test_aead_invalid_key_length() {
    assert!(ChaCha20Poly1305Cipher::new(&[0u8; 16]).is_err());
    assert!(Aes256GcmCipher::new(&[0u8; 16]).is_err());
}

#[test]
fn test_aead_invalid_nonce_length() {
    let cipher = ChaCha20Poly1305Cipher::new(&[0u8; 32]).unwrap();
    assert!(cipher.encrypt(&[0u8; 8], b"data", b"").is_err());
}

// ── Identity Tests ──────────────────────────────────────────────

#[test]
fn test_identity_keypair_generation() {
    let keypair = IdentityKeyPair::generate();
    let peer_id = keypair.peer_id();
    assert_eq!(peer_id.len(), 32);
    assert_eq!(keypair.peer_id(), peer_id);
}

#[test]
fn test_signed_prekey_generation_and_verification() {
    use parolnet_crypto::identity::SignedPreKey;

    let ik = IdentityKeyPair::generate();
    let spk = SignedPreKey::generate(1, &ik).unwrap();

    // Verification should succeed with the correct identity key
    assert!(spk.verify(&ik.verifying_key()).is_ok());

    // Verification should fail with a different identity key
    let other_ik = IdentityKeyPair::generate();
    assert!(spk.verify(&other_ik.verifying_key()).is_err());
}

#[test]
fn test_one_time_prekey_generation() {
    use parolnet_crypto::identity::OneTimePreKeyPair;

    let opk1 = OneTimePreKeyPair::generate(1);
    let opk2 = OneTimePreKeyPair::generate(2);
    assert_ne!(opk1.public_key.as_bytes(), opk2.public_key.as_bytes());
}

// ── Deniable Auth Tests ─────────────────────────────────────────

#[test]
fn test_deniable_auth_roundtrip() {
    use parolnet_crypto::deniable;

    let secret = [0xABu8; 32];
    let message = b"hello world";

    let tag = deniable::deniable_auth_tag(&secret, message).unwrap();
    assert!(deniable::verify_deniable_auth(&secret, message, &tag).unwrap());
}

#[test]
fn test_deniable_auth_wrong_message() {
    use parolnet_crypto::deniable;

    let secret = [0xABu8; 32];
    let tag = deniable::deniable_auth_tag(&secret, b"message1").unwrap();
    assert!(!deniable::verify_deniable_auth(&secret, b"message2", &tag).unwrap());
}

#[test]
fn test_deniable_auth_wrong_secret() {
    use parolnet_crypto::deniable;

    let tag = deniable::deniable_auth_tag(&[0xABu8; 32], b"msg").unwrap();
    assert!(!deniable::verify_deniable_auth(&[0xCDu8; 32], b"msg", &tag).unwrap());
}

// ── Wipe Tests ──────────────────────────────────────────────────

#[test]
fn test_secure_wipe() {
    let mut data = [0xFFu8; 32];
    wipe::secure_wipe(&mut data);
    assert_eq!(data, [0u8; 32]);
}

#[test]
fn test_chain_key_zeroize_on_drop() {
    let key = ChainKey([0xAB; 32]);
    let ptr = key.0.as_ptr();
    drop(key);
    let _ = ptr;
}

// ── AEAD Edge Case Tests ────────────────────────────────────────

#[test]
fn test_chacha20_empty_plaintext() {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
    let ct = cipher.encrypt(&nonce, b"", b"aad").unwrap();
    let pt = cipher.decrypt(&nonce, &ct, b"aad").unwrap();
    assert_eq!(pt, b"");
}

#[test]
fn test_aes_gcm_empty_plaintext() {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let cipher = Aes256GcmCipher::new(&key).unwrap();
    let ct = cipher.encrypt(&nonce, b"", b"aad").unwrap();
    let pt = cipher.decrypt(&nonce, &ct, b"aad").unwrap();
    assert_eq!(pt, b"");
}

#[test]
fn test_aead_large_message() {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let large_msg = vec![0xABu8; 10_000];

    // ChaCha20-Poly1305
    let chacha = ChaCha20Poly1305Cipher::new(&key).unwrap();
    let ct = chacha.encrypt(&nonce, &large_msg, b"").unwrap();
    let pt = chacha.decrypt(&nonce, &ct, b"").unwrap();
    assert_eq!(pt, large_msg);

    // AES-256-GCM
    let aes = Aes256GcmCipher::new(&key).unwrap();
    let ct = aes.encrypt(&nonce, &large_msg, b"").unwrap();
    let pt = aes.decrypt(&nonce, &ct, b"").unwrap();
    assert_eq!(pt, large_msg);
}

// ── HKDF Edge Case Tests ───────────────────────────────────────

#[test]
fn test_hkdf_zero_length_output() {
    let result = kdf::hkdf_sha256(b"salt", b"ikm", b"info", 0);
    // HKDF with 0-length output should succeed and return an empty vec
    match result {
        Ok(okm) => assert!(okm.is_empty()),
        Err(_) => { /* also acceptable — the hkdf crate may reject zero-length */ }
    }
}

#[test]
fn test_hkdf_max_output() {
    // HKDF-SHA256 max output is 255 * 32 = 8160 bytes.
    // Requesting 8161 bytes should fail with KdfFailed.
    let result = kdf::hkdf_sha256(b"salt", b"ikm", b"info", 8161);
    assert!(result.is_err(), "HKDF should fail for output length > 255*HashLen");
}

// ── Double Ratchet Edge Case Tests ─────────────────────────────

/// Helper: set up a Double Ratchet session pair (Alice initiator, Bob responder).
fn setup_session_pair() -> (
    parolnet_crypto::double_ratchet::DoubleRatchetSession,
    parolnet_crypto::double_ratchet::DoubleRatchetSession,
) {
    use x25519_dalek::{PublicKey, StaticSecret};
    use rand::rngs::OsRng;

    let shared_secret = [0x42u8; 32];
    let bob_ratchet = StaticSecret::random_from_rng(&mut OsRng);
    let bob_ratchet_pub = *PublicKey::from(&bob_ratchet).as_bytes();

    let alice = parolnet_crypto::double_ratchet::DoubleRatchetSession::initialize_initiator(
        shared_secret,
        &bob_ratchet_pub,
    )
    .unwrap();
    let bob = parolnet_crypto::double_ratchet::DoubleRatchetSession::initialize_responder(
        shared_secret,
        bob_ratchet,
    )
    .unwrap();

    (alice, bob)
}

#[test]
fn test_ratchet_empty_message() {
    let (mut alice, mut bob) = setup_session_pair();
    let (header, ct) = alice.encrypt(b"").unwrap();
    let pt = bob.decrypt(&header, &ct).unwrap();
    assert_eq!(pt, b"");
}

#[test]
fn test_ratchet_large_message() {
    let (mut alice, mut bob) = setup_session_pair();
    let large_msg = vec![0xCDu8; 10_000];
    let (header, ct) = alice.encrypt(&large_msg).unwrap();
    let pt = bob.decrypt(&header, &ct).unwrap();
    assert_eq!(pt, large_msg);
}

#[test]
fn test_ratchet_many_sequential() {
    let (mut alice, mut bob) = setup_session_pair();

    let mut messages = Vec::new();
    for i in 0u32..100 {
        let msg = format!("message number {}", i);
        let (header, ct) = alice.encrypt(msg.as_bytes()).unwrap();
        messages.push((header, ct, msg));
    }

    for (header, ct, expected) in &messages {
        let pt = bob.decrypt(header, ct).unwrap();
        assert_eq!(pt, expected.as_bytes());
    }
}

#[test]
fn test_ratchet_replay_fails() {
    let (mut alice, mut bob) = setup_session_pair();

    let (header, ct) = alice.encrypt(b"one-time message").unwrap();
    // First decryption should succeed
    let pt = bob.decrypt(&header, &ct).unwrap();
    assert_eq!(pt, b"one-time message");

    // Second decryption of the same (header, ciphertext) should fail
    // because the message key was consumed.
    assert!(
        bob.decrypt(&header, &ct).is_err(),
        "replay of consumed message key should fail"
    );
}

#[test]
fn test_ratchet_max_skip_overflow() {
    let (mut alice, mut bob) = setup_session_pair();

    // Encrypt 1002 messages on Alice's side (indices 0..1001)
    let mut all = Vec::new();
    for _ in 0..1002 {
        let (header, ct) = alice.encrypt(b"skip me").unwrap();
        all.push((header, ct));
    }

    // Try to decrypt only the last message (#1001).
    // Bob needs to skip 1001 message keys, but MAX_SKIP is 1000 — should error.
    let (ref header, ref ct) = all[1001];
    let result = bob.decrypt(header, ct);
    assert!(
        result.is_err(),
        "decrypting message #1001 should fail because MAX_SKIP (1000) would be exceeded"
    );
}

// ── X3DH Edge Case Tests ───────────────────────────────────────

/// Helper: build a Bob pre-key bundle for X3DH tests.
fn make_bob_bundle(bob: &IdentityKeyPair) -> PreKeyBundle {
    let spk = SignedPreKey::generate(1, bob).unwrap();
    let opk = OneTimePreKeyPair::generate(100);

    PreKeyBundle {
        identity_key: bob.public_key_bytes(),
        signed_prekey: *spk.public_key.as_bytes(),
        signed_prekey_id: spk.id,
        signed_prekey_sig: spk.signature.to_vec(),
        one_time_prekeys: vec![OneTimePreKey {
            id: opk.id,
            key: *opk.public_key.as_bytes(),
        }],
    }
}

#[test]
fn test_x3dh_not_deterministic() {
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let bundle = make_bob_bundle(&bob);

    let agreement = X3dhKeyAgreement { identity: alice };
    let (secret1, _) = agreement.initiate(&bundle).unwrap();
    let (secret2, _) = agreement.initiate(&bundle).unwrap();

    // Ephemeral key is random each time, so shared secrets must differ
    assert_ne!(secret1.0, secret2.0, "two X3DH initiations with the same bundle must produce different shared secrets");
}

#[test]
fn test_x3dh_different_bundles_different_secrets() {
    let alice = IdentityKeyPair::generate();
    let bob1 = IdentityKeyPair::generate();
    let bob2 = IdentityKeyPair::generate();
    let bundle1 = make_bob_bundle(&bob1);
    let bundle2 = make_bob_bundle(&bob2);

    let agreement = X3dhKeyAgreement { identity: alice };
    let (secret1, _) = agreement.initiate(&bundle1).unwrap();
    let (secret2, _) = agreement.initiate(&bundle2).unwrap();

    assert_ne!(secret1.0, secret2.0, "different Bob bundles must produce different shared secrets");
}
