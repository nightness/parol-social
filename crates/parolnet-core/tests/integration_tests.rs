//! Cross-crate integration tests for ParolNet.
//!
//! These tests exercise interactions across the crypto, protocol, relay, and core crates.

use parolnet_core::bootstrap;
use parolnet_core::{ParolNet, ParolNetConfig};
use parolnet_crypto::aead::ChaCha20Poly1305Cipher;
use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use parolnet_crypto::{Aead, IdentityKeyPair, RatchetSession};
use parolnet_protocol::padding::BucketPadding;
use parolnet_protocol::{BUCKET_SIZES, PaddingStrategy};
use parolnet_relay::circuit::EstablishedCircuit;
use parolnet_relay::onion::{self, HopKeys};
use x25519_dalek::{PublicKey, StaticSecret};

/// End-to-end Double Ratchet message exchange between two peers.
///
/// Alice initializes as initiator, Bob as responder.
/// Verifies bidirectional encrypt/decrypt produces correct plaintext.
#[test]
fn test_end_to_end_message_exchange() {
    let shared_secret = [0x42u8; 32];

    // Bob generates his ratchet keypair
    let bob_ratchet_secret = StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
    let bob_ratchet_pub = *PublicKey::from(&bob_ratchet_secret).as_bytes();

    let mut alice = DoubleRatchetSession::initialize_initiator(shared_secret, &bob_ratchet_pub)
        .expect("Alice init failed");
    let mut bob = DoubleRatchetSession::initialize_responder(shared_secret, bob_ratchet_secret)
        .expect("Bob init failed");

    // Alice -> Bob
    let (header, ciphertext) = alice.encrypt(b"hello bob").expect("Alice encrypt failed");
    let plaintext = bob
        .decrypt(&header, &ciphertext)
        .expect("Bob decrypt failed");
    assert_eq!(plaintext, b"hello bob");

    // Bob -> Alice
    let (header2, ciphertext2) = bob.encrypt(b"hi alice").expect("Bob encrypt failed");
    let plaintext2 = alice
        .decrypt(&header2, &ciphertext2)
        .expect("Alice decrypt failed");
    assert_eq!(plaintext2, b"hi alice");
}

/// Bootstrap flow: Alice generates a QR, Bob processes it, both derive the same secret.
#[test]
fn test_bootstrap_to_session() {
    let alice = ParolNet::new(ParolNetConfig::default());
    let bob = ParolNet::new(ParolNetConfig::default());

    // Alice generates a QR payload.
    let qr_data = alice.generate_qr(None).expect("generate_qr failed");

    // Bob processes the scanned QR.
    let (payload, bob_bs) = bob.process_qr(&qr_data).expect("process_qr failed");

    // Alice derives the same bootstrap secret from the seed and both public keys.
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&payload.seed);
    let alice_bs =
        bootstrap::derive_bootstrap_secret(&seed, &alice.public_key(), &bob.public_key())
            .expect("derive_bootstrap_secret failed");

    assert_eq!(
        alice_bs, bob_bs,
        "Alice and Bob must derive the same bootstrap secret"
    );
}

/// Full encrypt-pad-unpad-decrypt cycle across crypto and protocol crates.
#[test]
fn test_envelope_encrypt_pad_encode_decode_unpad() {
    let key = [0xABu8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"secret message";

    // Encrypt with ChaCha20-Poly1305.
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher init failed");
    let ciphertext = cipher
        .encrypt(&nonce, plaintext, &[])
        .expect("encrypt failed");

    // Pad the ciphertext with BucketPadding.
    let padder = BucketPadding;
    let padded = padder.pad(&ciphertext);

    // Verify padded size is one of the defined BUCKET_SIZES.
    assert!(
        BUCKET_SIZES.contains(&padded.len()),
        "padded size {} is not a valid bucket size",
        padded.len()
    );

    // Unpad and verify it matches the ciphertext.
    let unpadded = padder.unpad(&padded).expect("unpad failed");
    assert_eq!(unpadded, ciphertext, "unpadded data must match ciphertext");

    // Decrypt and verify it matches the original plaintext.
    let decrypted = cipher
        .decrypt(&nonce, &unpadded, &[])
        .expect("decrypt failed");
    assert_eq!(decrypted, plaintext, "decrypted data must match plaintext");
}

/// Onion circuit wrap + manual peel: verify 3-layer encryption round-trips.
#[test]
fn test_onion_circuit_data_flow() {
    // Create 3 HopKeys from different shared secrets.
    let hop1 = HopKeys::from_shared_secret(&[1u8; 32]).expect("hop1 key derivation failed");
    let hop2 = HopKeys::from_shared_secret(&[2u8; 32]).expect("hop2 key derivation failed");
    let hop3 = HopKeys::from_shared_secret(&[3u8; 32]).expect("hop3 key derivation failed");

    let circuit =
        EstablishedCircuit::from_hop_keys(vec![hop1.clone(), hop2.clone(), hop3.clone()], 42);

    // Wrap the payload (encrypts 3 layers: hop3 first, then hop2, then hop1 outermost).
    let wrapped = circuit
        .wrap_data(b"circuit payload")
        .expect("wrap_data failed");

    // Manually peel 3 layers in order (hop1 outermost, then hop2, then hop3).
    let after_hop1 = onion::onion_peel(&wrapped, &hop1.forward_key, &hop1.forward_nonce_seed, 0)
        .expect("peel hop1 failed");

    let after_hop2 = onion::onion_peel(&after_hop1, &hop2.forward_key, &hop2.forward_nonce_seed, 0)
        .expect("peel hop2 failed");

    let after_hop3 = onion::onion_peel(&after_hop2, &hop3.forward_key, &hop3.forward_nonce_seed, 0)
        .expect("peel hop3 failed");

    assert_eq!(
        after_hop3, b"circuit payload",
        "final peeled payload must match original"
    );
}
