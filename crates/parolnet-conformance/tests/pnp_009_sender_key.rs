//! PNP-009 conformance — group sender-key chain.

use parolnet_clause::clause;
use parolnet_crypto::sender_key::{SenderKeyMessage, SenderKeyState};

// -- §6.1 Symmetric encryption + chain advance ---------------------------------

#[clause("PNP-009-MUST-003", "PNP-009-MUST-008")]
#[test]
fn sender_encrypts_and_receiver_decrypts() {
    let mut sender = SenderKeyState::new();
    let dist = sender.create_distribution([0xAA; 32]);
    let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

    let msg = sender.encrypt(b"hello group").unwrap();
    let out = receiver.decrypt(&msg).unwrap();
    assert_eq!(out, b"hello group");
}

// -- §6.1 Chain advance — two encrypts produce distinct chain_index ------------

#[clause("PNP-009-MUST-007")]
#[test]
fn chain_index_advances_per_message() {
    let mut sender = SenderKeyState::new();
    let m1 = sender.encrypt(b"one").unwrap();
    let m2 = sender.encrypt(b"two").unwrap();
    let m3 = sender.encrypt(b"three").unwrap();
    assert_eq!(m1.chain_index, 0);
    assert_eq!(m2.chain_index, 1);
    assert_eq!(m3.chain_index, 2);
}

// -- §6.2 Out-of-order decrypt via stored skipped keys -------------------------

#[clause("PNP-009-MUST-012", "PNP-009-MUST-013", "PNP-009-MUST-015")]
#[test]
fn out_of_order_delivery_with_skipped_keys() {
    let mut sender = SenderKeyState::new();
    let dist = sender.create_distribution([0xAA; 32]);
    let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

    let m1 = sender.encrypt(b"one").unwrap();
    let m2 = sender.encrypt(b"two").unwrap();
    let m3 = sender.encrypt(b"three").unwrap();

    // Deliver 3, then 1, then 2 — all MUST decrypt correctly.
    assert_eq!(receiver.decrypt(&m3).unwrap(), b"three");
    assert_eq!(receiver.decrypt(&m1).unwrap(), b"one");
    assert_eq!(receiver.decrypt(&m2).unwrap(), b"two");
}

// -- §6.2 Stored key deleted after use (MUST-016) ------------------------------
// Re-delivering the same ciphertext after consuming its stored key must fail.

#[clause("PNP-009-MUST-016", "PNP-009-MUST-018")]
#[test]
fn stored_skipped_key_deleted_after_use() {
    let mut sender = SenderKeyState::new();
    let dist = sender.create_distribution([0xAA; 32]);
    let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

    let m1 = sender.encrypt(b"one").unwrap();
    let m2 = sender.encrypt(b"two").unwrap();

    receiver.decrypt(&m2).unwrap();
    receiver.decrypt(&m1).unwrap();

    // Re-delivery of m1 after its stored key was consumed MUST fail.
    receiver.decrypt(&m1).expect_err(
        "MUST-016 / MUST-018: replay after key deletion must be rejected",
    );
}

// -- §6.2 MAX_SKIP = 1000 resource cap ----------------------------------------

#[clause("PNP-009-MUST-014")]
#[test]
fn skip_beyond_max_is_rejected() {
    let mut sender = SenderKeyState::new();
    let dist = sender.create_distribution([0xAA; 32]);
    let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

    // Consume 1002 messages on the sender, then try to decrypt only the last
    // one on the receiver — skip count = 1001 > MAX_SKIP.
    let mut last: Option<SenderKeyMessage> = None;
    for _ in 0..1002 {
        last = Some(sender.encrypt(b"x").unwrap());
    }
    let last = last.unwrap();
    receiver
        .decrypt(&last)
        .expect_err("MUST-014: skip > MAX_SKIP (1000) MUST be rejected");
}

// -- §6.1 Signature verification on ciphertext --------------------------------

#[clause("PNP-009-MUST-010", "PNP-009-MUST-011")]
#[test]
fn tampered_ciphertext_is_rejected_via_signature_check() {
    let mut sender = SenderKeyState::new();
    let dist = sender.create_distribution([0xAA; 32]);
    let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

    let mut m = sender.encrypt(b"payload").unwrap();
    m.ciphertext[0] ^= 0xFF;
    receiver
        .decrypt(&m)
        .expect_err("MUST-011: tampered ciphertext MUST fail signature verification");
}

#[clause("PNP-009-MUST-011")]
#[test]
fn tampered_signature_is_rejected() {
    let mut sender = SenderKeyState::new();
    let dist = sender.create_distribution([0xAA; 32]);
    let mut receiver = SenderKeyState::from_distribution(&dist).unwrap();

    let mut m = sender.encrypt(b"payload").unwrap();
    m.signature[0] ^= 0xFF;
    receiver
        .decrypt(&m)
        .expect_err("MUST-011: tampered signature MUST fail verification");
}

// -- §7 Sender key rotation --------------------------------------------------

#[clause("PNP-009-MUST-028", "PNP-009-MUST-030")]
#[test]
fn rotate_resets_chain_and_discards_old_state() {
    let mut sender = SenderKeyState::new();
    // Emit a few messages to advance chain_index.
    sender.encrypt(b"a").unwrap();
    sender.encrypt(b"b").unwrap();
    sender.encrypt(b"c").unwrap();

    let pre = sender.create_distribution([0xAA; 32]);
    assert_eq!(pre.chain_index, 3);

    sender.rotate();

    let post = sender.create_distribution([0xAA; 32]);
    assert_eq!(
        post.chain_index, 0,
        "MUST-030: rotate MUST reset chain index to 0"
    );
    assert_ne!(
        pre.chain_key, post.chain_key,
        "MUST-028: rotate MUST generate a new chain key"
    );
}

// -- §6.1 Nonce construction — per PNP-001 §9 scheme N-SENDERKEY --------------
// The library derives nonce = SHA-256(signing_pubkey)[0..8] || chain_index.be.
// Two senders with different signing keys MUST therefore produce distinct
// ciphertext streams even with identical chain_index values.

#[clause("PNP-009-MUST-009")]
#[test]
fn two_senders_produce_distinct_nonces_and_ciphertexts() {
    let mut s1 = SenderKeyState::new();
    let mut s2 = SenderKeyState::new();
    let m1 = s1.encrypt(b"same plaintext").unwrap();
    let m2 = s2.encrypt(b"same plaintext").unwrap();
    assert_eq!(m1.chain_index, m2.chain_index);
    assert_ne!(
        m1.ciphertext, m2.ciphertext,
        "N-SENDERKEY nonce depends on signing pubkey — distinct senders MUST diverge"
    );
}
