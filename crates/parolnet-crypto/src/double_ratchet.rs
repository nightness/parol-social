//! Double Ratchet protocol implementation.
//!
//! Provides forward secrecy and future secrecy for ongoing message encryption.
//! Initialized from the shared secret produced by X3DH (PNP-002).
//!
//! Each message uses a unique key derived through the ratchet chain.

use crate::aead::ChaCha20Poly1305Cipher;
use crate::kdf::hkdf_sha256;
use crate::{Aead, CryptoError, RatchetHeader, RatchetSession};
use rand::rngs::OsRng;
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum number of skipped message keys to store.
const MAX_SKIP: u32 = 1000;

/// State for an active Double Ratchet session.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DoubleRatchetSession {
    /// Root key — ratcheted on each DH ratchet step.
    root_key: [u8; 32],
    /// Current sending chain key.
    send_chain_key: Option<[u8; 32]>,
    /// Current receiving chain key.
    recv_chain_key: Option<[u8; 32]>,
    /// Our current DH ratchet private key.
    #[zeroize(skip)]
    dh_self: Option<StaticSecret>,
    /// Their current DH ratchet public key.
    #[zeroize(skip)]
    dh_remote: Option<PublicKey>,
    /// Message number in current sending chain.
    send_n: u32,
    /// Message number in current receiving chain.
    recv_n: u32,
    /// Number of messages in previous sending chain.
    previous_send_n: u32,
    /// Skipped message keys: (ratchet_pubkey, message_number) -> message_key
    #[zeroize(skip)]
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl DoubleRatchetSession {
    /// Initialize as the initiator (Alice) after X3DH.
    ///
    /// Alice sends the first message, so she:
    /// - Uses SK as the root key
    /// - Generates her first DH ratchet keypair
    /// - Performs a DH ratchet with Bob's ratchet public key
    pub fn initialize_initiator(
        shared_secret: [u8; 32],
        remote_ratchet_key: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        let dh_self = StaticSecret::random_from_rng(OsRng);
        let dh_remote = PublicKey::from(*remote_ratchet_key);

        // Perform initial DH ratchet
        let dh_output = dh_self.diffie_hellman(&dh_remote);
        let kdf_out = hkdf_sha256(
            &shared_secret,
            dh_output.as_bytes(),
            b"ParolNet_ratchet_v1",
            64,
        )?;

        let mut root_key = [0u8; 32];
        let mut send_chain_key = [0u8; 32];
        root_key.copy_from_slice(&kdf_out[..32]);
        send_chain_key.copy_from_slice(&kdf_out[32..64]);

        Ok(Self {
            root_key,
            send_chain_key: Some(send_chain_key),
            recv_chain_key: None,
            dh_self: Some(dh_self),
            dh_remote: Some(dh_remote),
            send_n: 0,
            recv_n: 0,
            previous_send_n: 0,
            skipped_keys: HashMap::new(),
        })
    }

    /// Initialize as the responder (Bob) after X3DH.
    ///
    /// Bob waits for Alice's first message, which will contain her ratchet key.
    pub fn initialize_responder(
        shared_secret: [u8; 32],
        our_ratchet_secret: StaticSecret,
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            root_key: shared_secret,
            send_chain_key: None,
            recv_chain_key: None,
            dh_self: Some(our_ratchet_secret),
            dh_remote: None,
            send_n: 0,
            recv_n: 0,
            previous_send_n: 0,
            skipped_keys: HashMap::new(),
        })
    }

    /// Get our current ratchet public key.
    pub fn our_ratchet_public_key(&self) -> Option<[u8; 32]> {
        self.dh_self
            .as_ref()
            .map(|s| *PublicKey::from(s).as_bytes())
    }

    /// Perform a DH ratchet step when receiving a new ratchet public key.
    fn dh_ratchet(&mut self, new_remote_key: &[u8; 32]) -> Result<(), CryptoError> {
        let dh_remote = PublicKey::from(*new_remote_key);

        // Derive receiving chain key from current DH
        if let Some(ref dh_self) = self.dh_self {
            let dh_output = dh_self.diffie_hellman(&dh_remote);
            let kdf_out = hkdf_sha256(
                &self.root_key,
                dh_output.as_bytes(),
                b"ParolNet_ratchet_v1",
                64,
            )?;
            self.root_key.copy_from_slice(&kdf_out[..32]);
            let mut recv_ck = [0u8; 32];
            recv_ck.copy_from_slice(&kdf_out[32..64]);
            self.recv_chain_key = Some(recv_ck);
        }

        self.dh_remote = Some(dh_remote);

        // Generate new DH keypair for sending
        let new_dh_self = StaticSecret::random_from_rng(OsRng);
        let dh_output = new_dh_self.diffie_hellman(&dh_remote);
        let kdf_out = hkdf_sha256(
            &self.root_key,
            dh_output.as_bytes(),
            b"ParolNet_ratchet_v1",
            64,
        )?;
        self.root_key.copy_from_slice(&kdf_out[..32]);
        let mut send_ck = [0u8; 32];
        send_ck.copy_from_slice(&kdf_out[32..64]);
        self.send_chain_key = Some(send_ck);
        self.dh_self = Some(new_dh_self);
        self.previous_send_n = self.send_n;
        self.send_n = 0;
        self.recv_n = 0;

        Ok(())
    }

    /// Derive the next message key from a chain key (symmetric ratchet step).
    fn chain_ratchet(chain_key: &mut [u8; 32]) -> Result<[u8; 32], CryptoError> {
        // Message key = HMAC-SHA256(chain_key, 0x01)
        let mk_bytes = hkdf_sha256(chain_key, &[0x01], b"ParolNet_msg_key", 32)?;
        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&mk_bytes);

        // New chain key = HMAC-SHA256(chain_key, 0x02)
        let ck_bytes = hkdf_sha256(chain_key, &[0x02], b"ParolNet_chain_key", 32)?;
        chain_key.copy_from_slice(&ck_bytes);

        Ok(message_key)
    }

    /// Skip message keys for out-of-order delivery.
    fn skip_message_keys(&mut self, remote_key: &[u8; 32], until: u32) -> Result<(), CryptoError> {
        if let Some(ref mut ck) = self.recv_chain_key {
            while self.recv_n < until {
                if self.skipped_keys.len() >= MAX_SKIP as usize {
                    return Err(CryptoError::RatchetError {
                        reason: "too many skipped message keys".into(),
                    });
                }
                let mk = Self::chain_ratchet(ck)?;
                self.skipped_keys.insert((*remote_key, self.recv_n), mk);
                self.recv_n += 1;
            }
        }
        Ok(())
    }
}

impl RatchetSession for DoubleRatchetSession {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<(RatchetHeader, Vec<u8>), CryptoError> {
        let send_ck = self
            .send_chain_key
            .as_mut()
            .ok_or(CryptoError::RatchetError {
                reason: "no sending chain key established".into(),
            })?;

        let message_key = Self::chain_ratchet(send_ck)?;

        let ratchet_pub = self
            .our_ratchet_public_key()
            .ok_or(CryptoError::RatchetError {
                reason: "no DH ratchet key".into(),
            })?;

        let header = RatchetHeader {
            ratchet_key: ratchet_pub,
            previous_chain_length: self.previous_send_n,
            message_number: self.send_n,
        };

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305Cipher::new(&message_key)?;
        // Nonce from message number (per PNP-001: chain_index || seq_number)
        let mut nonce = [0u8; 12];
        nonce[8..12].copy_from_slice(&self.send_n.to_be_bytes());
        let ciphertext = cipher.encrypt(&nonce, plaintext, &header.ratchet_key)?;

        self.send_n += 1;

        Ok((header, ciphertext))
    }

    fn decrypt(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // Check for skipped message key
        if let Some(mk) = self
            .skipped_keys
            .remove(&(header.ratchet_key, header.message_number))
        {
            let cipher = ChaCha20Poly1305Cipher::new(&mk)?;
            let mut nonce = [0u8; 12];
            nonce[8..12].copy_from_slice(&header.message_number.to_be_bytes());
            return cipher.decrypt(&nonce, ciphertext, &header.ratchet_key);
        }

        // Check if we need a DH ratchet step
        let need_dh_ratchet = self
            .dh_remote
            .as_ref()
            .map(|r| *r.as_bytes() != header.ratchet_key)
            .unwrap_or(true);

        if need_dh_ratchet {
            // Skip any remaining messages in the current receiving chain
            if self.dh_remote.is_some() && self.recv_chain_key.is_some() {
                let remote_key = *self.dh_remote.as_ref().unwrap().as_bytes();
                self.skip_message_keys(&remote_key, header.previous_chain_length)?;
            }
            self.dh_ratchet(&header.ratchet_key)?;
        }

        // Skip to the correct message number
        self.skip_message_keys(&header.ratchet_key, header.message_number)?;

        // Derive the message key
        let recv_ck = self
            .recv_chain_key
            .as_mut()
            .ok_or(CryptoError::RatchetError {
                reason: "no receiving chain key".into(),
            })?;
        let message_key = Self::chain_ratchet(recv_ck)?;
        self.recv_n += 1;

        // Decrypt
        let cipher = ChaCha20Poly1305Cipher::new(&message_key)?;
        let mut nonce = [0u8; 12];
        nonce[8..12].copy_from_slice(&header.message_number.to_be_bytes());
        cipher.decrypt(&nonce, ciphertext, &header.ratchet_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_session_pair() -> (DoubleRatchetSession, DoubleRatchetSession) {
        let shared_secret = [0x42u8; 32];

        // Bob generates his initial ratchet keypair
        let bob_ratchet = StaticSecret::random_from_rng(&mut OsRng);
        let bob_ratchet_pub = *PublicKey::from(&bob_ratchet).as_bytes();

        let alice =
            DoubleRatchetSession::initialize_initiator(shared_secret, &bob_ratchet_pub).unwrap();
        let bob = DoubleRatchetSession::initialize_responder(shared_secret, bob_ratchet).unwrap();

        (alice, bob)
    }

    #[test]
    fn test_alice_sends_bob_decrypts() {
        let (mut alice, mut bob) = setup_session_pair();

        let (header, ct) = alice.encrypt(b"hello bob").unwrap();
        let pt = bob.decrypt(&header, &ct).unwrap();
        assert_eq!(pt, b"hello bob");
    }

    #[test]
    fn test_bidirectional() {
        let (mut alice, mut bob) = setup_session_pair();

        // Alice -> Bob
        let (h1, ct1) = alice.encrypt(b"hello").unwrap();
        let pt1 = bob.decrypt(&h1, &ct1).unwrap();
        assert_eq!(pt1, b"hello");

        // Bob -> Alice
        let (h2, ct2) = bob.encrypt(b"hi alice").unwrap();
        let pt2 = alice.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"hi alice");

        // Alice -> Bob again (new ratchet step)
        let (h3, ct3) = alice.encrypt(b"how are you?").unwrap();
        let pt3 = bob.decrypt(&h3, &ct3).unwrap();
        assert_eq!(pt3, b"how are you?");
    }

    #[test]
    fn test_multiple_messages_same_direction() {
        let (mut alice, mut bob) = setup_session_pair();

        let (h1, ct1) = alice.encrypt(b"msg1").unwrap();
        let (h2, ct2) = alice.encrypt(b"msg2").unwrap();
        let (h3, ct3) = alice.encrypt(b"msg3").unwrap();

        // Decrypt in order
        assert_eq!(bob.decrypt(&h1, &ct1).unwrap(), b"msg1");
        assert_eq!(bob.decrypt(&h2, &ct2).unwrap(), b"msg2");
        assert_eq!(bob.decrypt(&h3, &ct3).unwrap(), b"msg3");
    }

    #[test]
    fn test_out_of_order_delivery() {
        let (mut alice, mut bob) = setup_session_pair();

        let (h1, ct1) = alice.encrypt(b"msg1").unwrap();
        let (h2, ct2) = alice.encrypt(b"msg2").unwrap();
        let (h3, ct3) = alice.encrypt(b"msg3").unwrap();

        // Deliver out of order: 3, 1, 2
        assert_eq!(bob.decrypt(&h3, &ct3).unwrap(), b"msg3");
        assert_eq!(bob.decrypt(&h1, &ct1).unwrap(), b"msg1");
        assert_eq!(bob.decrypt(&h2, &ct2).unwrap(), b"msg2");
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (mut alice, mut bob) = setup_session_pair();

        let (header, mut ct) = alice.encrypt(b"secret").unwrap();
        ct[0] ^= 0xFF; // tamper
        assert!(bob.decrypt(&header, &ct).is_err());
    }

    #[test]
    fn test_different_keys_produce_different_ciphertexts() {
        let (mut alice1, _) = setup_session_pair();
        let (mut alice2, _) = setup_session_pair();

        let (_, ct1) = alice1.encrypt(b"same message").unwrap();
        let (_, ct2) = alice2.encrypt(b"same message").unwrap();
        assert_ne!(ct1, ct2); // different session keys
    }
}
