//! # parolnet-core
//!
//! Top-level ParolNet client library.
//!
//! Provides the public API for:
//! - Bootstrap (QR code / shared secret, no phone/email ever)
//! - Session management (open, send, receive)
//! - Panic wipe (securely erase all state)
//! - Decoy mode (fake app UI for plausible deniability)
//! - C FFI for mobile integration

mod time_compat;
pub(crate) use time_compat::*;

#[cfg(feature = "native")]
pub mod audio;
pub mod bootstrap;
pub mod call;
pub mod client;
pub mod config;
pub mod decoy;
pub mod error;
pub mod ffi;
pub mod file_transfer;
pub mod group;
pub mod group_call;
pub mod panic;
pub mod session;
#[cfg(feature = "native")]
pub mod video;

pub use config::ParolNetConfig;
pub use error::CoreError;

use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use parolnet_crypto::{IdentityKeyPair, RatchetHeader, SharedSecret};
use parolnet_protocol::address::PeerId;
use session::SessionManager;
use std::sync::Arc;

/// The main ParolNet client handle.
pub struct ParolNet {
    /// Our identity keypair.
    identity: IdentityKeyPair,
    /// Our PeerId.
    peer_id: PeerId,
    /// Active sessions with peers.
    sessions: Arc<SessionManager>,
    /// Configuration.
    config: ParolNetConfig,
    /// Decoy mode state.
    decoy_state: decoy::DecoyState,
    /// Group manager.
    group_manager: Arc<group::GroupManager>,
    /// Group call manager.
    group_call_manager: Arc<group_call::GroupCallManager>,
}

impl ParolNet {
    /// Create a new ParolNet instance with a fresh identity.
    pub fn new(config: ParolNetConfig) -> Self {
        let identity = IdentityKeyPair::generate();
        let peer_id = PeerId::from_public_key(&identity.public_key_bytes());

        Self {
            identity,
            peer_id,
            sessions: Arc::new(SessionManager::new()),
            decoy_state: if config.decoy_mode {
                decoy::DecoyState::Active
            } else {
                decoy::DecoyState::Normal
            },
            config,
            group_manager: Arc::new(group::GroupManager::new()),
            group_call_manager: Arc::new(group_call::GroupCallManager::new()),
        }
    }

    /// Create a ParolNet instance from an existing identity keypair.
    /// Used to restore a previously saved identity.
    pub fn from_identity(config: ParolNetConfig, identity: IdentityKeyPair) -> Self {
        let peer_id = PeerId::from_public_key(&identity.public_key_bytes());
        Self {
            identity,
            peer_id,
            sessions: Arc::new(SessionManager::new()),
            decoy_state: if config.decoy_mode {
                decoy::DecoyState::Active
            } else {
                decoy::DecoyState::Normal
            },
            config,
            group_manager: Arc::new(group::GroupManager::new()),
            group_call_manager: Arc::new(group_call::GroupCallManager::new()),
        }
    }

    /// Export the identity secret key bytes for persistence.
    pub fn export_identity_secret(&self) -> [u8; 32] {
        self.identity.secret_bytes()
    }

    /// Get our PeerId.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Get our public key bytes.
    pub fn public_key(&self) -> [u8; 32] {
        self.identity.public_key_bytes()
    }

    /// Generate a QR payload for peer introduction.
    pub fn generate_qr(&self, relay_hint: Option<&str>) -> Result<Vec<u8>, CoreError> {
        bootstrap::generate_qr_payload(&self.identity.public_key_bytes(), relay_hint)
    }

    /// Process a scanned QR payload and derive the bootstrap secret.
    pub fn process_qr(
        &self,
        qr_data: &[u8],
    ) -> Result<(bootstrap::QrPayload, [u8; 32]), CoreError> {
        let payload = bootstrap::parse_qr_payload(qr_data)?;

        let mut their_ik = [0u8; 32];
        their_ik.copy_from_slice(&payload.ik);

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&payload.seed);

        let bs = bootstrap::derive_bootstrap_secret(
            &seed,
            &self.identity.public_key_bytes(),
            &their_ik,
        )?;

        Ok((payload, bs))
    }

    /// Establish a Double Ratchet session as the **initiator** (scanner side).
    ///
    /// The initiator knows the remote peer's ratchet public key (from QR payload)
    /// and uses it to perform the initial DH ratchet step.
    pub fn establish_session(
        &self,
        peer_id: PeerId,
        shared_secret: SharedSecret,
        remote_ratchet_key: &[u8; 32],
        is_initiator: bool,
    ) -> Result<(), CoreError> {
        let ratchet = if is_initiator {
            DoubleRatchetSession::initialize_initiator(shared_secret.0, remote_ratchet_key)
        } else {
            // Responder path — should use establish_responder_session instead
            return Err(CoreError::BootstrapFailed(
                "use establish_responder_session for responder side".into(),
            ));
        };

        let ratchet = ratchet.map_err(CoreError::Crypto)?;
        self.sessions.add_session(peer_id, ratchet);
        Ok(())
    }

    /// Establish a Double Ratchet session as the **responder** (QR presenter side).
    ///
    /// The responder provides their own ratchet secret key (generated during QR creation)
    /// and waits for the first message from the initiator to complete the ratchet.
    pub fn establish_responder_session(
        &self,
        peer_id: PeerId,
        shared_secret: SharedSecret,
        our_ratchet_secret: [u8; 32],
    ) -> Result<(), CoreError> {
        use x25519_dalek::StaticSecret;
        let secret = StaticSecret::from(our_ratchet_secret);
        let ratchet = DoubleRatchetSession::initialize_responder(shared_secret.0, secret)
            .map_err(CoreError::Crypto)?;
        self.sessions.add_session(peer_id, ratchet);
        Ok(())
    }

    /// Send a message within an established session.
    ///
    /// Automatically pads the plaintext to a bucket size before encrypting,
    /// ensuring no unpadded message reaches the transport layer.
    pub fn send(
        &self,
        peer_id: &PeerId,
        message: &[u8],
    ) -> Result<(RatchetHeader, Vec<u8>), CoreError> {
        use parolnet_protocol::PaddingStrategy;
        use parolnet_protocol::padding::BucketPadding;
        let padder = BucketPadding;
        let padded = padder.pad(message)?;
        self.sessions.encrypt(peer_id, &padded)
    }

    /// Decrypt a received message.
    ///
    /// Automatically unpads the plaintext after decrypting.
    pub fn recv(
        &self,
        peer_id: &PeerId,
        header: &RatchetHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        use parolnet_protocol::PaddingStrategy;
        use parolnet_protocol::padding::BucketPadding;
        let padded_plaintext = self.sessions.decrypt(peer_id, header, ciphertext)?;
        let padder = BucketPadding;
        padder.unpad(&padded_plaintext).map_err(CoreError::Protocol)
    }

    /// Check if we have an active session with a peer.
    pub fn has_session(&self, peer_id: &PeerId) -> bool {
        self.sessions.has_session(peer_id)
    }

    /// Emergency: securely wipe all keys, sessions, and cached messages.
    pub fn panic_wipe(&mut self) -> Result<(), CoreError> {
        // Wipe all sessions
        self.sessions.wipe_all();

        // Wipe all group state
        self.group_manager.wipe_all();

        // Wipe all group call state
        self.group_call_manager.wipe_all();

        // Wipe storage
        panic::execute_panic_wipe(self.config.storage_path.as_deref())?;

        Ok(())
    }

    /// Switch to decoy mode: app appears as a calculator/notes app.
    pub fn enter_decoy_mode(&mut self) {
        self.decoy_state = decoy::DecoyState::Active;
    }

    /// Exit decoy mode.
    pub fn exit_decoy_mode(&mut self) {
        self.decoy_state = decoy::DecoyState::Normal;
    }

    /// Check if decoy mode is active.
    pub fn is_decoy_mode(&self) -> bool {
        self.decoy_state == decoy::DecoyState::Active
    }

    /// Get a reference to the group manager.
    pub fn group_manager(&self) -> &group::GroupManager {
        &self.group_manager
    }

    /// Get a reference to the group call manager.
    pub fn group_call_manager(&self) -> &group_call::GroupCallManager {
        &self.group_call_manager
    }

    /// Get the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.session_count()
    }
}
