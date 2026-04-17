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
pub mod envelope;
pub mod error;
pub mod ffi;
pub mod file_transfer;
pub mod group;
pub mod group_call;
pub mod group_file;
pub mod identity_rotation;
pub mod panic;
pub mod session;
#[cfg(feature = "native")]
pub mod video;

pub use config::{FederationConfig, ParolNetConfig};
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
    /// Group file transfer manager.
    group_file_manager: Arc<group_file::GroupFileManager>,
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
            group_file_manager: Arc::new(group_file::GroupFileManager::new()),
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
            group_file_manager: Arc::new(group_file::GroupFileManager::new()),
        }
    }

    /// Export the identity secret key bytes for persistence.
    pub fn export_identity_secret(&self) -> [u8; 32] {
        self.identity.secret_bytes()
    }

    /// Replace the active identity keypair while preserving all Double
    /// Ratchet session state and group managers.
    ///
    /// Used by the H5 identity-rotation flow (PNP-002 §7): after the caller
    /// has signed `IdentityRotationPayload` messages with the OLD identity
    /// and queued them for delivery, they swap in the new identity. Existing
    /// sessions re-peg to the new PeerId client-side; contacts auto-remap
    /// their stored peer_id when they verify the rotation payload.
    pub fn replace_identity_preserving_sessions(&mut self, new_identity: IdentityKeyPair) {
        self.peer_id = PeerId::from_public_key(&new_identity.public_key_bytes());
        self.identity = new_identity;
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

    /// Encrypt a message within an established session and return the
    /// envelope-ready ratchet header + ciphertext.
    ///
    /// This low-level API does not produce a PNP-001 envelope. Callers that
    /// want the full padded wire envelope should use
    /// [`envelope::encrypt_into_envelope`] instead.
    ///
    /// No `extra_aad` is bound; this path exists for session-layer unit tests
    /// and non-envelope use cases.
    pub fn send(
        &self,
        peer_id: &PeerId,
        message: &[u8],
    ) -> Result<(RatchetHeader, Vec<u8>), CoreError> {
        self.sessions.encrypt(peer_id, message, &[])
    }

    /// Decrypt a received ratchet message (no envelope wrapping).
    pub fn recv(
        &self,
        peer_id: &PeerId,
        header: &RatchetHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        self.sessions.decrypt(peer_id, header, ciphertext, &[])
    }

    /// Check if we have an active session with a peer.
    pub fn has_session(&self, peer_id: &PeerId) -> bool {
        self.sessions.has_session(peer_id)
    }

    /// Borrow the internal `SessionManager` (used by the envelope helpers).
    pub fn sessions(&self) -> &SessionManager {
        &self.sessions
    }

    /// Emergency: securely wipe all keys, sessions, and cached messages.
    pub fn panic_wipe(&mut self) -> Result<(), CoreError> {
        // Wipe all sessions
        self.sessions.wipe_all();

        // Wipe all group state
        self.group_manager.wipe_all();

        // Wipe all group call state
        self.group_call_manager.wipe_all();

        // Wipe all group file transfer state
        self.group_file_manager.wipe_all();

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

    /// Get a reference to the group file transfer manager.
    pub fn group_file_manager(&self) -> &group_file::GroupFileManager {
        &self.group_file_manager
    }

    /// Export all session state for persistence.
    pub fn export_sessions(&self) -> Vec<([u8; 32], Vec<u8>)> {
        self.sessions.export_all()
    }

    /// Restore sessions from previously exported state. Returns count restored.
    pub fn import_sessions(&self, data: Vec<([u8; 32], Vec<u8>)>) -> Result<usize, CoreError> {
        self.sessions.import_all(data)
    }

    /// Get the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.session_count()
    }
}
