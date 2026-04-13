//! Session management — wraps Double Ratchet sessions.

use parolnet_crypto::double_ratchet::DoubleRatchetSession;
use parolnet_crypto::{RatchetHeader, RatchetSession};
use parolnet_protocol::address::PeerId;
use std::collections::HashMap;
use std::sync::Mutex;

/// Internal session state for a conversation with a peer.
pub struct Session {
    pub peer_id: PeerId,
    pub ratchet: DoubleRatchetSession,
}

/// Manages all active sessions.
pub struct SessionManager {
    sessions: Mutex<HashMap<PeerId, Session>>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Register a new session with a peer.
    pub fn add_session(&self, peer_id: PeerId, ratchet: DoubleRatchetSession) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(peer_id, Session { peer_id, ratchet });
    }

    /// Encrypt a message for a peer using their Double Ratchet session.
    pub fn encrypt(
        &self,
        peer_id: &PeerId,
        plaintext: &[u8],
    ) -> Result<(RatchetHeader, Vec<u8>), crate::CoreError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(peer_id)
            .ok_or(crate::CoreError::NoSession)?;
        session
            .ratchet
            .encrypt(plaintext)
            .map_err(crate::CoreError::Crypto)
    }

    /// Decrypt a message from a peer using their Double Ratchet session.
    pub fn decrypt(
        &self,
        peer_id: &PeerId,
        header: &RatchetHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, crate::CoreError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(peer_id)
            .ok_or(crate::CoreError::NoSession)?;
        session
            .ratchet
            .decrypt(header, ciphertext)
            .map_err(crate::CoreError::Crypto)
    }

    /// Check if a session exists for a peer.
    pub fn has_session(&self, peer_id: &PeerId) -> bool {
        self.sessions.lock().unwrap().contains_key(peer_id)
    }

    /// Remove a session (for panic wipe or session close).
    pub fn remove_session(&self, peer_id: &PeerId) {
        self.sessions.lock().unwrap().remove(peer_id);
    }

    /// Remove all sessions (panic wipe).
    pub fn wipe_all(&self) {
        self.sessions.lock().unwrap().clear();
    }

    /// Get the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}
