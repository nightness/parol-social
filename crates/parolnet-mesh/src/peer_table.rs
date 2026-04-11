//! Local routing table of known peers and link quality.
//! Also implements peer scoring (PNP-005 Section 5.8).

use parolnet_protocol::address::PeerId;

/// Peer reputation score (PNP-005 Section 5.8).
#[derive(Clone, Debug)]
pub struct PeerScore {
    pub peer_id: PeerId,
    /// Score in range 0-200, initialized to 100.
    pub score: i32,
}

impl PeerScore {
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            score: 100,
        }
    }

    pub fn is_banned(&self) -> bool {
        self.score < 0
    }

    pub fn reward(&mut self) {
        self.score = (self.score + 1).min(200);
    }
    pub fn penalize_invalid(&mut self) {
        self.score -= 10;
    }
    pub fn penalize_expired(&mut self) {
        self.score -= 2;
    }
    pub fn penalize_duplicate(&mut self) {
        self.score -= 1;
    }
}
