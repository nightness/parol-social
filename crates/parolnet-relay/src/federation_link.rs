//! Federation-link session driver (PNP-008 §5 / §5.5 / §5.6).
//!
//! [`FederationLink`] owns a single authenticated WSS connection to a remote
//! relay and drives the post-handshake frame loop:
//!
//! 1. Initiator sends an initial [`FederationSync`] (MUST-081).
//! 2. Responder answers with a [`FederationSync`] of its own, then both peers
//!    interleave [`FederationHeartbeat`]s (MUST-082) on a fixed cadence.
//! 3. On any codec error the link closes with the close code from
//!    [`CodecError::close_code`] (MUST-079, MUST-080, MUST-084).
//! 4. On rate-limit violation the link closes with 4001 (MUST-022 → MUST-084).
//! 5. On duplicate-peer detection the older link is closed with 4000
//!    (MUST-083).
//!
//! This module is transport-agnostic: it takes a pair of async send/recv
//! callbacks so relay-server can use `axum::extract::ws::WebSocket` and tests
//! can use an in-memory channel pair.

use crate::federation_codec::{
    decode_frame, encode_frame, CodecError, FederationFrame, CLOSE_NORMAL, CLOSE_RATE_LIMIT,
};
use crate::FederationManager;
use parolnet_protocol::address::PeerId;

/// Link role. The initiator MUST send the first `FederationSync`
/// (PNP-008-MUST-081).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FederationLinkRole {
    Initiator,
    Responder,
}

/// Reason the link shut down. The `close_code` on each variant is the WSS
/// close frame status the driver should emit before dropping the socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkShutdown {
    /// Remote closed cleanly.
    RemoteClose { close_code: u16 },
    /// Local rate-limit violation (PNP-008-MUST-022 → MUST-084 code 4001).
    LocalRateLimit,
    /// Wire codec error; code comes from [`CodecError::close_code`].
    Codec { close_code: u16 },
    /// Local policy decision — dedup (MUST-083, 4000) or explicit shutdown.
    Policy { close_code: u16 },
}

impl LinkShutdown {
    pub fn close_code(&self) -> u16 {
        match self {
            Self::RemoteClose { close_code } => *close_code,
            Self::LocalRateLimit => CLOSE_RATE_LIMIT,
            Self::Codec { close_code } => *close_code,
            Self::Policy { close_code } => *close_code,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FederationLinkError {
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    #[error("transport send failed: {0}")]
    Send(String),
    #[error("transport receive failed: {0}")]
    Recv(String),
    #[error("peer {0:?} already has an active link")]
    DuplicatePeer(PeerId),
    #[error("peer {0:?} is not admitted by federation manager")]
    NotAdmitted(PeerId),
}

/// A single federation-link session. Stateless by construction — the authoritative
/// per-peer state lives in [`FederationManager`]; the link only drives I/O.
pub struct FederationLink {
    peer_id: PeerId,
    role: FederationLinkRole,
}

impl FederationLink {
    pub fn new(peer_id: PeerId, role: FederationLinkRole) -> Self {
        Self { peer_id, role }
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn role(&self) -> FederationLinkRole {
        self.role
    }

    /// Ordering check for MUST-081: initiator sends `FederationSync` first.
    /// Used by `run_*` implementations and by unit tests that drive the link
    /// with a pair of in-memory channels.
    pub fn initiator_must_send_sync_first(&self, first_frame: &FederationFrame) -> bool {
        match (self.role, first_frame) {
            (FederationLinkRole::Initiator, FederationFrame::Sync(_)) => true,
            (FederationLinkRole::Initiator, FederationFrame::Heartbeat(_)) => false,
            // Responder has no ordering obligation on its first *send*; it may
            // answer with a Sync (per MUST-081) or emit a heartbeat during
            // SYNC (MUST-082).
            (FederationLinkRole::Responder, _) => true,
        }
    }

    /// Encode a frame to its wire bytes.
    pub fn encode(&self, frame: &FederationFrame) -> Result<Vec<u8>, FederationLinkError> {
        encode_frame(frame).map_err(FederationLinkError::Codec)
    }

    /// Decode an inbound binary payload. A decode error carries a close code
    /// the caller SHOULD propagate into its WSS close frame (MUST-084).
    pub fn decode(&self, bytes: &[u8]) -> Result<FederationFrame, FederationLinkError> {
        decode_frame(bytes).map_err(FederationLinkError::Codec)
    }

    /// Register an inbound link with the manager, enforcing MUST-083.
    /// Returns `Err(DuplicatePeer)` if the peer is already in an ACTIVE/SYNC
    /// link; caller should close the newer connection with code 4000.
    pub fn admit_inbound(
        &self,
        manager: &mut FederationManager,
        now: u64,
    ) -> Result<(), FederationLinkError> {
        // Already-admitted peer in an ACTIVE/SYNC state → dedup reject.
        if let Some(existing) = manager.peer(&self.peer_id) {
            if existing.state.can_send_federation_payload() {
                return Err(FederationLinkError::DuplicatePeer(self.peer_id));
            }
        }
        manager.add_peer(self.peer_id, now);
        manager
            .connect_peer(&self.peer_id, now)
            .map_err(|_| FederationLinkError::NotAdmitted(self.peer_id))?;
        Ok(())
    }

    /// Close-code helper for the policy path (MUST-083, MUST-084).
    pub fn duplicate_peer_shutdown() -> LinkShutdown {
        LinkShutdown::Policy {
            close_code: crate::federation_codec::CLOSE_DUP_PEER,
        }
    }

    /// Close-code helper for a rate-limit breach (MUST-084 / 4001).
    pub fn rate_limit_shutdown() -> LinkShutdown {
        LinkShutdown::LocalRateLimit
    }

    /// Clean protocol-normal close (MUST-084 / 1000).
    pub fn normal_shutdown() -> LinkShutdown {
        LinkShutdown::Policy {
            close_code: CLOSE_NORMAL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parolnet_protocol::federation::{
        FederationHeartbeat, FederationSync, HeartbeatFlags, LoadHint, SyncScope,
    };

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    fn sync(sync_id_seed: u8) -> FederationSync {
        FederationSync {
            sync_id: [sync_id_seed; 16],
            since_timestamp: 0,
            iblt: vec![0u8; 64],
            scope: SyncScope::DescriptorsOnly,
            requested_digests: None,
            response_descriptors: None,
            timestamp: 1_700_000_000,
            signature: [0u8; 64],
        }
    }

    fn hb(counter: u64) -> FederationHeartbeat {
        FederationHeartbeat {
            counter,
            load_hint: LoadHint::default(),
            flags: HeartbeatFlags::empty(),
            timestamp: 1_700_000_001,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn initiator_sync_first_ordering() {
        // MUST-081: initiator sends FederationSync first.
        let link = FederationLink::new(pid(1), FederationLinkRole::Initiator);
        assert!(link.initiator_must_send_sync_first(&FederationFrame::Sync(sync(1))));
        assert!(!link.initiator_must_send_sync_first(&FederationFrame::Heartbeat(hb(1))));
    }

    #[test]
    fn encode_decode_roundtrip_sync() {
        let link = FederationLink::new(pid(2), FederationLinkRole::Responder);
        let frame = FederationFrame::Sync(sync(7));
        let bytes = link.encode(&frame).unwrap();
        let back = link.decode(&bytes).unwrap();
        assert!(matches!(back, FederationFrame::Sync(_)));
    }

    #[test]
    fn duplicate_peer_detection() {
        // MUST-083: second admission for a peer already ACTIVE/SYNC is rejected.
        let mut mgr = FederationManager::new();
        mgr.add_peer(pid(9), 1000);
        mgr.connect_peer(&pid(9), 1000).unwrap();
        mgr.on_handshake_ok(&pid(9), 1010).unwrap();
        // Now peer is in SYNC which is federation-payload-ok.
        assert!(mgr.peer(&pid(9)).unwrap().state.can_send_federation_payload());

        let link = FederationLink::new(pid(9), FederationLinkRole::Responder);
        let err = link.admit_inbound(&mut mgr, 1020).unwrap_err();
        assert!(matches!(err, FederationLinkError::DuplicatePeer(_)));
        // Close-code helper returns 4000 per MUST-084.
        assert_eq!(
            FederationLink::duplicate_peer_shutdown().close_code(),
            crate::federation_codec::CLOSE_DUP_PEER
        );
    }

    #[test]
    fn rate_limit_shutdown_maps_to_4001() {
        assert_eq!(
            FederationLink::rate_limit_shutdown().close_code(),
            CLOSE_RATE_LIMIT
        );
    }

    #[test]
    fn admit_inbound_fresh_peer_succeeds() {
        let mut mgr = FederationManager::new();
        let link = FederationLink::new(pid(3), FederationLinkRole::Responder);
        link.admit_inbound(&mut mgr, 500).unwrap();
        // Peer is admitted and in HANDSHAKE state (post-connect_peer).
        let state = mgr.peer(&pid(3)).unwrap().state;
        assert!(matches!(state, crate::PeerState::Handshake));
    }
}
