//! Group call manager (PNP-009 Section 4).
//!
//! Manages multi-party voice/video calls using full-mesh WebRTC.
//! Each pair of participants uses pairwise SRTP keyed from Double Ratchet
//! sessions (not sender keys), preserving post-compromise security.
//! Maximum 8 participants per call (28 pairwise circuits at full mesh).

use parolnet_protocol::address::PeerId;
use parolnet_protocol::group::{
    GroupCallSignal, GroupCallSignalType, GroupId, MAX_GROUP_CALL_PARTICIPANTS,
};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::CoreError;

/// A participant in a group call.
#[derive(Debug, Clone)]
pub struct GroupCallParticipant {
    pub peer_id: PeerId,
    pub joined_at: u64,
    pub muted: bool,
}

/// State of a group call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupCallState {
    Idle,
    Active,
    Ended,
}

/// Represents an active or pending group call.
#[derive(Debug)]
pub struct GroupCall {
    pub group_id: GroupId,
    pub call_id: [u8; 16],
    pub initiator: PeerId,
    pub participants: HashMap<PeerId, GroupCallParticipant>,
    pub state: GroupCallState,
    pub created_at: u64,
    pub max_participants: u8,
}

impl GroupCall {
    /// Create a new group call with the initiator as the first participant.
    pub fn new(group_id: GroupId, call_id: [u8; 16], initiator: PeerId) -> Self {
        let now = crate::now_epoch_ms();
        let mut participants = HashMap::new();
        participants.insert(
            initiator,
            GroupCallParticipant {
                peer_id: initiator,
                joined_at: now,
                muted: false,
            },
        );

        Self {
            group_id,
            call_id,
            initiator,
            participants,
            state: GroupCallState::Active,
            created_at: now,
            max_participants: MAX_GROUP_CALL_PARTICIPANTS,
        }
    }

    /// Add a participant to the call.
    pub fn add_participant(&mut self, peer_id: PeerId) -> Result<(), CoreError> {
        if self.is_full() {
            return Err(CoreError::GroupFull);
        }
        if self.is_participant(&peer_id) {
            return Err(CoreError::SessionError(
                "participant already in call".into(),
            ));
        }
        self.participants.insert(
            peer_id,
            GroupCallParticipant {
                peer_id,
                joined_at: crate::now_epoch_ms(),
                muted: false,
            },
        );
        Ok(())
    }

    /// Remove a participant from the call. If no participants remain, the call ends.
    pub fn remove_participant(&mut self, peer_id: &PeerId) {
        self.participants.remove(peer_id);
        if self.participants.is_empty() {
            self.state = GroupCallState::Ended;
        }
    }

    /// Set the mute state of a participant.
    pub fn set_muted(&mut self, peer_id: &PeerId, muted: bool) -> Result<(), CoreError> {
        let participant = self
            .participants
            .get_mut(peer_id)
            .ok_or_else(|| CoreError::SessionError("participant not in call".into()))?;
        participant.muted = muted;
        Ok(())
    }

    /// Get the number of participants.
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Check if a peer is a participant.
    pub fn is_participant(&self, peer_id: &PeerId) -> bool {
        self.participants.contains_key(peer_id)
    }

    /// Check if the call is at maximum capacity.
    pub fn is_full(&self) -> bool {
        self.participants.len() >= self.max_participants as usize
    }
}

/// Action returned from processing a group call signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupCallAction {
    CallStarted {
        call_id: [u8; 16],
    },
    ParticipantJoined {
        call_id: [u8; 16],
        peer_id: PeerId,
    },
    ParticipantLeft {
        call_id: [u8; 16],
        peer_id: PeerId,
    },
    MuteChanged {
        call_id: [u8; 16],
        peer_id: PeerId,
        muted: bool,
    },
    CallEnded {
        call_id: [u8; 16],
    },
}

/// Manages all active group calls.
pub struct GroupCallManager {
    calls: Mutex<HashMap<[u8; 16], GroupCall>>,
}

impl Default for GroupCallManager {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupCallManager {
    /// Create a new empty group call manager.
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(HashMap::new()),
        }
    }

    /// Start a new group call.
    pub fn start_call(&self, group_id: GroupId, initiator: PeerId) -> Result<[u8; 16], CoreError> {
        let mut call_id = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut call_id);

        let call = GroupCall::new(group_id, call_id, initiator);

        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(call_id, call);

        Ok(call_id)
    }

    /// Join an existing group call.
    pub fn join_call(&self, call_id: &[u8; 16], peer_id: PeerId) -> Result<(), CoreError> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let call = calls
            .get_mut(call_id)
            .ok_or_else(|| CoreError::SessionError("group call not found".into()))?;
        call.add_participant(peer_id)
    }

    /// Leave an existing group call. If no participants remain, the call ends.
    pub fn leave_call(&self, call_id: &[u8; 16], peer_id: &PeerId) -> Result<(), CoreError> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let call = calls
            .get_mut(call_id)
            .ok_or_else(|| CoreError::SessionError("group call not found".into()))?;
        call.remove_participant(peer_id);
        Ok(())
    }

    /// End a group call.
    pub fn end_call(&self, call_id: &[u8; 16]) -> Result<(), CoreError> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let call = calls
            .get_mut(call_id)
            .ok_or_else(|| CoreError::SessionError("group call not found".into()))?;
        call.state = GroupCallState::Ended;
        Ok(())
    }

    /// Toggle mute for a participant in a group call.
    pub fn toggle_mute(
        &self,
        call_id: &[u8; 16],
        peer_id: &PeerId,
        muted: bool,
    ) -> Result<(), CoreError> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let call = calls
            .get_mut(call_id)
            .ok_or_else(|| CoreError::SessionError("group call not found".into()))?;
        call.set_muted(peer_id, muted)
    }

    /// Get the list of participants in a group call.
    pub fn get_participants(&self, call_id: &[u8; 16]) -> Result<Vec<PeerId>, CoreError> {
        let calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let call = calls
            .get(call_id)
            .ok_or_else(|| CoreError::SessionError("group call not found".into()))?;
        Ok(call.participants.keys().copied().collect())
    }

    /// Get the state of a group call.
    pub fn get_state(&self, call_id: &[u8; 16]) -> Option<GroupCallState> {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(call_id)
            .map(|c| c.state)
    }

    /// Get the number of active group calls.
    pub fn active_call_count(&self) -> usize {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|c| c.state == GroupCallState::Active)
            .count()
    }

    /// Remove ended calls and return their call IDs.
    pub fn cleanup_empty(&self) -> Vec<[u8; 16]> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let ended: Vec<[u8; 16]> = calls
            .iter()
            .filter(|(_, c)| c.state == GroupCallState::Ended)
            .map(|(id, _)| *id)
            .collect();
        for id in &ended {
            calls.remove(id);
        }
        ended
    }

    /// Securely wipe all group call state (for panic_wipe).
    pub fn wipe_all(&self) {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Process an incoming group call signal and return the appropriate action.
    pub fn handle_signal(
        &self,
        signal: &GroupCallSignal,
        from_peer: PeerId,
    ) -> Result<GroupCallAction, CoreError> {
        match &signal.signal {
            GroupCallSignalType::Invite { sdp: _ } => {
                // Create new call if it doesn't already exist
                let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
                if calls.contains_key(&signal.call_id) {
                    return Err(CoreError::SessionError("group call already exists".into()));
                }
                let call = GroupCall::new(signal.group_id, signal.call_id, from_peer);
                let call_id = call.call_id;
                calls.insert(call_id, call);
                Ok(GroupCallAction::CallStarted { call_id })
            }
            GroupCallSignalType::Join { sdp: _ } => {
                let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
                let call = calls
                    .get_mut(&signal.call_id)
                    .ok_or_else(|| CoreError::SessionError("group call not found".into()))?;
                call.add_participant(from_peer)?;
                Ok(GroupCallAction::ParticipantJoined {
                    call_id: signal.call_id,
                    peer_id: from_peer,
                })
            }
            GroupCallSignalType::Leave => {
                let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
                let call = calls
                    .get_mut(&signal.call_id)
                    .ok_or_else(|| CoreError::SessionError("group call not found".into()))?;
                call.remove_participant(&from_peer);
                Ok(GroupCallAction::ParticipantLeft {
                    call_id: signal.call_id,
                    peer_id: from_peer,
                })
            }
            GroupCallSignalType::Mute { muted } => {
                let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
                let call = calls
                    .get_mut(&signal.call_id)
                    .ok_or_else(|| CoreError::SessionError("group call not found".into()))?;
                call.set_muted(&from_peer, *muted)?;
                Ok(GroupCallAction::MuteChanged {
                    call_id: signal.call_id,
                    peer_id: from_peer,
                    muted: *muted,
                })
            }
            GroupCallSignalType::EndCall => {
                let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
                let call = calls
                    .get_mut(&signal.call_id)
                    .ok_or_else(|| CoreError::SessionError("group call not found".into()))?;
                call.state = GroupCallState::Ended;
                Ok(GroupCallAction::CallEnded {
                    call_id: signal.call_id,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer_id(byte: u8) -> PeerId {
        PeerId([byte; 32])
    }

    fn make_group_id(byte: u8) -> GroupId {
        GroupId([byte; 32])
    }

    #[test]
    fn test_start_and_join_call() {
        let mgr = GroupCallManager::new();
        let initiator = make_peer_id(0x01);
        let peer2 = make_peer_id(0x02);
        let peer3 = make_peer_id(0x03);

        let call_id = mgr.start_call(make_group_id(0xAA), initiator).unwrap();

        // Initiator should already be a participant
        let participants = mgr.get_participants(&call_id).unwrap();
        assert_eq!(participants.len(), 1);
        assert!(participants.contains(&initiator));

        // Join two more peers
        mgr.join_call(&call_id, peer2).unwrap();
        mgr.join_call(&call_id, peer3).unwrap();

        let participants = mgr.get_participants(&call_id).unwrap();
        assert_eq!(participants.len(), 3);
        assert!(participants.contains(&peer2));
        assert!(participants.contains(&peer3));
    }

    #[test]
    fn test_leave_call() {
        let mgr = GroupCallManager::new();
        let initiator = make_peer_id(0x01);
        let peer2 = make_peer_id(0x02);

        let call_id = mgr.start_call(make_group_id(0xAA), initiator).unwrap();
        mgr.join_call(&call_id, peer2).unwrap();
        assert_eq!(mgr.get_participants(&call_id).unwrap().len(), 2);

        mgr.leave_call(&call_id, &peer2).unwrap();
        let participants = mgr.get_participants(&call_id).unwrap();
        assert_eq!(participants.len(), 1);
        assert!(!participants.contains(&peer2));
    }

    #[test]
    fn test_call_full() {
        let mgr = GroupCallManager::new();
        let initiator = make_peer_id(0x01);

        let call_id = mgr.start_call(make_group_id(0xAA), initiator).unwrap();

        // Fill to MAX_GROUP_CALL_PARTICIPANTS (initiator is already in)
        for i in 2..=MAX_GROUP_CALL_PARTICIPANTS {
            mgr.join_call(&call_id, make_peer_id(i)).unwrap();
        }

        // Next join should fail with GroupFull
        let result = mgr.join_call(&call_id, make_peer_id(0xFF));
        assert!(matches!(result, Err(CoreError::GroupFull)));
    }

    #[test]
    fn test_end_call() {
        let mgr = GroupCallManager::new();
        let initiator = make_peer_id(0x01);

        let call_id = mgr.start_call(make_group_id(0xAA), initiator).unwrap();
        assert_eq!(mgr.get_state(&call_id), Some(GroupCallState::Active));

        mgr.end_call(&call_id).unwrap();
        assert_eq!(mgr.get_state(&call_id), Some(GroupCallState::Ended));
    }

    #[test]
    fn test_mute_toggle() {
        let mgr = GroupCallManager::new();
        let initiator = make_peer_id(0x01);

        let call_id = mgr.start_call(make_group_id(0xAA), initiator).unwrap();

        // Initially not muted
        mgr.toggle_mute(&call_id, &initiator, true).unwrap();

        // Verify via internal state
        let calls = mgr.calls.lock().unwrap();
        let call = calls.get(&call_id).unwrap();
        assert!(call.participants.get(&initiator).unwrap().muted);
        drop(calls);

        // Unmute
        mgr.toggle_mute(&call_id, &initiator, false).unwrap();
        let calls = mgr.calls.lock().unwrap();
        let call = calls.get(&call_id).unwrap();
        assert!(!call.participants.get(&initiator).unwrap().muted);
    }

    #[test]
    fn test_handle_signal_invite() {
        let mgr = GroupCallManager::new();
        let peer = make_peer_id(0x01);
        let group_id = make_group_id(0xBB);
        let call_id = [0x42u8; 16];

        let signal = GroupCallSignal {
            group_id,
            call_id,
            signal: GroupCallSignalType::Invite {
                sdp: "v=0\r\n".into(),
            },
        };

        let action = mgr.handle_signal(&signal, peer).unwrap();
        assert_eq!(action, GroupCallAction::CallStarted { call_id });

        // Call should exist with the peer as participant
        let participants = mgr.get_participants(&call_id).unwrap();
        assert_eq!(participants.len(), 1);
        assert!(participants.contains(&peer));
    }

    #[test]
    fn test_handle_signal_lifecycle() {
        let mgr = GroupCallManager::new();
        let initiator = make_peer_id(0x01);
        let joiner = make_peer_id(0x02);
        let group_id = make_group_id(0xCC);
        let call_id = [0x55u8; 16];

        // Invite
        let invite = GroupCallSignal {
            group_id,
            call_id,
            signal: GroupCallSignalType::Invite {
                sdp: "v=0\r\n".into(),
            },
        };
        let action = mgr.handle_signal(&invite, initiator).unwrap();
        assert_eq!(action, GroupCallAction::CallStarted { call_id });

        // Join
        let join = GroupCallSignal {
            group_id,
            call_id,
            signal: GroupCallSignalType::Join {
                sdp: "v=0\r\n".into(),
            },
        };
        let action = mgr.handle_signal(&join, joiner).unwrap();
        assert_eq!(
            action,
            GroupCallAction::ParticipantJoined {
                call_id,
                peer_id: joiner,
            }
        );
        assert_eq!(mgr.get_participants(&call_id).unwrap().len(), 2);

        // Mute
        let mute = GroupCallSignal {
            group_id,
            call_id,
            signal: GroupCallSignalType::Mute { muted: true },
        };
        let action = mgr.handle_signal(&mute, joiner).unwrap();
        assert_eq!(
            action,
            GroupCallAction::MuteChanged {
                call_id,
                peer_id: joiner,
                muted: true,
            }
        );

        // Leave
        let leave = GroupCallSignal {
            group_id,
            call_id,
            signal: GroupCallSignalType::Leave,
        };
        let action = mgr.handle_signal(&leave, joiner).unwrap();
        assert_eq!(
            action,
            GroupCallAction::ParticipantLeft {
                call_id,
                peer_id: joiner,
            }
        );
        assert_eq!(mgr.get_participants(&call_id).unwrap().len(), 1);

        // EndCall
        let end = GroupCallSignal {
            group_id,
            call_id,
            signal: GroupCallSignalType::EndCall,
        };
        let action = mgr.handle_signal(&end, initiator).unwrap();
        assert_eq!(action, GroupCallAction::CallEnded { call_id });
        assert_eq!(mgr.get_state(&call_id), Some(GroupCallState::Ended));
    }

    #[test]
    fn test_empty_call_ends() {
        let mgr = GroupCallManager::new();
        let initiator = make_peer_id(0x01);
        let peer2 = make_peer_id(0x02);

        let call_id = mgr.start_call(make_group_id(0xAA), initiator).unwrap();
        mgr.join_call(&call_id, peer2).unwrap();

        // Both leave
        mgr.leave_call(&call_id, &initiator).unwrap();
        assert_eq!(mgr.get_state(&call_id), Some(GroupCallState::Active));

        mgr.leave_call(&call_id, &peer2).unwrap();
        assert_eq!(mgr.get_state(&call_id), Some(GroupCallState::Ended));
    }
}
