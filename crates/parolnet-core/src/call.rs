//! Call signaling state machine (PNP-007 Section 4).
//!
//! Manages voice and video call lifecycle:
//! IDLE -> OFFERING -> RINGING -> ACTIVE -> ENDED

use parolnet_protocol::address::PeerId;
use parolnet_protocol::media::{
    AudioCodec, CallSignalMessage, CallState, MediaSource, VideoConfig,
};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// Call timeout for unanswered calls (milliseconds).
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Platform-agnostic millisecond timestamp (avoids web_time::Instant which
/// requires the Performance API and breaks WASM instantiation).
fn now_ms() -> u64 {
    crate::now_epoch_ms()
}

/// Elapsed time since a timestamp in milliseconds.
fn elapsed_ms(since: u64) -> Duration {
    let now = now_ms();
    Duration::from_millis(now.saturating_sub(since))
}

/// Represents an active or pending call.
#[derive(Debug)]
pub struct Call {
    pub call_id: [u8; 16],
    pub peer_id: PeerId,
    pub state: CallState,
    pub audio_codec: Option<AudioCodec>,
    pub video_config: Option<VideoConfig>,
    pub muted: bool,
    /// Local user is screen sharing.
    pub screen_sharing: bool,
    /// Remote peer is screen sharing.
    pub peer_screen_sharing: bool,
    /// Current video source (camera pauses during screen share).
    pub video_source: MediaSource,
    pub created_at: u64,
    pub started_at: Option<u64>,
}

impl Call {
    /// Create a new outgoing call (we are the caller).
    pub fn new_outgoing(call_id: [u8; 16], peer_id: PeerId) -> Self {
        Self {
            call_id,
            peer_id,
            state: CallState::Offering,
            audio_codec: None,
            video_config: None,
            muted: false,
            screen_sharing: false,
            peer_screen_sharing: false,
            video_source: MediaSource::Camera,
            created_at: now_ms(),
            started_at: None,
        }
    }

    /// Create a new incoming call (we are the callee).
    pub fn new_incoming(call_id: [u8; 16], peer_id: PeerId) -> Self {
        Self {
            call_id,
            peer_id,
            state: CallState::Ringing,
            audio_codec: None,
            video_config: None,
            muted: false,
            screen_sharing: false,
            peer_screen_sharing: false,
            video_source: MediaSource::Camera,
            created_at: now_ms(),
            started_at: None,
        }
    }

    /// Check if the call has timed out (unanswered for > CALL_TIMEOUT).
    pub fn is_timed_out(&self) -> bool {
        matches!(self.state, CallState::Offering | CallState::Ringing)
            && elapsed_ms(self.created_at) > CALL_TIMEOUT
    }

    /// Get call duration (None if not active/ended).
    pub fn duration(&self) -> Option<Duration> {
        self.started_at.map(elapsed_ms)
    }

    /// Transition the call state based on a signaling message.
    pub fn handle_signal(&mut self, signal: &CallSignalMessage) -> Result<(), crate::CoreError> {
        match signal {
            CallSignalMessage::Answer { call_id, .. } => {
                if *call_id != self.call_id {
                    return Err(crate::CoreError::SessionError("call_id mismatch".into()));
                }
                match self.state {
                    CallState::Offering => {
                        self.state = CallState::Active;
                        self.started_at = Some(now_ms());
                        Ok(())
                    }
                    _ => Err(crate::CoreError::SessionError(format!(
                        "cannot answer call in state {:?}",
                        self.state
                    ))),
                }
            }

            CallSignalMessage::Reject { call_id } => {
                if *call_id != self.call_id {
                    return Err(crate::CoreError::SessionError("call_id mismatch".into()));
                }
                match self.state {
                    CallState::Offering | CallState::Ringing => {
                        self.state = CallState::Rejected;
                        Ok(())
                    }
                    _ => Err(crate::CoreError::SessionError(format!(
                        "cannot reject call in state {:?}",
                        self.state
                    ))),
                }
            }

            CallSignalMessage::Hangup { call_id } => {
                if *call_id != self.call_id {
                    return Err(crate::CoreError::SessionError("call_id mismatch".into()));
                }
                self.state = CallState::Ended;
                Ok(())
            }

            CallSignalMessage::Mute { call_id, muted } => {
                if *call_id != self.call_id {
                    return Err(crate::CoreError::SessionError("call_id mismatch".into()));
                }
                if self.state != CallState::Active {
                    return Err(crate::CoreError::SessionError(
                        "can only mute/unmute active calls".into(),
                    ));
                }
                self.muted = *muted;
                Ok(())
            }

            CallSignalMessage::ScreenShareStart { call_id, .. } => {
                if *call_id != self.call_id {
                    return Err(crate::CoreError::SessionError("call_id mismatch".into()));
                }
                if self.state != CallState::Active {
                    return Err(crate::CoreError::SessionError(
                        "can only start screen share in active calls".into(),
                    ));
                }
                self.peer_screen_sharing = true;
                Ok(())
            }

            CallSignalMessage::ScreenShareStop { call_id } => {
                if *call_id != self.call_id {
                    return Err(crate::CoreError::SessionError("call_id mismatch".into()));
                }
                if self.state != CallState::Active {
                    return Err(crate::CoreError::SessionError(
                        "can only stop screen share in active calls".into(),
                    ));
                }
                self.peer_screen_sharing = false;
                Ok(())
            }

            CallSignalMessage::Offer { .. } => {
                // Incoming offer creates a new call -- handled at the manager level
                Err(crate::CoreError::SessionError(
                    "offer should be handled by CallManager, not an existing call".into(),
                ))
            }
        }
    }
}

/// Manages all active and pending calls.
pub struct CallManager {
    calls: Mutex<HashMap<[u8; 16], Call>>,
}

impl Default for CallManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CallManager {
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(HashMap::new()),
        }
    }

    /// Start an outgoing call to a peer.
    pub fn start_call(&self, peer_id: PeerId) -> Result<[u8; 16], crate::CoreError> {
        let mut call_id = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut call_id);

        let call = Call::new_outgoing(call_id, peer_id);

        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(call_id, call);
        Ok(call_id)
    }

    /// Register an incoming call.
    pub fn incoming_call(&self, call_id: [u8; 16], peer_id: PeerId) {
        let call = Call::new_incoming(call_id, peer_id);
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(call_id, call);
    }

    /// Answer an incoming call (transition Ringing -> Active).
    pub fn answer(&self, call_id: &[u8; 16]) -> Result<(), crate::CoreError> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let call = calls
            .get_mut(call_id)
            .ok_or(crate::CoreError::SessionError("call not found".into()))?;

        match call.state {
            CallState::Ringing => {
                call.state = CallState::Active;
                call.started_at = Some(now_ms());
                Ok(())
            }
            _ => Err(crate::CoreError::SessionError(format!(
                "cannot answer call in state {:?}",
                call.state
            ))),
        }
    }

    /// Reject an incoming call.
    pub fn reject(&self, call_id: &[u8; 16]) -> Result<(), crate::CoreError> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let call = calls
            .get_mut(call_id)
            .ok_or(crate::CoreError::SessionError("call not found".into()))?;

        match call.state {
            CallState::Ringing | CallState::Offering => {
                call.state = CallState::Rejected;
                Ok(())
            }
            _ => Err(crate::CoreError::SessionError(format!(
                "cannot reject call in state {:?}",
                call.state
            ))),
        }
    }

    /// Hang up an active call.
    pub fn hangup(&self, call_id: &[u8; 16]) -> Result<(), crate::CoreError> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let call = calls
            .get_mut(call_id)
            .ok_or(crate::CoreError::SessionError("call not found".into()))?;
        call.state = CallState::Ended;
        Ok(())
    }

    /// Toggle mute on an active call.
    pub fn toggle_mute(&self, call_id: &[u8; 16], muted: bool) -> Result<(), crate::CoreError> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let call = calls
            .get_mut(call_id)
            .ok_or(crate::CoreError::SessionError("call not found".into()))?;
        if call.state != CallState::Active {
            return Err(crate::CoreError::SessionError(
                "can only mute active calls".into(),
            ));
        }
        call.muted = muted;
        Ok(())
    }

    /// Start screen sharing on an active call (pauses camera).
    pub fn start_screen_share(&self, call_id: &[u8; 16]) -> Result<(), crate::CoreError> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let call = calls
            .get_mut(call_id)
            .ok_or(crate::CoreError::SessionError("call not found".into()))?;
        if call.state != CallState::Active {
            return Err(crate::CoreError::SessionError(
                "can only screen share in active calls".into(),
            ));
        }
        call.screen_sharing = true;
        call.video_source = MediaSource::Screen;
        Ok(())
    }

    /// Stop screen sharing on an active call (resumes camera).
    pub fn stop_screen_share(&self, call_id: &[u8; 16]) -> Result<(), crate::CoreError> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let call = calls
            .get_mut(call_id)
            .ok_or(crate::CoreError::SessionError("call not found".into()))?;
        if call.state != CallState::Active {
            return Err(crate::CoreError::SessionError(
                "can only stop screen share in active calls".into(),
            ));
        }
        call.screen_sharing = false;
        call.video_source = MediaSource::Camera;
        Ok(())
    }

    /// Check if local user is screen sharing on a call.
    pub fn is_screen_sharing(&self, call_id: &[u8; 16]) -> Result<bool, crate::CoreError> {
        let calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let call = calls
            .get(call_id)
            .ok_or(crate::CoreError::SessionError("call not found".into()))?;
        Ok(call.screen_sharing)
    }

    /// Check if remote peer is screen sharing on a call.
    pub fn is_peer_screen_sharing(&self, call_id: &[u8; 16]) -> Result<bool, crate::CoreError> {
        let calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let call = calls
            .get(call_id)
            .ok_or(crate::CoreError::SessionError("call not found".into()))?;
        Ok(call.peer_screen_sharing)
    }

    /// Get a call's state.
    pub fn get_state(&self, call_id: &[u8; 16]) -> Option<CallState> {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(call_id)
            .map(|c| c.state)
    }

    /// Remove timed-out calls.
    pub fn cleanup_timed_out(&self) -> Vec<[u8; 16]> {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let timed_out: Vec<[u8; 16]> = calls
            .iter()
            .filter(|(_, c)| c.is_timed_out())
            .map(|(id, _)| *id)
            .collect();

        for id in &timed_out {
            if let Some(call) = calls.get_mut(id) {
                call.state = CallState::Ended;
            }
        }

        timed_out
    }

    /// Get the number of active calls.
    pub fn active_call_count(&self) -> usize {
        self.calls
            .lock()
            .unwrap()
            .values()
            .filter(|c| c.state == CallState::Active)
            .count()
    }

    /// Get total call count (all states).
    pub fn total_call_count(&self) -> usize {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Remove ended/rejected calls from the map.
    pub fn prune_finished(&self) -> usize {
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let before = calls.len();
        calls.retain(|_, c| !matches!(c.state, CallState::Ended | CallState::Rejected));
        before - calls.len()
    }
}
