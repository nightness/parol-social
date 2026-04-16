//! Real-time media protocol types (PNP-007).

use serde::{Deserialize, Serialize};

/// Audio codec identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AudioCodec {
    /// Opus codec (RFC 6716), 16kHz mono, 20ms frames.
    Opus = 0x01,
    /// Codec2 3200bps mode, 8kHz mono, ultra-low-bitrate.
    Codec2 = 0x02,
}

/// Video codec identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoCodec {
    VP8 = 0x01,
    VP9 = 0x02,
}

/// Identifies the source of a video stream (PNP-007 Section 6.7.1).
///
/// Carried inside the encrypted payload — never visible to relays.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MediaSource {
    /// Webcam capture (default).
    Camera = 0x00,
    /// Screen/window/tab capture.
    Screen = 0x01,
}

/// Call signaling messages (PNP-007 Section 4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CallSignalMessage {
    /// Initiate a call with SDP offer.
    Offer { call_id: [u8; 16], sdp: String },
    /// Accept a call with SDP answer.
    Answer { call_id: [u8; 16], sdp: String },
    /// Reject an incoming call.
    Reject { call_id: [u8; 16] },
    /// End an active call.
    Hangup { call_id: [u8; 16] },
    /// Toggle mute status.
    Mute { call_id: [u8; 16], muted: bool },
    /// Start screen sharing (PNP-007 Section 6.7.4).
    ScreenShareStart {
        call_id: [u8; 16],
        config: VideoConfig,
    },
    /// Stop screen sharing (PNP-007 Section 6.7.4).
    ScreenShareStop { call_id: [u8; 16] },
}

/// Call state machine states (PNP-007 Section 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallState {
    Idle,
    Offering,
    Ringing,
    Active,
    Ended,
    Rejected,
}

/// Video configuration for a call.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VideoConfig {
    pub width: u16,
    pub height: u16,
    pub bitrate_kbps: u32,
    pub keyframe_interval: u32,
    pub codec: VideoCodec,
}

impl Default for VideoConfig {
    fn default() -> Self {
        Self {
            width: 320,
            height: 240,
            bitrate_kbps: 200,
            keyframe_interval: 60, // 2 seconds at 30fps
            codec: VideoCodec::VP8,
        }
    }
}

impl VideoConfig {
    /// Configuration optimized for screen sharing (PNP-007 Section 6.7.3).
    pub fn screen_share() -> Self {
        Self {
            width: 1280,
            height: 720,
            bitrate_kbps: 800,
            keyframe_interval: 45, // 3 seconds at 15fps
            codec: VideoCodec::VP9,
        }
    }
}

/// Codec negotiation: bandwidth threshold for falling back to Codec2.
pub const CODEC2_BANDWIDTH_THRESHOLD_KBPS: u32 = 16;
