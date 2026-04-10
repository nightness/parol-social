//! Message types and payload structures.

use serde::{Deserialize, Serialize};

/// Message type codes (PNP-001 Section 3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    Text = 0x01,
    File = 0x02,
    Control = 0x03,
    Decoy = 0x04,
    Handshake = 0x05,
    RelayControl = 0x06,
    Audio = 0x07,
    Video = 0x08,
    FileChunk = 0x09,
    FileControl = 0x0A,
    CallSignal = 0x0B,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Text),
            0x02 => Some(Self::File),
            0x03 => Some(Self::Control),
            0x04 => Some(Self::Decoy),
            0x05 => Some(Self::Handshake),
            0x06 => Some(Self::RelayControl),
            0x07 => Some(Self::Audio),
            0x08 => Some(Self::Video),
            0x09 => Some(Self::FileChunk),
            0x0A => Some(Self::FileControl),
            0x0B => Some(Self::CallSignal),
            _ => None,
        }
    }
}

/// Flags bitfield for the encrypted payload (PNP-001 Section 3.3).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct MessageFlags(pub u8);

impl MessageFlags {
    pub fn is_decoy(self) -> bool { self.0 & 0x01 != 0 }
    pub fn requires_ack(self) -> bool { self.0 & 0x02 != 0 }
    pub fn is_fragment(self) -> bool { self.0 & 0x04 != 0 }
    pub fn is_final_fragment(self) -> bool { self.0 & 0x08 != 0 }

    pub fn set_decoy(&mut self) { self.0 |= 0x01; }
    pub fn set_requires_ack(&mut self) { self.0 |= 0x02; }
    pub fn set_fragment(&mut self) { self.0 |= 0x04; }
    pub fn set_final_fragment(&mut self) { self.0 |= 0x08; }
}
