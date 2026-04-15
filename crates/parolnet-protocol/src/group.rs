//! Group communication protocol types (PNP-009).

use crate::address::PeerId;
use crate::file::FileOffer;
use serde::{Deserialize, Serialize};

/// Maximum number of members in a group.
pub const MAX_GROUP_MEMBERS: u16 = 256;

/// Maximum number of participants in a group call.
pub const MAX_GROUP_CALL_PARTICIPANTS: u8 = 8;

/// Number of messages before sender key rotation is required.
pub const SENDER_KEY_ROTATION_MESSAGES: u32 = 1000;

/// Duration in seconds before sender key rotation is required (24 hours).
pub const SENDER_KEY_ROTATION_SECS: u64 = 86400;

/// Unique identifier for a group, derived from cryptographic material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(pub [u8; 32]);

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "...")
    }
}

/// Role of a member within a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum GroupRole {
    Admin = 0x01,
    Member = 0x02,
}

/// A member of a group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMember {
    pub peer_id: PeerId,
    pub role: GroupRole,
    /// Unix timestamp in seconds when the member joined.
    pub joined_at: u64,
}

/// Gossip payload describing the current state of a group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMetadataPayload {
    pub group_id: GroupId,
    /// Monotonically increasing version number.
    pub version: u64,
    pub name: String,
    pub members: Vec<GroupMember>,
    pub created_by: PeerId,
    /// Unix timestamp in seconds when the group was created.
    pub created_at: u64,
    /// Maximum number of members allowed in the group.
    pub max_members: u16,
}

impl Default for GroupMetadataPayload {
    fn default() -> Self {
        Self {
            group_id: GroupId([0u8; 32]),
            version: 0,
            name: String::new(),
            members: Vec::new(),
            created_by: PeerId([0u8; 32]),
            created_at: 0,
            max_members: MAX_GROUP_MEMBERS,
        }
    }
}

/// Types of operations that can be performed on a group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GroupOpType {
    AddMember { peer_id: PeerId },
    RemoveMember { peer_id: PeerId },
    PromoteAdmin { peer_id: PeerId },
    DemoteAdmin { peer_id: PeerId },
    UpdateName { name: String },
    RotateKeys,
}

/// A signed group operation authorized by an admin.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupOperation {
    pub group_id: GroupId,
    /// Version number this operation applies to.
    pub version: u64,
    pub op: GroupOpType,
    /// The admin peer who authorized this operation.
    pub admin_peer_id: PeerId,
    /// 64-byte Ed25519 signature over the operation.
    pub signature: Vec<u8>,
    /// Unix timestamp in seconds.
    pub timestamp: u64,
}

/// Signal types for group voice/video calls.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GroupCallSignalType {
    Invite { sdp: String },
    Join { sdp: String },
    Leave,
    Mute { muted: bool },
    EndCall,
}

/// A signaling message for group calls.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupCallSignal {
    pub group_id: GroupId,
    pub call_id: [u8; 16],
    pub signal: GroupCallSignalType,
}

/// A file offer directed to a group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupFileOffer {
    pub group_id: GroupId,
    pub offer: FileOffer,
}
