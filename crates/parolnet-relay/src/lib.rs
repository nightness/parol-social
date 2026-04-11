//! # parolnet-relay
//!
//! Onion-routed relay circuit protocol for ParolNet (PNP-004).
//!
//! Provides:
//! - Fixed 512-byte cell format
//! - Circuit construction through 3-hop relay chains
//! - Layer encryption/decryption (onion routing)
//! - Relay node behavior
//! - Gossip-based relay directory

pub mod circuit;
pub mod directory;
pub mod error;
pub mod handshake;
pub mod onion;
pub mod padding;
pub mod pool;
pub mod relay_node;

pub use error::RelayError;

use async_trait::async_trait;
use std::net::SocketAddr;

/// Fixed cell size (PNP-004 Section 3).
pub const CELL_SIZE: usize = 512;
/// Cell header size.
pub const CELL_HEADER_SIZE: usize = 7;
/// Cell payload size.
pub const CELL_PAYLOAD_SIZE: usize = CELL_SIZE - CELL_HEADER_SIZE;
/// Mandatory circuit hop count.
pub const REQUIRED_HOPS: usize = 3;

/// Cell types (PNP-004 Section 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CellType {
    Create = 0x01,
    Created = 0x02,
    Extend = 0x03,
    Extended = 0x04,
    Data = 0x05,
    Destroy = 0x06,
    Padding = 0x07,
    RelayEarly = 0x08,
    MediaData = 0x09,
}

/// Information about a relay node.
#[derive(Clone, Debug)]
pub struct RelayInfo {
    pub peer_id: parolnet_protocol::address::PeerId,
    pub identity_key: [u8; 32],
    pub x25519_key: [u8; 32],
    pub addr: SocketAddr,
    pub bandwidth_class: u8,
}

/// AEAD tag size (ChaCha20-Poly1305).
pub const AEAD_TAG_SIZE: usize = 16;
/// Maximum DATA payload for a 3-hop circuit: 505 - (3 * 16) = 457 bytes.
pub const MAX_DATA_PAYLOAD: usize = CELL_PAYLOAD_SIZE - (REQUIRED_HOPS * AEAD_TAG_SIZE);

/// A relay cell on the wire — exactly 512 bytes.
#[derive(Clone)]
pub struct RelayCell {
    pub circuit_id: u32,
    pub cell_type: CellType,
    pub payload: [u8; CELL_PAYLOAD_SIZE],
    pub payload_len: u16,
}

impl CellType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Create),
            0x02 => Some(Self::Created),
            0x03 => Some(Self::Extend),
            0x04 => Some(Self::Extended),
            0x05 => Some(Self::Data),
            0x06 => Some(Self::Destroy),
            0x07 => Some(Self::Padding),
            0x08 => Some(Self::RelayEarly),
            0x09 => Some(Self::MediaData),
            _ => None,
        }
    }
}

impl RelayCell {
    /// Serialize a cell to exactly 512 bytes on the wire.
    pub fn to_bytes(&self) -> [u8; CELL_SIZE] {
        let mut buf = [0u8; CELL_SIZE];
        buf[0..4].copy_from_slice(&self.circuit_id.to_be_bytes());
        buf[4] = self.cell_type as u8;
        buf[5..7].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[7..].copy_from_slice(&self.payload);
        buf
    }

    /// Deserialize a cell from exactly 512 bytes.
    pub fn from_bytes(buf: &[u8; CELL_SIZE]) -> Result<Self, RelayError> {
        let circuit_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let cell_type = CellType::from_u8(buf[4]).ok_or(RelayError::InvalidCellType(buf[4]))?;
        let payload_len = u16::from_be_bytes([buf[5], buf[6]]);
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        payload.copy_from_slice(&buf[7..]);
        Ok(Self {
            circuit_id,
            cell_type,
            payload,
            payload_len,
        })
    }

    /// Create a PADDING cell with random payload.
    pub fn padding(circuit_id: u32) -> Self {
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut payload);
        Self {
            circuit_id,
            cell_type: CellType::Padding,
            payload,
            payload_len: 0,
        }
    }

    /// Create a DESTROY cell.
    pub fn destroy(circuit_id: u32, reason: u8) -> Self {
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        payload[0] = reason;
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut payload[1..]);
        Self {
            circuit_id,
            cell_type: CellType::Destroy,
            payload,
            payload_len: 1,
        }
    }
}

/// Constructs an onion-encrypted circuit through multiple relays.
#[async_trait]
pub trait CircuitBuilder: Send + Sync {
    async fn build_circuit(&self, hops: &[RelayInfo]) -> Result<Box<dyn Circuit>, RelayError>;
}

/// An established circuit through the relay network.
#[async_trait]
pub trait Circuit: Send + Sync {
    async fn send(&self, data: &[u8]) -> Result<(), RelayError>;
    async fn recv(&self) -> Result<Vec<u8>, RelayError>;
    async fn extend(&self, hop: &RelayInfo) -> Result<(), RelayError>;
    async fn destroy(&self) -> Result<(), RelayError>;
}

/// A relay node that processes cells.
#[async_trait]
pub trait RelayNode: Send + Sync {
    async fn handle_cell(&self, cell: RelayCell) -> Result<RelayAction, RelayError>;
}

/// Action a relay takes after processing a cell.
pub enum RelayAction {
    Forward {
        next_hop: SocketAddr,
        cell: RelayCell,
    },
    Deliver {
        payload: Vec<u8>,
    },
    /// Send this cell back to the sender (e.g., CREATED in response to CREATE).
    Respond(RelayCell),
    Discard,
}
