//! Bluetooth Low Energy transport for offline mesh networking.
//!
//! BLE allows peers to communicate without internet infrastructure.
//! Used during mobile internet shutdowns.
//!
//! Platform-specific implementation required:
//! - Linux/Windows: btleplug crate
//! - macOS/iOS: CoreBluetooth via FFI
//! - Android: Android BLE API via JNI

use crate::TransportError;
use async_trait::async_trait;
use std::net::SocketAddr;

/// ParolNet BLE service UUID (derived from "parolnet" namespace).
pub const SERVICE_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

/// ParolNet BLE characteristic UUID for message exchange.
pub const CHARACTERISTIC_UUID: &str = "550e8400-e29b-41d4-a716-446655440001";

/// Maximum BLE MTU for data transfer (typical negotiated MTU minus overhead).
pub const BLE_MTU: usize = 244;

/// BLE connection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BleState {
    /// Not started.
    Idle,
    /// Scanning for peers.
    Scanning,
    /// Advertising our presence.
    Advertising,
    /// Connected to a peer.
    Connected,
    /// Disconnected.
    Disconnected,
}

/// Configuration for BLE transport.
#[derive(Debug, Clone)]
pub struct BleConfig {
    /// How long to scan before giving up (seconds).
    pub scan_duration_secs: u64,
    /// How long to advertise (seconds).
    pub advertise_duration_secs: u64,
    /// Whether to alternate between scanning and advertising.
    pub alternate_scan_advertise: bool,
    /// Peer ID bytes to include in advertisement.
    pub peer_id: [u8; 32],
}

impl Default for BleConfig {
    fn default() -> Self {
        Self {
            scan_duration_secs: 10,
            advertise_duration_secs: 10,
            alternate_scan_advertise: true,
            peer_id: [0; 32],
        }
    }
}

/// A BLE connection to a remote peer.
pub struct BleConnection {
    state: BleState,
    remote_peer_id: Option<[u8; 32]>,
    /// Buffered outgoing data (fragmented to BLE_MTU chunks).
    #[allow(dead_code)]
    outgoing: Vec<Vec<u8>>,
    /// Reassembly buffer for incoming fragmented data.
    incoming: Vec<u8>,
}

impl BleConnection {
    pub fn new() -> Self {
        Self {
            state: BleState::Idle,
            remote_peer_id: None,
            outgoing: Vec::new(),
            incoming: Vec::new(),
        }
    }

    /// Fragment a message into BLE_MTU-sized chunks.
    /// Format: [1 byte flags (0x01=first, 0x02=last)] [2 bytes total_len BE (first chunk only)] [data]
    pub fn fragment(data: &[u8]) -> Vec<Vec<u8>> {
        if data.is_empty() {
            return vec![];
        }
        let mut chunks = Vec::new();
        let mut offset = 0;
        let mut first = true;

        while offset < data.len() {
            let mut chunk = Vec::new();
            let is_last = offset + (BLE_MTU - 1) >= data.len();
            let mut flags: u8 = 0;
            if first {
                flags |= 0x01;
            }
            if is_last {
                flags |= 0x02;
            }
            chunk.push(flags);

            if first {
                // Include total length in first chunk
                chunk.extend_from_slice(&(data.len() as u16).to_be_bytes());
                let payload_space = BLE_MTU - 3; // 1 flag + 2 length
                let end = (offset + payload_space).min(data.len());
                chunk.extend_from_slice(&data[offset..end]);
                offset = end;
                first = false;
            } else {
                let payload_space = BLE_MTU - 1; // 1 flag
                let end = (offset + payload_space).min(data.len());
                chunk.extend_from_slice(&data[offset..end]);
                offset = end;
            }
            chunks.push(chunk);
        }
        chunks
    }

    /// Reassemble fragments into a complete message.
    /// Returns Some(data) when the last fragment is received, None otherwise.
    pub fn defragment(&mut self, chunk: &[u8]) -> Option<Vec<u8>> {
        if chunk.is_empty() {
            return None;
        }
        let flags = chunk[0];
        let is_first = flags & 0x01 != 0;
        let is_last = flags & 0x02 != 0;

        if is_first {
            self.incoming.clear();
            if chunk.len() < 3 {
                return None;
            }
            // Skip flags + total_length, just accumulate data
            self.incoming.extend_from_slice(&chunk[3..]);
        } else {
            self.incoming.extend_from_slice(&chunk[1..]);
        }

        if is_last {
            let data = std::mem::take(&mut self.incoming);
            Some(data)
        } else {
            None
        }
    }

    pub fn state(&self) -> &BleState {
        &self.state
    }

    pub fn remote_peer_id(&self) -> Option<&[u8; 32]> {
        self.remote_peer_id.as_ref()
    }
}

impl Default for BleConnection {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl crate::Connection for BleConnection {
    async fn send(&self, _data: &[u8]) -> Result<(), TransportError> {
        // TODO: Implement BLE GATT write
        // 1. Fragment data using Self::fragment()
        // 2. Write each chunk to the GATT characteristic
        // 3. Wait for write confirmation
        Err(TransportError::NotAvailable(
            "BLE transport not yet implemented".into(),
        ))
    }

    async fn recv(&self) -> Result<Vec<u8>, TransportError> {
        // TODO: Implement BLE GATT notification/read
        // 1. Wait for GATT notification on characteristic
        // 2. Call self.defragment() on each chunk
        // 3. Return reassembled message
        Err(TransportError::NotAvailable(
            "BLE transport not yet implemented".into(),
        ))
    }

    async fn close(&self) -> Result<(), TransportError> {
        // TODO: Disconnect BLE connection
        Ok(())
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        None // BLE doesn't use socket addresses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_single_chunk() {
        let data = vec![0xAA; 100]; // Small enough for one chunk
        let chunks = BleConnection::fragment(&data);
        assert_eq!(chunks.len(), 1);
        // First and last flags should both be set
        assert_eq!(chunks[0][0], 0x03); // 0x01 | 0x02
        // Total length in bytes 1-2
        let total_len = u16::from_be_bytes([chunks[0][1], chunks[0][2]]);
        assert_eq!(total_len as usize, data.len());
        // Payload follows
        assert_eq!(&chunks[0][3..], &data[..]);
    }

    #[test]
    fn test_fragment_multi_chunk() {
        let data = vec![0xBB; 500]; // Larger than BLE_MTU
        let chunks = BleConnection::fragment(&data);
        assert!(chunks.len() > 1);
        // First chunk has first flag
        assert_eq!(chunks[0][0] & 0x01, 0x01);
        // Last chunk has last flag
        assert_eq!(chunks[chunks.len() - 1][0] & 0x02, 0x02);
        // Middle chunks have no flags
        for chunk in &chunks[1..chunks.len() - 1] {
            assert_eq!(chunk[0], 0x00);
        }
    }

    #[test]
    fn test_fragment_defragment_roundtrip() {
        let data = vec![0xCC; 500];
        let chunks = BleConnection::fragment(&data);
        let mut conn = BleConnection::new();
        let mut result = None;
        for chunk in &chunks {
            result = conn.defragment(chunk);
        }
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_fragment_defragment_roundtrip_small() {
        let data = vec![0xDD; 10];
        let chunks = BleConnection::fragment(&data);
        assert_eq!(chunks.len(), 1);
        let mut conn = BleConnection::new();
        let result = conn.defragment(&chunks[0]);
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_fragment_empty_message() {
        let chunks = BleConnection::fragment(&[]);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_defragment_empty_chunk() {
        let mut conn = BleConnection::new();
        assert!(conn.defragment(&[]).is_none());
    }

    #[test]
    fn test_config_defaults() {
        let config = BleConfig::default();
        assert_eq!(config.scan_duration_secs, 10);
        assert_eq!(config.advertise_duration_secs, 10);
        assert!(config.alternate_scan_advertise);
        assert_eq!(config.peer_id, [0; 32]);
    }

    #[test]
    fn test_connection_initial_state() {
        let conn = BleConnection::new();
        assert_eq!(*conn.state(), BleState::Idle);
        assert!(conn.remote_peer_id().is_none());
    }

    #[test]
    fn test_fragment_defragment_roundtrip_exact_mtu() {
        // Exactly fills first chunk payload: BLE_MTU - 3 = 241 bytes
        let data = vec![0xEE; BLE_MTU - 3];
        let chunks = BleConnection::fragment(&data);
        assert_eq!(chunks.len(), 1);
        let mut conn = BleConnection::new();
        let result = conn.defragment(&chunks[0]);
        assert_eq!(result.unwrap(), data);
    }
}
