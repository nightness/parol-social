//! Circuit handshake protocol: CREATE/CREATED and EXTEND/EXTENDED (PNP-004 Section 5.3).
//!
//! Implements the X25519 Diffie-Hellman key exchange cells used to establish
//! shared keys between the circuit originator and each relay hop.

use crate::error::RelayError;
use crate::onion::HopKeys;
use crate::{CELL_PAYLOAD_SIZE, CellType, RelayCell};
use x25519_dalek::{PublicKey, StaticSecret};

/// Circuit handshake utilities for CREATE/CREATED and EXTEND/EXTENDED cells.
pub struct CircuitHandshake;

impl CircuitHandshake {
    /// Client side: create a CREATE cell with our ephemeral X25519 public key.
    ///
    /// Returns `(cell, our_secret)` so the caller can complete the handshake
    /// once the CREATED response arrives.
    pub fn create_cell(circuit_id: u32) -> (RelayCell, StaticSecret) {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);

        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        payload[..32].copy_from_slice(public.as_bytes());

        let cell = RelayCell {
            circuit_id,
            cell_type: CellType::Create,
            payload,
            payload_len: 32,
        };
        (cell, secret)
    }

    /// Relay side: handle a CREATE cell. Perform DH, return CREATED cell + derived keys.
    pub fn handle_create(
        cell: &RelayCell,
        our_x25519_secret: &StaticSecret,
    ) -> Result<(RelayCell, HopKeys), RelayError> {
        if cell.cell_type != CellType::Create {
            return Err(RelayError::CellError("expected CREATE cell".into()));
        }

        // Extract client's ephemeral public key from payload
        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&cell.payload[..32]);
        let client_public = PublicKey::from(client_pub);

        // DH
        let shared = our_x25519_secret.diffie_hellman(&client_public);
        let keys = HopKeys::from_shared_secret(shared.as_bytes())
            .map_err(|e| RelayError::KeyExchangeFailed(format!("{e}")))?;

        // Our public key goes in the CREATED response
        let our_public = PublicKey::from(our_x25519_secret);
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        payload[..32].copy_from_slice(our_public.as_bytes());

        let created = RelayCell {
            circuit_id: cell.circuit_id,
            cell_type: CellType::Created,
            payload,
            payload_len: 32,
        };
        Ok((created, keys))
    }

    /// Client side: process a CREATED cell using our secret to derive the same keys.
    pub fn process_created(
        cell: &RelayCell,
        our_secret: &StaticSecret,
    ) -> Result<HopKeys, RelayError> {
        if cell.cell_type != CellType::Created {
            return Err(RelayError::CellError("expected CREATED cell".into()));
        }

        let mut relay_pub = [0u8; 32];
        relay_pub.copy_from_slice(&cell.payload[..32]);
        let relay_public = PublicKey::from(relay_pub);

        let shared = our_secret.diffie_hellman(&relay_public);
        HopKeys::from_shared_secret(shared.as_bytes())
            .map_err(|e| RelayError::KeyExchangeFailed(format!("{e}")))
    }

    /// Client side: create an EXTEND cell to be sent through an existing circuit.
    ///
    /// Contains the target relay's socket address (length-prefixed) + our ephemeral
    /// X25519 public key at a fixed offset.
    pub fn extend_cell(
        circuit_id: u32,
        target_addr: std::net::SocketAddr,
    ) -> (RelayCell, StaticSecret) {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);

        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        // Encode target address as length-prefixed string
        let addr_str = target_addr.to_string();
        let addr_bytes = addr_str.as_bytes();
        let addr_len = addr_bytes.len().min(128);
        payload[0] = addr_len as u8;
        payload[1..1 + addr_len].copy_from_slice(&addr_bytes[..addr_len]);
        // Public key at fixed offset 129
        payload[129..161].copy_from_slice(public.as_bytes());

        let cell = RelayCell {
            circuit_id,
            cell_type: CellType::Extend,
            payload,
            payload_len: 161,
        };
        (cell, secret)
    }

    /// Relay side: parse an EXTEND cell to get target address and client's public key.
    pub fn parse_extend(cell: &RelayCell) -> Result<(std::net::SocketAddr, [u8; 32]), RelayError> {
        if cell.cell_type != CellType::Extend {
            return Err(RelayError::CellError("expected EXTEND cell".into()));
        }

        let addr_len = cell.payload[0] as usize;
        if addr_len == 0 || addr_len > 128 {
            return Err(RelayError::CellError(
                "invalid address length in EXTEND".into(),
            ));
        }
        let addr_str = std::str::from_utf8(&cell.payload[1..1 + addr_len])
            .map_err(|_| RelayError::CellError("invalid UTF-8 in EXTEND address".into()))?;
        let addr: std::net::SocketAddr = addr_str
            .parse()
            .map_err(|_| RelayError::CellError("invalid socket address in EXTEND".into()))?;

        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(&cell.payload[129..161]);

        Ok((addr, pub_key))
    }

    /// Create an EXTENDED cell (relay response to EXTEND, wrapping the next hop's
    /// CREATED response public key).
    pub fn extended_cell(circuit_id: u32, relay_public_key: &[u8; 32]) -> RelayCell {
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        payload[..32].copy_from_slice(relay_public_key);

        RelayCell {
            circuit_id,
            cell_type: CellType::Extended,
            payload,
            payload_len: 32,
        }
    }

    /// Client side: process an EXTENDED cell (same DH as CREATED).
    pub fn process_extended(
        cell: &RelayCell,
        our_secret: &StaticSecret,
    ) -> Result<HopKeys, RelayError> {
        if cell.cell_type != CellType::Extended {
            return Err(RelayError::CellError("expected EXTENDED cell".into()));
        }

        let mut relay_pub = [0u8; 32];
        relay_pub.copy_from_slice(&cell.payload[..32]);
        let relay_public = PublicKey::from(relay_pub);

        let shared = our_secret.diffie_hellman(&relay_public);
        HopKeys::from_shared_secret(shared.as_bytes())
            .map_err(|e| RelayError::KeyExchangeFailed(format!("{e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_created_roundtrip() {
        let circuit_id = 42;

        // Client creates a CREATE cell
        let (create_cell, client_secret) = CircuitHandshake::create_cell(circuit_id);
        assert_eq!(create_cell.cell_type, CellType::Create);
        assert_eq!(create_cell.circuit_id, circuit_id);

        // Relay handles CREATE, produces CREATED + keys
        let relay_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let (created_cell, relay_keys) =
            CircuitHandshake::handle_create(&create_cell, &relay_secret).unwrap();
        assert_eq!(created_cell.cell_type, CellType::Created);
        assert_eq!(created_cell.circuit_id, circuit_id);

        // Client processes CREATED to derive the same keys
        let client_keys = CircuitHandshake::process_created(&created_cell, &client_secret).unwrap();

        // Both sides must derive identical forward and backward keys
        assert_eq!(client_keys.forward_key, relay_keys.forward_key);
        assert_eq!(client_keys.backward_key, relay_keys.backward_key);
        assert_eq!(
            client_keys.forward_nonce_seed,
            relay_keys.forward_nonce_seed
        );
        assert_eq!(
            client_keys.backward_nonce_seed,
            relay_keys.backward_nonce_seed
        );
    }

    #[test]
    fn test_extend_parse_roundtrip() {
        let circuit_id = 99;
        let target: std::net::SocketAddr = "192.168.1.100:9001".parse().unwrap();

        let (extend_cell, _secret) = CircuitHandshake::extend_cell(circuit_id, target);
        assert_eq!(extend_cell.cell_type, CellType::Extend);

        let (parsed_addr, parsed_key) = CircuitHandshake::parse_extend(&extend_cell).unwrap();
        assert_eq!(parsed_addr, target);

        // The public key should be non-zero (derived from a random secret)
        assert_ne!(parsed_key, [0u8; 32]);
    }

    #[test]
    fn test_extend_ipv6_roundtrip() {
        let circuit_id = 100;
        let target: std::net::SocketAddr = "[::1]:9001".parse().unwrap();

        let (extend_cell, _secret) = CircuitHandshake::extend_cell(circuit_id, target);
        let (parsed_addr, _) = CircuitHandshake::parse_extend(&extend_cell).unwrap();
        assert_eq!(parsed_addr, target);
    }

    #[test]
    fn test_extended_roundtrip() {
        let circuit_id = 55;
        let target: std::net::SocketAddr = "10.0.0.1:443".parse().unwrap();

        // Client creates EXTEND
        let (_extend_cell, client_secret) = CircuitHandshake::extend_cell(circuit_id, target);

        // Next-hop relay does CREATE/CREATED internally, gives us its public key
        let relay_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let relay_public = PublicKey::from(&relay_secret);

        // Middle relay wraps it as EXTENDED
        let extended_cell = CircuitHandshake::extended_cell(circuit_id, relay_public.as_bytes());
        assert_eq!(extended_cell.cell_type, CellType::Extended);

        // Client processes EXTENDED
        let client_keys =
            CircuitHandshake::process_extended(&extended_cell, &client_secret).unwrap();

        // Relay derives the same keys from the client's public key
        let client_public = PublicKey::from(&client_secret);
        let shared = relay_secret.diffie_hellman(&client_public);
        let relay_keys = HopKeys::from_shared_secret(shared.as_bytes()).unwrap();

        assert_eq!(client_keys.forward_key, relay_keys.forward_key);
        assert_eq!(client_keys.backward_key, relay_keys.backward_key);
    }

    #[test]
    fn test_cell_serialization_roundtrip() {
        let (cell, _) = CircuitHandshake::create_cell(123);
        let bytes = cell.to_bytes();
        let recovered = RelayCell::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.circuit_id, 123);
        assert_eq!(recovered.cell_type, CellType::Create);
        assert_eq!(&recovered.payload[..32], &cell.payload[..32]);
    }
}
