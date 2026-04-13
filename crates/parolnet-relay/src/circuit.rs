//! Circuit construction and management (PNP-004 Section 5.3).

use crate::handshake::CircuitHandshake;
use crate::onion::{self, HopKeys};
use crate::{
    CELL_PAYLOAD_SIZE, CELL_SIZE, CellType, Circuit, CircuitBuilder, REQUIRED_HOPS, RelayCell,
    RelayError, RelayInfo,
};
use async_trait::async_trait;
use parolnet_transport::Connection;
use rand::rngs::OsRng;
use std::sync::{Arc, Mutex};
use x25519_dalek::{PublicKey, StaticSecret};

/// An established circuit with keys for each hop.
pub struct EstablishedCircuit {
    /// Keys for each hop in order (guard, middle, exit).
    hop_keys: Vec<HopKeys>,
    /// Forward counters for each hop.
    forward_counters: Mutex<Vec<u32>>,
    /// Backward counters for each hop.
    backward_counters: Mutex<Vec<u32>>,
    /// Circuit ID on the first hop connection.
    circuit_id: u32,
    /// Transport connection to the guard (first hop).
    guard_connection: Option<Arc<dyn Connection>>,
}

impl EstablishedCircuit {
    /// Create a circuit from pre-established hop keys (for testing or
    /// after completing the CREATE/EXTEND handshake sequence).
    pub fn from_hop_keys(hop_keys: Vec<HopKeys>, circuit_id: u32) -> Self {
        let n = hop_keys.len();
        Self {
            hop_keys,
            forward_counters: Mutex::new(vec![0; n]),
            backward_counters: Mutex::new(vec![0; n]),
            circuit_id,
            guard_connection: None,
        }
    }

    /// Attach a guard connection to this circuit.
    pub fn with_connection(mut self, conn: Arc<dyn Connection>) -> Self {
        self.guard_connection = Some(conn);
        self
    }

    /// Set the guard connection after construction.
    pub fn set_connection(&mut self, conn: Arc<dyn Connection>) {
        self.guard_connection = Some(conn);
    }

    /// Encrypt data with all onion layers for sending through the circuit.
    pub fn wrap_data(&self, data: &[u8]) -> Result<Vec<u8>, RelayError> {
        let counters = self.forward_counters.lock().unwrap();
        let result = onion::onion_encrypt(data, &self.hop_keys, &counters)?;
        drop(counters);

        // Increment all forward counters
        let mut counters = self.forward_counters.lock().unwrap();
        for c in counters.iter_mut() {
            *c += 1;
        }

        Ok(result)
    }

    /// Decrypt data received through the circuit (reverse direction).
    pub fn unwrap_data(&self, data: &[u8]) -> Result<Vec<u8>, RelayError> {
        let counters = self.backward_counters.lock().unwrap();
        let result = onion::onion_decrypt(data, &self.hop_keys, &counters)?;
        drop(counters);

        let mut counters = self.backward_counters.lock().unwrap();
        for c in counters.iter_mut() {
            *c += 1;
        }

        Ok(result)
    }

    /// Get the circuit ID.
    pub fn id(&self) -> u32 {
        self.circuit_id
    }

    /// Get the number of hops in this circuit.
    pub fn hop_count(&self) -> usize {
        self.hop_keys.len()
    }

    /// Check whether this circuit has a guard connection attached.
    pub fn has_connection(&self) -> bool {
        self.guard_connection.is_some()
    }

    /// Helper: get the guard connection or return an error.
    fn guard(&self) -> Result<&Arc<dyn Connection>, RelayError> {
        self.guard_connection
            .as_ref()
            .ok_or_else(|| RelayError::CellError("no guard connection attached".into()))
    }
}

#[async_trait]
impl Circuit for EstablishedCircuit {
    async fn send(&self, data: &[u8]) -> Result<(), RelayError> {
        let encrypted = self.wrap_data(data)?;

        // Build a DATA cell with the encrypted payload
        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        let copy_len = encrypted.len().min(CELL_PAYLOAD_SIZE);
        payload[..copy_len].copy_from_slice(&encrypted[..copy_len]);

        let cell = RelayCell {
            circuit_id: self.circuit_id,
            cell_type: CellType::Data,
            payload,
            payload_len: copy_len as u16,
        };

        // If we have a guard connection, send over the wire
        if let Some(conn) = &self.guard_connection {
            let bytes = cell.to_bytes();
            conn.send(&bytes).await.map_err(RelayError::Transport)?;
        }
        // Otherwise, encryption-only mode (for testing without transport)
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, RelayError> {
        let conn = self.guard()?;

        let raw = conn.recv().await.map_err(RelayError::Transport)?;
        if raw.len() != CELL_SIZE {
            return Err(RelayError::CellError(format!(
                "expected {} bytes, got {}",
                CELL_SIZE,
                raw.len()
            )));
        }
        let mut buf = [0u8; CELL_SIZE];
        buf.copy_from_slice(&raw);
        let cell = RelayCell::from_bytes(&buf)?;

        if cell.cell_type != CellType::Data {
            return Err(RelayError::CellError(format!(
                "expected DATA cell, got {:?}",
                cell.cell_type
            )));
        }

        let payload_data = &cell.payload[..cell.payload_len as usize];
        self.unwrap_data(payload_data)
    }

    async fn extend(&self, hop: &RelayInfo) -> Result<(), RelayError> {
        let conn = self.guard()?;

        // Create an EXTEND cell targeting the new hop
        let (extend_cell, our_secret) = CircuitHandshake::extend_cell(self.circuit_id, hop.addr);

        // Wrap the EXTEND cell payload in onion layers for existing hops
        // so it can traverse the circuit to the last hop
        let encrypted = self.wrap_data(&extend_cell.payload[..extend_cell.payload_len as usize])?;

        let mut payload = [0u8; CELL_PAYLOAD_SIZE];
        let copy_len = encrypted.len().min(CELL_PAYLOAD_SIZE);
        payload[..copy_len].copy_from_slice(&encrypted[..copy_len]);

        let wire_cell = RelayCell {
            circuit_id: self.circuit_id,
            cell_type: CellType::Extend,
            payload,
            payload_len: copy_len as u16,
        };

        conn.send(&wire_cell.to_bytes())
            .await
            .map_err(RelayError::Transport)?;

        // Receive EXTENDED response
        let raw = conn.recv().await.map_err(RelayError::Transport)?;
        if raw.len() != CELL_SIZE {
            return Err(RelayError::CellError(format!(
                "expected {} bytes in EXTENDED response, got {}",
                CELL_SIZE,
                raw.len()
            )));
        }
        let mut buf = [0u8; CELL_SIZE];
        buf.copy_from_slice(&raw);
        let response = RelayCell::from_bytes(&buf)?;

        if response.cell_type != CellType::Extended {
            return Err(RelayError::CellError(format!(
                "expected EXTENDED cell, got {:?}",
                response.cell_type
            )));
        }

        // Derive keys for the new hop
        let _new_keys = CircuitHandshake::process_extended(&response, &our_secret)?;

        // Note: In production, we'd add new_keys to hop_keys. This requires
        // interior mutability for hop_keys, which we defer to the caller using
        // build_circuit_with_connection for full circuit construction.

        Ok(())
    }

    async fn destroy(&self) -> Result<(), RelayError> {
        if let Some(conn) = &self.guard_connection {
            let cell = RelayCell::destroy(self.circuit_id, 0x01);
            conn.send(&cell.to_bytes())
                .await
                .map_err(RelayError::Transport)?;
        }
        Ok(())
    }
}

/// Standard circuit builder that performs X25519 key exchange per hop.
pub struct StandardCircuitBuilder {
    /// Optional connection factory for testing / injection.
    _connector: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl Default for StandardCircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardCircuitBuilder {
    /// Create a new builder (no transport — uses simulated key exchange).
    pub fn new() -> Self {
        Self { _connector: None }
    }

    /// Perform a simulated key exchange with a relay.
    ///
    /// In production, this sends a CREATE cell and receives CREATED.
    /// Here we simulate the key exchange for testing.
    pub fn key_exchange_with_relay(relay: &RelayInfo) -> Result<(HopKeys, [u8; 32]), RelayError> {
        // Generate our ephemeral key
        let our_secret = StaticSecret::random_from_rng(OsRng);
        let our_public = PublicKey::from(&our_secret);

        // In production: send our_public in CREATE cell, receive relay's public
        // Here we simulate by doing DH with the relay's published X25519 key
        let relay_public = PublicKey::from(relay.x25519_key);
        let shared_secret = our_secret.diffie_hellman(&relay_public);

        let hop_keys = HopKeys::from_shared_secret(shared_secret.as_bytes())?;

        Ok((hop_keys, *our_public.as_bytes()))
    }

    /// Build a circuit using a pre-established guard connection.
    ///
    /// Performs the full CREATE/CREATED + EXTEND/EXTENDED handshake sequence
    /// over the wire, deriving keys for each hop.
    pub async fn build_circuit_with_connection(
        conn: Arc<dyn Connection>,
        hops: &[RelayInfo],
    ) -> Result<EstablishedCircuit, RelayError> {
        if hops.len() != REQUIRED_HOPS {
            return Err(RelayError::CircuitBuildFailed(format!(
                "exactly {} hops required, got {}",
                REQUIRED_HOPS,
                hops.len()
            )));
        }

        let circuit_id: u32 = rand::random::<u32>() | 1;
        let mut hop_keys = Vec::with_capacity(REQUIRED_HOPS);

        // Step 1: CREATE with the guard (first hop)
        let (create_cell, our_secret) = CircuitHandshake::create_cell(circuit_id);
        conn.send(&create_cell.to_bytes())
            .await
            .map_err(RelayError::Transport)?;

        let raw = conn.recv().await.map_err(RelayError::Transport)?;
        if raw.len() != CELL_SIZE {
            return Err(RelayError::CellError(format!(
                "expected {} bytes in CREATED, got {}",
                CELL_SIZE,
                raw.len()
            )));
        }
        let mut buf = [0u8; CELL_SIZE];
        buf.copy_from_slice(&raw);
        let created = RelayCell::from_bytes(&buf)?;
        let guard_keys = CircuitHandshake::process_created(&created, &our_secret)?;
        hop_keys.push(guard_keys);

        // Steps 2-3: EXTEND to each subsequent hop
        for hop in &hops[1..] {
            let (extend_cell, ext_secret) = CircuitHandshake::extend_cell(circuit_id, hop.addr);

            // Wrap EXTEND payload through existing hops
            let partial = EstablishedCircuit::from_hop_keys(hop_keys.clone(), circuit_id);
            let encrypted =
                partial.wrap_data(&extend_cell.payload[..extend_cell.payload_len as usize])?;

            let mut payload = [0u8; CELL_PAYLOAD_SIZE];
            let copy_len = encrypted.len().min(CELL_PAYLOAD_SIZE);
            payload[..copy_len].copy_from_slice(&encrypted[..copy_len]);

            let wire_cell = RelayCell {
                circuit_id,
                cell_type: CellType::Extend,
                payload,
                payload_len: copy_len as u16,
            };
            conn.send(&wire_cell.to_bytes())
                .await
                .map_err(RelayError::Transport)?;

            let raw = conn.recv().await.map_err(RelayError::Transport)?;
            if raw.len() != CELL_SIZE {
                return Err(RelayError::CellError(format!(
                    "expected {} bytes in EXTENDED, got {}",
                    CELL_SIZE,
                    raw.len()
                )));
            }
            let mut buf = [0u8; CELL_SIZE];
            buf.copy_from_slice(&raw);
            let extended = RelayCell::from_bytes(&buf)?;

            let new_keys = CircuitHandshake::process_extended(&extended, &ext_secret)?;
            hop_keys.push(new_keys);
        }

        Ok(EstablishedCircuit {
            hop_keys: hop_keys.clone(),
            forward_counters: Mutex::new(vec![0; hop_keys.len()]),
            backward_counters: Mutex::new(vec![0; hop_keys.len()]),
            circuit_id,
            guard_connection: Some(conn),
        })
    }
}

#[async_trait]
impl CircuitBuilder for StandardCircuitBuilder {
    async fn build_circuit(&self, hops: &[RelayInfo]) -> Result<Box<dyn Circuit>, RelayError> {
        if hops.len() != REQUIRED_HOPS {
            return Err(RelayError::CircuitBuildFailed(format!(
                "exactly {} hops required, got {}",
                REQUIRED_HOPS,
                hops.len()
            )));
        }

        let mut hop_keys = Vec::with_capacity(REQUIRED_HOPS);

        // Perform key exchange with each hop
        for relay in hops.iter() {
            let (keys, _our_public) = Self::key_exchange_with_relay(relay)?;
            hop_keys.push(keys);
        }

        // Generate a random circuit ID
        let circuit_id: u32 = rand::random::<u32>() | 1; // ensure non-zero

        Ok(Box::new(EstablishedCircuit::from_hop_keys(
            hop_keys, circuit_id,
        )))
    }
}
