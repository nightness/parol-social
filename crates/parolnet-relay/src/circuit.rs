//! Circuit construction and management (PNP-004 Section 5.3).

use crate::onion::{self, HopKeys};
use crate::{
    Circuit, CircuitBuilder, RelayCell, RelayError, RelayInfo,
    CellType, CELL_PAYLOAD_SIZE, REQUIRED_HOPS,
};
use async_trait::async_trait;
use parolnet_crypto::kdf::hkdf_sha256;
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
        }
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
}

#[async_trait]
impl Circuit for EstablishedCircuit {
    async fn send(&self, data: &[u8]) -> Result<(), RelayError> {
        let _encrypted = self.wrap_data(data)?;
        // In a full implementation, this would send the encrypted data
        // as a DATA cell through the transport layer to the first hop.
        // For now, the encryption itself is tested.
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, RelayError> {
        // In a full implementation, this would receive a DATA cell
        // from the transport layer and unwrap the onion layers.
        Err(RelayError::CellError("recv requires transport integration".into()))
    }

    async fn extend(&self, _hop: &RelayInfo) -> Result<(), RelayError> {
        // Extending requires sending EXTEND cell through existing circuit
        Err(RelayError::CellError("extend requires transport integration".into()))
    }

    async fn destroy(&self) -> Result<(), RelayError> {
        // Send DESTROY cell through the circuit
        Ok(())
    }
}

/// Standard circuit builder that performs X25519 key exchange per hop.
pub struct StandardCircuitBuilder;

impl StandardCircuitBuilder {
    /// Perform a simulated key exchange with a relay.
    ///
    /// In production, this sends a CREATE cell and receives CREATED.
    /// Here we simulate the key exchange for testing.
    pub fn key_exchange_with_relay(
        relay: &RelayInfo,
    ) -> Result<(HopKeys, [u8; 32]), RelayError> {
        // Generate our ephemeral key
        let our_secret = StaticSecret::random_from_rng(&mut OsRng);
        let our_public = PublicKey::from(&our_secret);

        // In production: send our_public in CREATE cell, receive relay's public
        // Here we simulate by doing DH with the relay's published X25519 key
        let relay_public = PublicKey::from(relay.x25519_key);
        let shared_secret = our_secret.diffie_hellman(&relay_public);

        let hop_keys = HopKeys::from_shared_secret(shared_secret.as_bytes())?;

        Ok((hop_keys, *our_public.as_bytes()))
    }
}

#[async_trait]
impl CircuitBuilder for StandardCircuitBuilder {
    async fn build_circuit(
        &self,
        hops: &[RelayInfo],
    ) -> Result<Box<dyn Circuit>, RelayError> {
        if hops.len() != REQUIRED_HOPS {
            return Err(RelayError::CircuitBuildFailed(format!(
                "exactly {} hops required, got {}",
                REQUIRED_HOPS,
                hops.len()
            )));
        }

        let mut hop_keys = Vec::with_capacity(REQUIRED_HOPS);

        // Perform key exchange with each hop
        for (i, relay) in hops.iter().enumerate() {
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
