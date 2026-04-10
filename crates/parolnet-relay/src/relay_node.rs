//! Relay node behavior (PNP-004 Section 5.5).

use crate::onion::{self, HopKeys};
use crate::{CellType, RelayAction, RelayCell, RelayError, RelayNode, CELL_PAYLOAD_SIZE};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

/// Maximum simultaneous circuits per relay node.
pub const MAX_CIRCUITS: usize = 8192;
/// Maximum buffered cells per circuit.
pub const MAX_CELLS_PER_CIRCUIT: usize = 64;

/// State for one side of a circuit at a relay.
struct CircuitEntry {
    /// Hop keys for this circuit leg.
    keys: HopKeys,
    /// Forward direction counter.
    forward_counter: u32,
    /// Backward direction counter.
    backward_counter: u32,
    /// Next hop: (address, circuit_id) or None if this is the exit.
    next_hop: Option<(SocketAddr, u32)>,
}

/// A relay node that processes cells according to PNP-004.
pub struct StandardRelayNode {
    /// Circuit table: circuit_id -> circuit entry.
    circuits: Mutex<HashMap<u32, CircuitEntry>>,
}

impl StandardRelayNode {
    pub fn new() -> Self {
        Self {
            circuits: Mutex::new(HashMap::new()),
        }
    }

    /// Register a circuit after handling a CREATE cell.
    pub fn register_circuit(
        &self,
        circuit_id: u32,
        keys: HopKeys,
        next_hop: Option<(SocketAddr, u32)>,
    ) -> Result<(), RelayError> {
        let mut circuits = self.circuits.lock().unwrap();
        if circuits.len() >= MAX_CIRCUITS {
            return Err(RelayError::CircuitLimitExceeded);
        }
        circuits.insert(circuit_id, CircuitEntry {
            keys,
            forward_counter: 0,
            backward_counter: 0,
            next_hop,
        });
        Ok(())
    }

    /// Remove a circuit.
    pub fn remove_circuit(&self, circuit_id: u32) {
        self.circuits.lock().unwrap().remove(&circuit_id);
    }

    /// Get the current number of active circuits.
    pub fn circuit_count(&self) -> usize {
        self.circuits.lock().unwrap().len()
    }
}

#[async_trait]
impl RelayNode for StandardRelayNode {
    async fn handle_cell(&self, cell: RelayCell) -> Result<RelayAction, RelayError> {
        match cell.cell_type {
            CellType::Padding => {
                // Silently discard padding cells
                Ok(RelayAction::Discard)
            }

            CellType::Destroy => {
                // Teardown circuit
                self.remove_circuit(cell.circuit_id);
                // Forward DESTROY to next hop if one exists
                // (In a full implementation, we'd look up the next hop first)
                Ok(RelayAction::Discard)
            }

            CellType::Data => {
                let mut circuits = self.circuits.lock().unwrap();
                let entry = circuits
                    .get_mut(&cell.circuit_id)
                    .ok_or(RelayError::CircuitNotFound(cell.circuit_id))?;

                // Check counter overflow
                if entry.forward_counter >= u32::MAX {
                    return Err(RelayError::NonceOverflow);
                }

                // Peel one onion layer
                let payload_data = &cell.payload[..cell.payload_len as usize];
                let decrypted = onion::onion_peel(
                    payload_data,
                    &entry.keys.forward_key,
                    &entry.keys.forward_nonce_seed,
                    entry.forward_counter,
                )?;
                entry.forward_counter += 1;

                match entry.next_hop {
                    Some((addr, next_cid)) => {
                        // Forward to next hop
                        let mut new_payload = [0u8; CELL_PAYLOAD_SIZE];
                        let copy_len = decrypted.len().min(CELL_PAYLOAD_SIZE);
                        new_payload[..copy_len].copy_from_slice(&decrypted[..copy_len]);

                        let forwarded = RelayCell {
                            circuit_id: next_cid,
                            cell_type: CellType::Data,
                            payload: new_payload,
                            payload_len: copy_len as u16,
                        };
                        Ok(RelayAction::Forward {
                            next_hop: addr,
                            cell: forwarded,
                        })
                    }
                    None => {
                        // This is the exit relay — deliver payload
                        Ok(RelayAction::Deliver { payload: decrypted })
                    }
                }
            }

            _ => {
                // CREATE, CREATED, EXTEND, EXTENDED handled at a higher level
                // (circuit construction protocol, not per-cell processing)
                Ok(RelayAction::Discard)
            }
        }
    }
}
