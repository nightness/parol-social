//! Circuit pool management (PNP-004 Section 5.8).
//!
//! Maintains a pool of pre-built circuits ready for immediate use.
//! Circuits are built proactively so that sending a message does not
//! incur the latency of circuit construction.

use crate::circuit::EstablishedCircuit;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Default target pool size.
pub const DEFAULT_POOL_SIZE: usize = 4;

/// A pool of pre-built onion circuits.
pub struct CircuitPool {
    /// Available circuits.
    circuits: Mutex<Vec<Arc<EstablishedCircuit>>>,
    /// Target number of circuits to maintain.
    target_size: usize,
}

impl CircuitPool {
    /// Create a new circuit pool with the given target size.
    pub fn new(target_size: usize) -> Self {
        Self {
            circuits: Mutex::new(Vec::with_capacity(target_size)),
            target_size,
        }
    }

    /// Get an available circuit, if any.
    ///
    /// Returns the first circuit in the pool without removing it, so it can
    /// be shared across multiple sends until it is explicitly removed.
    pub async fn get_circuit(&self) -> Option<Arc<EstablishedCircuit>> {
        let circuits = self.circuits.lock().await;
        circuits.first().cloned()
    }

    /// Take and remove the first available circuit from the pool.
    ///
    /// Use this when exclusive ownership is needed (e.g., for a dedicated
    /// stream that will use the circuit until it is torn down).
    pub async fn take_circuit(&self) -> Option<Arc<EstablishedCircuit>> {
        let mut circuits = self.circuits.lock().await;
        if circuits.is_empty() {
            None
        } else {
            Some(circuits.remove(0))
        }
    }

    /// Add a pre-built circuit to the pool.
    pub async fn add_circuit(&self, circuit: Arc<EstablishedCircuit>) {
        let mut circuits = self.circuits.lock().await;
        circuits.push(circuit);
    }

    /// Remove a specific circuit by circuit ID (e.g., after failure or teardown).
    pub async fn remove_circuit(&self, circuit_id: u32) {
        let mut circuits = self.circuits.lock().await;
        circuits.retain(|c| c.id() != circuit_id);
    }

    /// Get current pool size.
    pub async fn size(&self) -> usize {
        self.circuits.lock().await.len()
    }

    /// Check if pool needs more circuits to meet the target size.
    pub async fn needs_circuits(&self) -> bool {
        self.circuits.lock().await.len() < self.target_size
    }

    /// Get the target pool size.
    pub fn target_size(&self) -> usize {
        self.target_size
    }

    /// How many more circuits are needed to reach the target.
    pub async fn deficit(&self) -> usize {
        let current = self.circuits.lock().await.len();
        self.target_size.saturating_sub(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::HopKeys;

    fn test_hop_keys(seed: u8) -> HopKeys {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        HopKeys::from_shared_secret(&secret).unwrap()
    }

    fn make_circuit(id: u32) -> Arc<EstablishedCircuit> {
        let keys = vec![test_hop_keys(1), test_hop_keys(2), test_hop_keys(3)];
        Arc::new(EstablishedCircuit::from_hop_keys(keys, id))
    }

    #[tokio::test]
    async fn test_pool_new_empty() {
        let pool = CircuitPool::new(4);
        assert_eq!(pool.size().await, 0);
        assert!(pool.needs_circuits().await);
        assert_eq!(pool.deficit().await, 4);
    }

    #[tokio::test]
    async fn test_pool_add_and_get() {
        let pool = CircuitPool::new(2);
        let c1 = make_circuit(1);
        pool.add_circuit(c1.clone()).await;

        let got = pool.get_circuit().await;
        assert!(got.is_some());
        assert_eq!(got.unwrap().id(), 1);
        // get_circuit does not remove
        assert_eq!(pool.size().await, 1);
    }

    #[tokio::test]
    async fn test_pool_take_removes() {
        let pool = CircuitPool::new(2);
        pool.add_circuit(make_circuit(10)).await;
        pool.add_circuit(make_circuit(20)).await;

        let taken = pool.take_circuit().await;
        assert_eq!(taken.unwrap().id(), 10);
        assert_eq!(pool.size().await, 1);
    }

    #[tokio::test]
    async fn test_pool_remove_by_id() {
        let pool = CircuitPool::new(4);
        pool.add_circuit(make_circuit(1)).await;
        pool.add_circuit(make_circuit(2)).await;
        pool.add_circuit(make_circuit(3)).await;

        pool.remove_circuit(2).await;
        assert_eq!(pool.size().await, 2);

        // Remaining circuits are 1 and 3
        let c = pool.take_circuit().await.unwrap();
        assert_eq!(c.id(), 1);
        let c = pool.take_circuit().await.unwrap();
        assert_eq!(c.id(), 3);
    }

    #[tokio::test]
    async fn test_pool_needs_circuits() {
        let pool = CircuitPool::new(2);
        assert!(pool.needs_circuits().await);

        pool.add_circuit(make_circuit(1)).await;
        assert!(pool.needs_circuits().await);

        pool.add_circuit(make_circuit(2)).await;
        assert!(!pool.needs_circuits().await);
    }

    #[tokio::test]
    async fn test_pool_empty_get_returns_none() {
        let pool = CircuitPool::new(2);
        assert!(pool.get_circuit().await.is_none());
        assert!(pool.take_circuit().await.is_none());
    }
}
