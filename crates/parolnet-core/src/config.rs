//! Configuration for a ParolNet node.

use std::path::PathBuf;

/// Top-level configuration for a ParolNet node.
#[derive(Clone, Debug)]
pub struct ParolNetConfig {
    /// Path for persistent storage (None = ephemeral only).
    pub storage_path: Option<PathBuf>,
    /// Whether to start in decoy mode.
    pub decoy_mode: bool,
    /// Maximum number of relay circuits to pre-build.
    pub circuit_pool_size: usize,
}

impl Default for ParolNetConfig {
    fn default() -> Self {
        Self {
            storage_path: None,
            decoy_mode: false,
            circuit_pool_size: 3,
        }
    }
}
