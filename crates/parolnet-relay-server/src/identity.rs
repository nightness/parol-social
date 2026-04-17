//! Persistent relay identity loader.
//!
//! Priority order for obtaining the 32-byte Ed25519 secret:
//!
//! 1. Environment variable `RELAY_SECRET_KEY` (hex). Kept for tests and
//!    operators that prefer secret-store injection. Never touches disk.
//! 2. File at `RELAY_KEY_FILE` (default `/data/relay.key`). Loaded as 32
//!    raw bytes. Enables identity stability across container restarts.
//! 3. Freshly generated 32 bytes, persisted to the same file with mode
//!    `0600` (parent directory created with mode `0700` if missing) so
//!    subsequent boots load the same key.
//!
//! The returned value is the raw 32-byte seed. Callers convert via
//! `ed25519_dalek::SigningKey::from_bytes`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Default on-disk location for the persisted relay identity.
/// Matches the `VOLUME /data` directive in the production Dockerfile.
pub const DEFAULT_RELAY_KEY_FILE: &str = "/data/relay.key";

/// Name of the env var that points to the persisted key file.
pub const RELAY_KEY_FILE_ENV: &str = "RELAY_KEY_FILE";

/// Name of the env var that carries an inline hex-encoded key.
/// Takes precedence over the key file — useful for CI / one-shot tests.
pub const RELAY_SECRET_KEY_ENV: &str = "RELAY_SECRET_KEY";

/// Result of identity loading: the raw key plus metadata for logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    /// Key came from the `RELAY_SECRET_KEY` env var.
    EnvVar,
    /// Key was loaded from an existing file at `RELAY_KEY_FILE`.
    ExistingFile,
    /// Key was generated on this boot and written to `RELAY_KEY_FILE`.
    GeneratedAndPersisted,
}

/// Resolve the effective key-file path from env (fallback to the default).
pub fn key_file_path() -> PathBuf {
    std::env::var(RELAY_KEY_FILE_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_RELAY_KEY_FILE))
}

/// Load the relay identity according to the priority order above.
///
/// `key_file` is the on-disk location; ignored if `RELAY_SECRET_KEY` is set.
/// The file will be created (with parent directories) if it does not exist.
///
/// Errors are fatal for the relay process: invalid env hex, unreadable file,
/// wrong file size, or filesystem I/O failure.
pub fn load_or_generate_relay_identity(
    key_file: &Path,
) -> io::Result<([u8; 32], IdentitySource)> {
    // 1. Environment override — never touches disk.
    if let Ok(hex_key) = std::env::var(RELAY_SECRET_KEY_ENV) {
        let bytes = hex::decode(hex_key.trim())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!(
                "{RELAY_SECRET_KEY_ENV} must be valid hex: {e}"
            )))?;
        if bytes.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{RELAY_SECRET_KEY_ENV} must be 32 bytes (64 hex chars), got {}",
                    bytes.len()
                ),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok((arr, IdentitySource::EnvVar));
    }

    // 2. Existing file on disk.
    if key_file.exists() {
        let bytes = fs::read(key_file)?;
        if bytes.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "relay key file {} must be 32 bytes, got {}",
                    key_file.display(),
                    bytes.len()
                ),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok((arr, IdentitySource::ExistingFile));
    }

    // 3. Generate fresh key + persist.
    use rand::RngCore;
    let mut arr = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut arr);

    if let Some(parent) = key_file.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)?;
            set_dir_mode_0700(parent)?;
        }
    }

    write_key_file_0600(key_file, &arr)?;
    Ok((arr, IdentitySource::GeneratedAndPersisted))
}

/// Write exactly 32 bytes with Unix mode 0600. On non-Unix systems, mode
/// tightening is a no-op (the disk content is still the raw bytes).
fn write_key_file_0600(path: &Path, bytes: &[u8; 32]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        use std::io::Write;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
    }
}

#[cfg(unix)]
fn set_dir_mode_0700(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_path: &Path) -> io::Result<()> {
    Ok(())
}
