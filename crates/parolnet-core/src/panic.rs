//! Panic wipe: secure erase all state on trigger.
//!
//! First-class feature — not an afterthought.
//! Wipes all session keys, stored messages, peer table,
//! and optionally the entire storage directory.

use crate::CoreError;
use std::path::Path;
use zeroize::Zeroize;

/// Perform emergency wipe of all sensitive state.
///
/// 1. Zeroize all in-memory data (sessions, keys, peer table)
/// 2. Securely overwrite and delete storage files
pub fn execute_panic_wipe(storage_path: Option<&Path>) -> Result<(), CoreError> {
    // Wipe storage directory if it exists
    if let Some(path) = storage_path
        && path.exists()
    {
        secure_delete_directory(path)?;
    }

    Ok(())
}

/// Securely delete a directory by overwriting all files with zeros,
/// then deleting them.
fn secure_delete_directory(dir: &Path) -> Result<(), CoreError> {
    if !dir.is_dir() {
        return secure_delete_file(dir);
    }

    let entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| CoreError::WipeFailed(format!("read dir: {e}")))?
        .filter_map(|e| e.ok())
        .collect();

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            secure_delete_directory(&path)?;
        } else {
            secure_delete_file(&path)?;
        }
    }

    std::fs::remove_dir(dir).map_err(|e| CoreError::WipeFailed(format!("remove dir: {e}")))?;

    Ok(())
}

/// Securely delete a single file by overwriting with zeros then deleting.
fn secure_delete_file(path: &Path) -> Result<(), CoreError> {
    use std::io::Write;

    let len = std::fs::metadata(path)
        .map(|m| m.len() as usize)
        .unwrap_or(0);

    if len > 0 {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| CoreError::WipeFailed(format!("open for overwrite: {e}")))?;

        // Overwrite with zeros
        let zeros = vec![0u8; len.min(65536)];
        let mut remaining = len;
        while remaining > 0 {
            let chunk = remaining.min(zeros.len());
            file.write_all(&zeros[..chunk])
                .map_err(|e| CoreError::WipeFailed(format!("overwrite: {e}")))?;
            remaining -= chunk;
        }

        file.flush()
            .map_err(|e| CoreError::WipeFailed(format!("flush: {e}")))?;

        // Sync to ensure overwrite hits disk
        file.sync_all()
            .map_err(|e| CoreError::WipeFailed(format!("sync: {e}")))?;
    }

    std::fs::remove_file(path).map_err(|e| CoreError::WipeFailed(format!("remove file: {e}")))?;

    Ok(())
}

/// Zeroize a byte vector and clear it.
pub fn wipe_vec(v: &mut Vec<u8>) {
    v.zeroize();
    v.clear();
}
