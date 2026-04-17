//! Integration tests for `load_or_generate_relay_identity`.
//!
//! These tests manipulate process-global env vars (`RELAY_SECRET_KEY`,
//! `RELAY_KEY_FILE`) so they must be serialized behind a mutex — Cargo
//! runs integration tests concurrently by default.

use std::path::PathBuf;
use std::sync::Mutex;

use parolnet_relay_server::identity::{
    IdentitySource, RELAY_KEY_FILE_ENV, RELAY_SECRET_KEY_ENV, load_or_generate_relay_identity,
};

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Allocate a unique temp path for an isolated relay.key.
fn fresh_key_file(tag: &str) -> PathBuf {
    // Nanosecond-ish uniqueness + pid + tag. Good enough for a test scratch
    // file; the file is removed on teardown either way.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut p = std::env::temp_dir();
    p.push(format!(
        "parolnet-relay-identity-test-{pid}-{nanos}-{tag}"
    ));
    p.push("relay.key");
    p
}

fn rm_parent_dir(path: &std::path::Path) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::remove_dir_all(parent);
    }
}

/// RAII guard: clears both env vars on drop so one test's env does not
/// leak into another within the same process.
struct EnvGuard<'a> {
    _inner: std::sync::MutexGuard<'a, ()>,
}

impl<'a> EnvGuard<'a> {
    fn acquire() -> Self {
        let g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Safety: we hold the global lock so no other test is touching env.
        unsafe {
            std::env::remove_var(RELAY_SECRET_KEY_ENV);
            std::env::remove_var(RELAY_KEY_FILE_ENV);
        }
        Self { _inner: g }
    }
}

impl Drop for EnvGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var(RELAY_SECRET_KEY_ENV);
            std::env::remove_var(RELAY_KEY_FILE_ENV);
        }
    }
}

#[test]
fn identity_generated_and_persisted_on_first_boot() {
    let _g = EnvGuard::acquire();
    let path = fresh_key_file("first-boot");
    assert!(!path.exists(), "precondition: key file must not exist");

    let (bytes, source) = load_or_generate_relay_identity(&path)
        .expect("load_or_generate_relay_identity should succeed on fresh path");

    assert_eq!(source, IdentitySource::GeneratedAndPersisted);
    assert!(path.exists(), "key file should have been created");
    let on_disk = std::fs::read(&path).expect("key file readable");
    assert_eq!(on_disk.len(), 32, "key file must be exactly 32 bytes");
    assert_eq!(on_disk, bytes, "returned key must match persisted bytes");

    // Mode 0600 on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file must be mode 0600, got {mode:o}");
    }

    rm_parent_dir(&path);
}

#[test]
fn identity_stable_across_restarts() {
    let _g = EnvGuard::acquire();
    let path = fresh_key_file("stable");

    let (first, src1) =
        load_or_generate_relay_identity(&path).expect("first boot");
    assert_eq!(src1, IdentitySource::GeneratedAndPersisted);

    let (second, src2) =
        load_or_generate_relay_identity(&path).expect("second boot");
    assert_eq!(src2, IdentitySource::ExistingFile);

    assert_eq!(
        first, second,
        "identity must survive restart when RELAY_KEY_FILE points at an existing key"
    );

    rm_parent_dir(&path);
}

#[test]
fn env_var_overrides_file() {
    let _g = EnvGuard::acquire();
    let path = fresh_key_file("env-override");

    // Seed the file with a distinct key.
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let file_key = [0x11u8; 32];
    std::fs::write(&path, file_key).unwrap();

    // Env key is all 0x22 bytes.
    let env_key = [0x22u8; 32];
    let env_hex = hex::encode(env_key);
    unsafe {
        std::env::set_var(RELAY_SECRET_KEY_ENV, &env_hex);
    }

    let (bytes, source) =
        load_or_generate_relay_identity(&path).expect("should load from env");
    assert_eq!(source, IdentitySource::EnvVar);
    assert_eq!(
        bytes, env_key,
        "RELAY_SECRET_KEY must win over an existing RELAY_KEY_FILE"
    );

    // File must be untouched.
    let on_disk = std::fs::read(&path).unwrap();
    assert_eq!(
        on_disk, file_key,
        "env-var path must not overwrite the on-disk key file"
    );

    unsafe {
        std::env::remove_var(RELAY_SECRET_KEY_ENV);
    }
    rm_parent_dir(&path);
}
