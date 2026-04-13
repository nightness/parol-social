//! Platform-agnostic time helpers (works on both native and WASM).

/// Platform-agnostic epoch seconds (works on both native and WASM).
#[cfg(target_arch = "wasm32")]
pub(crate) fn now_epoch_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn now_epoch_ms() -> u64 {
    js_sys::Date::now() as u64
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
