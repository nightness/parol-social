//! # parolnet-transport
//!
//! Pluggable transport layer for ParolNet.
//!
//! Provides:
//! - `Transport` / `Connection` / `Listener` traits for pluggable transports
//! - Custom TLS stream transport (rustls, no QUIC — maximum fingerprint control)
//! - WebSocket-over-TLS transport (looks like normal HTTPS to DPI)
//! - `TrafficShaper` — mandatory traffic shaping (PNP-006)
//! - TLS ClientHello camouflage (match Chrome/Firefox fingerprints)
//!
//! Native only — WASM clients use `parolnet-wasm` for browser WebSocket.

pub mod ble;
pub mod domain_front;
pub mod error;
pub mod noise;
pub mod obfs;
pub mod pluggable;
pub mod tls_camouflage;
pub mod tls_stream;
pub mod traits;
pub mod websocket;
pub mod websocket_listener;
pub mod wifi_direct;

pub use error::TransportError;
pub use traits::*;
