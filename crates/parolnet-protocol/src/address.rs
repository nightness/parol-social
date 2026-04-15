//! Peer identity and addressing.
//!
//! PeerId is derived from SHA-256(Ed25519_identity_public_key).
//! No phone number, email, or any external identifier ever touches the wire.

use crate::error::ProtocolError;
use serde::{Deserialize, Serialize};

/// A unique peer identifier derived from a cryptographic public key.
///
/// `PeerId = SHA-256(Ed25519_identity_public_key)`
///
/// This is the only form of identity in ParolNet. No phone numbers,
/// email addresses, usernames, or any other external identifiers exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    /// Create a PeerId from an Ed25519 public key by hashing it.
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        Self(hasher.finalize().into())
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display as hex, truncated for readability
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "...")
    }
}

/// A bridge relay address for censorship circumvention.
///
/// Bridge relays are unlisted relays distributed out-of-band (QR codes,
/// trusted contacts). They support optional domain fronting via CDN.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeAddress {
    /// The actual relay host (IP or hostname).
    pub host: String,
    /// The relay port.
    pub port: u16,
    /// Optional CDN front domain for domain fronting.
    /// When set, the client connects to this domain instead of `host`.
    /// The CDN terminates TLS and proxies to the real relay.
    pub front_domain: Option<String>,
    /// Optional fingerprint (SHA-256 of relay's Ed25519 public key)
    /// for pinning the relay identity.
    pub fingerprint: Option<[u8; 32]>,
}

impl BridgeAddress {
    /// Create a new bridge address with host and port.
    pub fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            front_domain: None,
            fingerprint: None,
        }
    }

    /// Builder: set the CDN front domain for domain fronting.
    pub fn with_front_domain(mut self, domain: String) -> Self {
        self.front_domain = Some(domain);
        self
    }

    /// Builder: set the relay fingerprint for identity pinning.
    pub fn with_fingerprint(mut self, fp: [u8; 32]) -> Self {
        self.fingerprint = Some(fp);
        self
    }

    /// Returns the WebSocket URL for connecting to this bridge.
    ///
    /// If `front_domain` is set, connects via `wss://{front_domain}/ws`.
    /// Otherwise connects directly via `wss://{host}:{port}/ws`.
    pub fn ws_url(&self) -> String {
        if let Some(ref fd) = self.front_domain {
            format!("wss://{fd}/ws")
        } else {
            format!("wss://{}:{}/ws", self.host, self.port)
        }
    }

    /// Returns the HTTP URL for directory/API access.
    ///
    /// If `front_domain` is set, uses `https://{front_domain}`.
    /// Otherwise uses `https://{host}:{port}`.
    pub fn http_url(&self) -> String {
        if let Some(ref fd) = self.front_domain {
            format!("https://{fd}")
        } else {
            format!("https://{}:{}", self.host, self.port)
        }
    }

    /// Encode as a compact string suitable for QR codes.
    ///
    /// Format: `bridge:{host}:{port}[;front={front_domain}][;fp={hex_fingerprint}]`
    pub fn to_qr_string(&self) -> String {
        let mut s = format!("bridge:{}:{}", self.host, self.port);
        if let Some(ref fd) = self.front_domain {
            s.push_str(&format!(";front={fd}"));
        }
        if let Some(ref fp) = self.fingerprint {
            s.push_str(&format!(";fp={}", hex::encode(fp)));
        }
        s
    }

    /// Parse a bridge address from the compact QR string format.
    ///
    /// Format: `bridge:{host}:{port}[;front={front_domain}][;fp={hex_fingerprint}]`
    pub fn from_qr_string(s: &str) -> Result<Self, ProtocolError> {
        let s = s.trim();
        let rest = s
            .strip_prefix("bridge:")
            .ok_or_else(|| ProtocolError::InvalidBridgeAddress("must start with 'bridge:'".into()))?;

        if rest.is_empty() {
            return Err(ProtocolError::InvalidBridgeAddress("missing host and port".into()));
        }

        // Split into main part (host:port) and optional params (;key=value)
        let mut parts = rest.splitn(2, ';');
        let host_port = parts.next().unwrap();
        let params_str = parts.next().unwrap_or("");

        // Parse host:port — find the last colon for port (supports IPv6 without brackets)
        let last_colon = host_port
            .rfind(':')
            .ok_or_else(|| ProtocolError::InvalidBridgeAddress("missing port separator".into()))?;

        let host = &host_port[..last_colon];
        let port_str = &host_port[last_colon + 1..];

        if host.is_empty() {
            return Err(ProtocolError::InvalidBridgeAddress("empty host".into()));
        }

        let port: u16 = port_str
            .parse()
            .map_err(|_| ProtocolError::InvalidBridgeAddress(format!("invalid port: {port_str}")))?;

        let mut front_domain = None;
        let mut fingerprint = None;

        // Parse optional parameters
        if !params_str.is_empty() {
            for param in params_str.split(';') {
                if let Some(val) = param.strip_prefix("front=") {
                    front_domain = Some(val.to_string());
                } else if let Some(val) = param.strip_prefix("fp=") {
                    let fp_bytes = hex::decode(val).map_err(|e| {
                        ProtocolError::InvalidBridgeAddress(format!("invalid fingerprint hex: {e}"))
                    })?;
                    let fp: [u8; 32] = fp_bytes.try_into().map_err(|_| {
                        ProtocolError::InvalidBridgeAddress(
                            "fingerprint must be 32 bytes".into(),
                        )
                    })?;
                    fingerprint = Some(fp);
                }
            }
        }

        Ok(Self {
            host: host.to_string(),
            port,
            front_domain,
            fingerprint,
        })
    }
}

impl std::fmt::Display for BridgeAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref fd) = self.front_domain {
            write!(f, "{fd} (bridge {}:{})", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_address_basic() {
        let addr = BridgeAddress::new("1.2.3.4".into(), 9000);
        assert_eq!(addr.ws_url(), "wss://1.2.3.4:9000/ws");
        assert_eq!(addr.http_url(), "https://1.2.3.4:9000");
        assert!(addr.front_domain.is_none());
    }

    #[test]
    fn bridge_address_with_front_domain() {
        let addr = BridgeAddress::new("1.2.3.4".into(), 9000)
            .with_front_domain("cdn.example.com".into());
        assert_eq!(addr.ws_url(), "wss://cdn.example.com/ws");
        assert_eq!(addr.http_url(), "https://cdn.example.com");
    }

    #[test]
    fn bridge_qr_roundtrip() {
        let addr = BridgeAddress::new("10.0.0.1".into(), 443)
            .with_front_domain("cdn.cloudflare.com".into());
        let qr = addr.to_qr_string();
        let parsed = BridgeAddress::from_qr_string(&qr).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn bridge_qr_with_fingerprint() {
        let fp = [0xABu8; 32];
        let addr = BridgeAddress::new("relay.example.org".into(), 8443)
            .with_fingerprint(fp);
        let qr = addr.to_qr_string();
        let parsed = BridgeAddress::from_qr_string(&qr).unwrap();
        assert_eq!(parsed.fingerprint, Some(fp));
    }

    #[test]
    fn bridge_qr_minimal() {
        let qr = "bridge:1.2.3.4:9000";
        let addr = BridgeAddress::from_qr_string(qr).unwrap();
        assert_eq!(addr.host, "1.2.3.4");
        assert_eq!(addr.port, 9000);
        assert!(addr.front_domain.is_none());
        assert!(addr.fingerprint.is_none());
    }

    #[test]
    fn bridge_qr_invalid() {
        assert!(BridgeAddress::from_qr_string("notabridge").is_err());
        assert!(BridgeAddress::from_qr_string("bridge:").is_err());
        assert!(BridgeAddress::from_qr_string("bridge:host").is_err());
    }
}
