//! WiFi Direct transport for high-bandwidth local mesh networking.
//!
//! WiFi Direct creates a peer-to-peer WiFi connection without an access point.
//! Once the WiFi Direct link is established, standard WebSocket transport
//! runs over it for higher bandwidth than BLE.
//!
//! Platform-specific implementation required:
//! - Android: WiFi P2P API via JNI
//! - iOS: Multipeer Connectivity framework via FFI
//! - Linux: wpa_supplicant P2P support

/// WiFi Direct group role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupRole {
    /// Group owner (acts as AP).
    Owner,
    /// Group client.
    Client,
}

/// WiFi Direct connection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WiFiDirectState {
    Idle,
    Discovering,
    Connecting,
    Connected { role: GroupRole, group_ip: String },
    Disconnected,
}

/// Configuration for WiFi Direct transport.
#[derive(Debug, Clone)]
pub struct WiFiDirectConfig {
    /// Service name for discovery.
    pub service_name: String,
    /// Port to use for WebSocket over WiFi Direct.
    pub ws_port: u16,
    /// Peer ID for service advertisement.
    pub peer_id: [u8; 32],
}

impl Default for WiFiDirectConfig {
    fn default() -> Self {
        Self {
            service_name: "parolnet".into(),
            ws_port: 19533,
            peer_id: [0; 32],
        }
    }
}

/// Placeholder for WiFi Direct transport.
///
/// Once a WiFi Direct link is established (platform-specific),
/// this wraps a standard WebSocket connection over the local link.
/// The WebSocket transport from `crate::websocket` is reused.
pub struct WiFiDirectTransport {
    config: WiFiDirectConfig,
    state: WiFiDirectState,
}

impl WiFiDirectTransport {
    pub fn new(config: WiFiDirectConfig) -> Self {
        Self {
            config,
            state: WiFiDirectState::Idle,
        }
    }

    pub fn state(&self) -> &WiFiDirectState {
        &self.state
    }

    pub fn config(&self) -> &WiFiDirectConfig {
        &self.config
    }

    /// Start WiFi Direct discovery.
    /// TODO: Platform-specific implementation.
    pub async fn start_discovery(&mut self) -> Result<(), crate::TransportError> {
        self.state = WiFiDirectState::Discovering;
        Err(crate::TransportError::NotAvailable(
            "WiFi Direct not yet implemented".into(),
        ))
    }

    /// Connect to a discovered peer.
    /// TODO: Platform-specific implementation.
    pub async fn connect_to_peer(
        &mut self,
        _peer_id: &[u8; 32],
    ) -> Result<(), crate::TransportError> {
        self.state = WiFiDirectState::Connecting;
        Err(crate::TransportError::NotAvailable(
            "WiFi Direct not yet implemented".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = WiFiDirectConfig::default();
        assert_eq!(config.service_name, "parolnet");
        assert_eq!(config.ws_port, 19533);
        assert_eq!(config.peer_id, [0; 32]);
    }

    #[test]
    fn test_initial_state() {
        let transport = WiFiDirectTransport::new(WiFiDirectConfig::default());
        assert_eq!(*transport.state(), WiFiDirectState::Idle);
    }

    #[tokio::test]
    async fn test_discovery_returns_not_available() {
        let mut transport = WiFiDirectTransport::new(WiFiDirectConfig::default());
        let result = transport.start_discovery().await;
        assert!(result.is_err());
        assert_eq!(*transport.state(), WiFiDirectState::Discovering);
    }

    #[tokio::test]
    async fn test_connect_returns_not_available() {
        let mut transport = WiFiDirectTransport::new(WiFiDirectConfig::default());
        let peer_id = [0x42; 32];
        let result = transport.connect_to_peer(&peer_id).await;
        assert!(result.is_err());
        assert_eq!(*transport.state(), WiFiDirectState::Connecting);
    }

    #[test]
    fn test_state_equality() {
        assert_eq!(WiFiDirectState::Idle, WiFiDirectState::Idle);
        assert_ne!(WiFiDirectState::Idle, WiFiDirectState::Discovering);
        assert_eq!(
            WiFiDirectState::Connected {
                role: GroupRole::Owner,
                group_ip: "192.168.49.1".into(),
            },
            WiFiDirectState::Connected {
                role: GroupRole::Owner,
                group_ip: "192.168.49.1".into(),
            },
        );
    }
}
