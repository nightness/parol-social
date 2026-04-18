//! Domain-fronted pluggable transport (PNP-008 §9.2.2).
//!
//! This module carries the metadata + validation primitives a domain-fronted
//! client/bridge pair needs: the front-domain SNI is distinct from the
//! inner-Host bridge hostname, and a bridge that sees `SNI == inner_host`
//! MUST reject the connection because it indicates an unfronted client
//! which defeats the censorship-resistance threat model (MUST-094).
//!
//! The actual TLS client/server wiring goes through the existing
//! [`crate::tls_camouflage`] + [`crate::websocket`] modules; this file
//! provides the config struct and pre-handshake validation logic that
//! sits above them.

use crate::pluggable::{PluggableTransport, TRANSPORT_ID_DOMAIN_FRONT};

/// Configuration for a domain-fronted connection (MUST-094).
#[derive(Clone, Debug)]
pub struct DomainFrontConfig {
    /// SNI presented during TLS handshake. MUST be the CDN-hosted front
    /// domain whose TLS certificate the client will see.
    pub front_domain: String,
    /// Inner hostname sent in the HTTP `Host:` header (or HTTP/2
    /// `:authority` pseudo-header). MUST route to the bridge inside the CDN.
    pub inner_host: String,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DomainFrontError {
    #[error("MUST-094: SNI ({sni}) must differ from inner Host ({inner}) — unfronted client")]
    UnfrontedConnection { sni: String, inner: String },
    #[error("front domain is empty")]
    EmptyFrontDomain,
    #[error("inner host is empty")]
    EmptyInnerHost,
}

impl DomainFrontConfig {
    pub fn new(
        front_domain: impl Into<String>,
        inner_host: impl Into<String>,
    ) -> Result<Self, DomainFrontError> {
        let front_domain = front_domain.into();
        let inner_host = inner_host.into();
        if front_domain.is_empty() {
            return Err(DomainFrontError::EmptyFrontDomain);
        }
        if inner_host.is_empty() {
            return Err(DomainFrontError::EmptyInnerHost);
        }
        if front_domain.eq_ignore_ascii_case(&inner_host) {
            return Err(DomainFrontError::UnfrontedConnection {
                sni: front_domain,
                inner: inner_host,
            });
        }
        Ok(Self {
            front_domain,
            inner_host,
        })
    }

    /// Validate an inbound connection at the bridge (MUST-094). `observed_sni`
    /// is the SNI the TLS layer saw; `observed_inner` is the HTTP `Host:`
    /// header or HTTP/2 `:authority` from the application layer. A bridge
    /// MUST reject a connection where the two match.
    pub fn validate_inbound(
        observed_sni: &str,
        observed_inner: &str,
    ) -> Result<(), DomainFrontError> {
        if observed_sni.eq_ignore_ascii_case(observed_inner) {
            return Err(DomainFrontError::UnfrontedConnection {
                sni: observed_sni.to_string(),
                inner: observed_inner.to_string(),
            });
        }
        Ok(())
    }
}

/// Minimal transport wrapper exposing the registry id. The actual dial/accept
/// wiring reuses the rest of the crate's TLS + WebSocket surface.
pub struct DomainFrontTransport {
    pub config: DomainFrontConfig,
}

impl DomainFrontTransport {
    pub fn new(config: DomainFrontConfig) -> Self {
        Self { config }
    }
}

impl PluggableTransport for DomainFrontTransport {
    fn id(&self) -> &'static str {
        TRANSPORT_ID_DOMAIN_FRONT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_config_accepts_distinct_sni_and_host() {
        let c = DomainFrontConfig::new("cdn.example.net", "bridge.secret.invalid").unwrap();
        assert_eq!(c.front_domain, "cdn.example.net");
        assert_eq!(c.inner_host, "bridge.secret.invalid");
    }

    #[test]
    fn identity_rejected() {
        // MUST-094: SNI == inner Host indicates an unfronted client.
        let err =
            DomainFrontConfig::new("bridge.secret.invalid", "bridge.secret.invalid").unwrap_err();
        assert!(matches!(err, DomainFrontError::UnfrontedConnection { .. }));
    }

    #[test]
    fn validate_inbound_rejects_identity_case_insensitive() {
        let err = DomainFrontConfig::validate_inbound("Bridge.Example", "bridge.example").unwrap_err();
        assert!(matches!(err, DomainFrontError::UnfrontedConnection { .. }));
    }

    #[test]
    fn validate_inbound_accepts_distinct() {
        DomainFrontConfig::validate_inbound("cdn.example.net", "bridge.secret.invalid").unwrap();
    }

    #[test]
    fn empty_fields_rejected() {
        assert!(matches!(
            DomainFrontConfig::new("", "bridge").unwrap_err(),
            DomainFrontError::EmptyFrontDomain
        ));
        assert!(matches!(
            DomainFrontConfig::new("cdn", "").unwrap_err(),
            DomainFrontError::EmptyInnerHost
        ));
    }

    #[test]
    fn id_matches_registry() {
        let t = DomainFrontTransport::new(
            DomainFrontConfig::new("cdn.x", "bridge.y").unwrap(),
        );
        assert_eq!(t.id(), TRANSPORT_ID_DOMAIN_FRONT);
    }
}
