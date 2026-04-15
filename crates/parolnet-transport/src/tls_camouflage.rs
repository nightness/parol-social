//! TLS ClientHello fingerprint camouflage (PNP-006 Section 5.1).
//!
//! Configures rustls to produce a TLS ClientHello that matches the
//! fingerprint of a mainstream browser (Chrome or Firefox).
//!
//! This is critical for DPI evasion from day one: the TLS handshake
//! is the first thing a network observer sees.
//!
//! NOTE: Full ClientHello mimicry (extension ordering, padding) requires
//! capabilities beyond what rustls currently exposes. This module provides
//! the best approximation possible with rustls and documents the limitations.

/// A browser fingerprint profile for TLS ClientHello mimicry.
#[derive(Clone, Debug)]
pub struct FingerprintProfile {
    pub name: String,
    /// Cipher suite IDs in the order they appear in the ClientHello.
    pub cipher_suites: Vec<u16>,
    /// TLS extension IDs in order.
    pub extensions: Vec<u16>,
    /// Supported groups (named curves) in order.
    pub supported_groups: Vec<u16>,
    /// ALPN protocol names.
    pub alpn_protocols: Vec<String>,
}

impl FingerprintProfile {
    /// Chrome 120+ fingerprint profile.
    ///
    /// Cipher suites and groups match Chrome's current defaults.
    /// Extension ordering cannot be fully controlled via rustls,
    /// which is a known limitation.
    pub fn chrome() -> Self {
        Self {
            name: "Chrome 120+".into(),
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            ],
            extensions: vec![
                0x0000, // server_name
                0x0017, // extended_master_secret
                0xFF01, // renegotiation_info
                0x000A, // supported_groups
                0x000B, // ec_point_formats
                0x0023, // session_ticket
                0x0010, // application_layer_protocol_negotiation
                0x0005, // status_request
                0x0012, // signed_certificate_timestamp
                0x002B, // supported_versions
                0x000D, // signature_algorithms
                0x0033, // key_share
                0x001C, // record_size_limit
                0x0015, // padding
            ],
            supported_groups: vec![
                0x001D, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
            ],
            alpn_protocols: vec!["h2".into(), "http/1.1".into()],
        }
    }

    /// Firefox 120+ fingerprint profile.
    pub fn firefox() -> Self {
        Self {
            name: "Firefox 120+".into(),
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            ],
            extensions: vec![
                0x0000, // server_name
                0x0017, // extended_master_secret
                0xFF01, // renegotiation_info
                0x000A, // supported_groups
                0x000B, // ec_point_formats
                0x0023, // session_ticket
                0x0010, // application_layer_protocol_negotiation
                0x0005, // status_request
                0x000D, // signature_algorithms
                0x002B, // supported_versions
                0x0033, // key_share
                0x001C, // record_size_limit
            ],
            supported_groups: vec![
                0x001D, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
                0x0100, // ffdhe2048
            ],
            alpn_protocols: vec!["h2".into(), "http/1.1".into()],
        }
    }

    /// Build a rustls ClientConfig that approximates this fingerprint.
    ///
    /// Applies cipher suite ordering from the profile to the CryptoProvider,
    /// reordering rustls's default suites to match the browser fingerprint.
    ///
    /// Limitations:
    /// - Extension ordering is controlled by rustls internally and cannot be
    ///   customized (would require a utls-equivalent library for Rust)
    /// - Some Chrome/Firefox extensions (e.g., GREASE, compressed_certificate)
    ///   are not available in rustls
    /// - Supported groups ordering is not fully controllable via the public API
    /// - For full ClientHello mimicry, a custom TLS implementation or a
    ///   utls-equivalent Rust crate would be needed
    ///
    /// TODO: When a Rust utls-equivalent becomes available, replace this with
    /// full ClientHello construction including extension ordering, GREASE values,
    /// and padding extension.
    pub fn build_client_config(&self) -> Result<rustls::ClientConfig, Box<dyn std::error::Error>> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // Get the default crypto provider and reorder cipher suites to match
        // the browser fingerprint profile.
        let default_provider = rustls::crypto::aws_lc_rs::default_provider();
        let reordered_suites = self.reorder_cipher_suites(&default_provider.cipher_suites);

        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: reordered_suites,
            ..default_provider
        };

        let mut config = rustls::ClientConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Set ALPN protocols
        config.alpn_protocols = self
            .alpn_protocols
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();

        Ok(config)
    }

    /// Reorder the given cipher suites to match this profile's cipher_suites order.
    ///
    /// Suites present in the profile are placed first (in profile order),
    /// followed by any remaining suites from the provider that aren't in the
    /// profile (preserving their original order).
    fn reorder_cipher_suites(
        &self,
        available: &[rustls::SupportedCipherSuite],
    ) -> Vec<rustls::SupportedCipherSuite> {
        let mut result = Vec::with_capacity(available.len());

        // First: add suites in profile order
        for &profile_id in &self.cipher_suites {
            if let Some(&suite) = available
                .iter()
                .find(|s| u16::from(s.suite()) == profile_id)
                && !result
                    .iter()
                    .any(|r: &rustls::SupportedCipherSuite| u16::from(r.suite()) == profile_id)
            {
                result.push(suite);
            }
        }

        // Then: add any remaining suites not in the profile
        for &suite in available {
            if !result
                .iter()
                .any(|r| u16::from(r.suite()) == u16::from(suite.suite()))
            {
                result.push(suite);
            }
        }

        result
    }
}
