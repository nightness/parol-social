//! Pluggable transport registry and per-session selector (PNP-008 §9.2).
//!
//! The spec contract lives here:
//! - [`PluggableTransport`] — trait marker every concrete transport
//!   implements; provides a stable registry ID (MUST-093) and the on-wire
//!   behaviour a bridge advertises to clients.
//! - [`TransportRegistry`] — immutable per-bridge list of advertised
//!   transports.
//! - [`TransportSelector`] — uniform-random per-session picker (MUST-098).
//! - Constants and scraping helpers for the v1 registry identifiers
//!   (MUST-093).

use rand::seq::SliceRandom;

/// Registry identifiers defined by PNP-008 v0.7.
pub const TRANSPORT_ID_DOMAIN_FRONT: &str = "domain_front";
pub const TRANSPORT_ID_OBFS: &str = "obfs";
pub const TRANSPORT_ID_DIRECT_TLS: &str = "direct_tls";

/// All v1 registered transport identifiers. Extending this list in a future
/// spec version is a backwards-compatible addition.
pub const V1_REGISTRY_IDS: &[&str] = &[
    TRANSPORT_ID_DOMAIN_FRONT,
    TRANSPORT_ID_OBFS,
    TRANSPORT_ID_DIRECT_TLS,
];

/// Mandatory baseline transport that every implementation MUST ship
/// (PNP-008-MUST-097).
pub const MANDATORY_BASELINE_ID: &str = TRANSPORT_ID_DIRECT_TLS;

/// Marker trait implemented by concrete pluggable transports (MUST-091..093).
///
/// Implementations carry their own configuration and state; this trait
/// exposes only the stable metadata the registry needs.
pub trait PluggableTransport: Send + Sync {
    /// PNP-008 §9.2 registry identifier. MUST match `[a-z0-9_-]{1,32}`
    /// (MUST-093). Identifiers not in the compiled-in registry are a
    /// release-blocking error.
    fn id(&self) -> &'static str;
}

/// Validate that `s` matches the registry identifier regex
/// `[a-z0-9_-]{1,32}` (MUST-093). Pure function — no heap allocation.
pub fn is_valid_transport_id(s: &str) -> bool {
    let len = s.len();
    if !(1..=32).contains(&len) {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// A bridge's advertised set of transports.
///
/// Construction validates that every id is registry-valid and that the
/// mandatory baseline (`direct_tls`) is present — MUST-097.
#[derive(Clone, Debug)]
pub struct TransportRegistry {
    ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("transport id {0:?} fails MUST-093 regex [a-z0-9_-]{{1,32}}")]
    InvalidId(String),
    #[error("registry MUST include the MUST-097 baseline transport {MANDATORY_BASELINE_ID:?}")]
    MissingBaseline,
    #[error("registry MUST NOT be empty")]
    Empty,
}

impl TransportRegistry {
    pub fn new(ids: impl IntoIterator<Item = impl Into<String>>) -> Result<Self, RegistryError> {
        let ids: Vec<String> = ids.into_iter().map(Into::into).collect();
        if ids.is_empty() {
            return Err(RegistryError::Empty);
        }
        for id in &ids {
            if !is_valid_transport_id(id) {
                return Err(RegistryError::InvalidId(id.clone()));
            }
        }
        if !ids.iter().any(|id| id == MANDATORY_BASELINE_ID) {
            return Err(RegistryError::MissingBaseline);
        }
        Ok(Self { ids })
    }

    pub fn ids(&self) -> &[String] {
        &self.ids
    }

    /// Uniform-random per-session transport pick (MUST-098). Callers pass a
    /// CSPRNG (e.g. `rand::thread_rng()`); deterministic picks are a spec
    /// violation.
    pub fn choose<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> &str {
        self.ids.choose(rng).expect("registry non-empty by construction")
    }
}

/// Per-session transport selector tracking the pick so upper layers can
/// log/diagnose without re-rolling (which would lose the uniformity
/// property).
pub struct TransportSelector<'a> {
    registry: &'a TransportRegistry,
    picked: &'a str,
}

impl<'a> TransportSelector<'a> {
    pub fn new<R: rand::Rng + ?Sized>(registry: &'a TransportRegistry, rng: &mut R) -> Self {
        let picked = registry.choose(rng);
        Self { registry, picked }
    }
    pub fn id(&self) -> &str {
        self.picked
    }
    pub fn registry(&self) -> &TransportRegistry {
        self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn registry_ids_match_spec_v1() {
        assert_eq!(V1_REGISTRY_IDS.len(), 3);
        assert!(V1_REGISTRY_IDS.contains(&TRANSPORT_ID_DOMAIN_FRONT));
        assert!(V1_REGISTRY_IDS.contains(&TRANSPORT_ID_OBFS));
        assert!(V1_REGISTRY_IDS.contains(&TRANSPORT_ID_DIRECT_TLS));
    }

    #[test]
    fn valid_id_regex_accepts_registered() {
        for id in V1_REGISTRY_IDS {
            assert!(is_valid_transport_id(id), "{id} must be valid");
        }
    }

    #[test]
    fn valid_id_regex_rejects_uppercase_and_specials() {
        for bad in ["Domain_Front", "obfs4!", "", "x".repeat(33).as_str()] {
            assert!(!is_valid_transport_id(bad), "{bad:?} must be invalid");
        }
    }

    #[test]
    fn registry_requires_mandatory_baseline() {
        // MUST-097: direct_tls MUST always be included.
        let err = TransportRegistry::new(["obfs", "domain_front"]).unwrap_err();
        assert_eq!(err, RegistryError::MissingBaseline);
    }

    #[test]
    fn registry_rejects_bad_id() {
        let err = TransportRegistry::new(["direct_tls", "BadId"]).unwrap_err();
        assert!(matches!(err, RegistryError::InvalidId(_)));
    }

    #[test]
    fn selector_uniform_over_registry() {
        // MUST-098: with a CSPRNG and 3 transports, no single id should get
        // picked more than ~70 % of 900 draws (expected 33 % ± noise).
        let r = TransportRegistry::new(["direct_tls", "obfs", "domain_front"]).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEAD_BEEF);
        let mut counts = std::collections::HashMap::new();
        for _ in 0..900 {
            let pick = r.choose(&mut rng).to_string();
            *counts.entry(pick).or_insert(0u32) += 1;
        }
        for (_, n) in counts {
            assert!(
                n < 630,
                "one transport got {n}/900 picks — distribution not uniform"
            );
        }
    }

    #[test]
    fn selector_records_pick() {
        let r = TransportRegistry::new(["direct_tls", "obfs"]).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let sel = TransportSelector::new(&r, &mut rng);
        assert!(r.ids().iter().any(|id| id == sel.id()));
    }
}
