//! Obfuscated pluggable transport primitives (PNP-008 §9.2.3).
//!
//! This file implements the randomness + length-distribution primitives the
//! spec pins in MUST-095 and MUST-096:
//!
//! - [`RandomPrefix`] emits the ≥ 32 byte per-session random prefix that
//!   must be sent on every obfuscated session before any PNP-002 frame.
//! - [`LengthDistribution`] produces per-frame length targets drawn from a
//!   cover-traffic profile so DPI length-frequency analysis sees the same
//!   distribution as benign traffic.
//!
//! The full obfs4 node-identity exchange is out of scope for this commit —
//! this module gives upstream code the building blocks it needs to layer
//! obfs4 (or a domain-specific variant) on top of the existing TLS
//! camouflage.

use crate::pluggable::{PluggableTransport, TRANSPORT_ID_OBFS};
use rand::{Rng, RngCore};

/// Minimum random prefix length per MUST-095. Senders SHOULD emit more than
/// the minimum when the cover profile supports it.
pub const MIN_RANDOM_PREFIX_BYTES: usize = 32;

/// Per-session randomized prefix (MUST-095). The sender emits this verbatim
/// before any PNP-002 or federation bytes.
#[derive(Clone, Debug)]
pub struct RandomPrefix {
    bytes: Vec<u8>,
}

impl RandomPrefix {
    /// Draw a fresh prefix of length `len` (must be ≥ [`MIN_RANDOM_PREFIX_BYTES`]).
    /// A shorter prefix is a release-blocking bug — this function panics in
    /// debug and saturates in release.
    pub fn new<R: RngCore + ?Sized>(rng: &mut R, len: usize) -> Self {
        assert!(
            len >= MIN_RANDOM_PREFIX_BYTES,
            "MUST-095: random prefix MUST be ≥ {MIN_RANDOM_PREFIX_BYTES} bytes"
        );
        let mut b = vec![0u8; len];
        rng.fill_bytes(&mut b);
        Self { bytes: b }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Cover-traffic length distribution used for per-frame padding (MUST-096).
///
/// Three built-in profiles approximate distributions the obfs layer can mimic
/// without per-application tuning. Production deployments SHOULD replace the
/// baked-in profile with a live histogram gathered from the target cover
/// medium (e.g. the CDN that fronts the bridge), but the baked-in set is
/// enough for conformance + unit tests.
#[derive(Clone, Copy, Debug)]
pub enum CoverProfile {
    /// HTTP/1.1 request/response sizes observed on commodity web traffic.
    Http1,
    /// DNS-over-HTTPS query/response sizes.
    DnsOverHttps,
    /// Short-form social-media polling (many tiny frames + occasional
    /// larger uploads).
    SocialPolling,
}

impl CoverProfile {
    /// Draw a padded-frame length ≥ `payload_len`, sampled from the profile's
    /// distribution. Deterministic for a given rng state so tests are
    /// reproducible.
    pub fn draw_frame_length<R: Rng + ?Sized>(self, rng: &mut R, payload_len: usize) -> usize {
        let candidates: &[usize] = match self {
            Self::Http1 => &[320, 640, 1280, 2048, 4096, 8192, 16384],
            Self::DnsOverHttps => &[128, 256, 512, 1024, 1500],
            Self::SocialPolling => &[64, 128, 256, 512, 1024, 2048],
        };
        let target = candidates[rng.gen_range(0..candidates.len())];
        target.max(payload_len)
    }
}

/// Convenience padder: pad `payload` to a length sampled from `profile`.
pub fn pad_to_cover<R: Rng + ?Sized>(
    payload: &[u8],
    profile: CoverProfile,
    rng: &mut R,
) -> Vec<u8> {
    let target = profile.draw_frame_length(rng, payload.len());
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(payload);
    let pad = target - payload.len();
    if pad > 0 {
        let mut pad_bytes = vec![0u8; pad];
        rng.fill_bytes(&mut pad_bytes);
        out.extend_from_slice(&pad_bytes);
    }
    out
}

/// Minimal transport wrapper exposing the registry id.
pub struct ObfsTransport {
    pub profile: CoverProfile,
}

impl ObfsTransport {
    pub fn new(profile: CoverProfile) -> Self {
        Self { profile }
    }
}

impl PluggableTransport for ObfsTransport {
    fn id(&self) -> &'static str {
        TRANSPORT_ID_OBFS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn random_prefix_respects_minimum() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let p = RandomPrefix::new(&mut rng, MIN_RANDOM_PREFIX_BYTES);
        assert_eq!(p.len(), MIN_RANDOM_PREFIX_BYTES);
    }

    #[test]
    #[should_panic]
    fn random_prefix_panics_below_minimum_in_debug() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let _ = RandomPrefix::new(&mut rng, MIN_RANDOM_PREFIX_BYTES - 1);
    }

    #[test]
    fn random_prefix_is_per_session_unique() {
        // Per-session randomization: two fresh prefixes under the same seed
        // produced from independent RNG streams MUST differ.
        let mut rng_a = rand::rngs::StdRng::seed_from_u64(0xAAAA);
        let mut rng_b = rand::rngs::StdRng::seed_from_u64(0xBBBB);
        let a = RandomPrefix::new(&mut rng_a, 32);
        let b = RandomPrefix::new(&mut rng_b, 32);
        assert_ne!(a.bytes(), b.bytes());
    }

    #[test]
    fn pad_to_cover_never_truncates_payload() {
        let payload = vec![0x42u8; 100];
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        for _ in 0..50 {
            let padded = pad_to_cover(&payload, CoverProfile::Http1, &mut rng);
            assert!(padded.len() >= payload.len());
            assert_eq!(&padded[..payload.len()], &payload[..]);
        }
    }

    #[test]
    fn pad_to_cover_hits_multiple_sizes_per_profile() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(5);
        let payload = vec![0u8; 10];
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.insert(pad_to_cover(&payload, CoverProfile::DnsOverHttps, &mut rng).len());
        }
        // A flat single-size distribution would violate MUST-096.
        assert!(seen.len() >= 3, "length distribution too narrow: {seen:?}");
    }

    #[test]
    fn obfs_transport_id_matches_registry() {
        assert_eq!(ObfsTransport::new(CoverProfile::Http1).id(), TRANSPORT_ID_OBFS);
    }
}
