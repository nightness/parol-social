//! DNS TXT bootstrap channel (PNP-008 §8.3).
//!
//! Queries `_parolnet-relay._tcp.<domain>` and concatenates the TXT record
//! segments in lexicographic order (MUST-044) before base64-decoding into a
//! `BootstrapBundle`.
//!
//! The resolver uses `hickory-resolver` for async DNS over the system
//! resolv.conf; callers can override the resolver to point at a custom
//! DoH/DoT endpoint.

use super::bundle::BootstrapBundle;
use super::{
    ChannelError, ChannelKind, CHANNEL_ATTEMPT_TIMEOUT_SECS,
};
use base64::Engine;
use std::time::Duration;

/// DNS-SD-style prefix per PNP-008-MUST-041.
pub const DNS_RECORD_PREFIX: &str = "_parolnet-relay._tcp.";

/// Build the full TXT record name for a configured domain.
///
/// e.g. `fqdn("parol.example")` → `"_parolnet-relay._tcp.parol.example"`.
pub fn fqdn(domain: &str) -> String {
    let d = domain.trim_end_matches('.');
    format!("{DNS_RECORD_PREFIX}{d}")
}

/// Sort TXT segments per MUST-044 (lexicographic) and concatenate.
///
/// Split across `&str` slices — individual DNS character-strings are bounded
/// to 255 bytes by DNS, which is why the spec mandates concatenation on the
/// receiver.
pub fn join_segments<'a, I: IntoIterator<Item = &'a str>>(segments: I) -> String {
    let mut v: Vec<&str> = segments.into_iter().collect();
    v.sort();
    v.concat()
}

/// Decode a joined base64 TXT record into a `BootstrapBundle`.
pub fn decode_bundle(joined_b64: &str) -> Result<BootstrapBundle, ChannelError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(joined_b64.trim())
        .map_err(|e| ChannelError::Transport(format!("base64 decode: {e}")))?;
    BootstrapBundle::from_cbor(&raw).map_err(ChannelError::from)
}

/// DNS channel using `hickory-resolver` with the MUST-074 timeout applied.
pub struct DnsChannel;

impl DnsChannel {
    pub fn kind() -> ChannelKind {
        ChannelKind::DnsTxt
    }

    /// Query `<DNS_RECORD_PREFIX><domain>` and return the decoded bundle
    /// bytes. Does NOT verify the bundle — that's the caller's job via
    /// [`BootstrapBundle::verify_and_validate`].
    pub async fn fetch(domain: &str) -> Result<BootstrapBundle, ChannelError> {
        use hickory_resolver::TokioAsyncResolver;
        let name = fqdn(domain);
        let resolver = TokioAsyncResolver::tokio(Default::default(), Default::default());

        let fut = resolver.txt_lookup(name);
        let txt = tokio::time::timeout(Duration::from_secs(CHANNEL_ATTEMPT_TIMEOUT_SECS), fut)
            .await
            .map_err(|_| ChannelError::Timeout(CHANNEL_ATTEMPT_TIMEOUT_SECS))?
            .map_err(|e| match e.kind() {
                hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. } => {
                    ChannelError::NotFound
                }
                _ => ChannelError::Transport(format!("dns: {e}")),
            })?;

        // hickory gives us TXT records each as a set of character-strings.
        // Per MUST-044 we concatenate all segments in lex order across the
        // whole TXT record set.
        let mut segs: Vec<String> = Vec::new();
        for record in txt.iter() {
            for bytes in record.iter() {
                if let Ok(s) = std::str::from_utf8(bytes) {
                    segs.push(s.to_owned());
                }
            }
        }
        if segs.is_empty() {
            return Err(ChannelError::NotFound);
        }
        let joined = join_segments(segs.iter().map(|s| s.as_str()));
        decode_bundle(&joined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn_matches_spec_prefix() {
        assert_eq!(
            fqdn("parol.example"),
            "_parolnet-relay._tcp.parol.example"
        );
        // Trailing dots trimmed so the prefix format is stable.
        assert_eq!(
            fqdn("parol.example."),
            "_parolnet-relay._tcp.parol.example"
        );
    }

    #[test]
    fn dns_prefix_constant_matches_spec() {
        assert_eq!(DNS_RECORD_PREFIX, "_parolnet-relay._tcp.");
        assert!(DNS_RECORD_PREFIX.starts_with("_parolnet-relay."));
        assert!(DNS_RECORD_PREFIX.ends_with("._tcp."));
    }

    #[test]
    fn segments_joined_in_lex_order() {
        // MUST-044: receivers MUST concatenate segments in lex order before
        // base64 decode.
        let joined = join_segments(["zz", "aa", "mm"]);
        assert_eq!(joined, "aammzz");
    }

    #[test]
    fn decode_bundle_rejects_garbage_base64() {
        let err = decode_bundle("!@#$not_base64").unwrap_err();
        assert!(matches!(err, ChannelError::Transport(_)));
    }
}
