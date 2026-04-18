//! HTTPS directory bootstrap channel (PNP-008 §8.4).
//!
//! Fetches a signed `BootstrapBundle` from a TLS-secured URL. The body is
//! gated on MIME type (MUST-076) *before* any CBOR parse attempt, and the
//! bundle signature is verified independently of the TLS channel
//! (MUST-046) — a compromised CA cannot inject descriptors.

use super::bundle::BootstrapBundle;
use super::{ChannelError, ChannelKind, CHANNEL_ATTEMPT_TIMEOUT_SECS};
use std::time::Duration;

/// Accepted content-type for the body, per MUST-076. The parameterised form
/// `application/cbor; charset=binary` is also allowed.
pub const REQUIRED_CONTENT_TYPE: &str = "application/cbor";

/// Return whether `content_type` is spec-compliant for the HTTPS bundle body.
pub fn content_type_accepted(content_type: &str) -> bool {
    let lower = content_type.to_ascii_lowercase();
    let trimmed = lower.trim();
    trimmed == REQUIRED_CONTENT_TYPE
        || trimmed.starts_with(&format!("{REQUIRED_CONTENT_TYPE};"))
}

/// HTTPS channel.
pub struct HttpsChannel;

impl HttpsChannel {
    pub fn kind() -> ChannelKind {
        ChannelKind::Https
    }

    /// Fetch a bundle from `url`. The URL MUST be HTTPS; a non-TLS scheme
    /// is rejected before any network I/O.
    pub async fn fetch(url: &str) -> Result<BootstrapBundle, ChannelError> {
        if !url.starts_with("https://") {
            return Err(ChannelError::Transport(format!(
                "URL must be https://: got {url}"
            )));
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(CHANNEL_ATTEMPT_TIMEOUT_SECS))
            .build()
            .map_err(|e| ChannelError::Transport(format!("http client init: {e}")))?;
        let fut = client.get(url).send();
        let resp = tokio::time::timeout(Duration::from_secs(CHANNEL_ATTEMPT_TIMEOUT_SECS), fut)
            .await
            .map_err(|_| ChannelError::Timeout(CHANNEL_ATTEMPT_TIMEOUT_SECS))?
            .map_err(|e| ChannelError::Transport(format!("http send: {e}")))?;
        if !resp.status().is_success() {
            return Err(ChannelError::Transport(format!(
                "HTTP status {}",
                resp.status()
            )));
        }

        // MUST-076: gate on content-type before parsing the body.
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        if !content_type_accepted(&ct) {
            return Err(ChannelError::ContentType(ct));
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| ChannelError::Transport(format!("http body: {e}")))?;
        BootstrapBundle::from_cbor(&body).map_err(ChannelError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_content_type_matches_spec() {
        assert_eq!(REQUIRED_CONTENT_TYPE, "application/cbor");
    }

    #[test]
    fn plain_cbor_accepted() {
        assert!(content_type_accepted("application/cbor"));
    }

    #[test]
    fn parameterised_cbor_accepted() {
        assert!(content_type_accepted("application/cbor; charset=binary"));
        assert!(content_type_accepted("application/cbor;foo=bar"));
    }

    #[test]
    fn common_sniff_payloads_rejected() {
        // MUST-076: defend against content-sniffing.
        for bad in [
            "text/html",
            "text/plain",
            "application/json",
            "application/octet-stream",
            "",
        ] {
            assert!(
                !content_type_accepted(bad),
                "content-type {bad:?} MUST be rejected"
            );
        }
    }

    #[test]
    fn case_insensitive_accept() {
        assert!(content_type_accepted("APPLICATION/CBOR"));
        assert!(content_type_accepted("Application/Cbor; charset=binary"));
    }

    #[tokio::test]
    async fn non_https_url_rejected_without_io() {
        let err = HttpsChannel::fetch("http://example.com/bundle").await.unwrap_err();
        match err {
            ChannelError::Transport(msg) => assert!(msg.contains("https://")),
            other => panic!("expected Transport error, got {other:?}"),
        }
    }
}
