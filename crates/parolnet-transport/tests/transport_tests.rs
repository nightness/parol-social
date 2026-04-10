use parolnet_transport::noise::{BandwidthMode, StandardShaper};
use parolnet_transport::tls_camouflage::FingerprintProfile;
use parolnet_transport::traits::TrafficShaper;
use std::time::Duration;

// ── Bandwidth Mode Tests ────────────────────────────────────────

#[test]
fn test_bandwidth_mode_intervals() {
    assert_eq!(BandwidthMode::Low.padding_interval(), Duration::from_millis(2000));
    assert_eq!(BandwidthMode::Normal.padding_interval(), Duration::from_millis(500));
    assert_eq!(BandwidthMode::High.padding_interval(), Duration::from_millis(100));
}

#[test]
fn test_bandwidth_mode_jitter() {
    assert_eq!(BandwidthMode::Low.jitter_max(), Duration::from_millis(500));
    assert_eq!(BandwidthMode::Normal.jitter_max(), Duration::from_millis(100));
    assert_eq!(BandwidthMode::High.jitter_max(), Duration::from_millis(30));
}

#[test]
fn test_dummy_traffic_percent() {
    assert_eq!(BandwidthMode::Low.dummy_traffic_percent(), 5);
    assert_eq!(BandwidthMode::Normal.dummy_traffic_percent(), 20);
    assert_eq!(BandwidthMode::High.dummy_traffic_percent(), 40);
}

// ── Traffic Shaper Tests ────────────────────────────────────────

#[test]
fn test_standard_shaper_has_dummy_interval() {
    let shaper = StandardShaper { mode: BandwidthMode::Normal };
    assert!(shaper.dummy_traffic_interval().is_some());
    assert_eq!(
        shaper.dummy_traffic_interval().unwrap(),
        Duration::from_millis(500)
    );
}

#[test]
fn test_shaper_delay_within_bounds() {
    let shaper = StandardShaper { mode: BandwidthMode::Normal };

    // Run 100 times and verify delays are within expected range
    for _ in 0..100 {
        let delay = shaper.delay_before_send();
        // Normal mode: 500ms base + 0-100ms jitter = 500-600ms
        assert!(delay >= Duration::from_millis(500), "delay {delay:?} too low");
        assert!(delay <= Duration::from_millis(600), "delay {delay:?} too high");
    }
}

#[test]
fn test_shaper_delay_low_mode() {
    let shaper = StandardShaper { mode: BandwidthMode::Low };
    for _ in 0..50 {
        let delay = shaper.delay_before_send();
        assert!(delay >= Duration::from_millis(2000));
        assert!(delay <= Duration::from_millis(2500));
    }
}

#[test]
fn test_shaper_delay_high_mode() {
    let shaper = StandardShaper { mode: BandwidthMode::High };
    for _ in 0..50 {
        let delay = shaper.delay_before_send();
        assert!(delay >= Duration::from_millis(100));
        assert!(delay <= Duration::from_millis(130));
    }
}

#[test]
fn test_shaper_burst_smoothing() {
    let shaper = StandardShaper { mode: BandwidthMode::Normal };

    // Small burst: all at base rate
    let messages: Vec<Vec<u8>> = (0..5).map(|i| vec![i]).collect();
    let shaped = shaper.shape(messages);
    assert_eq!(shaped.len(), 5);
    for (delay, _) in &shaped {
        assert!(*delay >= Duration::from_millis(500));
    }
}

#[test]
fn test_shaper_large_burst_doubles_rate() {
    let shaper = StandardShaper { mode: BandwidthMode::Normal };

    // Large burst (>32): first 32 at double rate
    let messages: Vec<Vec<u8>> = (0..50).map(|i| vec![i]).collect();
    let shaped = shaper.shape(messages);
    assert_eq!(shaped.len(), 50);

    // First 32 should have halved base interval (250ms + jitter)
    for (delay, _) in &shaped[..32] {
        assert!(*delay >= Duration::from_millis(250), "burst delay {delay:?} too low");
        assert!(*delay <= Duration::from_millis(350), "burst delay {delay:?} too high");
    }

    // Remaining should have normal interval
    for (delay, _) in &shaped[32..] {
        assert!(*delay >= Duration::from_millis(500));
    }
}

// ── TLS Fingerprint Tests ───────────────────────────────────────

#[test]
fn test_chrome_fingerprint_profile() {
    let profile = FingerprintProfile::chrome();
    assert!(!profile.cipher_suites.is_empty());
    assert!(profile.alpn_protocols.contains(&"h2".to_string()));
    assert!(profile.alpn_protocols.contains(&"http/1.1".to_string()));
    // x25519 should be in supported groups
    assert!(profile.supported_groups.contains(&0x001D));
}

#[test]
fn test_firefox_fingerprint_profile() {
    let profile = FingerprintProfile::firefox();
    assert!(!profile.cipher_suites.is_empty());
    assert!(profile.alpn_protocols.contains(&"h2".to_string()));
    // Firefox and Chrome have different cipher suite ordering
    assert_ne!(profile.cipher_suites, FingerprintProfile::chrome().cipher_suites);
}

#[test]
fn test_fingerprint_builds_client_config() {
    let profile = FingerprintProfile::chrome();
    let config = profile.build_client_config();
    assert!(config.is_ok());

    let config = config.unwrap();
    assert_eq!(config.alpn_protocols.len(), 2);
}

// ── Traffic Shaper Property Tests ──────────────────────────────

#[test]
fn test_shaper_jitter_never_below_base() {
    let shaper = StandardShaper { mode: BandwidthMode::Normal };
    let base = Duration::from_millis(500);
    for _ in 0..1000 {
        let delay = shaper.delay_before_send();
        assert!(
            delay >= base,
            "delay {delay:?} is below base interval {base:?}"
        );
    }
}

#[test]
fn test_shaper_shape_preserves_message_order() {
    let shaper = StandardShaper { mode: BandwidthMode::Normal };
    let messages: Vec<Vec<u8>> = (0..10).map(|i| format!("{i}").into_bytes()).collect();
    let shaped = shaper.shape(messages);
    assert_eq!(shaped.len(), 10);
    for (i, (_delay, data)) in shaped.iter().enumerate() {
        let expected = format!("{i}");
        assert_eq!(
            String::from_utf8_lossy(data),
            expected,
            "message at index {i} has wrong content"
        );
    }
}

#[test]
fn test_shaper_shape_empty_input() {
    let shaper = StandardShaper { mode: BandwidthMode::Normal };
    let shaped = shaper.shape(vec![]);
    assert!(shaped.is_empty());
}

// ── TLS Fingerprint Validation Tests ───────────────────────────

#[test]
fn test_fingerprint_both_profiles_have_cipher_suites() {
    let chrome = FingerprintProfile::chrome();
    let firefox = FingerprintProfile::firefox();
    assert!(!chrome.cipher_suites.is_empty(), "Chrome profile has no cipher suites");
    assert!(!firefox.cipher_suites.is_empty(), "Firefox profile has no cipher suites");
}

#[test]
fn test_fingerprint_alpn_h2_first() {
    let chrome = FingerprintProfile::chrome();
    let firefox = FingerprintProfile::firefox();
    assert_eq!(chrome.alpn_protocols[0], "h2", "Chrome ALPN[0] should be h2");
    assert_eq!(firefox.alpn_protocols[0], "h2", "Firefox ALPN[0] should be h2");
}

#[test]
fn test_fingerprint_x25519_in_groups() {
    let chrome = FingerprintProfile::chrome();
    let firefox = FingerprintProfile::firefox();
    assert!(
        chrome.supported_groups.contains(&0x001D),
        "Chrome profile missing x25519 (0x001D)"
    );
    assert!(
        firefox.supported_groups.contains(&0x001D),
        "Firefox profile missing x25519 (0x001D)"
    );
}

// ── Transport Error Tests ──────────────────────────────────────

#[test]
fn test_fingerprint_config_alpn_matches() {
    let profile = FingerprintProfile::chrome();
    let config = profile.build_client_config().expect("build_client_config failed");
    assert_eq!(
        config.alpn_protocols.len(),
        2,
        "Expected 2 ALPN entries in client config"
    );
}

#[test]
fn test_bandwidth_modes_are_distinct() {
    let modes = [BandwidthMode::Low, BandwidthMode::Normal, BandwidthMode::High];
    for i in 0..modes.len() {
        for j in (i + 1)..modes.len() {
            let a = modes[i];
            let b = modes[j];
            assert_ne!(
                a.padding_interval(),
                b.padding_interval(),
                "{a:?} and {b:?} have same padding_interval"
            );
            assert_ne!(
                a.jitter_max(),
                b.jitter_max(),
                "{a:?} and {b:?} have same jitter_max"
            );
            assert_ne!(
                a.dummy_traffic_percent(),
                b.dummy_traffic_percent(),
                "{a:?} and {b:?} have same dummy_traffic_percent"
            );
        }
    }
}
