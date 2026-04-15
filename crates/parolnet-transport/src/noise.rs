//! Traffic noise generation (PNP-006).
//!
//! Implements constant-rate padding, burst smoothing, dummy traffic
//! generation, and timing jitter to make traffic patterns
//! indistinguishable from normal HTTPS browsing.

use crate::traits::TrafficShaper;
use rand::Rng;
use rand::rngs::OsRng;
use std::time::Duration;

/// Bandwidth modes (PNP-006 Section 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BandwidthMode {
    /// ~2 KB/s idle, 5% dummy traffic, 2s padding interval.
    Low,
    /// ~8 KB/s idle, 20% dummy traffic, 500ms padding interval.
    Normal,
    /// ~40 KB/s idle, 40% dummy traffic, 100ms padding interval.
    High,
    /// ~50 cells/s, no burst smoothing, audio-sized padding.
    MediaCall,
}

impl BandwidthMode {
    pub fn padding_interval(self) -> Duration {
        match self {
            Self::Low => Duration::from_millis(2000),
            Self::Normal => Duration::from_millis(500),
            Self::High => Duration::from_millis(100),
            Self::MediaCall => Duration::from_millis(20),
        }
    }

    pub fn jitter_max(self) -> Duration {
        match self {
            Self::Low => Duration::from_millis(500),
            Self::Normal => Duration::from_millis(100),
            Self::High => Duration::from_millis(30),
            Self::MediaCall => Duration::from_millis(5),
        }
    }

    pub fn dummy_traffic_percent(self) -> u8 {
        match self {
            Self::Low => 5,
            Self::Normal => 20,
            Self::High => 40,
            Self::MediaCall => 10,
        }
    }
}

/// Standard traffic shaper implementing PNP-006 behavioral rules.
pub struct StandardShaper {
    pub mode: BandwidthMode,
}

impl TrafficShaper for StandardShaper {
    fn delay_before_send(&self) -> Duration {
        let base = self.mode.padding_interval();
        let jitter_max = self.mode.jitter_max();
        // Use OsRng (CSPRNG) for security-sensitive jitter — predictable jitter
        // patterns could leak traffic timing information to a network observer.
        let jitter_ms = OsRng.gen_range(0..=jitter_max.as_millis() as u64);
        base + Duration::from_millis(jitter_ms)
    }

    fn dummy_traffic_interval(&self) -> Option<Duration> {
        Some(self.mode.padding_interval())
    }

    fn shape(&self, messages: Vec<Vec<u8>>) -> Vec<(Duration, Vec<u8>)> {
        let base_interval = self.mode.padding_interval();
        // Use OsRng (CSPRNG) — traffic shaping jitter is security-sensitive
        // because predictable patterns aid traffic analysis attacks.
        let mut rng = OsRng;
        let mut result = Vec::with_capacity(messages.len());

        // Burst smoothing: if more than 32 messages, allow 2x rate for first batch
        let double_rate_count = if messages.len() > 32 { 32 } else { 0 };

        for (i, msg) in messages.into_iter().enumerate() {
            let interval = if i < double_rate_count {
                // Double rate: half the base interval
                base_interval / 2
            } else {
                base_interval
            };

            // Add jitter
            let jitter_max = self.mode.jitter_max();
            let jitter = Duration::from_millis(rng.gen_range(0..=jitter_max.as_millis() as u64));

            result.push((interval + jitter, msg));
        }

        result
    }
}
