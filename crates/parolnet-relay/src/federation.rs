//! Federation peer state machine (PNP-008 §5).
//!
//! Pure-data model of per-peer federation link state. No I/O, no networking —
//! callers (the forthcoming `FederationManager`) feed events in and use the
//! exposed timer/eligibility helpers to drive the actual transport.
//!
//! ## Spec mapping
//! - §5 state diagram (INIT → HANDSHAKE → SYNC → ACTIVE → IDLE → BANNED) →
//!   [`PeerState`]
//! - §5.2 MUST-018 (TLS camouflage + PNP-002 before payloads) — structurally
//!   enforced by `can_send_federation_payload()` returning `false` outside
//!   `Sync`/`Active`.
//! - §5.2 MUST-019 (descriptor unverifiable → close) → [`FederationPeer::handshake_failed`]
//! - §5.3 MUST-020 reconnect backoff → [`reconnect_backoff_delay`]
//! - §5.3 MUST-021 failure reset after ≥ 300 s ACTIVE → [`FederationPeer::active_stabilized`]
//! - §5.4 MUST-022 rate limits (100 desc/min, 10 syncs/hr) → [`TokenBucket`]
//! - §4.2 MUST-011 heartbeat cadence / unreachable threshold → [`FederationPeer::tick`]

use crate::federation_replay::SyncIdReplayCache;
use crate::health::ObservationEvent;
use parolnet_protocol::address::PeerId;
use parolnet_protocol::federation::{
    HEARTBEAT_UNREACHABLE_SECS, RATE_LIMIT_DESCRIPTORS_PER_MIN, RATE_LIMIT_SYNC_INITS_PER_HOUR,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Minimum ACTIVE dwell time before a successful session resets the failure
/// counter (PNP-008-MUST-021).
pub const STABILIZATION_ACTIVE_SECS: u64 = 300;

/// Default base reconnect delay in seconds (PNP-008-MUST-020:
/// `30 * 2^failures`, bounded).
pub const DEFAULT_RECONNECT_BASE_SECS: u64 = 30;

/// Maximum reconnect delay (PNP-008-MUST-020).
pub const DEFAULT_RECONNECT_MAX_SECS: u64 = 3600;

/// Federation peer lifecycle state (PNP-008 §5 diagram).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerState {
    /// Peer is known but no connection attempt has been made yet.
    Init,
    /// Transport open, TLS+PNP-002 handshake in progress; NO federation
    /// payloads may be exchanged yet (MUST-018).
    Handshake,
    /// Handshake complete; running initial `FederationSync`.
    Sync,
    /// Initial sync complete; exchanging heartbeats and periodic syncs.
    Active,
    /// Not connected; awaiting the MUST-020 reconnect backoff.
    Idle,
    /// Reputation decided to ban this peer (PNP-008-MUST-035 — enforced via
    /// [`crate::MeshError`] flow in the FederationManager; here we record
    /// that the state machine was transitioned into BANNED so other logic
    /// can refuse to re-enter HANDSHAKE during the cooldown).
    Banned,
}

impl PeerState {
    /// Whether this state may carry FederationSync / FederationHeartbeat
    /// payloads (PNP-008-MUST-018).
    ///
    /// `Init`, `Handshake`, `Idle`, `Banned` MUST NOT. `Sync` is allowed
    /// because the initial `FederationSync` is the transition trigger for
    /// `Active`.
    pub fn can_send_federation_payload(self) -> bool {
        matches!(self, Self::Sync | Self::Active)
    }
}

/// Token bucket for the MUST-022 rate-limit caps.
///
/// The bucket refills `capacity` tokens over `period_secs`. Elapsed time is
/// converted to fractional tokens and accumulated on each access — this is
/// what lets us model both fast rates (100/min) and slow rates (10/hr) with
/// a single integer time source. Unconsumed refill-fractions survive across
/// `try_take` calls because `last_refill` is advanced by the whole-second
/// equivalent of tokens minted.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenBucket {
    pub capacity: u32,
    pub period_secs: u64,
    pub tokens: u32,
    pub last_refill: u64,
}

impl TokenBucket {
    pub fn new(capacity: u32, period_secs: u64, now: u64) -> Self {
        Self {
            capacity,
            period_secs,
            tokens: capacity,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: u64) {
        if self.period_secs == 0 || self.capacity == 0 {
            return;
        }
        let elapsed = now.saturating_sub(self.last_refill);
        if elapsed == 0 {
            return;
        }
        // tokens_to_add = floor(elapsed * capacity / period_secs).
        let add = elapsed
            .saturating_mul(self.capacity as u64)
            / self.period_secs;
        if add == 0 {
            return;
        }
        let capped = add.min(self.capacity as u64) as u32;
        self.tokens = self.tokens.saturating_add(capped).min(self.capacity);
        // Advance last_refill by the whole-second equivalent of the tokens
        // we minted so fractional carry isn't lost across calls.
        let consumed_secs = (add.saturating_mul(self.period_secs)) / self.capacity as u64;
        self.last_refill = self.last_refill.saturating_add(consumed_secs);
    }

    /// Attempt to spend one token. Returns `true` on success.
    pub fn try_take(&mut self, now: u64) -> bool {
        self.refill(now);
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Compute the MUST-020 base reconnect delay in seconds.
///
/// `base * 2^failures`, capped at `max`. Caller adds the ±25 % jitter.
pub fn reconnect_backoff_delay(failures: u32, base_secs: u64, max_secs: u64) -> u64 {
    let shift = failures.min(63);
    let raw = base_secs.saturating_mul(1u64 << shift);
    raw.min(max_secs)
}

/// Per-peer federation link state (PNP-008 §5).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationPeer {
    pub peer_id: PeerId,
    pub state: PeerState,
    /// Consecutive connection failures since the last stabilized ACTIVE
    /// session (PNP-008-MUST-021).
    pub failures: u32,
    /// Unix seconds the peer most recently transitioned into ACTIVE.
    pub active_since: Option<u64>,
    /// Unix seconds of the last state transition (for liveness queries).
    pub last_transition: u64,
    /// Unix seconds the peer's last heartbeat arrived.
    pub last_heartbeat_rx: Option<u64>,
    /// Monotonic counter of the last heartbeat we accepted (MUST-010).
    pub last_heartbeat_counter: Option<u64>,
    /// Rate-limit bucket for descriptor deliveries (MUST-022, 100/min).
    pub descriptor_bucket: TokenBucket,
    /// Rate-limit bucket for FederationSync initiations (MUST-022, 10/hr).
    pub sync_init_bucket: TokenBucket,
}

impl FederationPeer {
    /// New peer at `Init` state.
    pub fn new(peer_id: PeerId, now: u64) -> Self {
        Self {
            peer_id,
            state: PeerState::Init,
            failures: 0,
            active_since: None,
            last_transition: now,
            last_heartbeat_rx: None,
            last_heartbeat_counter: None,
            descriptor_bucket: TokenBucket::new(RATE_LIMIT_DESCRIPTORS_PER_MIN, 60, now),
            sync_init_bucket: TokenBucket::new(RATE_LIMIT_SYNC_INITS_PER_HOUR, 3600, now),
        }
    }

    fn transition(&mut self, to: PeerState, now: u64) {
        self.state = to;
        self.last_transition = now;
    }

    /// Begin connection — legal only from `Init` or `Idle`, and never when
    /// `Banned`.
    pub fn connect(&mut self, now: u64) -> Result<(), TransitionError> {
        match self.state {
            PeerState::Init | PeerState::Idle => {
                self.transition(PeerState::Handshake, now);
                Ok(())
            }
            PeerState::Banned => Err(TransitionError::Banned),
            other => Err(TransitionError::IllegalFrom(other)),
        }
    }

    /// Handshake completed successfully → advance to SYNC.
    pub fn handshake_ok(&mut self, now: u64) -> Result<(), TransitionError> {
        if self.state != PeerState::Handshake {
            return Err(TransitionError::IllegalFrom(self.state));
        }
        self.transition(PeerState::Sync, now);
        Ok(())
    }

    /// Handshake failed — MUST-019 requires the transport to be closed; we
    /// fall back to IDLE, increment failures, and let the caller consult
    /// [`Self::reconnect_delay`] for MUST-020 backoff.
    pub fn handshake_failed(&mut self, now: u64) {
        self.failures = self.failures.saturating_add(1);
        self.active_since = None;
        self.transition(PeerState::Idle, now);
    }

    /// Initial `FederationSync` round completed → advance to ACTIVE.
    pub fn sync_complete(&mut self, now: u64) -> Result<(), TransitionError> {
        if self.state != PeerState::Sync {
            return Err(TransitionError::IllegalFrom(self.state));
        }
        self.transition(PeerState::Active, now);
        self.active_since = Some(now);
        Ok(())
    }

    /// Record an accepted heartbeat. Caller has already verified the
    /// signature and monotonicity; this method records the counter.
    pub fn heartbeat_seen(&mut self, counter: u64, now: u64) {
        self.last_heartbeat_rx = Some(now);
        self.last_heartbeat_counter = Some(counter);
    }

    /// Drive time-based transitions. Call periodically from the manager's
    /// ticker. Returns `true` if the state changed.
    ///
    /// Currently implements MUST-011: if ACTIVE and the last heartbeat is
    /// older than `HEARTBEAT_UNREACHABLE_SECS`, transition to IDLE.
    pub fn tick(&mut self, now: u64) -> bool {
        if self.state != PeerState::Active {
            return false;
        }
        if let Some(last) = self.last_heartbeat_rx
            && now.saturating_sub(last) > HEARTBEAT_UNREACHABLE_SECS
        {
            self.failures = self.failures.saturating_add(1);
            self.active_since = None;
            self.transition(PeerState::Idle, now);
            return true;
        }
        // Session has been ACTIVE long enough — reset failures (MUST-021).
        if self.active_stabilized(now) {
            self.failures = 0;
        }
        false
    }

    /// Whether the current ACTIVE session has passed the MUST-021
    /// stabilization threshold (≥ 300 s).
    pub fn active_stabilized(&self, now: u64) -> bool {
        match self.active_since {
            Some(since) => now.saturating_sub(since) >= STABILIZATION_ACTIVE_SECS,
            None => false,
        }
    }

    /// MUST-020 reconnect delay for the current failure count.
    pub fn reconnect_delay(&self) -> u64 {
        reconnect_backoff_delay(
            self.failures,
            DEFAULT_RECONNECT_BASE_SECS,
            DEFAULT_RECONNECT_MAX_SECS,
        )
    }

    /// Wall-clock time at which reconnect becomes eligible, given the peer
    /// is in IDLE. Returns `None` if not applicable.
    pub fn next_reconnect_eligible_at(&self) -> Option<u64> {
        match self.state {
            PeerState::Idle => Some(self.last_transition + self.reconnect_delay()),
            _ => None,
        }
    }

    /// Move to BANNED. Called by the FederationManager when the reputation
    /// subsystem raises the BANNED flag.
    pub fn ban(&mut self, now: u64) {
        self.active_since = None;
        self.transition(PeerState::Banned, now);
    }

    /// Move out of BANNED (back to IDLE) — called by the manager once the
    /// reputation layer has observed the 24 h cooldown passing.
    pub fn unban(&mut self, now: u64) {
        if self.state == PeerState::Banned {
            self.failures = 0;
            self.transition(PeerState::Idle, now);
        }
    }

    /// Attempt to charge one `FederationSync` initiation against the
    /// MUST-022 rate limit. Returns `true` if permitted.
    pub fn charge_sync_init(&mut self, now: u64) -> bool {
        self.sync_init_bucket.try_take(now)
    }

    /// Attempt to charge one descriptor delivery against the MUST-022 rate
    /// limit. Returns `true` if permitted.
    pub fn charge_descriptor_delivery(&mut self, now: u64) -> bool {
        self.descriptor_bucket.try_take(now)
    }
}

/// Errors from illegal state transitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// The attempted transition is not allowed from this state.
    IllegalFrom(PeerState),
    /// Peer is currently BANNED and cannot reconnect.
    Banned,
}

/// Errors surfaced by `FederationManager` event-ingestion methods.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManagerError {
    /// No entry for this peer — call `add_peer` first.
    UnknownPeer,
    /// The transition attempted by the event is not legal from the peer's
    /// current state.
    Transition(TransitionError),
    /// Heartbeat arrived with a counter ≤ the previously accepted counter
    /// (PNP-008-MUST-010).
    HeartbeatCounterNotMonotonic,
    /// Sync_id was replayed within the MUST-006 window.
    SyncIdReplay,
    /// MUST-015: can't promote more peers — already at cap.
    ActivePeerCapReached,
}

impl From<TransitionError> for ManagerError {
    fn from(e: TransitionError) -> Self {
        Self::Transition(e)
    }
}

/// Aggregator over per-peer federation link state (PNP-008 §5).
///
/// Owns a `HashMap<PeerId, FederationPeer>` and a per-peer `sync_id` replay
/// cache. Event-ingestion methods update state and return a
/// `Vec<ObservationEvent>` the caller feeds into its reputation store
/// (`RelayDirectory::record_reputation_event` in the relay crate). This
/// indirection keeps `parolnet-mesh` unaware of relay-side reputation types.
///
/// MUST-015 admission control lives here: `connect_peer` and
/// `sync_complete` refuse to promote past `max_active_peers` ACTIVE peers.
/// Receive-side validation (descriptor signatures, endorsement chain) is
/// still the caller's responsibility — the manager only tracks the
/// after-the-fact state transitions.
#[derive(Debug)]
pub struct FederationManager {
    peers: HashMap<PeerId, FederationPeer>,
    replay_caches: HashMap<PeerId, SyncIdReplayCache>,
    /// MUST-015 cap on concurrent ACTIVE federation peers.
    pub max_active_peers: usize,
}

impl FederationManager {
    /// New manager with the spec-default cap of 8 active peers
    /// (PNP-008-MUST-015).
    pub fn new() -> Self {
        Self::with_capacity(8)
    }

    /// New manager with an explicit active-peer cap.
    pub fn with_capacity(max_active_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            replay_caches: HashMap::new(),
            max_active_peers,
        }
    }

    /// Number of peers currently known to the manager (any state).
    pub fn known_peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of peers currently in `ACTIVE` state (MUST-015 scope).
    pub fn active_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Active)
            .count()
    }

    /// Whether a new peer could be promoted into `ACTIVE` without
    /// violating the MUST-015 cap.
    pub fn can_admit_new_active(&self) -> bool {
        self.active_count() < self.max_active_peers
    }

    /// Add a peer entry at `INIT`. Idempotent — re-adding a known peer is
    /// a no-op so the caller can safely replay directory updates.
    pub fn add_peer(&mut self, peer_id: PeerId, now: u64) {
        self.peers
            .entry(peer_id)
            .or_insert_with(|| FederationPeer::new(peer_id, now));
        self.replay_caches
            .entry(peer_id)
            .or_insert_with(SyncIdReplayCache::new);
    }

    /// Forget a peer entirely. Used when a descriptor is pruned or an
    /// operator removes a federation entry from config.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
        self.replay_caches.remove(peer_id);
    }

    /// Borrow a peer's full state for callers that need to inspect state or
    /// timer fields.
    pub fn peer(&self, peer_id: &PeerId) -> Option<&FederationPeer> {
        self.peers.get(peer_id)
    }

    /// Iterator over every known peer.
    pub fn peers(&self) -> impl Iterator<Item = &FederationPeer> {
        self.peers.values()
    }

    fn peer_mut(&mut self, peer_id: &PeerId) -> Result<&mut FederationPeer, ManagerError> {
        self.peers.get_mut(peer_id).ok_or(ManagerError::UnknownPeer)
    }

    /// Begin connection to a peer. No observations — handshakes drive those.
    pub fn connect_peer(&mut self, peer_id: &PeerId, now: u64) -> Result<(), ManagerError> {
        self.peer_mut(peer_id)?.connect(now)?;
        Ok(())
    }

    /// Handshake succeeded; peer advances to `SYNC`.
    pub fn on_handshake_ok(
        &mut self,
        peer_id: &PeerId,
        now: u64,
    ) -> Result<Vec<ObservationEvent>, ManagerError> {
        self.peer_mut(peer_id)?.handshake_ok(now)?;
        Ok(Vec::new())
    }

    /// Handshake failed — peer falls to `IDLE`. Observations: none (the
    /// transport closed before any federation-layer signal).
    pub fn on_handshake_failed(
        &mut self,
        peer_id: &PeerId,
        now: u64,
    ) -> Result<Vec<ObservationEvent>, ManagerError> {
        self.peer_mut(peer_id)?.handshake_failed(now);
        Ok(Vec::new())
    }

    /// `FederationSync` round completed. MUST-015: refuse if the ACTIVE
    /// cap would be exceeded. Emits `FederationSyncSuccess`.
    pub fn on_sync_complete(
        &mut self,
        peer_id: &PeerId,
        now: u64,
    ) -> Result<Vec<ObservationEvent>, ManagerError> {
        if !self.can_admit_new_active() {
            return Err(ManagerError::ActivePeerCapReached);
        }
        self.peer_mut(peer_id)?.sync_complete(now)?;
        Ok(vec![ObservationEvent::FederationSyncSuccess])
    }

    /// Observe an incoming `sync_id` (PNP-008-MUST-006 replay check).
    ///
    /// Returns `[ReplayedWithinWindow]` if the sync_id was recently seen;
    /// the caller MUST drop the sync and forward the observation. Otherwise
    /// returns an empty vec and the sync_id is recorded.
    pub fn observe_sync_id(
        &mut self,
        peer_id: &PeerId,
        sync_id: &[u8; 16],
        now: u64,
    ) -> Result<Vec<ObservationEvent>, ManagerError> {
        if !self.peers.contains_key(peer_id) {
            return Err(ManagerError::UnknownPeer);
        }
        let cache = self
            .replay_caches
            .entry(*peer_id)
            .or_insert_with(SyncIdReplayCache::new);
        if cache.observe(sync_id, now).is_err() {
            return Ok(vec![ObservationEvent::ReplayedWithinWindow]);
        }
        Ok(Vec::new())
    }

    /// Accept a heartbeat from `peer_id`.
    ///
    /// Enforces MUST-010 counter monotonicity — returns
    /// `HeartbeatCounterNotMonotonic` and does NOT record the heartbeat if
    /// `counter` is not strictly greater than the peer's last accepted
    /// value. Observations: `[HeartbeatOnTime]` on acceptance.
    pub fn on_heartbeat(
        &mut self,
        peer_id: &PeerId,
        counter: u64,
        now: u64,
    ) -> Result<Vec<ObservationEvent>, ManagerError> {
        let peer = self.peer_mut(peer_id)?;
        if let Some(prev) = peer.last_heartbeat_counter
            && counter <= prev
        {
            return Err(ManagerError::HeartbeatCounterNotMonotonic);
        }
        peer.heartbeat_seen(counter, now);
        Ok(vec![ObservationEvent::HeartbeatOnTime])
    }

    /// Report that a descriptor signature failed verification. The caller
    /// has already dropped the descriptor. Emits the observation so
    /// reputation can accumulate toward the MUST-035 ban threshold.
    pub fn on_invalid_signature(
        &mut self,
        peer_id: &PeerId,
    ) -> Result<Vec<ObservationEvent>, ManagerError> {
        if !self.peers.contains_key(peer_id) {
            return Err(ManagerError::UnknownPeer);
        }
        Ok(vec![ObservationEvent::DescriptorSignatureInvalid])
    }

    /// Report a rate-limit violation against MUST-022. The caller has
    /// already dropped the offending message.
    pub fn on_rate_limit_exceeded(
        &mut self,
        peer_id: &PeerId,
    ) -> Result<Vec<ObservationEvent>, ManagerError> {
        if !self.peers.contains_key(peer_id) {
            return Err(ManagerError::UnknownPeer);
        }
        Ok(vec![ObservationEvent::RateLimitExceeded])
    }

    /// Record the manager's view that a peer should be BANNED. Called by
    /// the caller once the reputation subsystem raises the flag.
    pub fn ban_peer(&mut self, peer_id: &PeerId, now: u64) -> Result<(), ManagerError> {
        self.peer_mut(peer_id)?.ban(now);
        Ok(())
    }

    /// Record the manager's view that a peer may be reconnected. Called
    /// once the reputation subsystem has observed the MUST-035 cooldown
    /// passing.
    pub fn unban_peer(&mut self, peer_id: &PeerId, now: u64) -> Result<(), ManagerError> {
        self.peer_mut(peer_id)?.unban(now);
        Ok(())
    }

    /// Drive every peer's time-based transitions. Returns one
    /// `(peer_id, observation)` pair per peer whose state advanced because
    /// of elapsed time — typically `HeartbeatMissed` when a peer has been
    /// silent beyond the MUST-011 threshold.
    pub fn tick(&mut self, now: u64) -> Vec<(PeerId, ObservationEvent)> {
        let mut out = Vec::new();
        for (peer_id, peer) in self.peers.iter_mut() {
            let was_active = peer.state == PeerState::Active;
            if peer.tick(now) && was_active {
                out.push((*peer_id, ObservationEvent::HeartbeatMissed));
            }
        }
        // Also prune replay caches opportunistically so memory doesn't grow.
        for cache in self.replay_caches.values_mut() {
            cache.prune(now);
        }
        out
    }
}

impl Default for FederationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    #[test]
    fn state_diagram_happy_path() {
        let mut p = FederationPeer::new(pid(1), 0);
        assert_eq!(p.state, PeerState::Init);
        p.connect(10).unwrap();
        assert_eq!(p.state, PeerState::Handshake);
        p.handshake_ok(20).unwrap();
        assert_eq!(p.state, PeerState::Sync);
        p.sync_complete(30).unwrap();
        assert_eq!(p.state, PeerState::Active);
        assert_eq!(p.active_since, Some(30));
    }

    #[test]
    fn handshake_failed_drops_to_idle_and_bumps_failures() {
        let mut p = FederationPeer::new(pid(1), 0);
        p.connect(1).unwrap();
        p.handshake_failed(5);
        assert_eq!(p.state, PeerState::Idle);
        assert_eq!(p.failures, 1);

        p.connect(10).unwrap();
        p.handshake_failed(12);
        assert_eq!(p.failures, 2);
    }

    #[test]
    fn banned_rejects_connect() {
        let mut p = FederationPeer::new(pid(1), 0);
        p.ban(100);
        assert_eq!(p.state, PeerState::Banned);
        assert_eq!(p.connect(200), Err(TransitionError::Banned));
    }

    #[test]
    fn unban_resets_failures_and_moves_to_idle() {
        let mut p = FederationPeer::new(pid(1), 0);
        p.connect(1).unwrap();
        p.handshake_failed(5);
        assert_eq!(p.failures, 1);
        p.ban(10);
        p.unban(100);
        assert_eq!(p.state, PeerState::Idle);
        assert_eq!(p.failures, 0);
    }

    #[test]
    fn reconnect_backoff_matches_spec_formula() {
        // 30 * 2^failures, capped at 3600.
        assert_eq!(reconnect_backoff_delay(0, 30, 3600), 30);
        assert_eq!(reconnect_backoff_delay(1, 30, 3600), 60);
        assert_eq!(reconnect_backoff_delay(6, 30, 3600), 1920);
        // 30 * 128 = 3840 → capped at 3600.
        assert_eq!(reconnect_backoff_delay(7, 30, 3600), 3600);
        assert_eq!(reconnect_backoff_delay(63, 30, 3600), 3600);
    }

    #[test]
    fn next_reconnect_eligible_at_only_defined_for_idle() {
        let mut p = FederationPeer::new(pid(1), 0);
        assert_eq!(p.next_reconnect_eligible_at(), None); // Init
        p.connect(1).unwrap();
        assert_eq!(p.next_reconnect_eligible_at(), None); // Handshake
        p.handshake_failed(5);
        // Idle at t=5, failures=1 → 60s delay → eligible at 65.
        assert_eq!(p.next_reconnect_eligible_at(), Some(5 + 60));
    }

    #[test]
    fn tick_demotes_active_after_heartbeat_silence() {
        let mut p = FederationPeer::new(pid(1), 0);
        p.connect(1).unwrap();
        p.handshake_ok(2).unwrap();
        p.sync_complete(3).unwrap();
        p.heartbeat_seen(1, 4);
        // Within 180 s — no change.
        assert!(!p.tick(10));
        assert_eq!(p.state, PeerState::Active);
        // > 180 s silence — transition to IDLE.
        assert!(p.tick(4 + HEARTBEAT_UNREACHABLE_SECS + 1));
        assert_eq!(p.state, PeerState::Idle);
        assert_eq!(p.failures, 1);
    }

    #[test]
    fn failure_counter_resets_after_300s_active() {
        let mut p = FederationPeer::new(pid(1), 0);
        // Accumulate failures.
        p.connect(1).unwrap();
        p.handshake_failed(2);
        p.connect(3).unwrap();
        p.handshake_failed(4);
        assert_eq!(p.failures, 2);
        // Establish ACTIVE at t=10.
        p.connect(5).unwrap();
        p.handshake_ok(6).unwrap();
        p.sync_complete(10).unwrap();
        p.heartbeat_seen(1, 11);
        // Before 300 s stabilize — still carries failures.
        p.tick(100);
        assert_eq!(p.failures, 2);
        // After 300 s ACTIVE — failures reset.
        p.heartbeat_seen(2, 11 + STABILIZATION_ACTIVE_SECS);
        p.tick(11 + STABILIZATION_ACTIVE_SECS);
        assert_eq!(p.failures, 0);
    }

    #[test]
    fn federation_payload_gated_by_state() {
        // MUST-018: no FederationSync / Heartbeat before SYNC state.
        assert!(!PeerState::Init.can_send_federation_payload());
        assert!(!PeerState::Handshake.can_send_federation_payload());
        assert!(PeerState::Sync.can_send_federation_payload());
        assert!(PeerState::Active.can_send_federation_payload());
        assert!(!PeerState::Idle.can_send_federation_payload());
        assert!(!PeerState::Banned.can_send_federation_payload());
    }

    #[test]
    fn rate_limit_descriptor_deliveries_100_per_minute() {
        let mut p = FederationPeer::new(pid(1), 0);
        // 100 tokens at t=0.
        for _ in 0..100 {
            assert!(p.charge_descriptor_delivery(0));
        }
        // 101st at t=0 must fail.
        assert!(!p.charge_descriptor_delivery(0));
    }

    #[test]
    fn rate_limit_sync_inits_10_per_hour() {
        let mut p = FederationPeer::new(pid(1), 0);
        for _ in 0..10 {
            assert!(p.charge_sync_init(0));
        }
        assert!(!p.charge_sync_init(0));
    }

    #[test]
    fn rate_limit_refills_over_time() {
        let mut p = FederationPeer::new(pid(1), 0);
        // Drain descriptor bucket.
        for _ in 0..100 {
            p.charge_descriptor_delivery(0);
        }
        assert!(!p.charge_descriptor_delivery(0));
        // 60 s later — full refill at 100/min = 1 token every 0.6 s.
        assert!(p.charge_descriptor_delivery(60));
    }

    #[test]
    fn illegal_transition_from_wrong_state_errors() {
        let mut p = FederationPeer::new(pid(1), 0);
        assert!(matches!(
            p.handshake_ok(1),
            Err(TransitionError::IllegalFrom(PeerState::Init))
        ));
        assert!(matches!(
            p.sync_complete(1),
            Err(TransitionError::IllegalFrom(PeerState::Init))
        ));
    }

    // -- FederationManager aggregator --------------------------------------

    fn drive_to_sync(mgr: &mut FederationManager, peer_id: PeerId, t: &mut u64) {
        mgr.add_peer(peer_id, *t);
        mgr.connect_peer(&peer_id, *t + 1).unwrap();
        mgr.on_handshake_ok(&peer_id, *t + 2).unwrap();
        *t += 3;
    }

    #[test]
    fn manager_defaults_enforce_must_015_cap() {
        let m = FederationManager::new();
        assert_eq!(m.max_active_peers, 8);
        assert!(m.can_admit_new_active());
    }

    #[test]
    fn manager_add_peer_is_idempotent() {
        let mut m = FederationManager::new();
        m.add_peer(pid(1), 0);
        m.add_peer(pid(1), 100);
        assert_eq!(m.known_peer_count(), 1);
        // Re-adding didn't reset the peer's last_transition (idempotent).
        assert_eq!(m.peer(&pid(1)).unwrap().last_transition, 0);
    }

    #[test]
    fn manager_active_count_tracks_state() {
        let mut m = FederationManager::new();
        let mut t = 0u64;
        for i in 1..=3u8 {
            drive_to_sync(&mut m, pid(i), &mut t);
            let obs = m.on_sync_complete(&pid(i), t).unwrap();
            t += 1;
            assert_eq!(obs, vec![ObservationEvent::FederationSyncSuccess]);
        }
        assert_eq!(m.active_count(), 3);
    }

    #[test]
    fn manager_refuses_sync_complete_past_active_cap() {
        let mut m = FederationManager::with_capacity(2);
        let mut t = 0u64;
        for i in 1..=2u8 {
            drive_to_sync(&mut m, pid(i), &mut t);
            m.on_sync_complete(&pid(i), t).unwrap();
            t += 1;
        }
        drive_to_sync(&mut m, pid(3), &mut t);
        assert_eq!(
            m.on_sync_complete(&pid(3), t),
            Err(ManagerError::ActivePeerCapReached)
        );
        // Peer remains in Sync state; caller can retry after shedding a
        // different peer.
        assert_eq!(m.peer(&pid(3)).unwrap().state, PeerState::Sync);
    }

    #[test]
    fn manager_heartbeat_enforces_counter_monotonicity() {
        let mut m = FederationManager::new();
        let mut t = 0u64;
        drive_to_sync(&mut m, pid(1), &mut t);
        m.on_sync_complete(&pid(1), t).unwrap();
        t += 1;

        let obs = m.on_heartbeat(&pid(1), 5, t).unwrap();
        assert_eq!(obs, vec![ObservationEvent::HeartbeatOnTime]);

        // Replayed counter → reject.
        assert_eq!(
            m.on_heartbeat(&pid(1), 5, t + 1),
            Err(ManagerError::HeartbeatCounterNotMonotonic)
        );
        // Lower counter → reject.
        assert_eq!(
            m.on_heartbeat(&pid(1), 4, t + 2),
            Err(ManagerError::HeartbeatCounterNotMonotonic)
        );
        // Strictly greater → accepted.
        assert!(m.on_heartbeat(&pid(1), 6, t + 3).is_ok());
    }

    #[test]
    fn manager_replay_cache_is_per_peer() {
        let mut m = FederationManager::new();
        m.add_peer(pid(1), 0);
        m.add_peer(pid(2), 0);
        let sid = [0xAA; 16];
        assert!(m.observe_sync_id(&pid(1), &sid, 1).unwrap().is_empty());
        // Same sync_id from a different peer: accepted (cache is per-peer).
        assert!(m.observe_sync_id(&pid(2), &sid, 2).unwrap().is_empty());
        // Replay on peer 1 within window: observation fires.
        assert_eq!(
            m.observe_sync_id(&pid(1), &sid, 100).unwrap(),
            vec![ObservationEvent::ReplayedWithinWindow]
        );
    }

    #[test]
    fn manager_tick_emits_heartbeat_missed_observations() {
        let mut m = FederationManager::new();
        let mut t = 0u64;
        drive_to_sync(&mut m, pid(1), &mut t);
        m.on_sync_complete(&pid(1), t).unwrap();
        t += 1;
        m.on_heartbeat(&pid(1), 1, t).unwrap();

        // Silence past the MUST-011 threshold.
        let obs = m.tick(t + HEARTBEAT_UNREACHABLE_SECS + 1);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].0, pid(1));
        assert_eq!(obs[0].1, ObservationEvent::HeartbeatMissed);
        assert_eq!(m.peer(&pid(1)).unwrap().state, PeerState::Idle);
    }

    #[test]
    fn manager_invalid_signature_emits_observation() {
        let mut m = FederationManager::new();
        m.add_peer(pid(1), 0);
        assert_eq!(
            m.on_invalid_signature(&pid(1)).unwrap(),
            vec![ObservationEvent::DescriptorSignatureInvalid]
        );
    }

    #[test]
    fn manager_rate_limit_emits_observation() {
        let mut m = FederationManager::new();
        m.add_peer(pid(1), 0);
        assert_eq!(
            m.on_rate_limit_exceeded(&pid(1)).unwrap(),
            vec![ObservationEvent::RateLimitExceeded]
        );
    }

    #[test]
    fn manager_ban_rejects_reconnect() {
        let mut m = FederationManager::new();
        m.add_peer(pid(1), 0);
        m.ban_peer(&pid(1), 100).unwrap();
        assert_eq!(
            m.connect_peer(&pid(1), 200),
            Err(ManagerError::Transition(TransitionError::Banned))
        );
        m.unban_peer(&pid(1), 3600).unwrap();
        assert!(m.connect_peer(&pid(1), 3601).is_ok());
    }

    #[test]
    fn manager_unknown_peer_errors() {
        let mut m = FederationManager::new();
        assert_eq!(m.connect_peer(&pid(9), 0), Err(ManagerError::UnknownPeer));
        assert_eq!(
            m.on_heartbeat(&pid(9), 1, 0),
            Err(ManagerError::UnknownPeer)
        );
        assert_eq!(
            m.on_invalid_signature(&pid(9)),
            Err(ManagerError::UnknownPeer)
        );
    }

    #[test]
    fn manager_remove_peer_clears_replay_cache() {
        let mut m = FederationManager::new();
        m.add_peer(pid(1), 0);
        m.observe_sync_id(&pid(1), &[0x11; 16], 1).unwrap();
        m.remove_peer(&pid(1));
        assert_eq!(m.known_peer_count(), 0);
        // Re-adding starts fresh — the old sync_id is no longer tracked.
        m.add_peer(pid(1), 100);
        assert!(m.observe_sync_id(&pid(1), &[0x11; 16], 101).unwrap().is_empty());
    }

}
