//! Relay pool: many relays, health-scored, with failover (DESIGN.md §19/§26).
//!
//! ## Why this exists
//!
//! A relay is just another bearer (§26), and the relay bearer takes exactly one URL.
//! That made a node's entire internet reach a function of one operator's fleet being
//! up. When `relays_enabled=false` tore hop's fleet down, reach went to zero, and no
//! amount of correct protocol helped: there was nowhere to dial.
//!
//! Compare a project that borrows its reach instead of owning it. bitchat ships four
//! hardcoded public Nostr relays plus a weekly-refreshed directory of ~415 more, none
//! of which it operates, and its relay manager holds connections across them. It cannot
//! be taken offline by one operator's decision, because no operator owns it.
//!
//! Hop can do better than borrow, because a hop bundle does not need the relay to be
//! trustworthy. A §39 private bundle carries no sender, no recipient, no path, and a
//! self-verifying id; a traced one is signed end to end. A relay is a dumb, untrusted
//! store-and-forward surface either way, so **anyone can run one** and pointing at a
//! stranger's relay costs no confidentiality. What was missing was not trust machinery.
//! It was the plumbing to hold more than one endpoint and move on when one dies.
//!
//! ## What this is, and what it is not
//!
//! This is **pure policy**: which endpoint to dial next, when to give up on one, when
//! to try it again. It performs no I/O and knows nothing about WebSockets, and that is
//! deliberate, it is the same split the BLE and LAN bearers already follow, so one
//! tested implementation serves Apple, Android, embedded, and the simulator instead of
//! being written once per platform.
//!
//! It is NOT a trust or admission decision. Whether a relay may carry your traffic is
//! §35 (carriage stamps); whether you believe what it hands back is the bundle's own
//! signature or self-verifying id. A pool entry is a place to dial, nothing more.

use std::collections::HashMap;

use crate::crypto::PubKeyBytes;

/// Cap on pooled endpoints. A directory of relays is attacker-influenced input (it can
/// arrive over gossip), so the pool is bounded and evicts the worst-scoring entry
/// rather than growing. Comfortably above the ~415 a public directory carries today.
pub const MAX_POOL_ENDPOINTS: usize = 512;

/// Consecutive failures before an endpoint is considered failing and backed off.
/// One failure is noise (a dropped link, a sleeping radio); two is a signal.
pub const FAILURES_BEFORE_BACKOFF: u32 = 2;

/// First backoff step once an endpoint is failing.
pub const BACKOFF_BASE_MS: u64 = 30_000;

/// Ceiling on the exponential backoff. A relay that has been down for hours is still
/// retried twice an hour: operators fix things, and a permanently-evicted endpoint
/// would make an outage irreversible without a restart.
pub const BACKOFF_MAX_MS: u64 = 1_800_000;

/// How an endpoint got into the pool. Kept because it drives eviction order: an
/// operator's explicitly configured relay should outlive a gossiped stranger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EndpointSource {
    /// Learned from a signed reach record or gossip. Evicted first.
    Discovered,
    /// Shipped with the build as a default.
    Bundled,
    /// Explicitly configured by the operator or user. Evicted last.
    Configured,
}

/// One candidate relay and its health.
#[derive(Clone, Debug)]
pub struct RelayEndpoint {
    /// Opaque dial string the bearer interprets, e.g. `wss://relay.example/_hop`.
    /// Deliberately opaque here: this module must not learn a transport.
    pub url: String,
    /// The relay's hop address, when we learned it from a signed reach record. `None`
    /// for a bare configured URL. Not used for admission (that is §35), only so a
    /// caller can tell two entries apart when one operator publishes several URLs.
    pub address: Option<PubKeyBytes>,
    pub source: EndpointSource,
    /// Consecutive failures since the last success.
    pub consecutive_failures: u32,
    /// Wall-clock ms before which this endpoint should not be dialed again.
    pub backoff_until_ms: u64,
    /// Last time a dial to this endpoint succeeded, for scoring and observability.
    pub last_success_ms: Option<u64>,
    /// Total successful dials, so a long-serving relay outranks a lucky newcomer.
    pub successes: u64,
}

impl RelayEndpoint {
    fn new(url: String, address: Option<PubKeyBytes>, source: EndpointSource) -> Self {
        Self {
            url,
            address,
            source,
            consecutive_failures: 0,
            backoff_until_ms: 0,
            last_success_ms: None,
            successes: 0,
        }
    }

    /// Is this endpoint dialable right now?
    pub fn available(&self, now_ms: u64) -> bool {
        now_ms >= self.backoff_until_ms
    }

    /// Preference score, higher is better. Deliberately simple and total, so selection
    /// is deterministic and testable rather than a heuristic that drifts.
    fn score(&self) -> (u32, u64, u64) {
        // Never-failed beats failing; then proven history; then configured-ness.
        let health = if self.consecutive_failures == 0 { 1 } else { 0 };
        (health, self.successes, self.source as u64)
    }
}

/// A health-scored set of relay endpoints with failover.
///
/// Selection is "best available now", not round-robin: a relay that works should keep
/// being used (connection reuse is cheap, churn is not), and a relay that fails should
/// step aside until its backoff lapses.
#[derive(Default, Debug)]
pub struct RelayPool {
    endpoints: Vec<RelayEndpoint>,
    /// url -> index, so repeated `add` of a known relay updates instead of duplicating.
    index: HashMap<String, usize>,
}

impl RelayPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or upgrade an endpoint. Adding a URL already present keeps its accumulated
    /// health (so a gossip refresh does not reset a relay's failure count, which would
    /// let a flapping relay be retried forever) and only raises its `source`.
    ///
    /// Returns false if the pool is full and this endpoint did not beat the worst entry.
    pub fn add(
        &mut self,
        url: impl Into<String>,
        address: Option<PubKeyBytes>,
        source: EndpointSource,
    ) -> bool {
        let url = url.into();
        if url.is_empty() {
            return false;
        }
        if let Some(&i) = self.index.get(&url) {
            let e = &mut self.endpoints[i];
            if source > e.source {
                e.source = source;
            }
            if address.is_some() {
                e.address = address;
            }
            return true;
        }
        if self.endpoints.len() >= MAX_POOL_ENDPOINTS {
            // Evict the worst entry, but only if the newcomer actually outranks it;
            // otherwise a gossip flood of junk URLs would churn out a working pool.
            let Some((worst_i, worst_score)) = self
                .endpoints
                .iter()
                .enumerate()
                .map(|(i, e)| (i, e.score()))
                .min_by_key(|(_, s)| *s)
            else {
                return false;
            };
            let newcomer = (1u32, 0u64, source as u64);
            if newcomer <= worst_score {
                return false;
            }
            let removed = self.endpoints.swap_remove(worst_i);
            self.index.remove(&removed.url);
            self.reindex();
        }
        self.index.insert(url.clone(), self.endpoints.len());
        self.endpoints
            .push(RelayEndpoint::new(url, address, source));
        true
    }

    fn reindex(&mut self) {
        self.index.clear();
        for (i, e) in self.endpoints.iter().enumerate() {
            self.index.insert(e.url.clone(), i);
        }
    }

    /// The best endpoint to dial right now, or `None` if every entry is backed off.
    ///
    /// `None` with a non-empty pool is a normal, temporary state, not an error: it
    /// means "wait", and the caller should retry rather than treat reach as dead.
    pub fn next_dial(&self, now_ms: u64) -> Option<&RelayEndpoint> {
        self.endpoints
            .iter()
            .filter(|e| e.available(now_ms))
            .max_by_key(|e| e.score())
    }

    /// Report that a dial to `url` succeeded. Clears the failure state entirely: a
    /// relay that answered is healthy again regardless of its history.
    pub fn record_success(&mut self, url: &str, now_ms: u64) {
        if let Some(&i) = self.index.get(url) {
            let e = &mut self.endpoints[i];
            e.consecutive_failures = 0;
            e.backoff_until_ms = 0;
            e.last_success_ms = Some(now_ms);
            e.successes = e.successes.saturating_add(1);
        }
    }

    /// Report that a dial to `url` failed. Backs the endpoint off once it has failed
    /// [`FAILURES_BEFORE_BACKOFF`] times in a row, doubling up to [`BACKOFF_MAX_MS`].
    pub fn record_failure(&mut self, url: &str, now_ms: u64) {
        let Some(&i) = self.index.get(url) else {
            return;
        };
        let e = &mut self.endpoints[i];
        e.consecutive_failures = e.consecutive_failures.saturating_add(1);
        if e.consecutive_failures < FAILURES_BEFORE_BACKOFF {
            return;
        }
        let steps = e.consecutive_failures - FAILURES_BEFORE_BACKOFF;
        let delay = BACKOFF_BASE_MS
            .saturating_mul(1u64 << steps.min(16))
            .min(BACKOFF_MAX_MS);
        e.backoff_until_ms = now_ms.saturating_add(delay);
    }

    /// Learn a relay from a **verified** self-certifying reach record ([`crate::reach`]).
    ///
    /// Takes an already-verified record rather than raw bytes on purpose: verification
    /// needs a clock, this module has none, and quietly accepting an unverified claim
    /// would let anyone inject dial targets by asserting someone else's address. The
    /// caller runs `ReachRecord::verify` (which checks the signature against the very
    /// address it claims, plus expiry) and hands the result here.
    ///
    /// Note what is and is not being trusted. The signature proves the address really
    /// published that endpoint; it proves nothing about whether the relay behaves. That
    /// is fine, and is the reason a stranger's relay is safe to dial at all: a §39
    /// private bundle exposes no sender, recipient, or path to whoever carries it.
    pub fn learn_from_reach(&mut self, record: &crate::reach::ReachRecord) -> bool {
        self.add(
            record.claim.endpoint.clone(),
            Some(record.claim.address),
            EndpointSource::Discovered,
        )
    }

    /// Every endpoint, for observability and persistence.
    pub fn endpoints(&self) -> &[RelayEndpoint] {
        &self.endpoints
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// How many endpoints are dialable right now. `0` with a non-empty pool means
    /// everything is backed off, which is the signal to surface "no reach" in a UI.
    pub fn available_count(&self, now_ms: u64) -> usize {
        self.endpoints
            .iter()
            .filter(|e| e.available(now_ms))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool_with(urls: &[&str]) -> RelayPool {
        let mut p = RelayPool::new();
        for u in urls {
            assert!(p.add(*u, None, EndpointSource::Configured));
        }
        p
    }

    #[test]
    fn empty_pool_offers_nothing() {
        let p = RelayPool::new();
        assert!(p.is_empty());
        assert!(p.next_dial(0).is_none());
    }

    #[test]
    fn adding_the_same_url_twice_does_not_duplicate() {
        let mut p = pool_with(&["wss://a"]);
        assert!(p.add("wss://a", None, EndpointSource::Discovered));
        assert_eq!(p.len(), 1, "a re-add updates rather than duplicating");
    }

    #[test]
    fn re_adding_does_not_reset_accumulated_failures() {
        // A gossip refresh must not launder a flapping relay's history, or a broken
        // endpoint that keeps being re-advertised would never stay backed off.
        let mut p = pool_with(&["wss://bad"]);
        p.record_failure("wss://bad", 1_000);
        p.record_failure("wss://bad", 1_000);
        let before = p.endpoints()[0].backoff_until_ms;
        assert!(before > 1_000);
        p.add("wss://bad", None, EndpointSource::Discovered);
        assert_eq!(p.endpoints()[0].backoff_until_ms, before);
        assert_eq!(p.endpoints()[0].consecutive_failures, 2);
    }

    #[test]
    fn source_is_upgraded_never_downgraded() {
        let mut p = RelayPool::new();
        p.add("wss://a", None, EndpointSource::Discovered);
        p.add("wss://a", None, EndpointSource::Configured);
        assert_eq!(p.endpoints()[0].source, EndpointSource::Configured);
        p.add("wss://a", None, EndpointSource::Discovered);
        assert_eq!(
            p.endpoints()[0].source,
            EndpointSource::Configured,
            "gossip must not demote an operator's own relay"
        );
    }

    #[test]
    fn a_single_failure_does_not_take_an_endpoint_out() {
        // One dropped link is noise (a sleeping radio, a transient network). Backing
        // off on it would make the pool thrash on a healthy relay.
        let mut p = pool_with(&["wss://a"]);
        p.record_failure("wss://a", 1_000);
        assert!(
            p.next_dial(1_000).is_some(),
            "still dialable after one failure"
        );
    }

    #[test]
    fn repeated_failure_fails_over_to_the_next_relay() {
        // The whole point: one operator going dark must not end reach.
        let mut p = pool_with(&["wss://a", "wss://b"]);
        p.record_success("wss://a", 0);
        assert_eq!(p.next_dial(1_000).unwrap().url, "wss://a");

        p.record_failure("wss://a", 1_000);
        p.record_failure("wss://a", 1_000);
        assert_eq!(
            p.next_dial(1_000).unwrap().url,
            "wss://b",
            "a failing relay must yield to a healthy one"
        );
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let mut p = pool_with(&["wss://a"]);
        let mut last = 0u64;
        for n in 1..=12 {
            p.record_failure("wss://a", 0);
            let until = p.endpoints()[0].backoff_until_ms;
            if n >= FAILURES_BEFORE_BACKOFF {
                assert!(until >= last, "backoff must not shrink");
                last = until;
            }
        }
        assert_eq!(
            last, BACKOFF_MAX_MS,
            "backoff must saturate, not overflow or grow forever"
        );
    }

    #[test]
    fn a_backed_off_relay_returns_after_its_window() {
        // Operators fix things. A permanently-evicted endpoint would make an outage
        // irreversible without a restart, so recovery has to be automatic.
        let mut p = pool_with(&["wss://a"]);
        p.record_failure("wss://a", 0);
        p.record_failure("wss://a", 0);
        assert!(p.next_dial(0).is_none(), "backed off right now");
        let until = p.endpoints()[0].backoff_until_ms;
        assert!(
            p.next_dial(until).is_some(),
            "dialable once the window lapses"
        );
    }

    #[test]
    fn success_clears_failure_state_completely() {
        let mut p = pool_with(&["wss://a"]);
        p.record_failure("wss://a", 0);
        p.record_failure("wss://a", 0);
        p.record_success("wss://a", 10_000);
        let e = &p.endpoints()[0];
        assert_eq!(e.consecutive_failures, 0);
        assert_eq!(e.backoff_until_ms, 0);
        assert_eq!(e.successes, 1);
    }

    #[test]
    fn all_backed_off_is_wait_not_dead() {
        let mut p = pool_with(&["wss://a", "wss://b"]);
        for u in ["wss://a", "wss://b"] {
            p.record_failure(u, 0);
            p.record_failure(u, 0);
        }
        assert!(p.next_dial(0).is_none());
        assert_eq!(p.available_count(0), 0);
        assert!(!p.is_empty(), "the pool still knows where to retry");
    }

    #[test]
    fn proven_relays_outrank_untried_ones() {
        let mut p = pool_with(&["wss://new", "wss://proven"]);
        p.record_success("wss://proven", 0);
        p.record_success("wss://proven", 1);
        assert_eq!(p.next_dial(10).unwrap().url, "wss://proven");
    }

    #[test]
    fn pool_is_bounded_against_a_gossip_flood() {
        // A relay directory can arrive over gossip, so it is attacker-influenced input.
        let mut p = RelayPool::new();
        for i in 0..MAX_POOL_ENDPOINTS {
            assert!(p.add(format!("wss://r{i}"), None, EndpointSource::Discovered));
        }
        assert_eq!(p.len(), MAX_POOL_ENDPOINTS);
        for i in 0..50 {
            p.add(format!("wss://flood{i}"), None, EndpointSource::Discovered);
        }
        assert_eq!(p.len(), MAX_POOL_ENDPOINTS, "the cap holds under a flood");
    }

    #[test]
    fn a_junk_flood_cannot_evict_working_relays() {
        // Eviction only happens when the newcomer actually outranks the worst entry.
        // Otherwise an attacker could churn out a pool of proven relays for free.
        let mut p = RelayPool::new();
        for i in 0..MAX_POOL_ENDPOINTS {
            p.add(format!("wss://good{i}"), None, EndpointSource::Configured);
        }
        for i in 0..MAX_POOL_ENDPOINTS {
            p.record_success(&format!("wss://good{i}"), 1);
        }
        for i in 0..100 {
            assert!(
                !p.add(format!("wss://junk{i}"), None, EndpointSource::Discovered),
                "a discovered newcomer must not displace a proven configured relay"
            );
        }
        assert!(p
            .endpoints()
            .iter()
            .all(|e| e.url.starts_with("wss://good")));
    }

    #[test]
    fn a_verified_reach_record_becomes_a_dial_target() {
        use crate::crypto::Identity;
        let relay = Identity::generate();
        let rec =
            crate::reach::ReachRecord::sign(&relay, "wss://community.example/_hop", 3600, 1_000);
        let mut p = RelayPool::new();
        assert!(p.learn_from_reach(&rec));
        let picked = p.next_dial(0).expect("a learned relay is dialable");
        assert_eq!(picked.url, "wss://community.example/_hop");
        assert_eq!(
            picked.address,
            Some(relay.address()),
            "the record binds the endpoint to the relay's own address"
        );
        assert_eq!(picked.source, EndpointSource::Discovered);
    }

    #[test]
    fn a_learned_relay_never_demotes_a_configured_one() {
        use crate::crypto::Identity;
        let relay = Identity::generate();
        let mut p = RelayPool::new();
        p.add("wss://mine/_hop", None, EndpointSource::Configured);
        let rec = crate::reach::ReachRecord::sign(&relay, "wss://mine/_hop", 3600, 1_000);
        p.learn_from_reach(&rec);
        assert_eq!(p.endpoints()[0].source, EndpointSource::Configured);
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn empty_url_is_rejected() {
        let mut p = RelayPool::new();
        assert!(!p.add("", None, EndpointSource::Configured));
        assert!(p.is_empty());
    }

    #[test]
    fn reporting_on_an_unknown_url_is_a_no_op() {
        // The bearer can report on a relay that was evicted mid-dial; that must not
        // panic or resurrect it.
        let mut p = pool_with(&["wss://a"]);
        p.record_failure("wss://gone", 0);
        p.record_success("wss://gone", 0);
        assert_eq!(p.len(), 1);
        assert_eq!(p.endpoints()[0].consecutive_failures, 0);
    }
}
