//! Learned routes: utility from observed deliveries (DESIGN.md §27).
//!
//! A node learns *which destinations it can route well to* from the traffic it
//! relays. When the delivery-ACK for a bundle it forwarded comes back **through**
//! it, the node has confirmed it sits on a working path between that bundle's `src`
//! and `dst`, in **both** directions, even if it never met either endpoint. It
//! records a recency-decayed reachability score per endpoint: higher = "I'm a good
//! path toward this address right now".
//!
//! The score orders transmissions (best first during short contacts) and eviction
//! (flush toward-unknown-destination bundles first). Scores decay on a half-life so
//! stale routes fade. Capacity is **tiered** (§27): phones keep a small table and
//! forget fast; cloud nodes keep a large one and become the long-memory backbone.

use std::collections::HashMap;

use crate::crypto::PubKeyBytes;

/// Reachability half-life: a learned route loses half its weight every 6h of
/// silence, so the table tracks *current* topology, not ancient history.
const HALF_LIFE_MS: f64 = 6.0 * 3_600_000.0;
/// Score added per confirmed delivery observation.
const BUMP: f64 = 1.0;

#[derive(Clone, Copy)]
struct Entry {
    score: f64,
    at: u64,
}

/// Per-endpoint learned reachability, recency-decayed and capacity-bounded.
pub struct RouteTable {
    scores: HashMap<PubKeyBytes, Entry>,
    cap: usize,
}

impl RouteTable {
    /// `cap` bounds the table (tiered: small on mobile, large on cloud nodes).
    pub fn new(cap: usize) -> Self {
        Self {
            scores: HashMap::new(),
            cap: cap.max(1),
        }
    }

    /// Resize the table (e.g. a cloud node raising its memory).
    pub fn set_capacity(&mut self, cap: usize) {
        self.cap = cap.max(1);
    }

    fn decayed(e: &Entry, now: u64) -> f64 {
        let dt = now.saturating_sub(e.at) as f64;
        e.score * 0.5_f64.powf(dt / HALF_LIFE_MS)
    }

    /// Record that this node is on a good path between `a` and `b` (bidirectional).
    pub fn learn(&mut self, a: &PubKeyBytes, b: &PubKeyBytes, now: u64) {
        self.bump(a, now);
        self.bump(b, now);
        self.evict_if_needed(now);
    }

    fn bump(&mut self, who: &PubKeyBytes, now: u64) {
        let e = self.scores.entry(*who).or_insert(Entry {
            score: 0.0,
            at: now,
        });
        e.score = Self::decayed(e, now) + BUMP;
        e.at = now;
    }

    /// Decayed reachability utility toward `dst` (0.0 if unknown).
    pub fn utility(&self, dst: &PubKeyBytes, now: u64) -> f64 {
        self.scores
            .get(dst)
            .map(|e| Self::decayed(e, now))
            .unwrap_or(0.0)
    }

    /// Whether we have any live learned route toward `dst`.
    pub fn knows(&self, dst: &PubKeyBytes, now: u64) -> bool {
        self.utility(dst, now) > 0.01
    }

    pub fn len(&self) -> usize {
        self.scores.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }

    /// Drop the least-useful (lowest decayed score) entries until within `cap`.
    fn evict_if_needed(&mut self, now: u64) {
        while self.scores.len() > self.cap {
            let Some(victim) = self
                .scores
                .iter()
                .min_by(|a, b| {
                    Self::decayed(a.1, now)
                        .partial_cmp(&Self::decayed(b.1, now))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(k, _)| *k)
            else {
                break;
            };
            self.scores.remove(&victim);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> PubKeyBytes {
        [n; 32]
    }

    #[test]
    fn learn_bumps_both_endpoints_bidirectionally() {
        let mut rt = RouteTable::new(64);
        let (s, d) = (addr(1), addr(2));
        rt.learn(&s, &d, 0);
        assert!(rt.knows(&s, 0), "learned src↔dst should mark src reachable");
        assert!(rt.knows(&d, 0), "and dst reachable, either direction");
        assert_eq!(
            rt.utility(&addr(9), 0),
            0.0,
            "unknown endpoint has no utility"
        );
    }

    #[test]
    fn utility_decays_over_time() {
        let mut rt = RouteTable::new(64);
        rt.learn(&addr(1), &addr(2), 0);
        let fresh = rt.utility(&addr(2), 0);
        let later = rt.utility(&addr(2), (HALF_LIFE_MS as u64) * 2); // two half-lives
        assert!(later < fresh, "score must decay with silence");
        assert!(later < fresh / 3.0, "≈ a quarter after two half-lives");
    }

    #[test]
    fn repeated_deliveries_outweigh_one_off_then_fade() {
        let mut rt = RouteTable::new(64);
        let hot = addr(2);
        for t in 0..4 {
            rt.learn(&addr(1), &hot, t * 1000);
        }
        let cold = addr(4);
        rt.learn(&addr(3), &cold, 0);
        assert!(
            rt.utility(&hot, 4000) > rt.utility(&cold, 4000),
            "repeated beats one-off"
        );
    }

    #[test]
    fn capacity_evicts_least_useful() {
        let mut rt = RouteTable::new(2);
        rt.learn(&addr(1), &addr(2), 0); // 1,2
                                         // Reinforce 2 so it's the strongest; 1 stays weak.
        rt.learn(&addr(2), &addr(2), 10);
        rt.learn(&addr(5), &addr(6), 20); // pushes the table over cap → evict weakest
        assert!(rt.len() <= 2, "table stays within capacity");
        assert!(rt.knows(&addr(2), 20), "strongest route survives eviction");
    }
}
