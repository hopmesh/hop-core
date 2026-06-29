//! Reliability-weighted relay scoring. See DESIGN.md §18.
//!
//! A node learns, from whom it repeatedly meets, which topics it is a *good relay*
//! for. The motivating case: "I see 4 people who want job-board updates from
//! company X every day, and I regularly pass company X — so I'm a reliable bridge
//! for that topic and should prioritize carrying and offering it."
//!
//! This is PRoPHET-style delivery predictability (recency/frequency-weighted
//! encounter history) specialized to pub/sub topics. Two signals per topic:
//! - **demand** — distinct peers we meet who *want* the topic, weighted by how
//!   regularly we meet them;
//! - **supply** — peers we meet who *carry/originate* the topic.
//!
//! A node sitting between strong demand and live supply scores high and should
//! pin that topic (full retention) and offer it first during short BLE contacts.

use std::collections::HashMap;

use crate::routing::PeerId;

/// Recency/frequency weight for one peer on one topic.
#[derive(Clone, Copy, Debug)]
struct Seen {
    last_ms: u64,
    weight: f64,
}

impl Seen {
    /// Exponentially decayed weight as of `now`, given a half-life.
    fn decayed(&self, now_ms: u64, half_life_ms: u64) -> f64 {
        if now_ms <= self.last_ms || half_life_ms == 0 {
            return self.weight;
        }
        let elapsed = (now_ms - self.last_ms) as f64;
        let hl = half_life_ms as f64;
        self.weight * 0.5f64.powf(elapsed / hl)
    }
}

/// Per-topic, per-peer encounter history that yields a relay-utility score.
pub struct RelayScorer {
    half_life_ms: u64,
    demand: HashMap<String, HashMap<PeerId, Seen>>,
    supply: HashMap<String, HashMap<PeerId, Seen>>,
}

impl RelayScorer {
    /// `half_life_ms` controls how fast old encounters fade (e.g. a day).
    pub fn new(half_life_ms: u64) -> Self {
        Self { half_life_ms, demand: HashMap::new(), supply: HashMap::new() }
    }

    fn bump(map: &mut HashMap<String, HashMap<PeerId, Seen>>, topic: &str, peer: PeerId, now: u64, hl: u64) {
        let entry = map.entry(topic.to_string()).or_default().entry(peer).or_insert(Seen {
            last_ms: now,
            weight: 0.0,
        });
        // Decay the existing weight to `now`, then add this fresh encounter.
        entry.weight = entry.decayed(now, hl) + 1.0;
        entry.last_ms = now;
    }

    /// Record that we met `peer`, who is interested in (subscribes to) `topic`.
    pub fn observe_interest(&mut self, topic: &str, peer: PeerId, now_ms: u64) {
        Self::bump(&mut self.demand, topic, peer, now_ms, self.half_life_ms);
    }

    /// Record that we met `peer`, who carries or originates `topic`.
    pub fn observe_supply(&mut self, topic: &str, peer: PeerId, now_ms: u64) {
        Self::bump(&mut self.supply, topic, peer, now_ms, self.half_life_ms);
    }

    fn sum(map: &HashMap<String, HashMap<PeerId, Seen>>, topic: &str, now: u64, hl: u64) -> f64 {
        map.get(topic)
            .map(|peers| peers.values().map(|s| s.decayed(now, hl)).sum())
            .unwrap_or(0.0)
    }

    /// Relay utility for `topic` as of `now`. High when we reliably meet both
    /// interested peers (demand) and carriers/publishers (supply). The small
    /// supply offset means demand alone still has some value (we may meet a
    /// source later), but bridging both is what scores highest.
    pub fn score(&self, topic: &str, now_ms: u64) -> f64 {
        let d = Self::sum(&self.demand, topic, now_ms, self.half_life_ms);
        let s = Self::sum(&self.supply, topic, now_ms, self.half_life_ms);
        d * (0.25 + s)
    }

    /// Topics ranked by relay utility, highest first.
    pub fn hot_topics(&self, now_ms: u64) -> Vec<(String, f64)> {
        let mut topics: Vec<String> =
            self.demand.keys().chain(self.supply.keys()).cloned().collect();
        topics.sort();
        topics.dedup();
        let mut scored: Vec<(String, f64)> =
            topics.into_iter().map(|t| { let s = self.score(&t, now_ms); (t, s) }).collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));
        scored
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> PeerId {
        [n; 32]
    }

    #[test]
    fn bridging_demand_and_supply_outranks_demand_alone() {
        let mut s = RelayScorer::new(86_400_000); // 1-day half-life
        let now = 0;

        // Topic A: 4 reliable subscribers AND we pass the publisher.
        for p in 1..=4 {
            s.observe_interest("jobs:companyX", peer(p), now);
        }
        s.observe_supply("jobs:companyX", peer(100), now);

        // Topic B: 4 subscribers but we never meet a source.
        for p in 10..=13 {
            s.observe_interest("jobs:companyY", peer(p), now);
        }

        assert!(s.score("jobs:companyX", now) > s.score("jobs:companyY", now));
        let hot = s.hot_topics(now);
        assert_eq!(hot[0].0, "jobs:companyX");
    }

    #[test]
    fn repeated_encounters_beat_one_offs_and_decay_over_time() {
        let mut s = RelayScorer::new(1_000); // fast 1s half-life
        // Peer 1 seen repeatedly; peer 2 once long ago.
        s.observe_interest("t", peer(2), 0);
        for t in [0u64, 1_000, 2_000, 3_000] {
            s.observe_interest("t", peer(1), t);
        }
        s.observe_supply("t", peer(9), 3_000);

        let recent = s.score("t", 3_000);
        let stale = s.score("t", 30_000); // long after, everything decays
        assert!(recent > stale);
        assert!(stale < recent / 10.0);
    }
}
