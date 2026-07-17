//! Store-and-forward queue with time-bounded dedup. See DESIGN.md §3 (Store
//! layer) and §7.
//!
//! Dedup is what gives Hop exactly-once *processing* (§7): a destination ignores
//! duplicate copies of a bundle it has already accepted. For that guarantee to
//! hold, an id must be remembered for at least as long as a duplicate of it can
//! still arrive — i.e. the bundle's lifetime. The `seen` set therefore carries a
//! **receiver-anchored expiry** (`now + lifetime` at first sight, robust to sender
//! clock skew), and [`Store::prune`] drops entries past it so memory stays bounded
//! without ever weakening the guarantee inside the window that matters.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::bundle::{Bundle, BundleId};

/// What a node knows it currently holds — used by routing to avoid re-offering
/// bundles a peer already has. Serializable so it can ride a `Wire::Have` custody beacon
/// (DESIGN.md §35): a node tells a directly-connected peer what it holds so the peer suppresses
/// re-offering those, cutting duplicate-ingress COGS.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HaveSet {
    pub ids: Vec<BundleId>,
}

/// Store of in-flight bundles plus a time-bounded dedup set. Backed by memory
/// ([`MemoryStore`]) or a database (`hop-store-sqlite`).
///
/// `get` returns an owned [`Bundle`] (not a reference) so a database backend can
/// implement it; the copy-budget mutations spray-and-wait needs are explicit
/// methods rather than `&mut` access into storage.
pub trait Store {
    /// Record a bundle for forwarding, stamping its dedup expiry from `now_ms`.
    /// Returns false if it was a duplicate (still within its dedup window).
    fn put(&mut self, bundle: Bundle, now_ms: u64) -> bool;
    /// Re-hold a bundle we already `seen` but EVICTED from held — a TRUSTED re-injection from our own
    /// durable storage (a mailbox pull or cross-partition handoff via [`crate::node::Node::ingest`],
    /// relay-A audit). Unlike [`Store::put`] it does NOT refuse on the surviving dedup entry: `remove`
    /// (eviction/delivery) drops the held copy but keeps `seen`, so a plain `put` of an evicted bundle
    /// returns false and the re-hydration would be lost after its durable mailbox copy is deleted. Keeps
    /// the existing dedup window; returns whether the bundle is now held. Default: falls back to `put`
    /// (a backend that never evicts-while-keeping-seen never needs the distinction). Backends that evict
    /// under memory/relay pressure MUST override.
    fn rehydrate(&mut self, bundle: Bundle, now_ms: u64) -> bool {
        self.put(bundle, now_ms)
    }
    /// Fetch a stored bundle by id.
    fn get(&self, id: &BundleId) -> Option<Bundle>;
    /// Remove a held bundle (e.g. on custody handoff or delivery). Its dedup entry
    /// is retained until it expires, so late duplicates are still rejected.
    fn remove(&mut self, id: &BundleId) -> Option<Bundle>;
    /// Are we still deduping this id (seen and not yet expired)?
    fn seen(&self, id: &BundleId) -> bool;
    /// Is this bundle currently held (not just seen)?
    fn contains(&self, id: &BundleId) -> bool;
    /// What we currently hold.
    fn have(&self) -> HaveSet;
    /// Drop held bundles and dedup entries whose window has closed at `now_ms`.
    fn prune(&mut self, now_ms: u64);
    /// Binary spray-and-wait handoff on the stored bundle: halve its copy budget,
    /// returning the number to give a peer (`floor(n/2)`). 0 if absent or at 1.
    fn split_copies(&mut self, id: &BundleId) -> u16;
    /// Set the stored bundle's copy budget (e.g. a retransmit reset). No-op if absent.
    fn set_copies(&mut self, id: &BundleId, copies: u16);
    /// The receiver-anchored dedup expiry (epoch-ms) recorded for `id` when it was stored, if still
    /// tracked. stores-r2-01 anchors this to the RECEIVER's clock (clamped), so it is the
    /// authoritative durable TTL for any re-mirror or handoff/spool of an already-held bundle —
    /// instead of recomputing from the sender's advisory `created_at`, which can be 0 (the wire
    /// default) or skewed-behind and would rewrite the durable `expireAt` into the past
    /// (stores-r3-01). Default: `None` (a backend that doesn't track dedup expiry; caller falls
    /// back to now+lifetime).
    fn seen_expiry(&self, _id: &BundleId) -> Option<u64> {
        None
    }

    // --- key/value persistence (DESIGN.md §25) --------------------------------------------
    // A small durable key→bytes surface alongside bundles, for state that must survive a
    // restart but isn't a bundle: forward-secret ratchet sessions, prekey secrets, etc. The
    // host supplies the backing store (SQLite on device, Firestore on the cloud relay); the
    // default no-ops keep ephemeral/relay backends working unchanged.

    /// Persist `value` under `key`, replacing any prior value. Default: no-op (not durable).
    fn put_kv(&mut self, _key: &str, _value: Vec<u8>) {}
    /// Fetch a persisted value by exact key. Default: `None`.
    fn get_kv(&self, _key: &str) -> Option<Vec<u8>> {
        None
    }
    /// Remove a persisted value. Default: no-op.
    fn remove_kv(&mut self, _key: &str) {}
    /// All persisted `(key, value)` pairs whose key starts with `prefix`. Default: empty.
    fn list_kv(&self, _prefix: &str) -> Vec<(String, Vec<u8>)> {
        Vec::new()
    }
    /// Drain any asynchronous/background writes, blocking up to `timeout`; returns whether the queue
    /// drained (F-21). Default: nothing is buffered (synchronous store) → immediately done. The
    /// Firestore mirror overrides this to wait for its best-effort background writer to catch up, so
    /// a shutdown (SIGTERM) doesn't drop a spool/handoff write accepted moments before.
    fn flush(&self, _timeout: std::time::Duration) -> bool {
        true
    }
}

/// Lets a node pick its store backend at runtime (`Node<Box<dyn Store>>`) — e.g. the
/// relay daemon choosing SQLite or Firestore from a flag.
impl Store for Box<dyn Store> {
    fn put(&mut self, bundle: Bundle, now_ms: u64) -> bool {
        (**self).put(bundle, now_ms)
    }
    fn rehydrate(&mut self, bundle: Bundle, now_ms: u64) -> bool {
        (**self).rehydrate(bundle, now_ms)
    }
    fn get(&self, id: &BundleId) -> Option<Bundle> {
        (**self).get(id)
    }
    fn remove(&mut self, id: &BundleId) -> Option<Bundle> {
        (**self).remove(id)
    }
    fn seen(&self, id: &BundleId) -> bool {
        (**self).seen(id)
    }
    fn contains(&self, id: &BundleId) -> bool {
        (**self).contains(id)
    }
    fn have(&self) -> HaveSet {
        (**self).have()
    }
    fn prune(&mut self, now_ms: u64) {
        (**self).prune(now_ms)
    }
    fn split_copies(&mut self, id: &BundleId) -> u16 {
        (**self).split_copies(id)
    }
    fn set_copies(&mut self, id: &BundleId, copies: u16) {
        (**self).set_copies(id, copies)
    }
    fn seen_expiry(&self, id: &BundleId) -> Option<u64> {
        (**self).seen_expiry(id)
    }
    fn put_kv(&mut self, key: &str, value: Vec<u8>) {
        (**self).put_kv(key, value)
    }
    fn get_kv(&self, key: &str) -> Option<Vec<u8>> {
        (**self).get_kv(key)
    }
    fn remove_kv(&mut self, key: &str) {
        (**self).remove_kv(key)
    }
    fn list_kv(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        (**self).list_kv(prefix)
    }
    fn flush(&self, timeout: std::time::Duration) -> bool {
        // Must forward: without this the trait default (`true`) wins by method resolution and a
        // boxed FirestoreStore's SIGTERM drain is a silent no-op (F-21 regression). Any method that
        // gains a non-default body on a backend has to be forwarded here too.
        (**self).flush(timeout)
    }
}

/// Hard cap on how long a `seen` dedup entry is retained, regardless of a bundle's claimed
/// `lifetime_ms` (F-07). `lifetime_ms` is a `u32` (~49 days) and, for an unsigned §39 private
/// bundle, unauthenticated, so a flood of long-lived ids could pin the dedup set open for weeks.
/// Mirrors hop-store-sqlite's clamp: retain at most a week; a duplicate past that is re-accepted
/// (harmless: it re-floods and is re-deduped) but the map cannot be held open indefinitely.
///
/// Exported (stores-r2-03) so a durable backend (Firestore) can clamp the `expires_at` it writes and
/// rehydrates with the SAME bound the in-memory clamp uses, instead of duplicating the constant and
/// letting it drift. A hostile ~49-day `lifetime_ms` that survives a scale-to-zero must not reinstate
/// a 49-day dedup window on cold start; it gets bounded to this exactly like a fresh `put()`.
pub const MAX_SEEN_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Row cap on the in-memory `seen` dedup set (F-07). Past this we evict nearest-to-expiry ids so a
/// bundle flood can't grow it without bound. Matches hop-store-sqlite's MAX_SEEN_ROWS.
const MAX_SEEN_ROWS: usize = 200_000;

/// Simple in-memory store for tests and the simulator.
#[derive(Default, Clone)]
pub struct MemoryStore {
    held: HashMap<BundleId, Bundle>,
    /// id → dedup expiry (receiver clock). The master TTL index; `held` is a subset.
    seen: HashMap<BundleId, u64>,
    /// Durable key→bytes side store (sessions, prekey secrets). In-memory here, so it
    /// survives only for the process lifetime — a persistent backend overrides this.
    kv: HashMap<String, Vec<u8>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rehydrate a held bundle with an EXPLICIT absolute dedup expiry (epoch-ms), rather than
    /// re-deriving it from `now + lifetime` (stores-02). A durable backend (Firestore) stores each
    /// bundle's real deadline; on cold start it must be reinstated as-is, or a `put(_, 0)` would
    /// anchor the seen window at epoch 0 and the first real-clock prune would wipe every rehydrated
    /// bundle. A duplicate id keeps its existing (earlier) expiry. Returns false if already seen.
    pub fn put_with_expiry(&mut self, bundle: Bundle, expiry_ms: u64) -> bool {
        let id = bundle.id();
        if self.seen.contains_key(&id) {
            return false;
        }
        self.seen.insert(id, expiry_ms);
        self.held.insert(id, bundle);
        self.enforce_seen_cap();
        true
    }

    /// The receiver-anchored dedup expiry (epoch-ms) recorded for `id` at `put`/`put_with_expiry`
    /// time, if still tracked. A durable backend (stores-r2-01) reuses this as the authoritative
    /// `expires_at` for any re-mirror of an already-held bundle (spray-and-wait split, retransmit
    /// set_copies), instead of recomputing from the sender's advisory `created_at`, which can be
    /// skewed-behind or 0 and would rewrite the durable TTL into the past.
    pub fn seen_expiry(&self, id: &BundleId) -> Option<u64> {
        self.seen.get(id).copied()
    }

    /// Keep the `seen` set under [`MAX_SEEN_ROWS`] by evicting nearest-to-expiry ids (F-07). We drop
    /// any held bundle for an evicted id too, so an evicted id never orphans a held bundle from
    /// lifetime prune (prune walks `seen`). Only runs the sort/scan when actually over the cap.
    fn enforce_seen_cap(&mut self) {
        if self.seen.len() <= MAX_SEEN_ROWS {
            return;
        }
        let mut by_expiry: Vec<(u64, BundleId)> =
            self.seen.iter().map(|(id, &exp)| (exp, *id)).collect();
        let excess = self.seen.len() - MAX_SEEN_ROWS;
        // Partial-sort the `excess` nearest-to-expiry to the front, then evict them.
        by_expiry.select_nth_unstable(excess.saturating_sub(1));
        for (_, id) in by_expiry.into_iter().take(excess) {
            self.seen.remove(&id);
            self.held.remove(&id);
        }
    }
}

impl Store for MemoryStore {
    fn put(&mut self, bundle: Bundle, now_ms: u64) -> bool {
        let id = bundle.id();
        if self.seen.contains_key(&id) {
            return false; // dedup: already seen within its window
        }
        // Clamp the retained dedup window so an attacker-set (and, for private bundles,
        // unauthenticated) lifetime_ms can't pin a `seen` entry open for weeks (F-07).
        let lifetime = (bundle.inner.lifetime_ms as u64).min(MAX_SEEN_LIFETIME_MS);
        let expiry = now_ms.saturating_add(lifetime);
        self.seen.insert(id, expiry);
        self.held.insert(id, bundle);
        self.enforce_seen_cap();
        true
    }

    fn rehydrate(&mut self, bundle: Bundle, now_ms: u64) -> bool {
        // Re-hold an evicted-but-durable bundle even though its `seen` row survives (relay-A audit):
        // keep the existing dedup window if present, else stamp a fresh one, then re-insert into held.
        let id = bundle.id();
        let lifetime = (bundle.inner.lifetime_ms as u64).min(MAX_SEEN_LIFETIME_MS);
        self.seen
            .entry(id)
            .or_insert_with(|| now_ms.saturating_add(lifetime));
        self.held.insert(id, bundle);
        self.enforce_seen_cap();
        true
    }

    fn get(&self, id: &BundleId) -> Option<Bundle> {
        self.held.get(id).cloned()
    }

    fn remove(&mut self, id: &BundleId) -> Option<Bundle> {
        self.held.remove(id)
    }

    fn seen(&self, id: &BundleId) -> bool {
        self.seen.contains_key(id)
    }

    fn contains(&self, id: &BundleId) -> bool {
        self.held.contains_key(id)
    }

    fn have(&self) -> HaveSet {
        HaveSet {
            ids: self.held.keys().copied().collect(),
        }
    }

    fn prune(&mut self, now_ms: u64) {
        let expired: Vec<BundleId> = self
            .seen
            .iter()
            .filter(|(_, &exp)| exp <= now_ms)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.seen.remove(&id);
            self.held.remove(&id);
        }
    }

    fn split_copies(&mut self, id: &BundleId) -> u16 {
        self.held.get_mut(id).map(|b| b.split_copies()).unwrap_or(0)
    }

    fn set_copies(&mut self, id: &BundleId, copies: u16) {
        if let Some(b) = self.held.get_mut(id) {
            b.env.copies = copies;
        }
    }

    fn seen_expiry(&self, id: &BundleId) -> Option<u64> {
        // Delegate to the inherent method (stores-r2-01) so the trait exposes the same
        // receiver-anchored deadline durable backends and the handoff/spool path rely on.
        MemoryStore::seen_expiry(self, id)
    }

    fn put_kv(&mut self, key: &str, value: Vec<u8>) {
        self.kv.insert(key.to_string(), value);
    }
    fn get_kv(&self, key: &str) -> Option<Vec<u8>> {
        self.kv.get(key).cloned()
    }
    fn remove_kv(&mut self, key: &str) {
        self.kv.remove(key);
    }
    fn list_kv(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        self.kv
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{BundleOpts, Destination, Payload};
    use crate::crypto::Identity;

    fn bundle(lifetime_ms: u32) -> Bundle {
        let alice = Identity::generate();
        let gw = Identity::generate();
        Bundle::create(
            &alice,
            Destination::Broadcast,
            &gw.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: vec![1],
            },
            BundleOpts {
                lifetime_ms,
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn dedups_on_put() {
        let b = bundle(3_600_000);
        let mut store = MemoryStore::new();
        assert!(store.put(b.clone(), 0));
        assert!(!store.put(b.clone(), 0)); // duplicate
        assert!(store.seen(&b.id()));
        assert_eq!(store.have().ids.len(), 1);
    }

    #[test]
    fn dedup_window_closes_after_lifetime_then_reaccepts() {
        let b = bundle(1_000); // expires (for dedup) at now + 1000
        let mut store = MemoryStore::new();
        assert!(store.put(b.clone(), 0));

        store.prune(500); // within window — still deduping, still held
        assert!(store.seen(&b.id()));
        assert!(store.contains(&b.id()));
        assert!(!store.put(b.clone(), 500));

        store.prune(2_000); // window closed
        assert!(!store.seen(&b.id()));
        assert!(!store.contains(&b.id()));
        // A copy arriving after the window is treated as new (but by now relays
        // would have dropped the expired bundle too).
        assert!(store.put(b, 2_000));
    }

    #[test]
    fn seen_lifetime_is_clamped_against_a_hostile_lifetime_ms() {
        // F-07 (stores-08): a bundle claiming a ~49-day lifetime must not pin its `seen` entry open
        // that long; the retained window is clamped to MAX_SEEN_LIFETIME_MS (one week), matching
        // hop-store-sqlite.
        let b = bundle(u32::MAX); // hostile: ~49 days
        let mut store = MemoryStore::new();
        assert!(store.put(b.clone(), 0));
        store.prune(MAX_SEEN_LIFETIME_MS + 1);
        assert!(
            !store.seen(&b.id()),
            "seen entry must be clamped to the max window, not the claimed lifetime"
        );
    }

    #[test]
    fn seen_set_is_capped_and_never_orphans_held_bundles() {
        // F-07 (stores-08): the in-memory dedup set is bounded; over the cap we evict the
        // nearest-to-expiry ids AND their held bundles (so an evicted id can't orphan a held bundle
        // from lifetime prune). We drive this with a tiny local override of the cap semantics by
        // inserting synthetic seen rows directly.
        let mut store = MemoryStore::new();
        // Fill exactly to the cap with far-future expiries (held mirrors seen for these ids).
        // Use synthetic ids so we don't have to mint 200k real bundles.
        for i in 0..MAX_SEEN_ROWS {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            store.seen.insert(id, 1_000_000_000);
        }
        assert_eq!(store.seen.len(), MAX_SEEN_ROWS);
        // A real put past the cap with a near expiry: the cap evicts the nearest-to-expiry id.
        let near = bundle(1_000); // expiry now+1000 = the nearest, evicted immediately
        assert!(store.put(near.clone(), 0));
        assert!(
            store.seen.len() <= MAX_SEEN_ROWS,
            "seen set stays bounded under flood"
        );
        // The just-inserted near-expiry bundle was the eviction target, so both its seen and held
        // rows are gone together (no orphan).
        assert!(!store.contains(&near.id()));
        assert!(!store.seen(&near.id()));
    }

    #[test]
    fn put_with_expiry_survives_a_real_clock_prune() {
        // stores-02: a rehydrated bundle stamped with its real absolute deadline must NOT be wiped
        // by the first real-clock prune. Contrast: put(_, 0) would anchor expiry at ~lifetime and a
        // prune at epoch-now would delete it.
        let b = bundle(3_600_000);
        let real_deadline = 1_700_000_000_000; // ~2023, an absolute epoch-ms deadline
        let mut store = MemoryStore::new();
        assert!(store.put_with_expiry(b.clone(), real_deadline));
        // Prune at a realistic "now" earlier than the deadline: bundle survives.
        store.prune(1_699_000_000_000);
        assert!(
            store.contains(&b.id()),
            "rehydrated bundle survives real-clock prune"
        );
        assert!(store.seen(&b.id()));
        // Past the deadline it is finally reaped.
        store.prune(real_deadline + 1);
        assert!(!store.contains(&b.id()));
    }

    #[test]
    fn boxed_store_forwards_flush() {
        // stores-01: a Box<dyn Store> must forward flush() rather than falling back to the trait
        // default, or a durable backend's SIGTERM drain silently no-ops. We assert forwarding
        // reaches the concrete impl via a flush-counting store.
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        #[derive(Default)]
        struct CountingStore {
            flushes: Arc<AtomicUsize>,
        }
        impl Store for CountingStore {
            fn put(&mut self, _b: Bundle, _n: u64) -> bool {
                false
            }
            fn get(&self, _id: &BundleId) -> Option<Bundle> {
                None
            }
            fn remove(&mut self, _id: &BundleId) -> Option<Bundle> {
                None
            }
            fn seen(&self, _id: &BundleId) -> bool {
                false
            }
            fn contains(&self, _id: &BundleId) -> bool {
                false
            }
            fn have(&self) -> HaveSet {
                HaveSet::default()
            }
            fn prune(&mut self, _n: u64) {}
            fn split_copies(&mut self, _id: &BundleId) -> u16 {
                0
            }
            fn set_copies(&mut self, _id: &BundleId, _c: u16) {}
            fn flush(&self, _timeout: std::time::Duration) -> bool {
                self.flushes.fetch_add(1, Ordering::SeqCst);
                true
            }
        }

        let flushes = Arc::new(AtomicUsize::new(0));
        let boxed: Box<dyn Store> = Box::new(CountingStore {
            flushes: flushes.clone(),
        });
        assert!(boxed.flush(std::time::Duration::from_secs(1)));
        assert_eq!(
            flushes.load(Ordering::SeqCst),
            1,
            "Box<dyn Store>::flush must forward to the concrete impl"
        );
    }

    #[test]
    fn boxed_store_forwards_every_trait_method_not_just_flush() {
        // The previous test (boxed_store_forwards_flush) only proves `flush` forwards. Every OTHER
        // method in `impl Store for Box<dyn Store>` has to forward too, or a `Node<Box<dyn Store>>`
        // silently falls back to the trait's inert defaults instead of the real backend (e.g. a
        // SQLite-backed store's kv reads would just go missing behind the box).
        let mut boxed: Box<dyn Store> = Box::new(MemoryStore::new());

        let b = bundle(3_600_000); // default copies = 8
        assert!(boxed.put(b.clone(), 0), "put forwards");
        assert!(
            !boxed.put(b.clone(), 0),
            "put forwards its dedup branch too"
        );
        assert_eq!(boxed.get(&b.id()), Some(b.clone()), "get forwards");
        assert!(boxed.seen(&b.id()), "seen forwards");
        assert!(boxed.contains(&b.id()), "contains forwards");
        assert_eq!(boxed.have().ids, vec![b.id()], "have forwards");
        assert_eq!(
            boxed.seen_expiry(&b.id()),
            Some(3_600_000),
            "seen_expiry forwards"
        );

        assert_eq!(
            boxed.split_copies(&b.id()),
            4,
            "split_copies forwards (8 copies -> give 4)"
        );
        boxed.set_copies(&b.id(), 1);
        assert_eq!(
            boxed.get(&b.id()).unwrap().env.copies,
            1,
            "set_copies forwards"
        );

        boxed.put_kv("session/alice", vec![9, 9]);
        assert_eq!(
            boxed.get_kv("session/alice"),
            Some(vec![9, 9]),
            "put_kv/get_kv forward"
        );
        assert_eq!(
            boxed.list_kv("session/"),
            vec![("session/alice".to_string(), vec![9, 9])],
            "list_kv forwards"
        );
        boxed.remove_kv("session/alice");
        assert_eq!(boxed.get_kv("session/alice"), None, "remove_kv forwards");

        boxed.prune(u64::MAX);
        assert!(!boxed.contains(&b.id()), "prune forwards");
        assert!(
            boxed.remove(&b.id()).is_none(),
            "remove forwards (already pruned, so nothing left to remove)"
        );
    }

    #[test]
    fn default_store_methods_are_inert_when_not_overridden() {
        // Covers the `Store` trait's own default bodies (kv side-store, flush, seen_expiry) with a
        // backend that deliberately leaves them unimplemented, e.g. an ephemeral/relay store that
        // doesn't need durable kv or an async flush. It must still compile and behave like "nothing
        // is durable" rather than panic.
        struct BareStore {
            held: HashMap<BundleId, Bundle>,
        }
        impl Store for BareStore {
            fn put(&mut self, bundle: Bundle, _now_ms: u64) -> bool {
                let id = bundle.id();
                if self.held.contains_key(&id) {
                    return false;
                }
                self.held.insert(id, bundle);
                true
            }
            fn get(&self, id: &BundleId) -> Option<Bundle> {
                self.held.get(id).cloned()
            }
            fn remove(&mut self, id: &BundleId) -> Option<Bundle> {
                self.held.remove(id)
            }
            fn seen(&self, id: &BundleId) -> bool {
                self.held.contains_key(id)
            }
            fn contains(&self, id: &BundleId) -> bool {
                self.held.contains_key(id)
            }
            fn have(&self) -> HaveSet {
                HaveSet {
                    ids: self.held.keys().copied().collect(),
                }
            }
            fn prune(&mut self, _now_ms: u64) {}
            fn split_copies(&mut self, _id: &BundleId) -> u16 {
                0
            }
            fn set_copies(&mut self, _id: &BundleId, _copies: u16) {}
        }

        let b = bundle(1_000);
        let mut store = BareStore {
            held: HashMap::new(),
        };
        assert!(store.put(b.clone(), 0));

        // None of these are overridden by BareStore, so they must fall back to the trait defaults.
        assert_eq!(
            store.seen_expiry(&b.id()),
            None,
            "default seen_expiry is None (no durable expiry tracked)"
        );
        store.put_kv("k", vec![1, 2, 3]); // default is a no-op; must not panic
        assert_eq!(
            store.get_kv("k"),
            None,
            "default get_kv never remembers anything put_kv was handed"
        );
        store.remove_kv("k"); // default is a no-op; must not panic
        assert_eq!(
            store.list_kv(""),
            Vec::<(String, Vec<u8>)>::new(),
            "default list_kv is always empty"
        );
        assert!(
            store.flush(std::time::Duration::from_millis(1)),
            "default flush reports done immediately, nothing is buffered"
        );
    }

    #[test]
    fn put_with_expiry_rejects_a_duplicate_id_and_keeps_the_first_expiry() {
        // stores-02: rehydrating a backend must not let a duplicate id clobber the already-recorded
        // (earlier) expiry with a later one, or a re-mirrored bundle could win extra dedup lifetime.
        let b = bundle(3_600_000);
        let mut store = MemoryStore::new();
        assert!(store.put_with_expiry(b.clone(), 1_000));
        assert!(
            !store.put_with_expiry(b.clone(), 2_000_000),
            "a duplicate id during rehydrate must be rejected, not overwrite the expiry"
        );
        assert_eq!(
            store.seen_expiry(&b.id()),
            Some(1_000),
            "the first expiry wins; a later duplicate can't push it out"
        );
    }

    #[test]
    fn split_copies_halves_the_budget_and_bottoms_out_at_zero_when_absent() {
        // The spray-and-wait copy budget must halve on the STORED bundle (not some detached copy),
        // reach the wait phase (give 0, keep the last copy) instead of underflowing, and an id we
        // don't hold gives 0 rather than panicking.
        let b = bundle(3_600_000); // default copies = 8
        let mut store = MemoryStore::new();
        assert!(store.put(b.clone(), 0));

        assert_eq!(store.split_copies(&b.id()), 4, "8 copies -> give 4, keep 4");
        assert_eq!(store.get(&b.id()).unwrap().env.copies, 4);

        assert_eq!(store.split_copies(&b.id()), 2, "4 copies -> give 2, keep 2");
        assert_eq!(store.split_copies(&b.id()), 1, "2 copies -> give 1, keep 1");
        assert_eq!(
            store.split_copies(&b.id()),
            0,
            "at 1 copy we're in the wait phase: give 0, keep the last copy"
        );
        assert_eq!(store.get(&b.id()).unwrap().env.copies, 1);

        // An id we've never stored can't be split; this must not panic.
        let missing = bundle(1_000);
        assert_eq!(store.split_copies(&missing.id()), 0);
    }
}
