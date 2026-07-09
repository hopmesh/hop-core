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

use crate::bundle::{Bundle, BundleId};

/// What a node knows it currently holds — used by routing to avoid re-offering
/// bundles a peer already has.
#[derive(Clone, Debug, Default)]
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
}

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
}

impl Store for MemoryStore {
    fn put(&mut self, bundle: Bundle, now_ms: u64) -> bool {
        let id = bundle.id();
        if self.seen.contains_key(&id) {
            return false; // dedup: already seen within its window
        }
        let expiry = now_ms.saturating_add(bundle.inner.lifetime_ms as u64);
        self.seen.insert(id, expiry);
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
}
