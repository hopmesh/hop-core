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

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::bundle::{Bundle, BundleId};

/// One mutation in an atomic security-critical store batch. Bundle custody and the KV state that
/// authorizes or advances it can share one commit, so no caller has to choose which half survives a
/// crash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvMutation {
    Put { key: String, value: Vec<u8> },
    Remove { key: String },
    PutBundle { bundle: Box<Bundle>, now_ms: u64 },
    RemoveBundle { id: BundleId },
}

/// One row returned by a bounded persisted-KV scan. `storage_id` is an optional opaque backend
/// identity used to remove a malformed row whose stored document does not match its claimed key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvPageRow {
    pub key: String,
    pub value: Option<Vec<u8>>,
    pub storage_id: Option<String>,
    pub canonical: bool,
}

impl KvPageRow {
    pub fn canonical(key: String, value: Vec<u8>) -> Self {
        Self {
            key,
            value: Some(value),
            storage_id: None,
            canonical: true,
        }
    }

    pub fn removal(key: String) -> Self {
        Self {
            key,
            value: None,
            storage_id: None,
            canonical: true,
        }
    }
}

/// One bounded persisted-KV page plus the actual remote work used to read it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KvPage {
    pub rows: Vec<KvPageRow>,
    pub scanned_bytes: usize,
    pub scanned_pages: usize,
}

/// Whether a durable store may currently accept protocol custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurabilityReadiness {
    Ready,
    NotReady,
    /// A write may have committed, but its outcome could not be reconciled. Continuing from the
    /// previous live state could reuse security state, so only a restart/reconciliation may clear it.
    Quarantined,
}

/// A cheap cross-thread readiness handle shared by a store, its I/O worker, and its host service.
#[derive(Clone)]
pub struct DurabilityHandle {
    state: Arc<AtomicU8>,
    unreconciled: Arc<Mutex<u64>>,
    failure_generation: Arc<Mutex<u64>>,
    transition: Arc<Mutex<()>>,
}

impl Default for DurabilityHandle {
    fn default() -> Self {
        Self::ready()
    }
}

impl DurabilityHandle {
    const READY: u8 = 0;
    const NOT_READY: u8 = 1;
    const QUARANTINED: u8 = 2;

    pub fn ready() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(Self::READY)),
            unreconciled: Arc::new(Mutex::new(0)),
            failure_generation: Arc::new(Mutex::new(0)),
            transition: Arc::new(Mutex::new(())),
        }
    }

    pub fn not_ready() -> Self {
        let handle = Self::ready();
        handle.mark_not_ready();
        handle
    }

    pub fn status(&self) -> DurabilityReadiness {
        match self.state.load(Ordering::Acquire) {
            Self::READY => DurabilityReadiness::Ready,
            Self::QUARANTINED => DurabilityReadiness::Quarantined,
            _ => DurabilityReadiness::NotReady,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.status() == DurabilityReadiness::Ready
    }

    pub fn unreconciled(&self) -> u64 {
        *self.unreconciled.lock().expect("unreconciled counter lock")
    }

    /// Monotonic generation advanced by every runtime durability failure. Recovery captures this
    /// before probing and may publish Ready only while the same generation is still current.
    pub fn failure_generation(&self) -> u64 {
        *self
            .failure_generation
            .lock()
            .expect("failure generation lock")
    }

    pub fn mark_not_ready(&self) {
        let _transition = self.transition.lock().expect("durability transition lock");
        let mut generation = self
            .failure_generation
            .lock()
            .expect("failure generation lock");
        *generation = generation.wrapping_add(1);
        if self.state.load(Ordering::Acquire) != Self::QUARANTINED {
            self.state.store(Self::NOT_READY, Ordering::Release);
        }
    }

    pub fn quarantine(&self) {
        let _transition = self.transition.lock().expect("durability transition lock");
        let mut generation = self
            .failure_generation
            .lock()
            .expect("failure generation lock");
        *generation = generation.wrapping_add(1);
        let mut unreconciled = self.unreconciled.lock().expect("unreconciled counter lock");
        *unreconciled = unreconciled.wrapping_add(1);
        self.state.store(Self::QUARANTINED, Ordering::Release);
    }

    /// Put admission in recovery mode and return the generation the caller must carry through its
    /// definitive probe. This transition does not itself count as a failure.
    pub fn begin_recovery(&self) -> u64 {
        let _transition = self.transition.lock().expect("durability transition lock");
        let generation = self.failure_generation();
        if self.unreconciled() == 0 {
            self.state.store(Self::NOT_READY, Ordering::Release);
        } else {
            self.state.store(Self::QUARANTINED, Ordering::Release);
        }
        generation
    }

    /// Restore admission only when no ambiguous mutation remains and no failure occurred after the
    /// caller began recovery. Counters are deliberately not cleared by a generic health probe because
    /// doing so would erase the evidence needed at restart.
    pub fn mark_ready_if_reconciled(&self, recovery_generation: u64) -> bool {
        let _transition = self.transition.lock().expect("durability transition lock");
        if self.unreconciled() != 0 {
            self.state.store(Self::QUARANTINED, Ordering::Release);
            return false;
        }
        if self.failure_generation() != recovery_generation {
            self.state.store(Self::NOT_READY, Ordering::Release);
            return false;
        }
        self.state.store(Self::READY, Ordering::Release);
        true
    }
}

/// What a node knows it currently holds — used by routing to avoid re-offering
/// bundles a peer already has. Serializable so it can ride a `Wire::Have` custody beacon
/// (DESIGN.md §35): a node tells a directly-connected peer what it holds so the peer suppresses
/// re-offering those, cutting duplicate-ingress COGS.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    // host supplies the backing store (SQLite on device, Firestore on the cloud relay). Best-effort
    // metadata methods default to no-ops; security-critical mutations are mandatory and fallible.

    /// Persist `value` under `key`, replacing any prior value. Default: no-op (not durable).
    fn put_kv(&mut self, _key: &str, _value: Vec<u8>) {}
    /// Atomically apply security-critical store mutations and report whether the backend durably
    /// accepted the whole batch. Implementations must not expose a prefix of the batch, return
    /// success for a no-op, queue work that can still be shed, or return while the outcome is
    /// unknown. An empty batch succeeds without touching storage.
    fn apply_kv_batch(&mut self, mutations: &[KvMutation]) -> std::result::Result<(), String>;
    /// Persist one security-critical value through the same atomic path used for multi-key commits.
    fn put_kv_critical(&mut self, key: &str, value: Vec<u8>) -> std::result::Result<(), String> {
        self.apply_kv_batch(&[KvMutation::Put {
            key: key.to_string(),
            value,
        }])
    }
    /// Fetch a persisted value by exact key. Default: `None`.
    fn get_kv(&self, _key: &str) -> Option<Vec<u8>> {
        None
    }
    /// Remove a persisted value. Default: no-op.
    fn remove_kv(&mut self, _key: &str) {}
    /// Durably remove security-critical state, reporting any failure before callers discard their
    /// live in-memory copy.
    fn remove_kv_critical(&mut self, key: &str) -> std::result::Result<(), String> {
        self.apply_kv_batch(&[KvMutation::Remove {
            key: key.to_string(),
        }])
    }
    /// One lexicographically ordered page of persisted `(key, value)` pairs whose key starts with
    /// `prefix`. `after` is an exclusive key cursor. Implementations must honor `limit`; callers use
    /// this for attacker-influenced namespaces where materializing every row before admission is not
    /// safe. Default: empty for stores without KV persistence.
    fn list_kv_page(
        &self,
        _prefix: &str,
        _after: Option<&str>,
        _limit: usize,
    ) -> Vec<(String, Vec<u8>)> {
        Vec::new()
    }
    /// Fallible bounded scan used by startup recovery. Remote stores override this to apply
    /// `max_bytes` before decoding the response and report the exact number of backend requests.
    fn list_kv_page_bounded(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
        max_bytes: usize,
    ) -> std::result::Result<KvPage, String> {
        if limit == 0 || max_bytes == 0 {
            return Ok(KvPage::default());
        }
        let rows: Vec<_> = self
            .list_kv_page(prefix, after, limit)
            .into_iter()
            .map(|(key, value)| KvPageRow::canonical(key, value))
            .collect();
        let scanned_bytes = rows.iter().fold(0usize, |total, row| {
            total
                .saturating_add(row.key.len())
                .saturating_add(row.value.as_ref().map_or(0, Vec::len))
        });
        if rows.len() > limit || scanned_bytes > max_bytes {
            return Err("persisted KV backend exceeded its bounded page request".into());
        }
        Ok(KvPage {
            rows,
            scanned_bytes,
            scanned_pages: 1,
        })
    }
    /// Remove rows returned by [`Store::list_kv_page_bounded`]. Callers keep batches below backend
    /// limits; the default removes canonical keys through the critical atomic path.
    fn remove_kv_rows_critical(&mut self, rows: &[KvPageRow]) -> std::result::Result<(), String> {
        let removals: Vec<_> = rows
            .iter()
            .map(|row| KvMutation::Remove {
                key: row.key.clone(),
            })
            .collect();
        self.apply_kv_batch(&removals)
    }
    /// All persisted `(key, value)` pairs whose key starts with `prefix`. Bounded consumers should
    /// call [`Store::list_kv_page`] directly; this compatibility helper walks fixed-size pages.
    fn list_kv(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        const PAGE: usize = 256;
        let mut out = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = self.list_kv_page(prefix, after.as_deref(), PAGE);
            if page.is_empty() {
                break;
            }
            let next = page.last().map(|(key, _)| key.clone());
            let short = page.len() < PAGE;
            out.extend(page);
            if short || next == after {
                break;
            }
            after = next;
        }
        out
    }
    /// Current durability admission state. Ephemeral and local transactional stores are ready by
    /// construction; remote stores override this with their shared runtime state.
    fn durability_status(&self) -> DurabilityReadiness {
        DurabilityReadiness::Ready
    }
    /// Cross-thread readiness handle for a host that admits producers outside the node owner thread.
    /// `None` means the backend is synchronously ready by construction.
    fn durability_handle(&self) -> Option<DurabilityHandle> {
        None
    }
    /// Perform a definitive backend write/read/delete probe. A remote store may restore readiness
    /// only after this succeeds and every previously accepted mutation is reconciled or flushed.
    fn probe_durability(&mut self) -> std::result::Result<(), String> {
        Ok(())
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
    fn apply_kv_batch(&mut self, mutations: &[KvMutation]) -> std::result::Result<(), String> {
        (**self).apply_kv_batch(mutations)
    }
    fn put_kv_critical(&mut self, key: &str, value: Vec<u8>) -> std::result::Result<(), String> {
        (**self).put_kv_critical(key, value)
    }
    fn get_kv(&self, key: &str) -> Option<Vec<u8>> {
        (**self).get_kv(key)
    }
    fn remove_kv(&mut self, key: &str) {
        (**self).remove_kv(key)
    }
    fn remove_kv_critical(&mut self, key: &str) -> std::result::Result<(), String> {
        (**self).remove_kv_critical(key)
    }
    fn list_kv(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        (**self).list_kv(prefix)
    }
    fn list_kv_page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Vec<(String, Vec<u8>)> {
        (**self).list_kv_page(prefix, after, limit)
    }
    fn list_kv_page_bounded(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
        max_bytes: usize,
    ) -> std::result::Result<KvPage, String> {
        (**self).list_kv_page_bounded(prefix, after, limit, max_bytes)
    }
    fn remove_kv_rows_critical(&mut self, rows: &[KvPageRow]) -> std::result::Result<(), String> {
        (**self).remove_kv_rows_critical(rows)
    }
    fn durability_status(&self) -> DurabilityReadiness {
        (**self).durability_status()
    }
    fn durability_handle(&self) -> Option<DurabilityHandle> {
        (**self).durability_handle()
    }
    fn probe_durability(&mut self) -> std::result::Result<(), String> {
        (**self).probe_durability()
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
pub const MAX_SEEN_ROWS: usize = 200_000;

/// Simple in-memory store for tests and the simulator.
#[derive(Default, Clone)]
pub struct MemoryStore {
    held: HashMap<BundleId, Bundle>,
    /// id → dedup expiry (receiver clock). The master TTL index; `held` is a subset.
    seen: HashMap<BundleId, u64>,
    /// Durable key→bytes side store (sessions, prekey secrets). In-memory here, so it
    /// survives only for the process lifetime — a persistent backend overrides this.
    kv: BTreeMap<String, Vec<u8>>,
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
    fn apply_kv_batch(&mut self, mutations: &[KvMutation]) -> std::result::Result<(), String> {
        let mut candidate = self.clone();
        let mut required_bundles = Vec::new();
        for mutation in mutations {
            match mutation {
                KvMutation::Put { key, value } => {
                    candidate.kv.insert(key.clone(), value.clone());
                }
                KvMutation::Remove { key } => {
                    candidate.kv.remove(key);
                }
                KvMutation::PutBundle { bundle, now_ms } => {
                    let id = bundle.id();
                    if !candidate.put(bundle.as_ref().clone(), *now_ms) {
                        return Err("critical batch bundle put was rejected".into());
                    }
                    required_bundles.push(id);
                }
                KvMutation::RemoveBundle { id } => {
                    candidate.remove(id);
                }
            }
        }
        if required_bundles.iter().any(|id| !candidate.contains(id)) {
            return Err("critical batch bundle custody was evicted before commit".into());
        }
        *self = candidate;
        Ok(())
    }
    fn get_kv(&self, key: &str) -> Option<Vec<u8>> {
        self.kv.get(key).cloned()
    }
    fn remove_kv(&mut self, key: &str) {
        self.kv.remove(key);
    }
    fn list_kv_page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Vec<(String, Vec<u8>)> {
        if limit == 0 {
            return Vec::new();
        }
        let start = after.unwrap_or(prefix);
        self.kv
            .range(start.to_string()..)
            .filter(|(key, _)| {
                key.starts_with(prefix) && after.is_none_or(|cursor| key.as_str() > cursor)
            })
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{BundleOpts, Destination, Payload};
    use crate::crypto::Identity;
    use proptest::prelude::*;

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
            fn apply_kv_batch(
                &mut self,
                _mutations: &[KvMutation],
            ) -> std::result::Result<(), String> {
                Err("critical kv persistence unsupported".into())
            }
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
        boxed
            .put_kv_critical("session/alice", vec![8, 8])
            .expect("put_kv_critical forwards");
        assert_eq!(boxed.get_kv("session/alice"), Some(vec![8, 8]));
        boxed
            .remove_kv_critical("session/alice")
            .expect("remove_kv_critical forwards");
        assert_eq!(boxed.get_kv("session/alice"), None);
        boxed
            .apply_kv_batch(&[
                KvMutation::Put {
                    key: "a".into(),
                    value: vec![1],
                },
                KvMutation::Put {
                    key: "b".into(),
                    value: vec![2],
                },
            ])
            .expect("apply_kv_batch forwards");
        assert_eq!(boxed.get_kv("a"), Some(vec![1]));
        assert_eq!(boxed.get_kv("b"), Some(vec![2]));

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
            fn apply_kv_batch(
                &mut self,
                _mutations: &[KvMutation],
            ) -> std::result::Result<(), String> {
                Err("critical kv persistence unsupported".into())
            }
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
        assert!(store.put_kv_critical("k", vec![1]).is_err());
        assert!(store.remove_kv_critical("k").is_err());
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(192))]

        #[test]
        fn mutation_sequences_preserve_dedup_and_atomic_failure(
            operations in prop::collection::vec((any::<u8>(), any::<u16>(), any::<u32>()), 0..128)
        ) {
            let mut store = MemoryStore::new();
            for (kind, value, now) in operations {
                let mut token = [0u8; 32];
                token[..2].copy_from_slice(&value.to_le_bytes());
                let candidate = Bundle::create_vaccine(
                    token,
                    BundleOpts { lifetime_ms: u32::from(value), ..Default::default() },
                );
                match kind % 5 {
                    0 => { store.put(candidate, u64::from(now)); }
                    1 => { store.remove(&candidate.id()); }
                    2 => store.prune(u64::from(now)),
                    3 => store.set_copies(&candidate.id(), value.max(1)),
                    _ => { store.split_copies(&candidate.id()); }
                }
                prop_assert!(store.seen.len() <= MAX_SEEN_ROWS);
                prop_assert!(store.held.keys().all(|id| store.seen.contains_key(id)));
            }

            let existing = bundle(10_000);
            prop_assert!(store.put(existing.clone(), 0));
            let before = store.clone();
            let failed = store.apply_kv_batch(&[
                KvMutation::Put { key: "must-not-leak".into(), value: vec![1, 2, 3] },
                KvMutation::PutBundle { bundle: Box::new(existing), now_ms: 0 },
            ]);
            prop_assert!(failed.is_err());
            prop_assert_eq!(&store.kv, &before.kv, "failed batch exposed a KV prefix");
            prop_assert_eq!(&store.held, &before.held, "failed batch changed bundle custody");
            prop_assert_eq!(&store.seen, &before.seen, "failed batch changed dedup state");
        }
    }
}
