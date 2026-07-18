//! Relayed discovery and topic pub/sub: a gossiped, signed directory of peers and
//! services. See DESIGN.md §15–§16.
//!
//! Bundles (see [`crate::bundle`]) are *addressed* — you must already know the
//! destination. Discovery answers the prior question: how do you learn a peer or
//! service exists and obtain its keys? A **service is a topic**: a publisher
//! broadcasts signed [`Advert`] records on it, consumers **subscribe** to receive
//! them, and every device relays best-effort regardless of whether it subscribes.
//! Records flood the mesh epidemically and land in each node's [`Directory`]. You
//! see a record the moment you meet any node carrying it — that is the
//! transitivity the product wants ("discoverable as soon as I've seen another
//! device that has seen it").
//!
//! **Keeping relays light (DESIGN.md §16).** Subscribed topics get full retention.
//! Everything else lands in a small, bounded, **compressed** relay cache (LRU
//! eviction) so a relay never pays unbounded storage to carry traffic for topics
//! it doesn't care about. This is what makes "all devices relay at best attempt"
//! affordable.
//!
//! Adverts are **public** to the mesh (no recipient, unsealed) — appropriate for a
//! public job board or marketplace. Private peer discovery (rendezvous via a
//! shared secret) is future work; see DESIGN.md §10, §15.
//!
//! Heavy content (listing photos) is NOT gossiped: an advert carries a summary
//! plus the publisher's keys, and the full object is fetched on demand with a
//! normal device-to-device bundle to the publisher.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::crypto::{self, Identity, PreKeyBundle, PubKeyBytes, Tag, XPubKeyBytes};
use crate::error::{Error, Result};
use crate::util;
use crate::{AppId, FABRIC_APP};

/// Reserved topic for control adverts (tombstones).
const TOPIC_CONTROL: &str = "_control";
/// Reserved topic for prekey bundles (forward-secret sessions, DESIGN.md §25).
const TOPIC_KEYS: &str = "_keys";
/// Reserved topic for `hps://` discoverable channel/service announcements (DESIGN.md §32).
const TOPIC_HPS: &str = "_hps";
/// §39 P4 receiver-beacons (routing gradient). Always-retained like the other control topics so
/// a beacon propagates a few hops to lay the gradient; short TTL keeps it soft-state.
const TOPIC_BEACON: &str = "_beacon";

/// Default bound on the best-effort relay cache (number of adverts).
pub const DEFAULT_RELAY_CACHE_CAP: usize = 256;

/// Full-retention and auxiliary-index bounds. Subscribed/control adverts remain much larger than
/// the relay cache, but no remote publisher can make any directory table grow without limit.
pub const DEFAULT_SUBSCRIBED_CAP: usize = 4_096;
pub const DEFAULT_SEEN_CAP: usize = 32_768;
pub const DEFAULT_REVOKED_CAP: usize = 4_096;
pub const DEFAULT_PREKEY_CAP: usize = 4_096;

/// An advert may remain live for at most seven days. Core's own prekey and HPS adverts use this
/// ceiling exactly, so ordinary discovery behavior is unchanged.
pub const MAX_ADVERT_TTL_MS: u32 = 7 * 24 * 60 * 60 * 1_000;
/// Publisher clocks may lead ours slightly, but not enough to pin an otherwise short-lived advert.
pub const MAX_ADVERT_FUTURE_SKEW_MS: u64 = 5 * 60 * 1_000;
/// Hard wire and field bounds checked before signature verification.
pub const MAX_ADVERT_WIRE_BYTES: usize = 8 * 1_024;
const MAX_SERVICE_BYTES: usize = 128;
const MAX_TITLE_BYTES: usize = 256;
const MAX_SUMMARY_BYTES: usize = 2 * 1_024;
const MAX_TAGS: usize = 32;
const MAX_TAG_BYTES: usize = 64;
const MAX_HPS_TOPIC_BYTES: usize = 7 * 1_024;

/// Hop cap on a §39 receiver-beacon (core-02). A beacon lays the routing gradient for the few nodes
/// near the recipient, but past this many hops it is neither re-gossiped nor stored, so a recipient's
/// cleartext-carrying beacon does NOT flood the whole connected component every refresh, honoring the
/// "propagates a few hops" claim above rather than laying the recipient's reachability network-wide.
/// A node still records the gradient for a beacon it hears within this radius; it just stops carrying
/// it onward. Beyond the cap, a private bundle falls back to blind-flood (the §39 privacy floor).
pub const MAX_RECV_BEACON_HOPS: u8 = 3;

/// Stable id of an advert: `BLAKE3(canonical body)`.
pub type AdvertId = [u8; 32];

/// What an advert announces. The protocol only knows **services** — apps build
/// presence/contacts on top (e.g. a "presence" service carrying a display name);
/// common names are not a core concept (DESIGN.md §4, §23).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdvertKind {
    /// A discoverable service/listing (a presence record, job board entry, …).
    Service {
        /// Namespace, e.g. "market" or "jobs" — what consumers filter on.
        service: String,
        title: String,
        summary: String,
        tags: Vec<String>,
    },
    /// A signed prekey bundle for forward-secret sessions (DESIGN.md §25). Floods on
    /// the reserved `_keys` topic so any peer who's heard of the publisher can open a
    /// session to it without a live round-trip. The advert signature already binds
    /// `spk_pub` to the publisher; `spk_sig` makes the reconstructed bundle
    /// self-verifying.
    PreKey {
        spk_pub: XPubKeyBytes,
        spk_sig: Vec<u8>,
    },
    /// Revokes a previously published advert (a sold item, a closed post).
    Tombstone { revokes: AdvertId },
    /// A discoverable `hps://` channel/service announcement (DESIGN.md §32). The descriptor
    /// (path, kind, title, access mode, …) is **encrypted** under the publisher app's discovery
    /// key, so only same-app nodes can read it — a foreign app can carry/relay it but can't
    /// enumerate the topic. Never carries the content key.
    HpsTopic { nonce: [u8; 12], ct: Vec<u8> },
    /// §39 P4 receiver-beacon: the publisher (a recipient in "route-to-me" mode) advertises its
    /// **mailbox-tag** so nodes lay a soft-state gradient toward it. As this floods a few hops, every
    /// node records "this mailbox is reachable via the link I heard it on", then forwards a matching
    /// **private** bundle down that gradient instead of blind-flooding (DESIGN.md §39). The mailbox
    /// tag is `H(address ‖ epoch)` and rotates per epoch (F-06). The advert's publisher signature
    /// alone does NOT stop a hijack; hijack is prevented at ingest (`Node::on_advert`, F-05) by
    /// requiring `mailbox == mailbox_tag(publisher's own signed address, current/recent epoch)`,
    /// which the relay recomputes from the beacon's own signed address (unforgeable for another).
    /// (A k-bit anonymity-set prefix was carried in v1 but never honored; it was removed rather than
    /// advertise a non-functional privacy control — reintroduce with a real prefix-routing design.)
    RecvBeacon { mailbox: Tag },
}

/// The signed body of an advert. The publisher signature covers this exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertBody {
    pub version: u8,
    /// Application namespace on the shared fabric (DESIGN.md §17).
    pub app: AppId,
    /// The publisher's address — discoverers learn this and can then message it
    /// directly (its sealing key is derived from the address — DESIGN.md §4).
    pub publisher: PubKeyBytes,
    pub kind: AdvertKind,
    /// Publisher clock in ms — advisory; also breaks ties on supersession.
    pub created_at: u64,
    /// Discard after `created_at + ttl_ms` (against the receiver's clock + skew).
    pub ttl_ms: u32,
    /// Monotonic per-publisher counter; a higher `seq` supersedes an older advert
    /// of the same logical slot (re-publishing an edited listing). v1 scaffold:
    /// supersession is by-id + tombstone; `seq` is carried for Phase 2.
    pub seq: u64,
}

/// A complete, gossiped advert.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advert {
    pub id: AdvertId,
    pub body: AdvertBody,
    pub sig: Vec<u8>,
    /// Hops from the publisher to wherever this copy is now — incremented on each
    /// re-gossip. NOT signed (advisory, like a bundle's hop_limit); lets a node
    /// show "N hops away". First arrival in a flood is usually the shortest path.
    pub hops: u8,
}

/// Current advert wire version.
// v2: RecvBeacon mailbox semantics changed to H(address ‖ epoch) with a rotation window (F-06).
pub const ADVERT_VERSION: u8 = 2;

impl Advert {
    /// Publish (build + sign) a new advert in the shared fabric namespace.
    pub fn publish(
        publisher: &Identity,
        kind: AdvertKind,
        created_at: u64,
        ttl_ms: u32,
        seq: u64,
    ) -> Result<Self> {
        Self::publish_in(FABRIC_APP, publisher, kind, created_at, ttl_ms, seq)
    }

    /// Publish into a specific application namespace (DESIGN.md §17).
    pub fn publish_in(
        app: AppId,
        publisher: &Identity,
        kind: AdvertKind,
        created_at: u64,
        ttl_ms: u32,
        seq: u64,
    ) -> Result<Self> {
        validate_kind_structure(&kind)?;
        let body = AdvertBody {
            version: ADVERT_VERSION,
            app,
            publisher: publisher.address(),
            kind,
            created_at,
            ttl_ms: ttl_ms.min(MAX_ADVERT_TTL_MS),
            seq,
        };
        let bytes = postcard::to_allocvec(&body)?;
        if bytes.len().saturating_add(96) > MAX_ADVERT_WIRE_BYTES {
            return Err(Error::Other("advert exceeds wire-size limit".into()));
        }
        let id = *blake3::hash(&bytes).as_bytes();
        let sig = publisher.sign(&bytes).to_vec();
        let advert = Advert {
            id,
            body,
            sig,
            hops: 0,
        };
        advert.validate_structure()?;
        Ok(advert)
    }

    /// Verify the id matches the body and the publisher signature is valid.
    pub fn verify(&self) -> Result<()> {
        self.validate_structure()?;
        // Reject an advert whose wire version this build doesn't speak, before trusting
        // any of its fields. Like [`Bundle::from_bytes`], this turns a silent misdecode
        // after a discriminant shift into a loud [`Error::UnsupportedVersion`].
        if self.body.version != ADVERT_VERSION {
            return Err(Error::UnsupportedVersion {
                got: self.body.version,
                supported: ADVERT_VERSION,
            });
        }
        let bytes = postcard::to_allocvec(&self.body)?;
        if *blake3::hash(&bytes).as_bytes() != self.id {
            return Err(Error::BadSignature);
        }
        if crypto::verify(&self.body.publisher, &bytes, &self.sig) {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }

    fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.expires_at()
    }

    fn expires_at(&self) -> u64 {
        self.body.created_at.saturating_add(self.body.ttl_ms as u64)
    }

    /// Reject attacker-controlled allocation and signature work on malformed adverts. This runs
    /// before cryptographic verification in [`Directory::ingest`].
    fn validate_structure(&self) -> Result<()> {
        if self.sig.len() != 64 {
            return Err(Error::BadSignature);
        }
        validate_kind_structure(&self.body.kind)?;
        if postcard::to_allocvec(self)?.len() > MAX_ADVERT_WIRE_BYTES {
            return Err(Error::Other("advert exceeds wire-size limit".into()));
        }
        Ok(())
    }

    /// The subscription topic this advert belongs to. Service adverts use their
    /// `service` namespace; control records use a reserved topic.
    pub fn topic(&self) -> &str {
        match &self.body.kind {
            AdvertKind::Service { service, .. } => service,
            AdvertKind::PreKey { .. } => TOPIC_KEYS,
            AdvertKind::Tombstone { .. } => TOPIC_CONTROL,
            AdvertKind::HpsTopic { .. } => TOPIC_HPS,
            AdvertKind::RecvBeacon { .. } => TOPIC_BEACON,
        }
    }
}

fn validate_kind_structure(kind: &AdvertKind) -> Result<()> {
    let valid = match kind {
        AdvertKind::Service {
            service,
            title,
            summary,
            tags,
        } => {
            service.len() <= MAX_SERVICE_BYTES
                && title.len() <= MAX_TITLE_BYTES
                && summary.len() <= MAX_SUMMARY_BYTES
                && tags.len() <= MAX_TAGS
                && tags.iter().all(|tag| tag.len() <= MAX_TAG_BYTES)
        }
        AdvertKind::PreKey { spk_sig, .. } => spk_sig.len() == 64,
        AdvertKind::Tombstone { .. } | AdvertKind::RecvBeacon { .. } => true,
        AdvertKind::HpsTopic { ct, .. } => ct.len() <= MAX_HPS_TOPIC_BYTES,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::Other("advert exceeds structural limits".into()))
    }
}

/// Bounded, compressed, LRU store for adverts on topics we don't subscribe to —
/// the best-effort relay path. Keeps relays light (DESIGN.md §16).
#[derive(Default)]
struct RelayCache {
    cap: usize,
    order: VecDeque<AdvertId>,
    blobs: HashMap<AdvertId, Vec<u8>>, // compressed postcard(Advert)
}

impl RelayCache {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            order: VecDeque::new(),
            blobs: HashMap::new(),
        }
    }

    fn put(&mut self, advert: &Advert) -> Result<Vec<AdvertId>> {
        if self.cap == 0 {
            return Ok(vec![advert.id]);
        }
        let mut evicted = Vec::new();
        let blob = util::compress(&postcard::to_allocvec(advert)?);
        if self.blobs.insert(advert.id, blob).is_none() {
            self.order.push_back(advert.id);
        }
        while self.blobs.len() > self.cap {
            if let Some(evict) = self.order.pop_front() {
                self.blobs.remove(&evict);
                evicted.push(evict);
            } else {
                break;
            }
        }
        Ok(evicted)
    }

    fn get(&self, id: &AdvertId) -> Option<Advert> {
        let blob = self.blobs.get(id)?;
        let bytes = util::decompress(blob).ok()?;
        postcard::from_bytes(&bytes).ok()
    }

    fn remove(&mut self, id: &AdvertId) -> Option<Advert> {
        let advert = self.get(id);
        self.blobs.remove(id);
        self.order.retain(|queued| queued != id);
        advert
    }

    fn adverts(&self) -> impl Iterator<Item = Advert> + '_ {
        self.blobs.keys().filter_map(|id| self.get(id))
    }

    fn expire(&mut self, now_ms: u64) -> Vec<AdvertId> {
        let expired: Vec<AdvertId> = self
            .adverts()
            .filter(|advert| advert.is_expired(now_ms))
            .map(|advert| advert.id)
            .collect();
        for id in &expired {
            self.remove(id);
        }
        self.order.retain(|id| self.blobs.contains_key(id));
        expired
    }
}

#[derive(Clone)]
struct PreKeyEntry {
    advert_id: AdvertId,
    created_at: u64,
    expires_at: u64,
    bundle: PreKeyBundle,
}

#[derive(Clone, Copy)]
struct DirectoryLimits {
    subscribed: usize,
    seen: usize,
    revoked: usize,
    prekeys: usize,
}

impl Default for DirectoryLimits {
    fn default() -> Self {
        Self {
            subscribed: DEFAULT_SUBSCRIBED_CAP,
            seen: DEFAULT_SEEN_CAP,
            revoked: DEFAULT_REVOKED_CAP,
            prekeys: DEFAULT_PREKEY_CAP,
        }
    }
}

/// A node's local directory. Service adverts flood through a bounded relay cache
/// (and full retention for subscribed topics). Presence, contacts, and any
/// common-name layer are built by apps on top of services — not the core
/// (DESIGN.md §4, §15–§16, §23).
pub struct Directory {
    /// Topics this node subscribes to (full retention).
    subscriptions: HashSet<String>,
    /// Full-retention store for subscribed service topics.
    subscribed: HashMap<AdvertId, Advert>,
    /// Best-effort, bounded, compressed store for other service broadcasts.
    relay: RelayCache,
    /// Latest prekey bundle per publisher (for opening forward-secret sessions).
    /// One entry per device; newest `created_at` wins (DESIGN.md §25).
    prekeys: HashMap<PubKeyBytes, PreKeyEntry>,
    /// Ids seen (even if since removed/revoked), with the advert's expiry for compaction.
    seen: HashMap<AdvertId, u64>,
    /// Revocation claims keyed by target, publisher, and app. Keeping the claimed owner is what
    /// makes tombstone-first ordering safe: a later target is suppressed only when its signed
    /// publisher and namespace match the earlier claim.
    revoked: HashMap<(AdvertId, PubKeyBytes, AppId), u64>,
    /// Held advert ids removed by capacity, expiry, or tombstone since the node last synchronized
    /// per-link gossip metadata.
    evicted: Vec<AdvertId>,
    limits: DirectoryLimits,
    /// This node's app fingerprint (DESIGN.md §17). Adverts in this app or the open
    /// [`FABRIC_APP`] get full retention / are browsable; other apps' adverts are still relayed
    /// (the fabric is shared) but never surfaced locally.
    app: AppId,
}

impl Default for Directory {
    fn default() -> Self {
        Self::new()
    }
}

impl Directory {
    pub fn new() -> Self {
        Self::with_relay_cap(DEFAULT_RELAY_CACHE_CAP)
    }

    /// Construct with an explicit relay-cache bound (0 disables best-effort carry).
    pub fn with_relay_cap(cap: usize) -> Self {
        Self::with_limits(cap, DirectoryLimits::default())
    }

    fn with_limits(relay_cap: usize, limits: DirectoryLimits) -> Self {
        Self {
            subscriptions: HashSet::new(),
            subscribed: HashMap::new(),
            relay: RelayCache::new(relay_cap),
            prekeys: HashMap::new(),
            seen: HashMap::new(),
            revoked: HashMap::new(),
            evicted: Vec::new(),
            limits,
            app: FABRIC_APP,
        }
    }

    /// Set this node's app fingerprint so full-retention / browse are scoped to it (§17).
    pub fn set_app(&mut self, app: AppId) {
        self.app = app;
    }

    /// Subscribe to a service topic — its adverts now get full retention.
    pub fn subscribe(&mut self, topic: impl Into<String>) {
        let topic = topic.into();
        // Promote anything already in the relay cache for this topic.
        let promote: Vec<Advert> = self
            .relay
            .adverts()
            .filter(|a| a.topic() == topic)
            .collect();
        for a in promote {
            let _ = self.relay.remove(&a.id);
            self.insert_subscribed(a);
        }
        self.subscriptions.insert(topic);
    }

    /// Unsubscribe from a topic (existing records stay until they expire).
    pub fn unsubscribe(&mut self, topic: &str) {
        self.subscriptions.remove(topic);
    }

    fn is_subscribed(&self, topic: &str) -> bool {
        topic == TOPIC_CONTROL
            || topic == TOPIC_KEYS
            || topic == TOPIC_HPS
            || topic == TOPIC_BEACON
            || self.subscriptions.contains(topic)
    }

    fn insert_subscribed(&mut self, advert: Advert) {
        if self.limits.subscribed == 0 {
            return;
        }
        self.subscribed.insert(advert.id, advert);
        while self.subscribed.len() > self.limits.subscribed {
            let victim = self
                .subscribed
                .iter()
                .min_by_key(|(_, advert)| (advert.expires_at(), advert.body.created_at))
                .map(|(id, _)| *id);
            let Some(victim) = victim else { break };
            self.subscribed.remove(&victim);
            self.evicted.push(victim);
        }
    }

    fn remember_seen(&mut self, id: AdvertId, expires_at: u64) {
        if self.limits.seen == 0 {
            return;
        }
        self.seen.insert(id, expires_at);
        while self.seen.len() > self.limits.seen {
            let victim = self
                .seen
                .iter()
                .min_by_key(|(_, expiry)| **expiry)
                .map(|(id, _)| *id);
            let Some(victim) = victim else { break };
            self.seen.remove(&victim);
        }
    }

    fn remember_revocation(&mut self, advert: &Advert, revokes: AdvertId) {
        if self.limits.revoked == 0 {
            return;
        }
        let key = (revokes, advert.body.publisher, advert.body.app);
        self.revoked.insert(key, advert.expires_at());
        while self.revoked.len() > self.limits.revoked {
            let victim = self
                .revoked
                .iter()
                .min_by_key(|(_, expiry)| **expiry)
                .map(|(key, _)| *key);
            let Some(victim) = victim else { break };
            self.revoked.remove(&victim);
        }
    }

    fn held_advert(&self, id: &AdvertId) -> Option<Advert> {
        self.subscribed
            .get(id)
            .cloned()
            .or_else(|| self.relay.get(id))
    }

    fn remove_held_advert(&mut self, id: &AdvertId) -> Option<Advert> {
        self.subscribed.remove(id).or_else(|| self.relay.remove(id))
    }

    fn remove_prekey_for_advert(&mut self, advert: &Advert) {
        if self
            .prekeys
            .get(&advert.body.publisher)
            .is_some_and(|entry| entry.advert_id == advert.id)
        {
            self.prekeys.remove(&advert.body.publisher);
        }
    }

    fn index_prekey(&mut self, advert: &Advert, spk_pub: XPubKeyBytes, spk_sig: &[u8]) {
        if self.limits.prekeys == 0 {
            return;
        }
        let publisher = advert.body.publisher;
        let newer = self
            .prekeys
            .get(&publisher)
            .is_none_or(|entry| advert.body.created_at >= entry.created_at);
        if !newer {
            return;
        }
        self.prekeys.insert(
            publisher,
            PreKeyEntry {
                advert_id: advert.id,
                created_at: advert.body.created_at,
                expires_at: advert.expires_at(),
                bundle: PreKeyBundle {
                    address: publisher,
                    spk_pub,
                    spk_sig: spk_sig.to_vec(),
                },
            },
        );
        while self.prekeys.len() > self.limits.prekeys {
            let victim = self
                .prekeys
                .iter()
                .min_by_key(|(_, entry)| (entry.expires_at, entry.created_at))
                .map(|(publisher, _)| *publisher);
            let Some(victim) = victim else { break };
            self.prekeys.remove(&victim);
        }
    }

    /// Accept a gossiped advert. Verifies signature, dedups, applies tombstones,
    /// drops expired records, and routes to full retention or the relay cache by
    /// subscription. Returns true if newly accepted (worth re-gossiping).
    pub fn ingest(&mut self, advert: Advert, now_ms: u64) -> Result<bool> {
        // Bound all attacker-controlled fields and allocations before the Ed25519 verification.
        advert.validate_structure()?;
        if advert.body.ttl_ms > MAX_ADVERT_TTL_MS {
            return Err(Error::Other("advert TTL exceeds limit".into()));
        }
        if advert.body.created_at > now_ms.saturating_add(MAX_ADVERT_FUTURE_SKEW_MS) {
            // Do not remember this id: once the receiver clock catches up, the same valid advert
            // must still be admissible.
            return Ok(false);
        }
        advert.verify()?;
        if advert.is_expired(now_ms) {
            return Ok(false);
        }
        // core-02: cap how far a receiver-beacon travels. Within the cap it lays the local gradient
        // and re-gossips one more hop; past the cap we record it as seen (so a later copy is deduped)
        // but neither store nor re-gossip it, and signal "not accepted" so the node doesn't carry it
        // onward. This stops the recipient's cleartext-carrying beacon flooding the whole component.
        if matches!(advert.body.kind, AdvertKind::RecvBeacon { .. })
            && advert.hops > MAX_RECV_BEACON_HOPS
        {
            self.remember_seen(advert.id, advert.expires_at());
            return Ok(false);
        }

        if self
            .seen
            .get(&advert.id)
            .is_some_and(|expiry| *expiry >= now_ms)
        {
            // Already seen — but a copy that travelled fewer hops means we found a
            // shorter path (e.g. a direct link after first hearing it via a relay).
            // Adopt the smaller hop count so "N hops away" reflects the closest path.
            if let Some(existing) = self.subscribed.get_mut(&advert.id) {
                if advert.hops < existing.hops {
                    existing.hops = advert.hops;
                }
            }
            return Ok(false); // dedup (don't re-gossip)
        }
        self.seen.remove(&advert.id);

        // If the target is already held, a tombstone is authorized only in the same signed
        // publisher/app namespace. An unauthorized record is not retained or re-gossiped.
        let tombstone_target = match &advert.body.kind {
            AdvertKind::Tombstone { revokes } => Some(*revokes),
            _ => None,
        };
        if let Some(revokes) = tombstone_target {
            if let Some(target) = self.held_advert(&revokes) {
                if target.body.publisher != advert.body.publisher
                    || target.body.app != advert.body.app
                {
                    self.remember_seen(advert.id, advert.expires_at());
                    return Ok(false);
                }
            }
        }

        self.remember_seen(advert.id, advert.expires_at());

        // A tombstone may have arrived before this target. Match the owner and namespace now that
        // the target's signed body is known. Claims by anyone else are conclusively unauthorized.
        let revocation_key = (advert.id, advert.body.publisher, advert.body.app);
        let revoked = self
            .revoked
            .get(&revocation_key)
            .is_some_and(|expiry| *expiry >= now_ms);
        if revoked {
            self.revoked.retain(|(id, publisher, app), _| {
                *id != advert.id || (*publisher == advert.body.publisher && *app == advert.body.app)
            });
            return Ok(false); // matching earlier tombstone suppresses storage and local side effects
        }
        self.revoked.retain(|(id, _, _), _| *id != advert.id);

        if let Some(revokes) = tombstone_target {
            self.remember_revocation(&advert, revokes);
            if let Some(target) = self.remove_held_advert(&revokes) {
                self.evicted.push(revokes);
                self.remove_prekey_for_advert(&target);
            }
        }

        // Index prekey bundles by publisher (newest wins) for session bootstrap,
        // alongside storing the advert for re-gossip.
        if let AdvertKind::PreKey { spk_pub, spk_sig } = &advert.body.kind {
            self.index_prekey(&advert, *spk_pub, spk_sig);
        }

        // App scoping (DESIGN.md §17): full retention only for our own app or the open fabric
        // (peer discovery / prekeys flood fabric-wide). Other apps' adverts are still carried in
        // the relay cache — the fabric is shared and must keep forwarding — just never surfaced
        // locally. This is what stops one app from discovering another app's hps topics.
        let our_app = advert.body.app == self.app || advert.body.app == FABRIC_APP;
        if our_app && self.is_subscribed(advert.topic()) {
            self.insert_subscribed(advert);
        } else {
            self.evicted.extend(self.relay.put(&advert)?); // best-effort carry for strangers / other apps
        }
        Ok(true)
    }

    /// The latest known prekey bundle for `address`, if we've seen one — used to
    /// open a forward-secret session without a live round-trip (DESIGN.md §25).
    pub fn prekey(&self, address: &PubKeyBytes) -> Option<PreKeyBundle> {
        self.prekeys.get(address).map(|entry| entry.bundle.clone())
    }

    /// Have we already seen this advert id (for gossip offer filtering)?
    pub fn seen(&self, id: &AdvertId) -> bool {
        self.seen.contains_key(id)
    }

    /// Whether this advert is still held for local use or re-gossip (not merely remembered in dedup).
    pub fn contains(&self, id: &AdvertId) -> bool {
        self.held_advert(id).is_some()
    }

    /// Every advert we currently hold, from both stores.
    fn all(&self) -> impl Iterator<Item = Advert> + '_ {
        self.subscribed
            .values()
            .cloned()
            .chain(self.relay.adverts())
    }

    /// Adverts a peer hasn't seen yet — the gossip offer set for this contact
    /// (service broadcasts: subscribed + relayed).
    pub fn gossip_offer(&self, peer_seen: &HashSet<AdvertId>) -> Vec<Advert> {
        self.all().filter(|a| !peer_seen.contains(&a.id)).collect()
    }

    /// Advert ids we currently hold that were published by `pubk` — our OWN prekey/presence when
    /// `pubk` is us. Used to ALWAYS re-offer our own securing adverts on link-up (and periodically),
    /// so a peer that lost state (restart / data-wipe / cache-evict) can re-secure — WITHOUT
    /// re-flooding the foreign directory bulk, which stays per-peer-deduped.
    pub fn advert_ids_by_publisher(&self, pubk: &PubKeyBytes) -> Vec<AdvertId> {
        self.all()
            .filter(|a| a.body.publisher == *pubk)
            .map(|a| a.id)
            .collect()
    }

    /// Advert ids that left all held directory stores since the previous call. Nodes use this to
    /// expire per-link/per-peer `sent_adverts` metadata at the same boundary as the data itself.
    pub fn take_evicted(&mut self) -> Vec<AdvertId> {
        std::mem::take(&mut self.evicted)
    }

    /// Drop expired service adverts. Call periodically (DESIGN.md §8, §23).
    pub fn expire(&mut self, now_ms: u64) {
        let expired_subscribed: Vec<_> = self
            .subscribed
            .iter()
            .filter(|(_, advert)| advert.is_expired(now_ms))
            .map(|(id, _)| *id)
            .collect();
        self.subscribed.retain(|_, a| !a.is_expired(now_ms));
        self.evicted.extend(expired_subscribed);
        self.evicted.extend(self.relay.expire(now_ms));
        self.seen.retain(|_, expiry| *expiry >= now_ms);
        self.revoked.retain(|_, expiry| *expiry >= now_ms);
        self.prekeys.retain(|_, entry| entry.expires_at >= now_ms);
    }

    /// Browse a service namespace, optionally filtered by tag (e.g. service
    /// "market", tag "bicycle"). This is how User B finds User A's bike post.
    /// Searches both stores so you find listings even before subscribing.
    pub fn browse(&self, service: &str, tag: Option<&str>) -> Vec<Advert> {
        self.all()
            .filter(|a| a.body.app == self.app || a.body.app == FABRIC_APP) // §17 app scoping
            .filter(|a| match &a.body.kind {
                AdvertKind::Service {
                    service: s, tags, ..
                } => s == service && tag.is_none_or(|t| tags.iter().any(|x| x == t)),
                _ => false,
            })
            .collect()
    }

    /// Same-app `hps://` discovery adverts (encrypted bodies; the node decrypts under its
    /// app key). Other apps' topics never appear here (DESIGN.md §17, §32).
    pub fn hps_topics(&self) -> Vec<Advert> {
        self.all()
            .filter(|a| a.body.app == self.app)
            .filter(|a| matches!(a.body.kind, AdvertKind::HpsTopic { .. }))
            .collect()
    }

    /// Like [`gossip_offer`], but ordered by relay utility (DESIGN.md §18) so the
    /// most valuable adverts go first during short BLE contacts.
    pub fn gossip_offer_ranked(
        &self,
        peer_seen: &HashSet<AdvertId>,
        scorer: &crate::relay::RelayScorer,
        now_ms: u64,
    ) -> Vec<Advert> {
        let mut offer = self.gossip_offer(peer_seen);
        offer.sort_by(|a, b| {
            scorer
                .score(b.topic(), now_ms)
                .total_cmp(&scorer.score(a.topic(), now_ms))
        });
        offer
    }

    /// Pin the topics this node is a reliable relay for (score above `threshold`)
    /// to full retention, so we keep carrying paths we reliably serve even under
    /// relay-cache pressure (DESIGN.md §18). Returns the topics pinned.
    pub fn pin_hot_topics(
        &mut self,
        scorer: &crate::relay::RelayScorer,
        now_ms: u64,
        threshold: f64,
    ) -> Vec<String> {
        let pin: Vec<String> = scorer
            .hot_topics(now_ms)
            .into_iter()
            .filter(|(_, s)| *s >= threshold)
            .map(|(t, _)| t)
            .collect();
        for topic in &pin {
            self.subscribe(topic.clone());
        }
        pin
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{Bundle, BundleOpts, Destination, Payload};

    #[test]
    fn publish_verify_roundtrip_and_tamper() {
        let a = Identity::generate();
        let mut adv = listing(&a, "Bike for sale", 1);
        adv.verify().unwrap();

        adv.body.created_at = 99; // tamper a signed field
        assert!(matches!(adv.verify(), Err(Error::BadSignature)));
    }

    #[test]
    fn directory_dedups_and_expires() {
        let a = Identity::generate();
        let adv = Advert::publish(
            &a,
            AdvertKind::Service {
                service: "market".into(),
                title: "A".into(),
                summary: "…".into(),
                tags: vec![],
            },
            0,
            1_000,
            1,
        )
        .unwrap();

        let mut dir = Directory::new();
        assert!(dir.ingest(adv.clone(), 0).unwrap());
        assert!(!dir.ingest(adv.clone(), 0).unwrap()); // dedup

        let mut dir2 = Directory::new();
        assert!(!dir2.ingest(adv, 5_000).unwrap()); // already expired on arrival
    }

    #[test]
    fn foreign_app_adverts_relayed_but_not_browsable() {
        let publisher = Identity::generate();
        let app_x = crate::app_id("app.x");
        let app_y = crate::app_id("app.y");

        let mut dir = Directory::new();
        dir.set_app(app_x);
        dir.subscribe("market");

        // Same-app listing → browsable.
        let mine = Advert::publish_in(
            app_x,
            &publisher,
            AdvertKind::Service {
                service: "market".into(),
                title: "mine".into(),
                summary: "".into(),
                tags: vec![],
            },
            0,
            10_000,
            1,
        )
        .unwrap();
        assert!(dir.ingest(mine, 0).unwrap());
        assert_eq!(dir.browse("market", None).len(), 1);

        // Foreign-app listing → still accepted for gossip/relay, but NOT surfaced to our app.
        let theirs = Advert::publish_in(
            app_y,
            &publisher,
            AdvertKind::Service {
                service: "market".into(),
                title: "theirs".into(),
                summary: "".into(),
                tags: vec![],
            },
            0,
            10_000,
            2,
        )
        .unwrap();
        assert!(
            dir.ingest(theirs, 0).unwrap(),
            "foreign advert still relayed"
        );
        assert_eq!(
            dir.browse("market", None).len(),
            1,
            "foreign advert not browsable"
        );
        assert_eq!(dir.browse("market", None)[0].body.app, app_x);
    }

    #[test]
    fn ingest_adopts_shorter_hop_path() {
        let publisher = Identity::generate();
        let mut dir = Directory::new();
        dir.subscribe("market");

        // A relayed copy (2 hops) arrives first and is stored.
        let mut relayed = listing(&publisher, "bike", 1);
        relayed.hops = 2;
        assert!(dir.ingest(relayed.clone(), 1).unwrap());
        assert_eq!(dir.browse("market", None)[0].hops, 2);

        // The same advert via a direct link (1 hop) arrives later — adopt the shorter
        // path even though it's a duplicate id (and don't re-gossip it).
        let mut direct = relayed.clone();
        direct.hops = 1;
        assert!(!dir.ingest(direct, 1).unwrap());
        assert_eq!(dir.browse("market", None)[0].hops, 1, "shorter path wins");
    }

    #[test]
    fn tombstone_revokes_listing() {
        let seller = Identity::generate();
        let listing = Advert::publish(
            &seller,
            AdvertKind::Service {
                service: "market".into(),
                title: "Bike for sale".into(),
                summary: "Blue road bike".into(),
                tags: vec!["bicycle".into()],
            },
            0,
            600_000,
            1,
        )
        .unwrap();

        let mut dir = Directory::new();
        dir.ingest(listing.clone(), 1).unwrap();
        assert_eq!(dir.browse("market", Some("bicycle")).len(), 1);

        let tomb = Advert::publish(
            &seller,
            AdvertKind::Tombstone {
                revokes: listing.id,
            },
            10,
            600_000,
            2,
        )
        .unwrap();
        dir.ingest(tomb, 11).unwrap();
        assert!(dir.browse("market", None).is_empty()); // sold → gone
    }

    #[test]
    fn tombstones_require_the_original_publisher_in_both_arrival_orders() {
        let seller = Identity::generate();
        let attacker = Identity::generate();
        let first = listing(&seller, "first", 1);
        let second = listing(&seller, "second", 2);
        let third = listing(&seller, "third", 3);
        let mut dir = Directory::new();

        dir.ingest(first.clone(), 1).unwrap();
        let forged_after = Advert::publish(
            &attacker,
            AdvertKind::Tombstone { revokes: first.id },
            1,
            600_000,
            1,
        )
        .unwrap();
        assert!(!dir.ingest(forged_after, 1).unwrap());
        assert_eq!(dir.browse("market", None).len(), 1);

        let forged_before = Advert::publish(
            &attacker,
            AdvertKind::Tombstone { revokes: second.id },
            1,
            600_000,
            2,
        )
        .unwrap();
        assert!(dir.ingest(forged_before, 1).unwrap());
        assert!(dir.ingest(second, 1).unwrap());
        assert_eq!(dir.browse("market", None).len(), 2);

        let valid_before = Advert::publish(
            &seller,
            AdvertKind::Tombstone { revokes: third.id },
            1,
            600_000,
            4,
        )
        .unwrap();
        assert!(dir.ingest(valid_before, 1).unwrap());
        assert!(!dir.ingest(third, 1).unwrap());
        assert!(dir.browse("market", None).iter().all(|advert| !matches!(
            &advert.body.kind,
            AdvertKind::Service { title, .. } if title == "third"
        )));
    }

    #[test]
    fn tombstones_remove_only_the_matching_prekey_index() {
        let publisher = Identity::generate();
        let prekey = publisher.derive_prekey();
        let first = Advert::publish(
            &publisher,
            AdvertKind::PreKey {
                spk_pub: prekey.public,
                spk_sig: prekey.sig.to_vec(),
            },
            0,
            1_000,
            1,
        )
        .unwrap();
        let mut dir = Directory::new();
        dir.ingest(first.clone(), 0).unwrap();
        assert!(dir.prekey(&publisher.address()).is_some());

        let tomb = Advert::publish(
            &publisher,
            AdvertKind::Tombstone { revokes: first.id },
            0,
            1_000,
            2,
        )
        .unwrap();
        dir.ingest(tomb, 0).unwrap();
        assert!(dir.prekey(&publisher.address()).is_none());

        let second = Advert::publish(
            &publisher,
            AdvertKind::PreKey {
                spk_pub: prekey.public,
                spk_sig: prekey.sig.to_vec(),
            },
            0,
            1_000,
            3,
        )
        .unwrap();
        let tomb_first = Advert::publish(
            &publisher,
            AdvertKind::Tombstone { revokes: second.id },
            0,
            1_000,
            4,
        )
        .unwrap();
        dir.ingest(tomb_first, 0).unwrap();
        assert!(!dir.ingest(second, 0).unwrap());
        assert!(dir.prekey(&publisher.address()).is_none());
    }

    #[test]
    fn future_skew_and_structural_limits_do_not_poison_seen() {
        let publisher = Identity::generate();
        let future = Advert::publish(
            &publisher,
            AdvertKind::Service {
                service: "market".into(),
                title: "future".into(),
                summary: String::new(),
                tags: vec![],
            },
            MAX_ADVERT_FUTURE_SKEW_MS + 1,
            1_000,
            1,
        )
        .unwrap();
        let mut dir = Directory::new();
        assert!(!dir.ingest(future.clone(), 0).unwrap());
        assert!(!dir.seen(&future.id));
        assert!(dir
            .ingest(future.clone(), MAX_ADVERT_FUTURE_SKEW_MS + 1)
            .unwrap());

        let mut oversized = listing(&publisher, "small", 2);
        oversized.body.kind = AdvertKind::Service {
            service: "market".into(),
            title: "x".repeat(MAX_TITLE_BYTES + 1),
            summary: String::new(),
            tags: vec![],
        };
        assert!(dir.ingest(oversized.clone(), 0).is_err());
        assert!(!dir.seen(&oversized.id));

        let capped = Advert::publish(
            &publisher,
            AdvertKind::RecvBeacon {
                mailbox: [0u8; crypto::TAG_LEN],
            },
            0,
            u32::MAX,
            3,
        )
        .unwrap();
        assert_eq!(capped.body.ttl_ms, MAX_ADVERT_TTL_MS);
        let mut hostile_ttl = capped.clone();
        hostile_ttl.body.ttl_ms = MAX_ADVERT_TTL_MS + 1;
        assert!(dir.ingest(hostile_ttl.clone(), 0).is_err());
        assert!(!dir.seen(&hostile_ttl.id));
    }

    #[test]
    fn every_directory_index_is_bounded_and_expired() {
        let limits = DirectoryLimits {
            subscribed: 2,
            seen: 4,
            revoked: 2,
            prekeys: 2,
        };
        let mut dir = Directory::with_limits(1, limits);
        for seq in 0..6 {
            let publisher = Identity::generate();
            let prekey = publisher.derive_prekey();
            let advert = Advert::publish(
                &publisher,
                AdvertKind::PreKey {
                    spk_pub: prekey.public,
                    spk_sig: prekey.sig.to_vec(),
                },
                0,
                10,
                seq,
            )
            .unwrap();
            dir.ingest(advert, 0).unwrap();
        }
        assert_eq!(dir.subscribed.len(), limits.subscribed);
        assert_eq!(dir.prekeys.len(), limits.prekeys);
        assert_eq!(dir.seen.len(), limits.seen);

        let publisher = Identity::generate();
        for seq in 0..5 {
            let tomb = Advert::publish(
                &publisher,
                AdvertKind::Tombstone {
                    revokes: [seq as u8; 32],
                },
                0,
                10,
                seq,
            )
            .unwrap();
            dir.ingest(tomb, 0).unwrap();
        }
        assert_eq!(dir.revoked.len(), limits.revoked);
        assert_eq!(dir.seen.len(), limits.seen);
        assert!(dir.subscribed.len() <= limits.subscribed);

        dir.expire(11);
        assert!(dir.subscribed.is_empty());
        assert!(dir.relay.blobs.is_empty());
        assert!(dir.relay.order.is_empty());
        assert!(dir.prekeys.is_empty());
        assert!(dir.seen.is_empty());
        assert!(dir.revoked.is_empty());
    }

    #[test]
    fn recv_beacon_past_hop_cap_is_not_regossiped() {
        // core-02: a receiver-beacon lays the gradient within a few hops but must stop being
        // re-gossiped/stored past the cap, so a recipient's cleartext-carrying beacon does not
        // flood the whole connected component.
        let recipient = Identity::generate();
        let mut beacon = Advert::publish(
            &recipient,
            AdvertKind::RecvBeacon {
                mailbox: crypto::mailbox_tag(&recipient.address(), 7),
            },
            0,
            90_000,
            1,
        )
        .unwrap();

        // Within the cap: accepted (worth re-gossiping) and carried.
        beacon.hops = MAX_RECV_BEACON_HOPS;
        let mut near = Directory::new();
        assert!(
            near.ingest(beacon.clone(), 1).unwrap(),
            "a beacon within the cap is accepted + re-gossiped"
        );

        // Past the cap: recorded as seen for dedup, but NOT accepted (not re-gossiped/stored).
        let mut far = Directory::new();
        beacon.hops = MAX_RECV_BEACON_HOPS + 1;
        assert!(
            !far.ingest(beacon.clone(), 1).unwrap(),
            "a beacon past the cap is not re-gossiped"
        );
        assert!(
            far.seen(&beacon.id),
            "still deduped so a later copy is dropped"
        );
        // Nothing was stored for onward gossip.
        assert!(far.gossip_offer(&HashSet::new()).is_empty());
    }

    fn listing(seller: &Identity, title: &str, seq: u64) -> Advert {
        Advert::publish(
            seller,
            AdvertKind::Service {
                service: "market".into(),
                title: title.into(),
                summary: "…".into(),
                tags: vec!["bicycle".into()],
            },
            0,
            600_000,
            seq,
        )
        .unwrap()
    }

    #[test]
    fn relay_cache_is_bounded_and_evicts_oldest() {
        // A node subscribed to nothing must not grow without bound while relaying.
        let seller = Identity::generate();
        let mut dir = Directory::with_relay_cap(3);
        for i in 0..10 {
            dir.ingest(listing(&seller, &format!("bike {i}"), i), 1)
                .unwrap();
        }
        // Only the cap's worth survive in the best-effort cache.
        assert_eq!(dir.browse("market", None).len(), 3);
    }

    #[test]
    fn subscribed_topics_get_full_retention() {
        let seller = Identity::generate();
        let mut dir = Directory::with_relay_cap(2);
        dir.subscribe("market");
        for i in 0..10 {
            dir.ingest(listing(&seller, &format!("bike {i}"), i), 1)
                .unwrap();
        }
        // Subscribed → not subject to the relay-cache bound.
        assert_eq!(dir.browse("market", None).len(), 10);
    }

    #[test]
    fn subscribing_promotes_already_cached_adverts() {
        let seller = Identity::generate();
        let mut dir = Directory::with_relay_cap(8);
        dir.ingest(listing(&seller, "bike", 1), 1).unwrap(); // cached best-effort
        dir.subscribe("market"); // later decide we care
        dir.expire(1); // would drop from a tiny relay cache; survives in subscribed
        assert_eq!(dir.browse("market", None).len(), 1);
    }

    /// End-to-end marketplace flow: A's listing reaches B transitively through a
    /// relay R that neither party is directly connected to at the same time, then
    /// B uses the discovered keys to send a sealed inquiry bundle to A.
    #[test]
    fn relayed_discovery_then_contact() {
        let alice = Identity::generate(); // seller
        let relay = Directory::new(); // stand-in: we move adverts by hand below
        let _ = relay;
        let bob = Identity::generate(); // buyer

        // A publishes; the advert gossips A -> R, then later R -> B.
        let listing = Advert::publish(
            &alice,
            AdvertKind::Service {
                service: "market".into(),
                title: "Bike for sale".into(),
                summary: "Blue road bike, $40".into(),
                tags: vec!["bicycle".into()],
            },
            0,
            600_000,
            1,
        )
        .unwrap();

        let mut relay_dir = Directory::new();
        relay_dir.ingest(listing.clone(), 1).unwrap(); // A met R

        // R later meets B and offers what B hasn't seen.
        let mut bob_dir = Directory::new();
        let offered = relay_dir.gossip_offer(&HashSet::new());
        for adv in offered {
            bob_dir.ingest(adv, 2).unwrap();
        }

        // B browses the marketplace and finds A's post — without ever meeting A.
        let hits = bob_dir.browse("market", Some("bicycle"));
        assert_eq!(hits.len(), 1);
        let post = &hits[0];
        assert_eq!(post.body.publisher, alice.address());

        // B seals an inquiry addressed to A using the keys from the advert.
        let inquiry = Bundle::create(
            &bob,
            Destination::Device(post.body.publisher),
            &post.body.publisher,
            &Payload::PeerMessage {
                content_type: "text/plain".into(),
                body: b"Is the bike still available?".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap();

        // Only Alice can open it.
        match inquiry.open(&alice).unwrap() {
            Payload::PeerMessage { body, .. } => {
                assert_eq!(body, b"Is the bike still available?")
            }
            _ => panic!("wrong payload"),
        }
    }
}
