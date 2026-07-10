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
        let body = AdvertBody {
            version: ADVERT_VERSION,
            app,
            publisher: publisher.address(),
            kind,
            created_at,
            ttl_ms,
            seq,
        };
        let bytes = postcard::to_allocvec(&body)?;
        let id = *blake3::hash(&bytes).as_bytes();
        let sig = publisher.sign(&bytes).to_vec();
        Ok(Advert {
            id,
            body,
            sig,
            hops: 0,
        })
    }

    /// Verify the id matches the body and the publisher signature is valid.
    pub fn verify(&self) -> Result<()> {
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
        now_ms > self.body.created_at.saturating_add(self.body.ttl_ms as u64)
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

    fn put(&mut self, advert: &Advert) -> Result<()> {
        if self.cap == 0 {
            return Ok(());
        }
        let blob = util::compress(&postcard::to_allocvec(advert)?);
        if self.blobs.insert(advert.id, blob).is_none() {
            self.order.push_back(advert.id);
        }
        while self.blobs.len() > self.cap {
            if let Some(evict) = self.order.pop_front() {
                self.blobs.remove(&evict);
            } else {
                break;
            }
        }
        Ok(())
    }

    fn get(&self, id: &AdvertId) -> Option<Advert> {
        let blob = self.blobs.get(id)?;
        let bytes = util::decompress(blob).ok()?;
        postcard::from_bytes(&bytes).ok()
    }

    fn remove(&mut self, id: &AdvertId) {
        self.blobs.remove(id);
    }

    fn adverts(&self) -> impl Iterator<Item = Advert> + '_ {
        self.blobs.keys().filter_map(|id| self.get(id))
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
    prekeys: HashMap<PubKeyBytes, (u64, PreKeyBundle)>,
    /// Ids seen (even if since removed/revoked), so we don't re-accept gossip.
    seen: HashSet<AdvertId>,
    /// Revoked ids — a tombstone may arrive before the advert it revokes.
    revoked: HashSet<AdvertId>,
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
        Self {
            subscriptions: HashSet::new(),
            subscribed: HashMap::new(),
            relay: RelayCache::new(cap),
            prekeys: HashMap::new(),
            seen: HashSet::new(),
            revoked: HashSet::new(),
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
            self.relay.remove(&a.id);
            self.subscribed.insert(a.id, a);
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

    /// Accept a gossiped advert. Verifies signature, dedups, applies tombstones,
    /// drops expired records, and routes to full retention or the relay cache by
    /// subscription. Returns true if newly accepted (worth re-gossiping).
    pub fn ingest(&mut self, advert: Advert, now_ms: u64) -> Result<bool> {
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
            self.seen.insert(advert.id);
            return Ok(false);
        }

        if !self.seen.insert(advert.id) {
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

        if let AdvertKind::Tombstone { revokes } = advert.body.kind {
            self.revoked.insert(revokes);
            self.subscribed.remove(&revokes);
            self.relay.remove(&revokes);
        }
        if self.revoked.contains(&advert.id) {
            return Ok(true); // seen for gossip, but don't store a revoked record
        }

        // Index prekey bundles by publisher (newest wins) for session bootstrap,
        // alongside storing the advert for re-gossip.
        if let AdvertKind::PreKey { spk_pub, spk_sig } = &advert.body.kind {
            let pubk = advert.body.publisher;
            let newer = self
                .prekeys
                .get(&pubk)
                .is_none_or(|(at, _)| advert.body.created_at >= *at);
            if newer {
                let bundle = PreKeyBundle {
                    address: pubk,
                    spk_pub: *spk_pub,
                    spk_sig: spk_sig.clone(),
                };
                self.prekeys.insert(pubk, (advert.body.created_at, bundle));
            }
        }

        // App scoping (DESIGN.md §17): full retention only for our own app or the open fabric
        // (peer discovery / prekeys flood fabric-wide). Other apps' adverts are still carried in
        // the relay cache — the fabric is shared and must keep forwarding — just never surfaced
        // locally. This is what stops one app from discovering another app's hps topics.
        let our_app = advert.body.app == self.app || advert.body.app == FABRIC_APP;
        if our_app && self.is_subscribed(advert.topic()) {
            self.subscribed.insert(advert.id, advert);
        } else {
            self.relay.put(&advert)?; // best-effort carry for strangers / other apps
        }
        Ok(true)
    }

    /// The latest known prekey bundle for `address`, if we've seen one — used to
    /// open a forward-secret session without a live round-trip (DESIGN.md §25).
    pub fn prekey(&self, address: &PubKeyBytes) -> Option<PreKeyBundle> {
        self.prekeys.get(address).map(|(_, b)| b.clone())
    }

    /// Have we already seen this advert id (for gossip offer filtering)?
    pub fn seen(&self, id: &AdvertId) -> bool {
        self.seen.contains(id)
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

    /// Drop expired service adverts. Call periodically (DESIGN.md §8, §23).
    pub fn expire(&mut self, now_ms: u64) {
        self.subscribed.retain(|_, a| !a.is_expired(now_ms));
        let expired: Vec<AdvertId> = self
            .relay
            .adverts()
            .filter(|a| a.is_expired(now_ms))
            .map(|a| a.id)
            .collect();
        for id in expired {
            self.relay.remove(&id);
        }
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
