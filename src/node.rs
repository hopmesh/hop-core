//! The node event loop — the orchestration that turns the tested pieces into a
//! running Hop node. See DESIGN.md §3 (it spans every layer).
//!
//! A [`Node`] is driven by [`BearerEvent`]s from a bearer and produces opaque
//! bytes to send back over it. Per connection it:
//! 1. runs a Noise XX handshake ([`crate::link`]), exchanging a signed binding so
//!    each side learns the other's *hop address* (Ed25519), not just its link key;
//! 2. once up, offers its stored bundles via binary spray-and-wait ([`crate::routing`])
//!    and gossips its directory of adverts ([`crate::discover`]);
//! 3. on receiving a bundle addressed to itself, delivers it to the inbox;
//!    otherwise stores it for onward relay.
//!
//! The loop is transport-agnostic and fully testable without a radio: feed it
//! events, drain its outgoing bytes, read its inbox. v1 sends each message as one
//! link packet; MTU fragmentation (`link::fragment`) wraps this when a bearer
//! needs it — a TODO for the BLE shim.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::access::{AccessPolicy, Admit, Stamper, TenantId, Usage};
use crate::app::AppKeys;
use crate::bundle::{
    Bundle, BundleFlags, BundleId, BundleOpts, Destination, Payload, StreamId, TraceHop,
    MAX_BUNDLE_WIRE_BYTES,
};
use crate::crypto::{
    self, short_addr, Identity, PubKeyBytes, ShortAddr, SignedPreKey, Tag, XPubKeyBytes,
};
use crate::discover::{Advert, AdvertId, AdvertKind, Directory};
use crate::error::{Error, Result};
use crate::hps;
use crate::link::{BearerEvent, LinkHandshake, LinkId, LinkSession, Role};
use crate::route::RouteTable;
use crate::routing::{BundleMeta, ForwardDecision, Router, SprayAndWait};
use crate::session::Session;
use crate::store::{KvMutation, KvPageRow, MemoryStore, Store, MAX_SEEN_LIFETIME_MS};
use crate::stream::StreamReassembler;
use crate::telemetry::TelemetryBatch;
use crate::{short_app, AppId, ShortApp, FABRIC_APP};

/// A link packet on the wire: a Noise handshake message, or an encrypted record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum LinkPacket {
    Handshake(Vec<u8>),
    Data(Vec<u8>),
    /// One fragment of a record too large for a single Noise message (max 65535 bytes).
    /// `idx`/`cnt` order reassembly; each fragment's `ct` is independently Noise-encrypted,
    /// so the receiver decrypts in order and concatenates the plaintext before decoding the
    /// [`Wire`]. Without this, an oversized record (e.g. a large `hps://` broadcast) would be
    /// silently dropped at `encrypt` (DESIGN.md §20).
    DataFrag {
        idx: u16,
        cnt: u16,
        ct: Vec<u8>,
    },
}

/// Max plaintext bytes per Noise transport message. Noise caps a message at 65535 bytes
/// including the 16-byte AEAD tag; we leave headroom for the postcard `LinkPacket` framing.
const MAX_RECORD_PLAINTEXT: usize = 60_000;
/// Hard aggregate cap for one link record. User payloads larger than this are not rejected: the
/// carrier-stream layer splits them into 48 KiB bundles before they reach link framing.
const MAX_REASSEMBLED_RECORD: usize = 1 << 20;
const MAX_RECORD_FRAGMENTS: usize = MAX_REASSEMBLED_RECORD.div_ceil(MAX_RECORD_PLAINTEXT);
/// Aggregate cap applied before decoding an attacker-controlled postcard link packet.
pub const MAX_LINK_PACKET_BYTES: usize = 64 * 1024;
const MAX_HANDSHAKE_MESSAGE_BYTES: usize = 1024;

/// Claims the peer's hop address during the Noise handshake. No signature needed:
/// the sealing key is derived from the address (Montgomery), so the peer is bound to
/// the address iff `address_to_x(address)` equals the static key Noise authenticated.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LinkAuth {
    pub(crate) address: PubKeyBytes,
}

/// An application record exchanged over an established link.
///
/// WIRE DISCIPLINE: append-only, same as the bundle enums. `Have` was appended as the §35
/// custody beacon (a node tells this peer what it already holds so the peer stops re-offering it);
/// added within the v8 wire bump.
#[derive(Serialize, Deserialize)]
pub(crate) enum Wire {
    Bundle(Bundle),
    Advert(Advert),
    /// §35 custody beacon: "I already hold these ids, do not offer them to me." Mode-1 only:
    /// exchanged over the authenticated Noise link with the peer it constrains, so it is the
    /// peer's own truthful claim about its own store (no forgery/censorship surface, unlike a
    /// flooded beacon). Cuts duplicate-ingress COGS.
    Have(crate::store::HaveSet),
}

/// Postcard encodes this two-variant enum with a one-byte discriminant (`Bundle = 0`, `Advert = 1`).
/// Pinning that below lets us reject an oversized advert before deserializing attacker-sized strings
/// and vectors. A unit test asserts the discriminant assumption against the actual serializer.
fn advert_record_exceeds_limit(plaintext: &[u8]) -> bool {
    plaintext.first() == Some(&1) && plaintext.len() > MAX_ADVERT_LINK_BYTES
}

struct Handshaking {
    hs: LinkHandshake,
    verified: Option<PubKeyBytes>,
}

struct Established {
    session: LinkSession,
    peer: PubKeyBytes,
    sent_bundles: HashSet<crate::bundle::BundleId>,
    sent_adverts: HashSet<crate::discover::AdvertId>,
    /// §35 custody beacon: ids this peer told us (over this authenticated link) it already holds,
    /// so we suppress re-offering them. Bounded by [`MAX_PEER_HAS`]; cleared on reconnect (the
    /// peer re-sends its `Wire::Have`).
    peer_has: HashSet<crate::bundle::BundleId>,
    /// Reassembly of an in-progress fragmented record (DESIGN.md §20): accumulated decrypted
    /// plaintext and the next fragment index expected. `frag_cnt == 0` means none in progress.
    frag_buf: Vec<u8>,
    frag_next: u16,
}

/// Per-PEER gossip dedup that SURVIVES link re-establishment. The per-`Established` `sent_*` sets
/// are wiped on every (re)connect; on a flapping BLE link that re-floods the whole directory to the
/// peer each cycle — the resource-exhaustion field bug (tx >> rx, real messages starve). We snapshot
/// them here on Disconnect, keyed by peer address, and restore them on the next Up to the same peer.
#[derive(Default)]
struct PeerSent {
    adverts: HashSet<crate::discover::AdvertId>,
    bundles: HashSet<crate::bundle::BundleId>,
    last_seen_ms: u64,
}

// Boxed because a Noise handshake state is much larger than an established session.
enum LinkState {
    Handshaking(Box<Handshaking>),
    Up(Box<Established>),
}

/// Tracking for a locally-originated bundle awaiting an end-to-end ACK (§7).
#[derive(Clone, Copy)]
struct PendingTx {
    copies: u16,
    created_at: u64,
    lifetime_ms: u32,
    next_retx_at: u64,
    /// Current backoff gap; doubles each retransmit up to [`MAX_RETX_INTERVAL_MS`].
    retx_interval: u64,
}

/// Default *initial* gap between retransmission attempts for an unacked bundle. Short so a copy
/// lost on a flaky local BLE link (drop mid-send) recovers in seconds, not half a minute; it then
/// backs off exponentially up to [`MAX_RETX_INTERVAL_MS`], so a days-long hop still costs only a
/// handful of retransmits rather than thousands. (Reconnects re-offer pending bundles immediately
/// via the link-up path, so this is the fallback for losses without a reconnect.)
pub const DEFAULT_RETX_INTERVAL_MS: u64 = 5_000;

/// Ceiling on the retransmission backoff (15 min). Past this, retries pace at this rate
/// for the rest of the bundle's lifetime.
pub const MAX_RETX_INTERVAL_MS: u64 = 900_000;

/// How often to re-gossip adverts (prekeys/presence) over already-up links, so a forward-secret
/// session can form without a reconnect (the "move out of range and back to send" bug). Cheap —
/// receivers dedup unchanged adverts.
pub const REGOSSIP_INTERVAL_MS: u64 = 12_000;

/// How many distinct peers a delivery-ACK is replicated to before it stops spreading
/// (DESIGN.md §7). Until then it rides along to every new contact — the ACK both confirms
/// delivery and vaccinates the mesh, so it's worth replicating, but bounded.
pub const ACK_REPLICATION_TARGET: usize = 3;

/// Hard cap on a delivery-ACK's lifetime (7 days). The ACK otherwise lives as long as the
/// message it confirms.
pub const MAX_ACK_LIFETIME_MS: u32 = 7 * 86_400_000;

/// Don't re-emit a delivery-ACK for the same message more often than this — a burst of
/// duplicate copies can't trigger an ACK storm (the re-ACK recovers a lost ACK; §7).
pub const REACK_MIN_INTERVAL_MS: u64 = 30_000;

/// Default cap on relayed (not-ours) bundles held for forwarding. Our own messages
/// are never counted or evicted; relayed ones decay under this bound.
pub const DEFAULT_MAX_RELAYED: usize = 128;

/// After we've relayed a not-ours bundle to ≥1 peer, keep it at least this long before
/// it becomes eviction-eligible — so in a populated area it can be handed off again, and
/// so a flood of big transfers can't immediately evict freshly-relayed traffic (DESIGN.md
/// §6). Under cap pressure, eviction *prefers* such already-relayed, past-grace bundles
/// and only drops a not-yet-relayed bundle when nothing else can be freed.
pub const EVICT_GRACE_MS: u64 = 180_000; // 3 minutes

/// Default cap on the learned-route table (DESIGN.md §27). Mobile-tier; cloud nodes
/// raise it via [`Node::set_route_capacity`] to become the long-memory backbone.
pub const DEFAULT_MAX_ROUTES: usize = 2_048;

/// Default cap on the "bundles I forwarded" memory used to correlate a returning
/// delivery-ACK with the forward path. Bounded; pruned by age in [`Node::tick`].
pub const DEFAULT_MAX_FORWARDED: usize = 4_096;

/// TTL for a published prekey advert (7 days). Re-publish before it lapses so peers
/// can always open a session (DESIGN.md §25).
pub const PREKEY_TTL_MS: u32 = 604_800_000;

/// §39 P4 receiver-beacon: how long a laid gradient entry lives without a refresh. Kept SHORT
/// (relative to [`PREKEY_TTL_MS`]) so a moved/silent recipient stops attracting bundles within
/// one TTL — no permanent black-hole. Refresh interval must be well under this.
pub const RECV_BEACON_TTL_MS: u32 = 90_000;
/// How often a "route-to-me" recipient re-emits its beacon to keep the gradient fresh. Well
/// under [`RECV_BEACON_TTL_MS`] so a single missed beacon self-heals; the gradient tracks a
/// mobile recipient at this cadence.
pub const RECV_BEACON_REFRESH_MS: u64 = 30_000;
/// §39 mailbox-tag rotation period (F-06). The pull pseudonym `H(address ‖ epoch)` rotates each
/// epoch so a global observer can't correlate a recipient's mailbox across epochs. A day is long
/// enough that a spooled bundle (pulled within minutes/hours) almost always drains inside one epoch.
pub const MAILBOX_EPOCH_MS: u64 = 86_400_000;
/// A forward-secret session unused for this long is GC'd from memory + the persisted `session/`
/// store (D6), so meeting many peers once doesn't grow storage without bound. 30 days is generous:
/// a real contact is touched far more often, and a pruned session just re-establishes on return.
const SESSION_MAX_IDLE_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// How many extra PAST epochs a recipient keeps beaconing and a relay keeps accepting, so a bundle
/// addressed/spooled just before an epoch boundary (or under a bit of clock skew) is still routed and
/// pulled after rotation. Window = 1 ⇒ current + previous epoch are live.
const MAILBOX_EPOCH_WINDOW: u64 = 1;

/// The current mailbox epoch for a clock reading.
fn mailbox_epoch(now_ms: u64) -> u64 {
    now_ms / MAILBOX_EPOCH_MS
}

/// security-privacy-r18-08 (ADV18-08): private bundles (and their ACKs) carry `created_at` in the
/// clear inside the signed inner, bound into the wire id. At millisecond resolution it is a sender
/// timing fingerprint: two private bundles a sender mints close together are correlatable by exact
/// stamp, and a relay on both legs can tie an ACK to its forward message by a matched pair of stamps.
/// Coarsen the stamp to a wide bucket on the private path so the wire value no longer resolves
/// individual sends. TTL/expiry still hold: bucketing rounds DOWN, so a bundle only ever looks
/// slightly older (it expires marginally sooner, never later). Latency the ACK reports is likewise
/// bucket-granular, which is an accepted trade: delivery latency is advisory UX, and per-message
/// timing precision is exactly the fingerprint we are removing. The bucket is a constant, so every
/// node coarsens identically.
const PRIVATE_TIME_BUCKET_MS: u64 = 60_000;

/// Round a wall-clock reading down to the private-path time bucket (ADV18-08).
fn private_created_at(now_ms: u64) -> u64 {
    (now_ms / PRIVATE_TIME_BUCKET_MS) * PRIVATE_TIME_BUCKET_MS
}

/// Signed-prekey rotation period (core-03). The published SPK rotates each epoch so a compromised
/// prekey secret only exposes the X3DH first-message roots (and recognition tags) of sessions
/// bootstrapped in that window, not for the identity's whole life. One week balances that bound
/// against churn: peers cache the prekey advert, so rotating too fast would strand cached openers.
const PREKEY_EPOCH_MS: u64 = 7 * 86_400_000;

/// How many PAST prekey epochs' secrets we retain (core-03). A session first-message minted against
/// the prior epoch's SPK (in flight across our rotation, or from a peer holding a slightly stale
/// advert) must still resolve, so we keep this many previous epochs' secrets before wiping them.
const PREKEY_EPOCH_WINDOW: u64 = 1;

/// The current prekey epoch for a clock reading.
fn prekey_epoch(now_ms: u64) -> u64 {
    now_ms / PREKEY_EPOCH_MS
}

/// sec-priv-04: the **routing key** for a mailbox-tag — its short prefix ([`crypto::mailbox_route`])
/// right-padded back into a full [`Tag`] with zeros. Every routing/spool/want-beacon DECISION keys on
/// this, never on the full tag, so an address-knower who can compute a target's full mailbox-tag only
/// ever sees a routing bucket shared by an *anonymity set* of every address that collides on the
/// prefix, instead of a unique per-recipient confirmation. Keeping the padded form a `Tag` means the
/// external spool/want APIs (and the relay's opaque-key durable spool) are unchanged on the wire while
/// their matching semantics silently widen to the prefix bucket. Delivery is unaffected: the final
/// "is this mine?" test is the per-message-ephemeral recognition tag, which stays unique + unlinkable.
fn route_key(tag: &Tag) -> Tag {
    route_key_from_prefix(&crypto::mailbox_route(tag))
}

/// The gradient/spool/want map key ([`route_key`]) for a mailbox routing PREFIX already in hand — e.g.
/// the [`crate::bundle::PrivateHeader::mailbox`] prefix a private bundle now carries on the wire
/// (core-protocol-r2-02). Right-pads the prefix into a full [`Tag`] with zeros so the map keys stay
/// `Tag`-typed and identical to those laid from a beacon's full tag via [`route_key`].
fn route_key_from_prefix(prefix: &crypto::MailboxRoute) -> Tag {
    let mut k = [0u8; crypto::TAG_LEN];
    k[..crypto::MAILBOX_ROUTE_PREFIX_BYTES].copy_from_slice(prefix);
    k
}

/// Reserved [`LinkId`] for our own local re-injection path (rehydrate, stream reassembly, and the
/// durable-storage re-ingest in [`Node::ingest`]) and the "no link to skip" argument to the offer
/// helpers (core-05). It is exempt from the F-07 private-ingest rate limit (this traffic comes from
/// our own trusted storage, not a live remote link), so a real bearer must NEVER assign it to a
/// transport connection; [`Node::on_connected`] refuses a link with this id defensively.
const LOCAL_LINK: LinkId = 0;

/// Per-link inbound rate limit for §39 **private** bundles (F-07). Private bundles are unsigned
/// and unlimited-mintable, so a hostile/buggy peer could flood them; a legitimate peer never
/// approaches this. Traced (signed, attributable) bundles and stream carriers are NOT limited.
const PRIV_INGEST_WINDOW_MS: u64 = 1_000;
const MAX_PRIV_BUNDLES_PER_WINDOW: u32 = 256;

/// Cap on distinct tenants the in-memory §35 usage map tracks between host flushes. Every
/// entry is backed by a VERIFIED stamp (forgeries never reach the meter), so this only bounds a
/// hostile issuer-side explosion or a very long flush gap. At the cap, new tenants are still
/// admitted (availability wins) but not metered until a drain frees space; the host flush
/// interval (tens of seconds) makes the unmetered window negligible.
const MAX_METERED_TENANTS: usize = 4_096;

/// Cap on the pending-attribution map (verified-at-admit tenant per held foreign bundle, awaiting
/// a delivery proof to bill). A relay holds at most `max_relayed` foreign bundles, so this
/// comfortably covers the held set plus the one-tick lag before `tick` prunes evicted entries.
const MAX_METERED_ATTRIBUTION: usize = 16_384;

/// §35 custody beacon: cap on ids advertised in one `Wire::Have`, and on ids remembered per peer.
/// Bounds the beacon's link bandwidth (a full held set can be large) and the per-link `peer_has`
/// memory; a relay that holds more than this simply advertises its most-recent slice.
const MAX_HAVE_ADVERTISE: usize = 4_096;
const ADVERT_VERIFY_WINDOW_MS: u64 = 1_000;
const MAX_ADVERTS_PER_LINK_WINDOW: u32 = 64;
const MAX_ADVERTS_GLOBAL_WINDOW: u32 = 512;
const MAX_ADVERT_LINK_BYTES: usize = crate::discover::MAX_ADVERT_WIRE_BYTES + 8;
const MAX_PEER_SENT: usize = 1_024;
const PEER_SENT_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
/// Cap on the soft-state gradient table (bounds a Sybil flooding fake mailbox-tags; signed
/// beacons stop *hijack*, this stops *bloat*). On overflow the nearest-to-expiry entry is evicted.
pub const MAX_RECV_GRADIENT: usize = 4_096;

/// core-protocol-r3-02: cap on remembered vaccine tokens whose target hadn't arrived yet (see
/// `seen_vaccine_tokens`). Bounds the memory a distinct-token vaccine flood can pin; on overflow the
/// oldest token is dropped (its target, if it ever arrives, then just falls back to TTL reclamation
/// (the pre-fix behavior), never a black-hole). Same order as the private-bundle store cap.
pub const MAX_SEEN_VACCINE_TOKENS: usize = 4_096;

/// TTL for an `hps://` discoverable-topic advert (7 days). Re-publish before it lapses so
/// same-app peers keep seeing the topic (DESIGN.md §32).
pub const HPS_TOPIC_TTL_MS: u32 = 604_800_000;

/// Floor on a cached HNS record's lifetime (DESIGN.md §30): even a 0-TTL DNS answer is held
/// briefly so a burst of lookups for the same domain coalesces.
pub const MIN_HNS_TTL_MS: u64 = 1_000;

/// Ceiling on a cached HNS record's lifetime (1 day) — a stale endpoint address can't linger
/// forever even if DNS hands back an absurd TTL.
pub const MAX_HNS_TTL_MS: u64 = 86_400_000;

/// How often to re-attempt a still-unresolved HNS query (delay-tolerant resolution, §30).
pub const HNS_RETRY_INTERVAL_MS: u64 = 15_000;

/// Delivery tracking for a message we originated (for status: Sending/Sent N/Delivered).
#[derive(Default)]
struct TxInfo {
    /// Distinct peers we've handed a copy to (the "Sent N" count).
    relayed: HashSet<PubKeyBytes>,
    /// The destination ACKed it back across the network.
    delivered: bool,
    /// Hops the original message took to *reach* the destination (forward path length).
    delivered_hops: u8,
    /// **Forward-path** latency to the destination in ms (the destination's receive time
    /// minus our send time, as it reported in the ACK) — the A→B leg, not the round trip.
    delivered_ms: u32,
}

/// §39 P4 (+ sec-priv-04): one soft-state next-hop under a mailbox **route prefix** — "a recipient in
/// this prefix's anonymity set is reachable via `inbound`." Recorded from a signed
/// [`AdvertKind::RecvBeacon`]; per inbound link the closest (fewest-hop), freshest (highest `seq`)
/// beacon wins. Pruned at `expires_at`.
#[derive(Clone, Copy, Debug)]
struct GradientLink {
    /// Distance to the recipient in advert-hops (lower = closer; breaks ties when re-pointing).
    hops: u8,
    /// `beacon.created_at + ttl_ms` — dropped once the clock passes this (no refresh ⇒ no route).
    expires_at: u64,
    /// The beacon's per-publisher `seq`; a strictly-higher seq supersedes on the same link.
    seq: u64,
    /// security-privacy-r2-04: OUR clock when we last accepted a beacon on this link. Per-bucket
    /// overflow evicts the LEAST-RECENTLY-SEEN link (not the nearest-to-expiry one). A legitimate
    /// recipient re-beacons on a short interval (`RECV_BEACON_REFRESH_MS`), so its link is always
    /// recently-seen and survives; a prefix-grinding Sybil that parks a slot with a far-future TTL but
    /// stops refreshing becomes stale-seen and is evicted first. That removes the old attack where a
    /// Sybil fleet of fresher-expiry beacons on a victim's prefix could crowd out the victim's own link.
    last_seen: u64,
}

/// sec-priv-04: routing keys on the tag PREFIX (an anonymity set), so a single bucket may cover
/// SEVERAL distinct recipients reachable via DIFFERENT next hops. A prefix collision is rare (a 2-byte
/// prefix ⇒ ~1/65536 per peer pair) but must not starve a colliding recipient, so the bucket holds a
/// bounded set of next-hop links and a matching private bundle is forwarded down ALL live links in it
/// (never to a link that did not beacon this prefix — the decoy stays excluded, so directed routing
/// still holds). The far end that isn't the intended recipient simply fails the per-message
/// recognition tag and drops its copy; the intended one recognizes and delivers.
#[derive(Clone, Debug, Default)]
struct GradientEntry {
    /// Next-hop links that beaconed this route prefix, each with its freshness. Bounded by
    /// [`MAX_GRADIENT_LINKS_PER_BUCKET`]; on overflow the LEAST-RECENTLY-SEEN link is evicted
    /// (security-privacy-r2-04), so a re-beaconing recipient is never crowded out by parked Sybils.
    links: Vec<(LinkId, GradientLink)>,
}

/// Bound on distinct next-hops kept per route-prefix bucket (sec-priv-04). Small: real collisions are
/// rare, and this only needs to cover the handful of anonymity-set members actually behind one relay.
const MAX_GRADIENT_LINKS_PER_BUCKET: usize = 8;

/// A queued message for the UI: either ours awaiting send, or a peer's awaiting relay.
#[derive(Clone, Debug)]
pub struct QueuedMessage {
    pub id: BundleId,
    /// True if we originated it (pinned — never evicted). False = relaying for a peer.
    pub own: bool,
    /// Destination device address, if addressed to one.
    pub to: Option<PubKeyBytes>,
    pub priority: u8,
    /// Hops travelled so far.
    pub hops: u8,
}

/// The plaintext inside a forward-secret session message — what the ratchet
/// encrypts, so `content_type` rides end-to-end like the body.
#[derive(Serialize, Deserialize)]
struct SessionInner {
    content_type: String,
    body: Vec<u8>,
}

/// Per-peer forward-secret session state (DESIGN.md §25).
#[derive(Clone, Serialize, Deserialize)]
struct PeerSession {
    session: Session,
    /// For an initiator that hasn't heard back yet: the X3DH material to repeat in a
    /// `SessionInit` so any copy can bootstrap the peer. `None` once confirmed (we've
    /// received a message from them) or for a responder.
    init_material: Option<(XPubKeyBytes, XPubKeyBytes)>, // (ek_pub, spk_pub)
    /// The initiator ephemeral that established this session, remembered so a *new*
    /// `SessionInit` (a peer that reinstalled / lost its ratchet) is recognized as a fresh
    /// handshake and **rebuilds** the session instead of failing to decrypt (DESIGN.md §25).
    established_by: Option<XPubKeyBytes>,
}

/// Device-to-device content held until we can ratchet it (DESIGN.md §25): we never static-seal
/// user content, so if the peer's prekey isn't known yet the message waits here.
#[derive(Clone, Serialize, Deserialize)]
struct PendingContent {
    display_id: BundleId, // the handle returned to the UI (stable across the deferral)
    dst: PubKeyBytes,
    content_type: String,
    body: Vec<u8>,
    request_ack: bool,
    private: bool, // §39: send untraceably (no cleartext src/dst, floods, recognized by tag)
}

/// The response variant an outstanding directed request is allowed to consume.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum RequestKind {
    Http,
    Service,
}

/// Durable authorization context for one outbound HTTP/service request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OutstandingRequest {
    responder: PubKeyBytes,
    kind: RequestKind,
    expires_at_ms: u64,
    custody_ids: Vec<BundleId>,
}

/// A decrypted user message ready for the inbox, uniform across static-sealed and
/// forward-secret session messages.
#[derive(Clone)]
pub struct ReadMessage {
    pub from: PubKeyBytes,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// A durable, already-authenticated inbox item. The bundle id is also the stable host dedup id.
/// Polling clones these records without removing them; only [`Node::accept_inbox`] deletes one and
/// releases its delivery acknowledgement.
#[derive(Clone, Serialize, Deserialize)]
pub struct InboxItem {
    pub id: BundleId,
    pub from: PubKeyBytes,
    pub content_type: String,
    pub body: Vec<u8>,
    pub hops: u8,
    pub created_at: u64,
    pub trace: Vec<TraceHop>,
    received_at: u64,
    acknowledgement: InboxAcknowledgement,
    /// Retained only for the legacy low-level `take_inbox`/`read_message` test seam. Redelivery and
    /// all public host APIs use the decrypted fields above and never consume the ratchet again.
    original: Bundle,
}

#[derive(Clone, Serialize, Deserialize)]
enum InboxAcknowledgement {
    None,
    Traced {
        to: PubKeyBytes,
        for_bundle_id: BundleId,
        delivery_hops: u8,
        delivery_ms: u32,
        lifetime_ms: u32,
        priority: u8,
    },
    Private {
        to: PubKeyBytes,
        for_bundle_id: BundleId,
        delivery_hops: u8,
        delivery_ms: u32,
        proof: Option<[u8; 32]>,
        vaccine: Option<[u8; 32]>,
        lifetime_ms: u32,
    },
}

#[derive(Clone, Serialize, Deserialize)]
struct ReceiverSeen {
    expires_at_ms: u64,
    acknowledgement: InboxAcknowledgement,
}

struct PreparedInbound {
    message: Option<ReadMessage>,
    session: Option<PeerSession>,
    flush_pending: bool,
}

/// An internet-egress HTTP request a gateway should fulfill (Use Case A, §9).
pub struct HttpReqItem {
    pub from: PubKeyBytes,
    pub id: BundleId,
    /// The domain this request targets. A `hops://` endpoint MUST validate this against the
    /// single domain it is authorized to serve and refuse anything else (no open proxy).
    pub host: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub max_resp: u32,
}

/// A cached HNS record (DESIGN.md §30). `address` is `None` for a negative (no such hops
/// endpoint) entry. Both honor the DNS TTL via `expires_at_ms`.
#[derive(Clone, Copy)]
pub struct HnsEntry {
    pub address: Option<PubKeyBytes>,
    pub expires_at_ms: u64,
}

/// A finished HNS resolution surfaced to the app. `address` is `None` when the domain served no
/// valid reach record (resolution error — e.g. `hops://thisdoesnotexist.com`).
pub struct HnsResult {
    pub domain: String,
    pub address: Option<PubKeyBytes>,
}

/// The outcome of starting an HNS resolution (DESIGN.md §30).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HnsLookup {
    /// Served from a fresh cache entry. `Some(addr)` resolved; `None` is a cached negative.
    Cached(Option<PubKeyBytes>),
    /// A lookup was kicked off (the host fetches the domain's well-known reach record); the
    /// result will arrive via [`Node::take_hns_results`].
    Pending,
    /// This node can't resolve on its own: it has no internet, so it cannot fetch the domain's
    /// `/.well-known/hop`, and there is deliberately no relayed resolution. Hand it the address
    /// directly instead (`hops://<address>`), which is self-certifying and needs no lookup.
    NeedsResolver,
}

/// An HTTP response a gateway sealed back to the requester.
#[derive(Clone, Serialize, Deserialize)]
pub struct HttpRespItem {
    pub from: PubKeyBytes,
    /// The response bundle id used for local queue acceptance.
    pub id: BundleId,
    pub for_id: BundleId,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// The built-in identity service (DESIGN.md §29): call it on any address to learn that
/// node's display name + kind. Answered by the node itself, not the app.
pub const SERVICE_IDENTIFY: &str = "hop.identify";

/// The built-in telemetry sink (OTel-over-Hop, DESIGN.md §40): a device exports a
/// [`TelemetryBatch`](crate::telemetry::TelemetryBatch) to a collector's address. One-way and
/// fire-and-forget (no response); the node decodes + bounds-checks it and surfaces it via
/// [`Node::take_telemetry`]. Statically sealed to the collector like any addressed service.
pub const SERVICE_TELEMETRY: &str = "hop.telemetry";

/// What kind of node this is, reported by [`SERVICE_IDENTIFY`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeKind {
    Device,
    Relay,
    Gateway,
    /// A `hops://` origin endpoint (DESIGN.md §30); its `name` is the domain it serves.
    Endpoint,
}

/// The reply body of [`SERVICE_IDENTIFY`]: who a node is. `name` is `None` when unset
/// (a device by default) — callers fall back to the short address. A relay sets its name
/// to its region domain. Carries the full `address` so a caller can resolve a short trace
/// hop it received against the responder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub name: Option<String>,
    pub kind: NodeKind,
    pub address: PubKeyBytes,
}

/// A service request addressed to this node that the embedding app should fulfill
/// (built-in `hop.` services are answered by the node and never surface here).
pub struct ServiceReqItem {
    pub from: PubKeyBytes,
    /// The request bundle's id — pass it to [`Node::send_service_response`] to reply.
    pub id: BundleId,
    pub service: String,
    pub method: String,
    pub args: Vec<u8>,
}

/// A service response sealed back to us (as the caller).
#[derive(Clone, Serialize, Deserialize)]
pub struct ServiceRespItem {
    pub from: PubKeyBytes,
    /// The response bundle id used for local queue acceptance.
    pub id: BundleId,
    pub for_id: BundleId,
    pub status: u16,
    pub body: Vec<u8>,
}

/// A telemetry batch received via `hop.telemetry` (OTel-over-Hop, §40), already decoded and
/// bounds-checked, for the embedding collector to drain and forward (to an OTel collector or a
/// warehouse) and to meter for the `hop_telemetry_events` observability dimension.
pub struct TelemetryIn {
    pub from: PubKeyBytes,
    pub batch: TelemetryBatch,
    /// The billing tenant recovered from the bundle's carriage stamp (§35), or `None` if the batch
    /// was unstamped or the node runs an `Open` access policy. Only attributed batches are billable
    /// to the `hop_telemetry_events` meter; the tenant is an app/org, never a user (§39-safe).
    pub tenant: Option<TenantId>,
}

/// Memory admission for host-facing queues. Limits apply per queue, across all host queues, and per
/// authenticated sender. Peer-message inbox rows remain durable and non-destructive after admission.
#[derive(Clone, Copy, Debug)]
pub struct AppQueueLimits {
    pub max_items_per_queue: usize,
    pub max_bytes_per_queue: usize,
    pub max_total_items: usize,
    pub max_total_bytes: usize,
    pub max_item_bytes: usize,
    pub max_sender_items: usize,
    pub max_sender_bytes: usize,
}

impl Default for AppQueueLimits {
    fn default() -> Self {
        Self {
            max_items_per_queue: 256,
            max_bytes_per_queue: 64 * 1024 * 1024,
            max_total_items: 1_024,
            max_total_bytes: 64 * 1024 * 1024,
            max_item_bytes: 36 * 1024 * 1024,
            max_sender_items: 64,
            max_sender_bytes: 36 * 1024 * 1024,
        }
    }
}

const APP_QUEUE_KINDS: usize = 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
enum AppQueueKind {
    PeerInbox = 0,
    GenericInbox = 1,
    HttpRequest = 2,
    HttpResponse = 3,
    ServiceRequest = 4,
    ServiceResponse = 5,
    HnsLookup = 6,
    HnsResult = 7,
    HpsMessage = 8,
    HpsInvite = 9,
    Telemetry = 10,
}

#[derive(Clone, Copy)]
struct AppQueueCharge {
    kind: AppQueueKind,
    source: Option<PubKeyBytes>,
    bytes: usize,
}

#[derive(Clone, Copy, Default)]
struct AppSenderUsage {
    items: usize,
    bytes: usize,
}

struct AppQueueUsage {
    items: usize,
    bytes: usize,
    counts: [usize; APP_QUEUE_KINDS],
    queue_bytes: [usize; APP_QUEUE_KINDS],
    senders: HashMap<PubKeyBytes, AppSenderUsage>,
}

impl Default for AppQueueUsage {
    fn default() -> Self {
        Self {
            items: 0,
            bytes: 0,
            counts: [0; APP_QUEUE_KINDS],
            queue_bytes: [0; APP_QUEUE_KINDS],
            senders: HashMap::new(),
        }
    }
}

#[derive(Clone, Copy)]
struct AppPayloadPolicy(u16);

impl AppPayloadPolicy {
    const fn all() -> Self {
        Self((1 << APP_QUEUE_KINDS) - 1)
    }

    const fn for_kind(kind: NodeKind) -> Self {
        let bits = match kind {
            NodeKind::Device => Self::all().0,
            NodeKind::Relay => 0,
            NodeKind::Gateway => 1 << AppQueueKind::HttpRequest as usize,
            NodeKind::Endpoint => {
                (1 << AppQueueKind::HttpRequest as usize) | (1 << AppQueueKind::HpsMessage as usize)
            }
        };
        Self(bits)
    }

    fn supports(self, kind: AppQueueKind) -> bool {
        self.0 & (1 << kind as usize) != 0
    }
}

struct PendingAppDelivery {
    bundle: Bundle,
    charge: AppQueueCharge,
}

/// In-progress reassembly of an inbound **carrier stream** (DESIGN.md §20): a bundle too
/// large to send in one shot is split into ordered chunks; when they're all here the
/// original bundle bytes are reconstructed and re-processed as if received whole. Keyed
/// by `(sender, stream_id)`.
struct IncomingStream {
    reassembler: StreamReassembler,
    data: Vec<u8>,
    chunks: HashMap<u64, IncomingChunk>,
    bytes: usize,
    started_at: u64, // absolute lifetime anchor; arrivals never refresh it
    at: u64,         // last activity, for pruning abandoned transfers
}

#[derive(Clone, Copy)]
struct IncomingChunk {
    hash: [u8; 32],
    fin: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedCarrierChunk {
    started_at: u64,
    received_at: u64,
    fin: bool,
    bytes: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct OutgoingCarrier {
    original: Bundle,
    chunks: Vec<BundleId>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedHttpResponse {
    item: HttpRespItem,
    received_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedServiceResponse {
    item: ServiceRespItem,
    received_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Clone, Copy, Default)]
struct IncomingStreamUsage {
    streams: usize,
    bytes: usize,
}

enum StreamChunkAcceptance {
    Retained,
    Complete(Vec<u8>),
    Rejected,
}

enum CarrierChunkOrigin {
    Live,
    Persisted { started_at: u64, received_at: u64 },
}

struct CarrierChunkInput {
    bytes: Vec<u8>,
    fin: bool,
    origin: CarrierChunkOrigin,
}

/// A bundle whose encoding exceeds this is carried as a stream of `STREAM_CHUNK`-sized
/// chunks (transparently); anything smaller goes as one bundle. Sized to fit comfortably
/// in one link record on every bearer (well under the 1 MiB frame cap).
const STREAM_CHUNK: usize = 48 * 1024;

const MAX_CARRIER_STREAM_BYTES: usize = MAX_BUNDLE_WIRE_BYTES;
const MAX_CARRIER_STREAM_CHUNKS: usize = MAX_CARRIER_STREAM_BYTES.div_ceil(STREAM_CHUNK);
const MAX_CARRIER_CONTENT_BYTES: usize = MAX_CARRIER_STREAM_BYTES - 64 * 1024;
const MAX_CARRIER_STREAMS_PER_SENDER: usize = 4;
const MAX_CARRIER_BYTES_PER_SENDER: usize = 32 * 1024 * 1024;
const MAX_CARRIER_STREAMS_GLOBAL: usize = 32;
const MAX_CARRIER_BYTES_GLOBAL: usize = 64 * 1024 * 1024;
const CARRIER_STREAM_IDLE_MS: u64 = 3_600_000;
const CARRIER_STREAM_LIFETIME_MS: u64 = 24 * 60 * 60 * 1_000;
const CARRIER_PERSISTED_PAGE_ROWS: usize = 16;
const CARRIER_REHYDRATE_MAX_ROWS: usize = 64;
const CARRIER_REHYDRATE_MAX_BYTES: usize = 96 * 1024 * 1024;
const CARRIER_REHYDRATE_MAX_PAGES: usize = 4;
const CARRIER_REHYDRATE_MAX_CLEANUP_OPERATIONS: usize = 128;
const CARRIER_CLEANUP_BATCH_ROWS: usize = 128;
const _: () = assert!(CARRIER_CLEANUP_BATCH_ROWS < 400);

#[derive(Clone, Copy)]
struct CarrierLimits {
    chunk_bytes: usize,
    stream_bytes: usize,
    stream_chunks: usize,
    sender_streams: usize,
    sender_bytes: usize,
    global_streams: usize,
    global_bytes: usize,
}

impl Default for CarrierLimits {
    fn default() -> Self {
        Self {
            chunk_bytes: STREAM_CHUNK,
            stream_bytes: MAX_CARRIER_STREAM_BYTES,
            stream_chunks: MAX_CARRIER_STREAM_CHUNKS,
            sender_streams: MAX_CARRIER_STREAMS_PER_SENDER,
            sender_bytes: MAX_CARRIER_BYTES_PER_SENDER,
            global_streams: MAX_CARRIER_STREAMS_GLOBAL,
            global_bytes: MAX_CARRIER_BYTES_GLOBAL,
        }
    }
}

#[derive(Default)]
struct CarrierRehydrateState {
    cursor: Option<String>,
    rejected_stream: Option<(PubKeyBytes, StreamId)>,
    cleanup: VecDeque<KvPageRow>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CarrierRehydrateUsage {
    rows: usize,
    bytes: usize,
    pages: usize,
    cleanup_operations: usize,
}

const HPS_SUBSCRIBE_PENDING_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_HPS_SUBSCRIBE_PENDING: usize = 256;
const MAX_HPS_PATH_BYTES: usize = 512;
const MAX_HPS_REPLAYS_PER_TOPIC: usize = 1_024;
const MAX_HPS_REPLAYS_GLOBAL: usize = 4_096;
const MAX_HPS_ACKED: usize = 4_096;
const HPS_REHYDRATE_PAGE: usize = 256;
const MAX_OUTSTANDING_REQUESTS: usize = 256;
const MAX_DURABLE_RESPONSES: usize = 256;
const MAX_DURABLE_HPS_MESSAGES: usize = 256;
const DURABLE_HOST_DELIVERY_TTL_MS: u64 = MAX_SEEN_LIFETIME_MS;

type HpsReplayTable = HashMap<([u8; 16], u32), Vec<(BundleId, u64)>>;

#[derive(Clone, Copy, Serialize, Deserialize)]
struct PendingHpsSubscription {
    host: PubKeyBytes,
    expires_at_ms: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedHpsReplay {
    topic_tag: [u8; 16],
    epoch: u32,
    entries: Vec<(BundleId, u64)>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedHpsInbox {
    message: HpsMessage,
    topic_tag: [u8; 16],
    epoch: u32,
    received_at_ms: u64,
    expires_at_ms: u64,
}

/// Reserved content-type for a content-less re-establishment ping sent to heal a desynced
/// ratchet (DESIGN.md §25). The receiver rebuilds the session as a side effect and does not
/// surface it as a user message.
const SESSION_ESTABLISH_CT: &str = "hop.session.establish";

/// A running Hop node, generic over its [`Store`] backend (in-memory by default;
/// `hop-store-sqlite` for persistence).
pub struct Node<S: Store = MemoryStore> {
    identity: Identity,
    pub store: S,
    router: SprayAndWait,
    pub directory: Directory,
    now_ms: u64,
    /// A non-zero host clock has been supplied. Response-bearing requests are refused before this
    /// anchor because their durable authorization expiry must never be based on the zero origin.
    clock_anchored: bool,
    /// Last time we re-gossiped adverts to all live links (so prekeys/presence propagate over
    /// STABLE links, not just at link-up — see the re-gossip in `tick`).
    last_regossip_ms: u64,
    /// Last time we emitted our §39 P4 receiver-beacon (re-emitted on [`RECV_BEACON_REFRESH_MS`]).
    last_recv_beacon_ms: u64,
    /// "Route-to-me" mode: emit a receiver-beacon so private bundles route to us via the gradient.
    /// Default on (the common case — be reachable); a max-privacy passive recipient sets it off and
    /// only recognizes what floods past, advertising no linkable mailbox handle (DESIGN.md §39).
    route_to_me: bool,
    links: HashMap<LinkId, LinkState>,
    /// Per-peer gossip dedup, preserved across link flaps so a reconnect doesn't re-flood the directory.
    peer_sent: HashMap<PubKeyBytes, PeerSent>,
    outgoing: Vec<(LinkId, Vec<u8>)>,
    /// Legacy raw-bundle view used by core tests. Public hosts poll [`Self::inbox_items`] instead.
    inbox: Vec<Bundle>,
    /// Decrypted messages durably staged before host delivery, keyed by their stable bundle id.
    durable_inbox: HashMap<BundleId, InboxItem>,
    inbox_order: Vec<BundleId>,
    /// Receiver-only dedup, separate from relay `Store::seen` so an unrecognized private-header
    /// chimera cannot suppress the genuine copy. The retained acknowledgement enables safe re-ACK.
    receiver_seen: HashMap<BundleId, ReceiverSeen>,
    /// Locally-originated bundles awaiting an ACK, retransmitted until acked/expired.
    pending: HashMap<BundleId, PendingTx>,
    retx_interval_ms: u64,
    /// Monotonic sequence for our own published adverts (supersession, §16).
    advert_seq: u64,
    /// Delivery status for messages we originated (Sending/Sent N/Delivered).
    tx: HashMap<BundleId, TxInfo>,
    /// Insertion order of relayed (not-ours) bundles, for capacity eviction.
    relay_order: Vec<BundleId>,
    max_relayed: usize,
    /// First time we relayed each not-ours bundle to a peer (custody policy, §6): eviction
    /// prefers bundles we've already handed off and held past [`EVICT_GRACE_MS`].
    relay_fwd: HashMap<BundleId, u64>,
    /// Our current signed prekey (published so peers can open sessions to us).
    prekey: SignedPreKey,
    /// The epoch our current `prekey` was derived for (core-03). Rotated in `tick` when the clock
    /// crosses into a new [`PREKEY_EPOCH_MS`] window.
    prekey_epoch: u64,
    /// Retained prekey secrets by public, so late session inits still resolve, including a bounded
    /// window of PAST epochs' secrets across a rotation (core-03).
    spk_secrets: HashMap<XPubKeyBytes, zeroize::Zeroizing<[u8; 32]>>,
    /// Per-link fixed-window counter for inbound §39 private-bundle rate limiting (F-07):
    /// `link → (window_start_ms, count)`. Bounds an unsigned-bundle flood per peer.
    priv_ingest: HashMap<LinkId, (u64, u32)>,
    /// Signature-verification admission, bounded per link and globally so fresh Sybil identities
    /// cannot multiply expensive advert work without bound.
    advert_ingest: HashMap<LinkId, (u64, u32)>,
    advert_ingest_global: (u64, u32),
    /// §39 P4 soft-state routing gradient: mailbox-tag → the next hop *toward* that recipient.
    /// Laid by recipients' signed [`AdvertKind::RecvBeacon`]s as they flood a few hops; a node
    /// then forwards a matching **private** bundle down `inbound` instead of blind-flooding. Soft
    /// state — pruned by `expires_at` in [`Node::tick`], superseded by a fresher/closer beacon,
    /// capped at [`MAX_RECV_GRADIENT`]. Empty ⇒ flood fallback (the privacy floor / cold start).
    recv_gradient: HashMap<Tag, GradientEntry>,
    /// §39 P5: mailbox-tags whose recipient just (re)beaconed here — i.e. a want-beacon. The host
    /// drains these via [`take_wanted_mailboxes`] and reloads that mailbox's durable blind spool, so
    /// an offline-deposited private bundle is pulled the moment the recipient comes back. Bounded.
    wanted_mailboxes: Vec<Tag>,
    /// Forward-secret sessions, by peer address (DESIGN.md §25).
    sessions: HashMap<PubKeyBytes, PeerSession>,
    /// Last time (ms) each session was used or (re)established. Sessions idle past
    /// [`SESSION_MAX_IDLE_MS`] are GC'd in [`Node::tick`] so `session/` doesn't leak entries for
    /// peers we never talk to again (a slow storage growth). Restored sessions are anchored on their
    /// first real tick because this timestamp is intentionally not part of persisted PeerSession.
    session_touch: HashMap<PubKeyBytes, u64>,
    /// Restored sessions have no persisted last-use timestamp. Anchor these to the first real tick
    /// before idle GC so an epoch-scale clock does not immediately reap every restored ratchet.
    unanchored_sessions: HashSet<PubKeyBytes>,
    /// Bundle ids we've been "vaccinated" against by a passing delivery ACK — we
    /// drop them on sight so a delivered message stops propagating (epidemic
    /// recovery, DESIGN.md §6). Pruned by age in [`Node::tick`].
    immune: HashMap<BundleId, u64>,
    /// core-protocol-r12-01 (§39 recognition-header chimera): ids of private bundles we've RECOGNIZED
    /// and delivered/handled, so delivery-once is decided HERE rather than off `store.seen`. The private
    /// id binds only the sealed payload (`compute_private_id` excludes the recognition header), so a
    /// verify()-passing same-id chimera with a corrupted header is never recognized — yet it still marks
    /// `store.seen` on the relay/flood path. Gating first-delivery on `seen` therefore let such a chimera
    /// suppress the genuine copy's `inbox.push` (silent loss) and fire a false "Delivered" ACK. Only a
    /// recognized-for-us bundle ever enters this set, so a chimera cannot poison it and it is not
    /// attacker-floodable. Pruned in [`Node::tick`] once `store.seen` lapses (same dedup window), so a
    /// still-live duplicate is deduped but an expired id can't pin the set open.
    delivered_private: HashSet<BundleId>,
    /// core-protocol-r3-02: delivery-vaccine tokens we saw BEFORE the target bundle they clear
    /// arrived here (the vaccine's `resolve_vaccine_target` scan found no held match at the time).
    /// Kept so that a later-arriving target private bundle is purged on FIRST STORE by the vaccine
    /// that raced ahead of it, instead of lingering until its (clamped) TTL. A token is a recipient's
    /// CDH value; a forged/foreign token matches no real bundle, so remembering it is harmless. Value
    /// is the insert time (ms); pruned by age in [`Node::tick`] on the same 1h horizon as `immune`,
    /// and capped at [`MAX_SEEN_VACCINE_TOKENS`] (oldest-evicted) so a distinct-token flood can't grow
    /// it without bound.
    seen_vaccine_tokens: HashMap<[u8; 32], u64>,
    /// Observability: when `observe` is on, each bundle sent over a link
    /// is recorded as (link, bundle_id, is_final_delivery), drained via [`Node::drain_transfers`].
    /// Never enabled in production; zero cost when off.
    observe: bool,
    transfers: Vec<(LinkId, BundleId, bool)>,
    sends_delivered: Vec<BundleId>,
    default_lifetime_ms: u32,
    beaconed_tick: bool,
    app_queue_limits: AppQueueLimits,
    app_queue_usage: AppQueueUsage,
    app_payload_policy: AppPayloadPolicy,
    pending_app_deliveries: HashMap<BundleId, PendingAppDelivery>,
    durable_inbox_charges: HashMap<BundleId, AppQueueCharge>,
    /// Egress HTTP requests addressed to us (as a gateway) awaiting fulfillment (§9).
    http_requests: Vec<HttpReqItem>,
    /// HTTP responses sealed back to us (as a requester).
    http_responses: Vec<HttpRespItem>,
    http_response_expires: HashMap<BundleId, u64>,
    http_response_charges: HashMap<BundleId, AppQueueCharge>,
    /// Outbound HTTP/service request id to the only authenticated signer and response kind allowed
    /// to complete it. Persisted independently of the request bundle for restart-safe authorization.
    outstanding_requests: HashMap<BundleId, OutstandingRequest>,
    /// Restored authorizations remain unusable until a real tick validates their absolute expiry.
    unanchored_outstanding_requests: HashSet<BundleId>,
    /// Learned reachability per endpoint, from observed deliveries (DESIGN.md §27):
    /// orders transmissions (best first) and eviction (flush unknown-dst first).
    routes: RouteTable,
    /// Device-addressed bundles we've forwarded/originated, `id → (src, dst, at)`. A
    /// returning delivery-ACK for one of these means we're on its path → learn the
    /// route. Bounded; pruned by age in [`Node::tick`].
    forwarded: HashMap<BundleId, (PubKeyBytes, PubKeyBytes, u64)>,
    /// This node's app key material (DESIGN.md §32): the public [`AppId`] stamped on hps
    /// adverts/handshakes, plus the secret-derived discovery/MAC keys that isolate this app's
    /// `hps://` channels from other apps. Set by the embedding app via [`Node::set_app_keys`].
    /// Defaults to the open fabric. Deliberately separate from [`Self::trace_app`] so enabling
    /// hps isolation doesn't reveal the app on every forwarded hop.
    app: AppKeys,
    /// The app label stamped into trace hops (DESIGN.md §27). Devices leave this at the generic
    /// [`FABRIC_APP`] (they show as "device"); only infra relays set it (to [`crate::relay_app_id`])
    /// so a relay hop reads "Hop Relay". Set via [`Node::set_app`].
    trace_app: AppId,
    /// This node's display name, returned by the built-in `hop.identify` service
    /// (DESIGN.md §29). `None` by default (a device) → callers show the short address;
    /// a relay sets it to its region domain.
    name: Option<String>,
    /// What kind of node this is, returned by `hop.identify`. Defaults to `Device`.
    kind: NodeKind,
    /// Egress service requests addressed to us that the app must fulfill (custom,
    /// non-`hop.` services). Built-in services are answered by the node itself.
    service_requests: Vec<ServiceReqItem>,
    /// Service responses sealed back to us as a caller.
    service_responses: Vec<ServiceRespItem>,
    /// Telemetry batches received via `hop.telemetry` (OTel-over-Hop, §40), decoded + bounded, for
    /// the embedding collector to drain and forward.
    telemetry_in: Vec<TelemetryIn>,
    telemetry_charges: Vec<AppQueueCharge>,
    service_response_expires: HashMap<BundleId, u64>,
    service_response_charges: HashMap<BundleId, AppQueueCharge>,
    /// In-progress inbound carrier-stream reassembly, keyed by `(sender, stream_id)` (§20).
    incoming_streams: HashMap<(PubKeyBytes, StreamId), IncomingStream>,
    incoming_stream_bytes: usize,
    incoming_sender_usage: HashMap<PubKeyBytes, IncomingStreamUsage>,
    carrier_limits: CarrierLimits,
    /// Startup carrier rows are scanned and cleaned in bounded rounds. While this is present, live
    /// carrier admission fails closed and tick maintenance resumes from the retained cursor.
    carrier_rehydrate: Option<CarrierRehydrateState>,
    carrier_rehydrate_usage: CarrierRehydrateUsage,
    /// Monotonic counter for our outbound stream ids.
    stream_seq: u64,
    /// Delivery-ACKs we originated, → the distinct peers we've handed each to. The ACK
    /// keeps riding to new contacts until it reaches [`ACK_REPLICATION_TARGET`] peers,
    /// then stops (DESIGN.md §7).
    ack_replicate: HashMap<BundleId, HashSet<PubKeyBytes>>,
    /// Last time we emitted a delivery-ACK for a given delivered message id — throttles
    /// re-ACKs so duplicate floods can't cause an ACK storm.
    last_ack: HashMap<BundleId, u64>,
    /// Carrier chunk id → the original message id it carries (DESIGN.md §20). Lets a chunked
    /// message report real relay progress ("Sent N") and ownership under its *original* id,
    /// even though the bytes travel as separate carrier bundles.
    carrier_owner: HashMap<BundleId, BundleId>,
    /// Exact reconstructed originals retained outside the forwarding queue until their own ACK arrives.
    outgoing_carriers: HashMap<BundleId, OutgoingCarrier>,
    /// Content awaiting a forward-secret session (DESIGN.md §25): device-to-device content is
    /// **never** static-sealed — if we don't yet hold the peer's prekey it's queued here and
    /// sent the moment one arrives, so every content message is ratcheted (always a 🔒).
    pending_content: Vec<PendingContent>,
    /// Real bundle id → the UI-facing id it should report under, for content that was deferred
    /// (and whose eventual ratcheted bundle has a different id than the handle we returned).
    tx_alias: HashMap<BundleId, BundleId>,
    /// Monotonic counter making each deferred-content handle id unique.
    pending_seq: u64,
    /// Last time we asked a peer to reset a desynced session — throttles reset requests so a
    /// burst of undecryptable messages can't cause a reset storm (DESIGN.md §25).
    last_reset_req: HashMap<PubKeyBytes, u64>,
    /// Whether this node can reach the public internet (and thus public DNS). Any node with
    /// this set resolves HNS itself — no relay round-trip required (DESIGN.md §30). Off by
    /// default; a relay or an internet-connected phone turns it on.
    internet: bool,
    /// HNS resolution cache: `domain → (address?, expires_at_ms)`. `None` is a negative
    /// (NXDOMAIN-like) cache entry. Honors the DNS TTL and propagates like a DNS resolver.
    hns_cache: HashMap<String, HnsEntry>,
    /// Domains we need the host to look up in real DNS (drained by [`Node::take_dns_lookups`]),
    /// with the in-flight set so we ask for each only once.
    dns_lookups: Vec<String>,
    dns_lookup_charges: Vec<AppQueueCharge>,
    dns_inflight: HashSet<String>,
    /// Completed HNS resolutions for the app to consume ([`Node::take_hns_results`]).
    hns_results: Vec<HnsResult>,
    hns_result_charges: Vec<AppQueueCharge>,
    /// Domains we're still trying to resolve (DESIGN.md §30). Resolution is delay-tolerant:
    /// if no internet/peer can answer right now, the domain stays here and is re-attempted as
    /// peers connect, when we gain internet, and periodically — until it resolves or the caller
    /// stops caring. Cleared once a record (positive or negative) arrives.
    pending_resolves: HashSet<String>,
    /// Last time we re-attempted pending resolutions, to throttle the periodic retry.
    last_resolve_retry_ms: u64,
    /// `hps://` topics we host, by path → keys (DESIGN.md §32).
    services: HashMap<String, hps::ServiceConfig>,
    /// `hps://` topics we've subscribed to, by path → the keys we were handed.
    subscriptions: HashMap<String, HpsSubscription>,
    /// Join/invite handshakes awaiting HpsKeys, by path to the exact host allowed to send them.
    hps_subscribe_pending: HashMap<String, PendingHpsSubscription>,
    /// Restored expectations are held but cannot authorize keys before the first real clock tick.
    unanchored_hps_subscribe_pending: HashSet<String>,
    /// Received, decrypted, sender-verified pub/sub messages for the app to drain.
    hps_inbox: Vec<HpsMessage>,
    hps_inbox_charges: Vec<AppQueueCharge>,
    hps_inbox_expires: HashMap<BundleId, u64>,
    /// Pending join requests for RequestToJoin topics we host: path → requester addresses.
    hps_pending: HashMap<String, Vec<PubKeyBytes>>,
    /// Invites we (host) have sent and await acceptance: (path, dest) → sent_at.
    hps_invites_out: HashMap<(String, PubKeyBytes), u64>,
    /// Invites we (member) have received and not yet accepted.
    hps_invites_in: Vec<HpsInviteItem>,
    hps_invite_charges: Vec<AppQueueCharge>,
    /// Reach tally for topics we host: path → unique acking addresses (current epoch).
    hps_reach: HashMap<String, std::collections::HashSet<PubKeyBytes>>,
    /// Retained-member set for rekey: path → member addresses (joins/approvals/invites/acks).
    hps_members: HashMap<String, std::collections::HashSet<PubKeyBytes>>,
    /// Live discovery advert id per hosted Discoverable path (for tombstoning on rekey).
    hps_adverts: HashMap<String, crate::discover::AdvertId>,
    /// (topic_tag, epoch) we've already reach-acked, with a bounded receiver-anchored expiry.
    hps_acked: HashMap<([u8; 16], u32), u64>,
    /// Authenticated publication content ids accepted per topic generation. This survives global
    /// bundle-dedup churn and restart, so rewrapping a signed publication in a fresh outer bundle id
    /// cannot replay it to the app.
    hps_replays: HpsReplayTable,
    /// Persisted records that failed to decode on the last [`Node::rehydrate`] (F-03). A
    /// non-empty report means an upgrade changed a struct's postcard layout and silently
    /// dropped state (this ate the deferred-send queue when `PendingContent` gained a field —
    /// commit 6bb5739). The host drains it via [`Node::take_rehydrate_report`] and surfaces it
    /// so a silent state wipe is observable instead of invisible.
    rehydrate_report: RehydrateReport,
    /// §35: the tenant cert + key this node stamps its originated bundles with (`None` on
    /// pure-P2P nodes). Applied in [`Node::submit`], the single origination choke point.
    stamper: Option<Stamper>,
    /// §35: admission policy for foreign bundles. `Open` (the default) preserves the
    /// pre-stamp behavior everywhere; a hosted relay sets `Keyed` to require stamps and meter.
    access_policy: AccessPolicy,
    /// §35 metering atoms per tenant, accumulated when delivery is PROVEN (via
    /// [`Node::meter_delivered`]) and drained by the host's flush loop via [`Node::take_usage`].
    /// Bounded by [`MAX_METERED_TENANTS`].
    usage: HashMap<TenantId, Usage>,
    /// §35 delivery-justified metering: the tenant + sealed bytes VERIFIED when we took custody of
    /// a foreign bundle, held until we either see proof of delivery (bill it, [`meter_delivered`])
    /// or drop it undelivered (evicted/expired: never billed as carriage, `tick` prunes these).
    /// Verifying at admit and carrying the result here means a delay-tolerant bundle delivered
    /// after its stamp epoch has rolled still bills correctly, and the mutable stamp is never
    /// re-read at delivery. Bounded by [`MAX_METERED_ATTRIBUTION`].
    metered_attribution: HashMap<BundleId, (TenantId, u64)>,
    /// Foreign bundles refused by the `Keyed` policy since the host last drained
    /// [`Node::take_access_refused`]. Observability only (netlog_private), never per-bundle.
    access_refused: u64,
    /// Accepted bundles NOT metered because the per-flush tenant map was at
    /// [`MAX_METERED_TENANTS`]. Carried but unattributed = lost revenue; surfaced via
    /// [`Node::take_usage_dropped`] so overflow is never silent.
    usage_dropped: u64,
    /// §35 custody beacon: whether this node advertises a `Wire::Have` on connect. Off by default
    /// (devices should not burn a constrained BLE link with a full held set); relays turn it on.
    emit_have: bool,
}

/// A tally of persisted records that failed to decode on startup, per kind. Empty is the
/// healthy case. See [`Node::rehydrate`] and F-03.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RehydrateReport {
    /// `(kind, count)` pairs — e.g. `("session", 3)` means three ratchet sessions could not
    /// be decoded (a field was added to `PeerSession` across an upgrade) and were dropped.
    pub dropped: Vec<(&'static str, u32)>,
}

impl RehydrateReport {
    fn note(&mut self, kind: &'static str) {
        match self.dropped.iter_mut().find(|(k, _)| *k == kind) {
            Some(e) => e.1 += 1,
            None => self.dropped.push((kind, 1)),
        }
    }
    /// Total records dropped across all kinds. `0` on a clean upgrade.
    pub fn total(&self) -> u32 {
        self.dropped.iter().map(|(_, n)| n).sum()
    }
    /// True when no persisted record failed to decode.
    pub fn is_empty(&self) -> bool {
        self.dropped.is_empty()
    }
}

/// What we keep for a subscribed `hps://` topic: the content key, plus (for a service) the
/// service public key to verify broadcasts against — `None` means a channel (verify each post
/// against its sender's own address).
#[derive(Clone, Serialize, Deserialize)]
pub struct HpsSubscription {
    pub content_key: [u8; 32],
    pub service_pubkey: Option<[u8; 32]>,
    /// The topic's host node — needed to re-resolve for reach acks, leave, and rekey.
    pub host: PubKeyBytes,
    /// Rekey generation we currently hold; a higher-epoch HpsRekey supersedes it.
    pub epoch: u32,
    /// Opaque per-topic tag (matches `HpsPublish.topic_tag`); precomputed for fast routing.
    pub topic_tag: [u8; 16],
}

/// A received `hps://` message, after decryption + sender verification.
#[derive(Clone, Serialize, Deserialize)]
pub struct HpsMessage {
    /// Stable authenticated publication id used for host deduplication and explicit acceptance.
    pub id: BundleId,
    pub path: String,
    pub sender: PubKeyBytes,
    pub body: Vec<u8>,
}

/// An invite we (member) have received and may accept (DESIGN.md §32 Invite mode).
#[derive(Clone)]
pub struct HpsInviteItem {
    pub path: String,
    pub host: PubKeyBytes,
    pub kind: hps::ServiceKind,
}

/// A topic we host or follow — used to rebuild the app's channel list after a restart (the
/// node persists topics; the app's in-memory list does not).
#[derive(Clone)]
pub struct HpsTopicState {
    pub host: PubKeyBytes,
    pub path: String,
    pub kind: hps::ServiceKind,
    pub hosting: bool,
    pub access: hps::AccessMode,
}

impl Node<MemoryStore> {
    /// Create a node with an in-memory store.
    pub fn new(identity: Identity) -> Self {
        Self::with_store(identity, MemoryStore::new())
    }

    /// Construct a node from previously-saved identity secret bytes (see
    /// [`crate::crypto::Identity::to_secret_bytes`]) so the address is stable across
    /// restarts. Falls back to a fresh identity if the bytes are the wrong length.
    pub fn from_identity_secret(secret: &[u8]) -> Self {
        let identity = match <[u8; 32]>::try_from(secret) {
            Ok(b) => Identity::from_secret_bytes(&b),
            Err(_) => Identity::generate(),
        };
        Self::with_store(identity, MemoryStore::new())
    }

    /// Test-only: snapshot this node's store (bundles + persisted KV) so a test can simulate
    /// a process restart / beacon-mode relaunch by rebuilding a node from the same store.
    #[cfg(test)]
    fn clone_store(&self) -> MemoryStore {
        self.store.clone()
    }

    /// Test-only: the currently-published prekey public (core-03 rotation observability).
    #[cfg(test)]
    fn current_prekey_public(&self) -> XPubKeyBytes {
        self.prekey.public
    }

    /// Test-only: do we still hold the secret for prekey public `pk`? (core-03 retention window.)
    #[cfg(test)]
    fn holds_prekey_secret(&self, pk: &XPubKeyBytes) -> bool {
        self.spk_secrets.contains_key(pk)
    }
}

impl<S: Store> Node<S> {
    /// Create a node with an explicit store backend (e.g. a persistent one).
    pub fn with_store(identity: Identity, store: S) -> Self {
        // Deterministic so it survives restarts (peers cache our prekey advert).
        let prekey = identity.derive_prekey();
        let mut spk_secrets = HashMap::new();
        spk_secrets.insert(
            prekey.public,
            zeroize::Zeroizing::new(prekey.secret_bytes()),
        );
        let mut node = Self {
            identity,
            store,
            router: SprayAndWait::new(),
            directory: Directory::new(),
            now_ms: 0,
            clock_anchored: false,
            last_regossip_ms: 0,
            last_recv_beacon_ms: 0,
            route_to_me: true,
            links: HashMap::new(),
            peer_sent: HashMap::new(),
            outgoing: Vec::new(),
            inbox: Vec::new(),
            durable_inbox: HashMap::new(),
            inbox_order: Vec::new(),
            receiver_seen: HashMap::new(),
            pending: HashMap::new(),
            retx_interval_ms: DEFAULT_RETX_INTERVAL_MS,
            advert_seq: 0,
            tx: HashMap::new(),
            relay_order: Vec::new(),
            max_relayed: DEFAULT_MAX_RELAYED,
            relay_fwd: HashMap::new(),
            prekey,
            prekey_epoch: 0,
            spk_secrets,
            recv_gradient: HashMap::new(),
            wanted_mailboxes: Vec::new(),
            sessions: HashMap::new(),
            session_touch: HashMap::new(),
            unanchored_sessions: HashSet::new(),
            immune: HashMap::new(),
            delivered_private: HashSet::new(),
            seen_vaccine_tokens: HashMap::new(),
            observe: false,
            transfers: Vec::new(),
            sends_delivered: Vec::new(),
            default_lifetime_ms: BundleOpts::default().lifetime_ms,
            beaconed_tick: false,
            app_queue_limits: AppQueueLimits::default(),
            app_queue_usage: AppQueueUsage::default(),
            app_payload_policy: AppPayloadPolicy::all(),
            pending_app_deliveries: HashMap::new(),
            durable_inbox_charges: HashMap::new(),
            http_requests: Vec::new(),
            http_responses: Vec::new(),
            http_response_expires: HashMap::new(),
            http_response_charges: HashMap::new(),
            outstanding_requests: HashMap::new(),
            unanchored_outstanding_requests: HashSet::new(),
            routes: RouteTable::new(DEFAULT_MAX_ROUTES),
            forwarded: HashMap::new(),
            app: AppKeys::fabric(),
            trace_app: FABRIC_APP,
            name: None,
            kind: NodeKind::Device,
            service_requests: Vec::new(),
            service_responses: Vec::new(),
            telemetry_in: Vec::new(),
            telemetry_charges: Vec::new(),
            service_response_expires: HashMap::new(),
            service_response_charges: HashMap::new(),
            incoming_streams: HashMap::new(),
            incoming_stream_bytes: 0,
            incoming_sender_usage: HashMap::new(),
            carrier_limits: CarrierLimits::default(),
            carrier_rehydrate: Some(CarrierRehydrateState::default()),
            carrier_rehydrate_usage: CarrierRehydrateUsage::default(),
            stream_seq: 0,
            ack_replicate: HashMap::new(),
            last_ack: HashMap::new(),
            carrier_owner: HashMap::new(),
            outgoing_carriers: HashMap::new(),
            pending_content: Vec::new(),
            tx_alias: HashMap::new(),
            pending_seq: 0,
            last_reset_req: HashMap::new(),
            internet: false,
            hns_cache: HashMap::new(),
            dns_lookups: Vec::new(),
            dns_lookup_charges: Vec::new(),
            dns_inflight: HashSet::new(),
            hns_results: Vec::new(),
            hns_result_charges: Vec::new(),
            pending_resolves: HashSet::new(),
            last_resolve_retry_ms: 0,
            services: HashMap::new(),
            subscriptions: HashMap::new(),
            hps_subscribe_pending: HashMap::new(),
            unanchored_hps_subscribe_pending: HashSet::new(),
            hps_inbox: Vec::new(),
            hps_inbox_charges: Vec::new(),
            hps_inbox_expires: HashMap::new(),
            hps_pending: HashMap::new(),
            hps_invites_out: HashMap::new(),
            hps_invites_in: Vec::new(),
            hps_invite_charges: Vec::new(),
            hps_reach: HashMap::new(),
            hps_members: HashMap::new(),
            hps_adverts: HashMap::new(),
            hps_acked: HashMap::new(),
            hps_replays: HashMap::new(),
            priv_ingest: HashMap::new(),
            advert_ingest: HashMap::new(),
            advert_ingest_global: (0, 0),
            rehydrate_report: RehydrateReport::default(),
            stamper: None,
            access_policy: AccessPolicy::Open,
            usage: HashMap::new(),
            metered_attribution: HashMap::new(),
            access_refused: 0,
            usage_dropped: 0,
            emit_have: false,
        };
        node.rehydrate();
        node
    }

    /// Create a node with an explicit store and app key material (DESIGN.md §17, §32). The app
    /// secret isolates this app's `hps://` channels from other apps; see [`AppKeys`].
    pub fn with_store_app(identity: Identity, store: S, app: AppKeys) -> Self {
        let mut node = Self::with_store(identity, store);
        node.set_app_keys(app);
        node
    }

    /// Rebuild in-memory tracking from a (possibly persistent) store on startup, so a
    /// restart resumes cleanly: our own undelivered messages keep retransmitting, and
    /// relayed bundles re-enter the eviction order so the store stays bounded
    /// (DESIGN.md §5, §6). A no-op on an empty (fresh) store.
    fn rehydrate(&mut self) {
        // Restore hosted hps topics (their keys + access/visibility) so they survive a restart
        // (DESIGN.md §32). Re-advertise discoverable ones.
        for (key, bytes) in self.store.list_kv("hps/svc/") {
            let Some(path) = key.strip_prefix("hps/svc/").map(str::to_string) else {
                continue;
            };
            match postcard::from_bytes::<hps::ServiceConfig>(&bytes) {
                Ok(cfg) => {
                    self.services.insert(path, cfg);
                }
                Err(_) => self.rehydrate_report.note("hps/svc"),
            }
        }
        // Restore subscriptions so we keep decrypting topics we follow.
        for (key, bytes) in self.store.list_kv("hps/sub/") {
            let Some(path) = key.strip_prefix("hps/sub/").map(str::to_string) else {
                continue;
            };
            match postcard::from_bytes::<HpsSubscription>(&bytes) {
                Ok(sub) => {
                    self.directory.subscribe(path.clone());
                    self.subscriptions.insert(path, sub);
                }
                Err(_) => self.rehydrate_report.note("hps/sub"),
            }
        }
        // Restore join/invite handshakes that are still waiting for keys. Their absolute expiries are
        // untrusted until the first real tick anchors the clock, so no restored row can authorize keys
        // during startup network processing.
        for (key, bytes) in self.store.list_kv("hps/sub-pending/") {
            let Some(path) = key.strip_prefix("hps/sub-pending/").map(str::to_string) else {
                continue;
            };
            if path.len() > MAX_HPS_PATH_BYTES || self.subscriptions.contains_key(&path) {
                let _ = self.store.remove_kv_critical(&key);
                continue;
            }
            match postcard::from_bytes::<PendingHpsSubscription>(&bytes) {
                Ok(pending) => {
                    self.unanchored_hps_subscribe_pending.insert(path.clone());
                    self.hps_subscribe_pending.insert(path, pending);
                }
                Err(_) => {
                    let _ = self.store.remove_kv_critical(&key);
                    self.rehydrate_report.note("hps/sub-pending");
                }
            }
        }
        let _ = self.enforce_hps_subscribe_pending_limit();
        // Restore pending join requests + the retained-member set for topics we host, so an
        // approval (and a later rekey) still works after a restart (DESIGN.md §32).
        for (key, bytes) in self.store.list_kv("hps/pending/") {
            let Some(path) = key.strip_prefix("hps/pending/").map(str::to_string) else {
                continue;
            };
            if let Ok(q) = postcard::from_bytes::<Vec<PubKeyBytes>>(&bytes) {
                if !q.is_empty() {
                    self.hps_pending.insert(path, q);
                }
            }
        }
        for (key, bytes) in self.store.list_kv("hps/members/") {
            let Some(path) = key.strip_prefix("hps/members/").map(str::to_string) else {
                continue;
            };
            if let Ok(m) = postcard::from_bytes::<Vec<PubKeyBytes>>(&bytes) {
                self.hps_members.insert(path, m.into_iter().collect());
            }
        }
        // Bound the durable inbox before admitting replay rows. Its stable ids must survive replay
        // pressure, or restart could discard an unaccepted message after evicting its replay marker.
        let mut restored_hps = Vec::new();
        let mut inbox_after: Option<String> = None;
        loop {
            let page =
                self.store
                    .list_kv_page("hps/inbox/", inbox_after.as_deref(), HPS_REHYDRATE_PAGE);
            if page.is_empty() {
                break;
            }
            let next = page.last().map(|(key, _)| key.clone());
            let short = page.len() < HPS_REHYDRATE_PAGE;
            for (key, bytes) in page {
                let Ok(inbox) = postcard::from_bytes::<PersistedHpsInbox>(&bytes) else {
                    let _ = self.store.remove_kv_critical(&key);
                    self.rehydrate_report.note("hps/inbox");
                    continue;
                };
                if key != Self::hps_inbox_key(&inbox.message.id) {
                    let _ = self.store.remove_kv_critical(&key);
                    self.rehydrate_report.note("hps/inbox-key");
                    continue;
                }
                if restored_hps.len() < MAX_DURABLE_HPS_MESSAGES {
                    restored_hps.push(inbox);
                    continue;
                }
                let (latest_index, latest_at) = restored_hps
                    .iter()
                    .enumerate()
                    .max_by_key(|(_, item)| item.received_at_ms)
                    .map(|(index, item)| (index, item.received_at_ms))
                    .expect("non-empty bounded HPS inbox");
                if inbox.received_at_ms < latest_at {
                    let evicted = std::mem::replace(&mut restored_hps[latest_index], inbox);
                    let _ = self
                        .store
                        .remove_kv_critical(&Self::hps_inbox_key(&evicted.message.id));
                } else {
                    let _ = self.store.remove_kv_critical(&key);
                }
            }
            if short || next == inbox_after {
                break;
            }
            inbox_after = next;
        }

        let protected_hps: HashSet<(([u8; 16], u32), BundleId)> = restored_hps
            .iter()
            .map(|inbox| ((inbox.topic_tag, inbox.epoch), inbox.message.id))
            .collect();
        let unprotected_budget = MAX_HPS_REPLAYS_GLOBAL.saturating_sub(protected_hps.len());

        // Replay rows are attacker-influenced and partitioned by topic generation. Walk bounded
        // pages and enforce one global budget while admitting them, deleting malformed or excess
        // rows as we go so a restart cannot materialize an unbounded generation table set.
        let mut replay_after: Option<String> = None;
        let mut unprotected_count = 0usize;
        loop {
            let page =
                self.store
                    .list_kv_page("hps/replay/", replay_after.as_deref(), HPS_REHYDRATE_PAGE);
            if page.is_empty() {
                break;
            }
            let next = page.last().map(|(key, _)| key.clone());
            let short = page.len() < HPS_REHYDRATE_PAGE;
            for (key, bytes) in page {
                let Ok(mut replay) = postcard::from_bytes::<PersistedHpsReplay>(&bytes) else {
                    let _ = self.store.remove_kv_critical(&key);
                    self.rehydrate_report.note("hps/replay");
                    continue;
                };
                let topic = (replay.topic_tag, replay.epoch);
                if key != Self::hps_replay_key(&replay.topic_tag, replay.epoch)
                    || self.hps_replays.contains_key(&topic)
                {
                    let _ = self.store.remove_kv_critical(&key);
                    self.rehydrate_report.note("hps/replay-key");
                    continue;
                }

                let original_len = replay.entries.len();
                replay.entries.sort_by_key(|(_, expires_at)| *expires_at);
                let mut ids = HashSet::new();
                replay.entries.retain(|(id, _)| ids.insert(*id));
                let is_protected = |id: &BundleId| protected_hps.contains(&(topic, *id));

                let protected_count = replay
                    .entries
                    .iter()
                    .filter(|(id, _)| is_protected(id))
                    .count();
                let topic_unprotected_budget =
                    MAX_HPS_REPLAYS_PER_TOPIC.saturating_sub(protected_count);
                let topic_unprotected = replay.entries.len().saturating_sub(protected_count);
                let mut drop_unprotected =
                    topic_unprotected.saturating_sub(topic_unprotected_budget);
                replay.entries.retain(|(id, _)| {
                    if drop_unprotected > 0 && !is_protected(id) {
                        drop_unprotected -= 1;
                        false
                    } else {
                        true
                    }
                });

                let remaining = unprotected_budget.saturating_sub(unprotected_count);
                let row_unprotected = replay
                    .entries
                    .iter()
                    .filter(|(id, _)| !is_protected(id))
                    .count();
                let mut drop_unprotected = row_unprotected.saturating_sub(remaining);
                replay.entries.retain(|(id, _)| {
                    if drop_unprotected > 0 && !is_protected(id) {
                        drop_unprotected -= 1;
                        false
                    } else {
                        true
                    }
                });
                if replay.entries.is_empty() {
                    let _ = self.store.remove_kv_critical(&key);
                    continue;
                }
                let normalized = replay.entries.len() != original_len;
                unprotected_count += replay
                    .entries
                    .iter()
                    .filter(|(id, _)| !is_protected(id))
                    .count();
                if normalized {
                    if let Ok(value) = postcard::to_allocvec(&replay) {
                        let _ = self.store.put_kv_critical(&key, value);
                    }
                }
                self.hps_replays.insert(topic, replay.entries);
            }
            if short || next == replay_after {
                break;
            }
            replay_after = next;
        }

        restored_hps.retain(|inbox| {
            let valid = self
                .hps_replays
                .get(&(inbox.topic_tag, inbox.epoch))
                .is_some_and(|entries| entries.iter().any(|(id, _)| *id == inbox.message.id));
            if !valid {
                let _ = self
                    .store
                    .remove_kv_critical(&Self::hps_inbox_key(&inbox.message.id));
                self.rehydrate_report.note("hps/inbox-orphan");
            }
            valid
        });
        restored_hps.sort_by_key(|inbox| inbox.received_at_ms);
        for inbox in restored_hps {
            let message = inbox.message;
            let Some(charge) = self.reserve_app_queue(
                AppQueueKind::HpsMessage,
                Some(message.sender),
                Self::hps_message_bytes(&message),
            ) else {
                continue;
            };
            self.hps_inbox_expires
                .insert(message.id, inbox.expires_at_ms);
            self.hps_inbox.push(message);
            self.hps_inbox_charges.push(charge);
        }
        // Restore received/outstanding invites (§32).
        if let Some(b) = self.store.get_kv("hps/invites_in") {
            if let Ok(v) = postcard::from_bytes::<Vec<(String, PubKeyBytes, bool)>>(&b) {
                for (path, host, channel) in v {
                    let Some(charge) = self.reserve_app_queue(
                        AppQueueKind::HpsInvite,
                        Some(host),
                        path.len().saturating_add(64),
                    ) else {
                        continue;
                    };
                    self.hps_invites_in.push(HpsInviteItem {
                        path,
                        host,
                        kind: if channel {
                            hps::ServiceKind::Channel
                        } else {
                            hps::ServiceKind::Service
                        },
                    });
                    self.hps_invite_charges.push(charge);
                }
            }
        }
        if let Some(b) = self.store.get_kv("hps/invites_out") {
            if let Ok(v) = postcard::from_bytes::<Vec<(String, PubKeyBytes)>>(&b) {
                for k in v {
                    self.hps_invites_out.insert(k, 0);
                }
            }
        }
        if let Some(bytes) = self.store.get_kv("outstanding_requests") {
            match postcard::from_bytes::<Vec<(BundleId, OutstandingRequest)>>(&bytes) {
                Ok(requests) => {
                    for (id, request) in requests.into_iter().take(MAX_OUTSTANDING_REQUESTS) {
                        for custody_id in &request.custody_ids {
                            if custody_id != &id {
                                self.carrier_owner.insert(*custody_id, id);
                            }
                        }
                        self.unanchored_outstanding_requests.insert(id);
                        self.outstanding_requests.insert(id, request);
                    }
                }
                Err(_) => self.rehydrate_report.note("outstanding_requests"),
            }
        }
        for (key, bytes) in self.store.list_kv("carrier-out/") {
            match postcard::from_bytes::<OutgoingCarrier>(&bytes) {
                Ok(carrier) => {
                    let original_id = carrier.original.id();
                    if key != Self::outgoing_carrier_key(&original_id) {
                        self.rehydrate_report.note("carrier-out/key");
                        continue;
                    }
                    for chunk in &carrier.chunks {
                        self.carrier_owner.insert(*chunk, original_id);
                    }
                    self.tx.entry(original_id).or_default();
                    self.outgoing_carriers.insert(original_id, carrier);
                }
                Err(_) => self.rehydrate_report.note("carrier-out"),
            }
        }

        let mut restored_http = Vec::new();
        for (_, bytes) in self.store.list_kv("response/http/") {
            match postcard::from_bytes::<PersistedHttpResponse>(&bytes) {
                Ok(response) => restored_http.push(response),
                Err(_) => self.rehydrate_report.note("response/http"),
            }
        }
        restored_http.sort_by_key(|response| response.received_at_ms);
        for response in restored_http.into_iter().take(MAX_DURABLE_RESPONSES) {
            let item = response.item;
            let Some(charge) = self.reserve_app_queue(
                AppQueueKind::HttpResponse,
                Some(item.from),
                Self::http_response_bytes(&item),
            ) else {
                continue;
            };
            self.http_response_expires
                .insert(item.id, response.expires_at_ms);
            self.http_response_charges.insert(item.id, charge);
            self.http_responses.push(item);
        }

        let mut restored_service = Vec::new();
        for (_, bytes) in self.store.list_kv("response/service/") {
            match postcard::from_bytes::<PersistedServiceResponse>(&bytes) {
                Ok(response) => restored_service.push(response),
                Err(_) => self.rehydrate_report.note("response/service"),
            }
        }
        restored_service.sort_by_key(|response| response.received_at_ms);
        for response in restored_service.into_iter().take(MAX_DURABLE_RESPONSES) {
            let item = response.item;
            let Some(charge) = self.reserve_app_queue(
                AppQueueKind::ServiceResponse,
                Some(item.from),
                Self::service_response_bytes(&item),
            ) else {
                continue;
            };
            self.service_response_expires
                .insert(item.id, response.expires_at_ms);
            self.service_response_charges.insert(item.id, charge);
            self.service_responses.push(item);
        }
        // Restore the deferred-content queue (sent messages awaiting a prekey, §25).
        if let Some(b) = self.store.get_kv("pending_content") {
            match postcard::from_bytes::<Vec<PendingContent>>(&b) {
                Ok(v) => {
                    for pc in &v {
                        self.tx.entry(pc.display_id).or_default();
                    } // still "Sending…"
                    self.pending_content = v;
                }
                // A layout change silently ate the queue before F-03; now it is counted so the
                // host can surface "N queued sends were lost across an upgrade".
                Err(_) => self.rehydrate_report.note("pending_content"),
            }
        }

        // Restore forward-secret sessions so a restart / beacon-mode relaunch resumes the
        // ratchet instead of desyncing the peer (DESIGN.md §25). A dropped session here is the
        // "Securing forever" class — count it loudly rather than desyncing the peer in silence.
        for (key, bytes) in self.store.list_kv("session/") {
            let Some(b58) = key.strip_prefix("session/") else {
                continue;
            };
            let Ok(addr_vec) = bs58::decode(b58).into_vec() else {
                continue;
            };
            let Ok(addr) = <PubKeyBytes>::try_from(addr_vec.as_slice()) else {
                continue;
            };
            match postcard::from_bytes::<PeerSession>(&bytes) {
                Ok(ps) => {
                    self.sessions.insert(addr, ps);
                    self.unanchored_sessions.insert(addr);
                }
                Err(_) => self.rehydrate_report.note("session"),
            }
        }

        // Restore receiver-only dedup before the decrypted inbox. The two records and any receive
        // session advance were committed in one Store batch, so a valid inbox row always has its
        // matching seen row and can be redelivered without touching the ratchet.
        for (_, bytes) in self.store.list_kv("inbox-seen/") {
            match postcard::from_bytes::<(BundleId, ReceiverSeen)>(&bytes) {
                Ok((id, seen)) => {
                    self.receiver_seen.insert(id, seen);
                }
                Err(_) => self.rehydrate_report.note("inbox-seen"),
            }
        }
        let mut restored_inbox = Vec::new();
        for (_, bytes) in self.store.list_kv("inbox/") {
            match postcard::from_bytes::<InboxItem>(&bytes) {
                Ok(item) if self.receiver_seen.contains_key(&item.id) => restored_inbox.push(item),
                Ok(_) => self.rehydrate_report.note("inbox/orphan"),
                Err(_) => self.rehydrate_report.note("inbox"),
            }
        }
        restored_inbox.sort_by(|a, b| {
            a.received_at
                .cmp(&b.received_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        for item in restored_inbox {
            let wire_bytes = item
                .original
                .to_bytes()
                .map(|bytes| bytes.len())
                .unwrap_or(0);
            let Some(charge) = self.reserve_app_queue(
                AppQueueKind::PeerInbox,
                Some(item.from),
                Self::inbox_item_bytes(&item).saturating_add(wire_bytes),
            ) else {
                // Keep the durable row untouched. It was never ACKed and remains recoverable from the
                // store; only the bounded in-memory working set is withheld under pressure.
                continue;
            };
            self.inbox.push(item.original.clone());
            self.inbox_order.push(item.id);
            self.durable_inbox_charges.insert(item.id, charge);
            self.durable_inbox.insert(item.id, item);
        }

        // Re-feed persisted carrier chunks in one bounded startup round. If the namespace is larger
        // or cleanup fails, tick maintenance resumes from the retained cursor and live carrier work
        // remains closed until every examined rejection is durably removed.
        let _ = self.continue_carrier_rehydrate();

        let me = self.address();
        for id in self.store.have().ids {
            let Some(mut b) = self.store.get(&id) else {
                continue;
            };
            if b.is_private() && !b.env.trace.is_empty() {
                b.env.trace.clear();
                self.store.remove(&id);
                self.store.rehydrate(b.clone(), self.now_ms);
            }
            if b.inner.src == me && !b.inner.flags.is_ack {
                // Our own message that wasn't yet ACKed (delivered ones were purged).
                let display = self.carrier_owner.get(&id).copied().unwrap_or(id);
                self.tx.entry(display).or_default();
                if b.inner.flags.request_ack {
                    self.pending.insert(
                        id,
                        PendingTx {
                            copies: b.env.copies,
                            created_at: b.inner.created_at,
                            lifetime_ms: b.inner.lifetime_ms,
                            next_retx_at: 0, // re-offer on the next tick
                            retx_interval: self.retx_interval_ms,
                        },
                    );
                }
            } else {
                self.relay_order.push(id); // relayed: subject to eviction bound
            }
        }
        self.evict_relayed_if_needed();
    }

    /// Export this node's identity secret so it can be persisted and restored.
    pub fn identity_secret(&self) -> [u8; 32] {
        self.identity.to_secret_bytes()
    }

    pub fn address(&self) -> PubKeyBytes {
        self.identity.address()
    }

    /// Advance the node's advisory clock (used for advert expiry/discovery).
    pub fn set_time(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        self.clock_anchored |= now_ms != 0;
    }

    /// The node's current clock (last value passed to [`tick`](Self::tick) or
    /// [`set_time`](Self::set_time)).
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// Whether persisted carrier admission and required cleanup have reached a safe startup state.
    /// Live carrier chunks fail closed while this is false.
    pub fn carrier_startup_ready(&self) -> bool {
        self.carrier_rehydrate.is_none()
    }

    /// Raise (or lower) the learned-route table capacity (DESIGN.md §27). Cloud nodes
    /// set this high to become the long-memory backbone; mobile nodes keep the default.
    pub fn set_route_capacity(&mut self, cap: usize) {
        self.routes.set_capacity(cap);
    }

    /// Set the relayed-bundle custody window (`max_relayed`). With the forward-before-evict
    /// policy this is a *sliding window* of concurrent custody, not a transfer-size limit,
    /// so a cloud relay can run a large window for many in-flight chunked transfers.
    pub fn set_max_relayed(&mut self, cap: usize) {
        self.max_relayed = cap;
        self.evict_relayed_if_needed();
    }

    /// Set the app id this node **publicly stamps** into each trace hop (DESIGN.md §27).
    ///
    /// Privacy: this advertises "this node carries app X" to every relay on the path,
    /// so ONLY public infra nodes should set it — a relay sets [`crate::relay_app_id`]
    /// to show as "Hop Relay". **End-user devices must leave this at [`FABRIC_APP`]**
    /// (the default) so they never advertise which app they run. (The FFI deliberately
    /// exposes no setter for this.)
    pub fn set_app(&mut self, app: AppId) {
        self.trace_app = app; // trace-hop label only (relay self-identifies); not an hps app
    }

    /// Set this node's full app key material from its 32-byte secret (DESIGN.md §17, §32). The
    /// embedding app calls this so its `hps://` channels/services are isolated from other apps:
    /// only same-secret peers can discover, join, or be invited to them. The secret is never
    /// persisted by core — pass it every launch (like the identity seed). Trace-hop labeling is
    /// unaffected (devices still show as generic "device", §27).
    pub fn set_app_keys(&mut self, keys: AppKeys) {
        self.directory.set_app(keys.id);
        self.app = keys;
    }

    /// Decayed learned reachability toward `dst` (0.0 if no route is known). Higher
    /// means this node is a better path to `dst` right now.
    pub fn route_utility(&self, dst: &PubKeyBytes) -> f64 {
        self.routes.utility(dst, self.now_ms)
    }

    /// Whether this node has learned any live route toward `dst`.
    pub fn knows_route(&self, dst: &PubKeyBytes) -> bool {
        self.routes.knows(dst, self.now_ms)
    }

    /// Subscribe the local directory to a service topic.
    pub fn subscribe(&mut self, topic: impl Into<String>) {
        self.directory.subscribe(topic);
    }

    /// §35: configure the tenant cert + key this node stamps its originated bundles with.
    /// `None` (the default) originates unstamped bundles: full pure-P2P function, but keyed
    /// relays will refuse them custody. Configured once per app/account; [`Node::submit`]
    /// then stamps everything this node originates, ACKs and control bundles included, so
    /// the return path is admissible at keyed relays too.
    pub fn set_stamper(&mut self, stamper: Option<Stamper>) {
        self.stamper = stamper;
    }

    /// §35: set the admission policy for foreign (not-ours) bundles. `Open` (the default)
    /// takes custody of any verifiable bundle, unmetered, on every device and open relay.
    /// A hosted relay sets `Keyed` to require a valid carriage stamp and meter per tenant.
    pub fn set_access_policy(&mut self, policy: AccessPolicy) {
        self.access_policy = policy;
    }

    /// The current §35 admission policy (hosts assert their configuration wired through).
    pub fn access_policy(&self) -> &AccessPolicy {
        &self.access_policy
    }

    /// Refresh the keyed-access epoch tables against the node's clock, now. A keyed host calls
    /// this once after configuring the policy and seeding the clock, so the first bundle that
    /// arrives before the first tick is admitted; thereafter [`Node::tick`] keeps them current.
    pub fn refresh_access(&mut self) {
        self.access_policy.refresh(self.now_ms);
    }

    /// §35: enable the custody beacon (advertise a `Wire::Have` on connect so peers stop
    /// re-offering bundles we already hold). Relays turn this on; devices leave it off to spare a
    /// constrained BLE link.
    pub fn set_emit_have(&mut self, on: bool) {
        self.emit_have = on;
    }

    /// Test-only: the ids a peer told us (via `Wire::Have`) it already holds on `link`.
    #[cfg(test)]
    fn link_peer_has(&self, link: LinkId) -> Vec<BundleId> {
        match self.links.get(&link) {
            Some(LinkState::Up(est)) => est.peer_has.iter().copied().collect(),
            _ => Vec::new(),
        }
    }

    /// Drain the §35 per-tenant usage accumulated at the custody choke point since the last
    /// call. The host's flush loop merges these into its durable ledger (§37); draining here
    /// keeps the in-memory map bounded and makes a host crash lose at most one interval.
    pub fn take_usage(&mut self) -> Vec<(TenantId, Usage)> {
        self.usage.drain().collect()
    }

    /// Drain the count of foreign bundles the `Keyed` policy refused since the last call.
    /// Aggregate observability for the host's private log, never a per-bundle event.
    pub fn take_access_refused(&mut self) -> u64 {
        std::mem::take(&mut self.access_refused)
    }

    /// Drain the count of accepted-but-unmetered bundles (tenant-map overflow) since the last
    /// call. Nonzero means the flush interval is too long for the tenant cardinality.
    pub fn take_usage_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.usage_dropped)
    }

    /// §35 delivery-justified billing: bill the tenant we recorded (verified) when we took custody
    /// of `id`, because its delivery is now PROVEN (an ACK or §39 vaccine cleared our held copy).
    /// Idempotent: the attribution is removed, so a re-flooded proof cannot double-charge, and a
    /// bundle we never metered (Open policy, our own send, or already billed) is a no-op.
    fn meter_delivered(&mut self, id: &BundleId) {
        if let Some((tenant, bytes)) = self.metered_attribution.remove(id) {
            if self.usage.len() < MAX_METERED_TENANTS || self.usage.contains_key(&tenant) {
                let u = self.usage.entry(tenant).or_default();
                u.bundles = u.bundles.saturating_add(1);
                u.payload_bytes = u.payload_bytes.saturating_add(bytes);
            } else {
                self.usage_dropped = self.usage_dropped.saturating_add(1);
            }
        }
    }

    /// Submit a locally-originated bundle for delivery; offers it to live links.
    /// If it requests an ACK, it's tracked for retransmission until acked/expired.
    pub fn submit(&mut self, bundle: Bundle) {
        let _ = self.submit_checked(bundle);
    }

    /// Store a locally-originated bundle before exposing it to any bearer. Public send APIs use
    /// this checked path so a store rejection is an error rather than a false successful send.
    fn submit_checked(&mut self, bundle: Bundle) -> Result<BundleId> {
        let id = self.store_submitted_bundle(bundle)?;
        self.offer_bundle_to_all_except(id, LOCAL_LINK);
        Ok(id)
    }

    /// Store and track a local bundle without offering it yet. Carrier streams stage every chunk
    /// through this path before exposing the first one, so a later chunk failure cannot emit a
    /// partial prefix.
    fn store_submitted_bundle(&mut self, mut bundle: Bundle) -> Result<BundleId> {
        if bundle.is_private() {
            bundle.env.trace.clear();
        }
        self.stamp_originated_bundle(&mut bundle);
        let id = bundle.id();
        let track = bundle.inner.flags.request_ack && !bundle.inner.flags.is_ack;
        let pend = PendingTx {
            copies: bundle.env.copies,
            created_at: bundle.inner.created_at,
            lifetime_ms: bundle.inner.lifetime_ms,
            next_retx_at: self.now_ms.saturating_add(self.retx_interval_ms),
            retx_interval: self.retx_interval_ms,
        };
        if !self.store.put(bundle, self.now_ms) {
            return Err(Error::Other(
                "store rejected locally-originated bundle".into(),
            ));
        }
        if track {
            self.pending.insert(id, pend);
        }
        Ok(id)
    }

    fn stamp_originated_bundle(&self, bundle: &mut Bundle) {
        if let Some(stamper) = &self.stamper {
            let is_vaccine = matches!(bundle.inner.dst, Destination::Vaccine(_));
            if bundle.env.access.is_none() && !is_vaccine {
                bundle.env.access = Some(Box::new(stamper.stamp(&bundle.id(), self.now_ms)));
            }
        }
    }

    /// Number of locally-originated bundles still awaiting an ACK.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Send `body` to `dst` — **untraceably, by default** (DESIGN.md §39). No cleartext
    /// src/dst: the bundle floods (`Broadcast`) and is recognized only by the holder of
    /// `dst`'s prekey ("is this mine?"). The content is still forward-secret (the inner
    /// ratchet) and the sender authenticated (its identity rides *inside* the seal). With
    /// `request_ack`, the recipient seals a private ACK back so delivery still confirms.
    ///
    /// We need `dst`'s published prekey for BOTH the recognition tag and the ratchet, so —
    /// exactly as the traced path — when we haven't seen it yet we DON'T static-seal: the
    /// content is queued ("Securing…") and flushes the moment the prekey arrives (§25).
    ///
    /// For the opt-in, fully-attributed path (cleartext src/dst, §27 provenance, route
    /// learning, relay vaccination), use [`send_message_traced`].
    pub fn send_message(
        &mut self,
        dst: PubKeyBytes,
        content_type: String,
        body: Vec<u8>,
        request_ack: bool,
    ) -> Result<BundleId> {
        if content_type.len().saturating_add(body.len()) > MAX_CARRIER_CONTENT_BYTES {
            return Err(Error::Other("message exceeds carrier stream limit".into()));
        }
        // Resolve the prekey BEFORE encrypting so we never advance the ratchet only to defer
        // (which would silently drop a real ciphertext and desync the session).
        let spk_pub = match self.directory.prekey(&dst) {
            Some(pb) => pb.spk_pub,
            None => return self.defer_content(dst, content_type, body, request_ack, true),
        };
        match self.session_payload(&dst, content_type.clone(), body.clone())? {
            Some((inner, session)) => {
                let id = self.dispatch_private(dst, spk_pub, inner, session, request_ack, None)?;
                self.flush_pending_content(); // a session may have just opened — flush deferrals
                Ok(id)
            }
            None => self.defer_content(dst, content_type, body, request_ack, true),
        }
    }

    /// Send `body` to `dst` with full §27 provenance — cleartext src/dst, an identity
    /// signature, route learning, carrier chunking, and relay-vaccinating ACKs. This is the
    /// **opt-in traced** path; the default [`send_message`] is untraceable (§39). Used for
    /// the rare cases that need a directed unicast (e.g. control to a directly-connected
    /// peer) or where the user has explicitly opted into a traceable send.
    pub fn send_message_traced(
        &mut self,
        dst: PubKeyBytes,
        content_type: String,
        body: Vec<u8>,
        request_ack: bool,
    ) -> Result<BundleId> {
        if content_type.len().saturating_add(body.len()) > MAX_CARRIER_CONTENT_BYTES {
            return Err(Error::Other("message exceeds carrier stream limit".into()));
        }
        // Require ratcheting device-to-device (DESIGN.md §25): if we can build a forward-secret
        // payload now, send it; otherwise we have no prekey yet — DON'T static-seal, queue the
        // content and return a stable handle. It flushes the moment a prekey arrives.
        match self.session_payload(&dst, content_type.clone(), body.clone())? {
            Some((payload, session)) => {
                let id = self.dispatch_content(dst, payload, session, request_ack, None)?;
                // Sending this may have just established a session to `dst` (the prekey path in
                // session_payload). Any EARLIER content deferred for the same peer ("Securing…")
                // can ratchet now — flush it immediately instead of waiting for the next tick,
                // which won't run if the app backgrounds right after this send. (The stuck-"Securing"
                // bug: a queued message never left because its flush only ever fired on tick.)
                self.flush_pending_content();
                Ok(id)
            }
            None => self.defer_content(dst, content_type, body, request_ack, false),
        }
    }

    /// Queue content we can't ratchet yet (no prekey for `dst`): we never static-seal user
    /// content (§25). Returns a stable handle the UI shows as "Sending…"; it flushes the
    /// moment we learn `dst`'s prekey. `private` routes the eventual send through §39.
    fn defer_content(
        &mut self,
        dst: PubKeyBytes,
        content_type: String,
        body: Vec<u8>,
        request_ack: bool,
        private: bool,
    ) -> Result<BundleId> {
        let pending_seq = self.pending_seq.saturating_add(1);
        let h = blake3::hash(
            &[
                &dst[..],
                content_type.as_bytes(),
                &body,
                &pending_seq.to_be_bytes(),
            ]
            .concat(),
        );
        let display_id: BundleId = *h.as_bytes();
        let pending = PendingContent {
            display_id,
            dst,
            content_type,
            body,
            request_ack,
            private,
        };
        let mut candidate = self.pending_content.clone();
        candidate.push(pending);
        self.persist_pending_content(&candidate)?;

        self.pending_seq = pending_seq;
        self.pending_content = candidate;
        self.tx.entry(display_id).or_default(); // shows as Sending… until ratcheted
        Ok(display_id)
    }

    /// Build + submit a ratcheted content bundle. `display_id` is `Some` when this content was
    /// deferred (the real bundle id differs from the handle the UI already holds) — we alias the
    /// real id to it so delivery status lands on the right message.
    fn dispatch_content(
        &mut self,
        dst: PubKeyBytes,
        payload: Payload,
        session: PeerSession,
        request_ack: bool,
        display_id: Option<BundleId>,
    ) -> Result<BundleId> {
        let bundle = Bundle::create(
            &self.identity,
            Destination::Device(dst),
            &dst,
            &payload,
            BundleOpts {
                created_at: self.now_ms,
                flags: BundleFlags {
                    request_ack,
                    ..Default::default()
                },
                ..Default::default()
            },
        )?;
        self.ensure_delivery_within_limits(&bundle)?;
        let real = bundle.id();
        let display = display_id.unwrap_or(real);
        let offer = self.store_session_delivery(dst, session, bundle)?;
        if display != real {
            self.tx_alias.insert(real, display);
        }
        // Track delivery status for the UI.
        self.tx.entry(display).or_default();
        // Remember our own send so the returning delivery-ACK teaches us the route (§27).
        self.forwarded
            .insert(real, (self.identity.address(), dst, self.now_ms));
        for id in offer {
            self.offer_bundle_to_all_except(id, LOCAL_LINK);
        }
        Ok(display)
    }

    /// Build + flood a §39 private bundle: wrap the (already forward-secret) `inner` payload
    /// with our identity, then seal the whole thing to `dst`'s address inside an anonymous,
    /// flooding envelope. `display_id` aliases a deferred send's handle (as in
    /// [`dispatch_content`]). With `request_ack` the envelope is marked so it's retx-tracked
    /// in `pending` until the recipient's private ACK clears it (the recipient reads that
    /// cleartext flag to decide whether to ACK). No `forwarded` route-learning and no carrier
    /// chunking — there's no cleartext dst to route toward (that's the gradient work, P4).
    fn dispatch_private(
        &mut self,
        dst: PubKeyBytes,
        spk_pub: XPubKeyBytes,
        inner: Payload,
        session: PeerSession,
        request_ack: bool,
        display_id: Option<BundleId>,
    ) -> Result<BundleId> {
        let wrapped = Payload::Private {
            sender: self.identity.address(),
            inner: Box::new(inner),
        };
        // §39 P4: stamp the recipient's mailbox ROUTING PREFIX so a node holding a gradient toward it can
        // route this bundle there (instead of blind-flooding) — without any cleartext dst. The sender
        // already has `spk_pub`, so it computes the SAME tag the recipient beacons. core-protocol-r2-02:
        // we put only the 2-byte PREFIX on the wire, never the full deterministic tag.
        let bundle = Bundle::create_private(
            &dst,
            &spk_pub,
            &wrapped,
            // mailbox routing prefix = the gradient key (P4 routing; P5 pull). Derived from the recipient's
            // address + current epoch (F-06), which the sender knows; rotates per epoch.
            Some(crypto::mailbox_route(&crypto::mailbox_tag(
                &dst,
                mailbox_epoch(self.now_ms),
            ))),
            BundleOpts {
                // ADV18-08: coarsen the cleartext, id-bound created_at so it is not a per-message
                // sender timing fingerprint.
                created_at: private_created_at(self.now_ms),
                lifetime_ms: self.default_lifetime_ms,
                flags: BundleFlags {
                    request_ack,
                    ..Default::default()
                },
                ..Default::default()
            },
        )?;
        let real = bundle.id();
        let display = display_id.unwrap_or(real);
        let offer = self.store_session_delivery(dst, session, bundle)?;
        if display != real {
            self.tx_alias.insert(real, display);
        }
        self.tx.entry(display).or_default(); // track delivery for the UI (private ACK flips it)
        for id in offer {
            self.offer_bundle_to_all_except(id, LOCAL_LINK);
        }
        Ok(display)
    }

    /// Try to flush queued content now that we may know more peers' prekeys (called when a
    /// prekey advert is accepted, and on tick). Anything still without a prekey stays queued.
    fn flush_pending_content(&mut self) {
        if self.pending_content.is_empty() {
            return;
        }
        let original = std::mem::take(&mut self.pending_content);
        let mut still = Vec::new();
        for pc in original.iter().cloned() {
            // A §39 private send also needs the recipient's prekey for its recognition tag —
            // resolve it before encrypting so we never advance the ratchet only to re-defer.
            let spk_pub = if pc.private {
                self.directory.prekey(&pc.dst).map(|b| b.spk_pub)
            } else {
                None
            };
            if pc.private && spk_pub.is_none() {
                still.push(pc); // no prekey yet → keep waiting (it gossips, §25)
                continue;
            }
            let dispatched =
                match self.session_payload(&pc.dst, pc.content_type.clone(), pc.body.clone()) {
                    Ok(Some((payload, session))) if pc.private => self.dispatch_private(
                        pc.dst,
                        spk_pub.unwrap(),
                        payload,
                        session,
                        pc.request_ack,
                        Some(pc.display_id),
                    ),
                    Ok(Some((payload, session))) => self.dispatch_content(
                        pc.dst,
                        payload,
                        session,
                        pc.request_ack,
                        Some(pc.display_id),
                    ),
                    Ok(None) => {
                        still.push(pc);
                        continue;
                    }
                    Err(_) => {
                        still.push(pc);
                        continue;
                    }
                };
            if dispatched.is_err() {
                // The session may already be durably advanced. Keep the content and retry under the
                // next send key; never roll the persisted candidate backward or lose the queue item.
                still.push(pc);
            }
        }
        if self.persist_pending_content(&still).is_ok() {
            self.pending_content = still;
        } else {
            // A failed queue-state write cannot make already-accepted deferred content disappear.
            self.pending_content = original;
        }
    }

    /// Resolve a bundle id to the UI-facing id its status should land on: a carrier chunk maps
    /// to its original message, and a deferred message's real id maps to its handle (§20, §25).
    fn display_id(&self, id: &BundleId) -> BundleId {
        let owned = self.carrier_owner.get(id).copied().unwrap_or(*id);
        self.tx_alias.get(&owned).copied().unwrap_or(owned)
    }

    /// Choose a forward-secret payload for a peer message: an established session, or a freshly
    /// opened one from the peer's published prekey. `None` when neither is available yet (no
    /// prekey) — the caller defers rather than static-sealing (DESIGN.md §25).
    fn session_payload(
        &mut self,
        dst: &PubKeyBytes,
        content_type: String,
        body: Vec<u8>,
    ) -> Result<Option<(Payload, PeerSession)>> {
        // Established session: ratchet-encrypt. Re-send as SessionInit until the peer
        // has replied (init_material present) so any copy can bootstrap them.
        if let Some(mut candidate) = self.sessions.get(dst).cloned() {
            let inner = postcard::to_allocvec(&SessionInner { content_type, body })?;
            let msg = candidate.session.encrypt(&inner)?;
            let out = match candidate.init_material {
                Some((ek_pub, spk_pub)) => Payload::SessionInit {
                    ek_pub,
                    spk_pub,
                    msg,
                },
                None => Payload::SessionMessage { msg },
            };
            return Ok(Some((out, candidate)));
        }
        // No session yet: open one if the peer has published a prekey we've seen.
        if let Some(bundle) = self.directory.prekey(dst) {
            let inner = postcard::to_allocvec(&SessionInner { content_type, body })?;
            let (ek_pub, root) = crypto::x3dh_initiate(&self.identity, &bundle)?;
            let mut session = Session::init_initiator(root, bundle.spk_pub);
            let msg = session.encrypt(&inner)?;
            let candidate = PeerSession {
                session,
                init_material: Some((ek_pub, bundle.spk_pub)),
                established_by: Some(ek_pub),
            };
            return Ok(Some((
                Payload::SessionInit {
                    ek_pub,
                    spk_pub: bundle.spk_pub,
                    msg,
                },
                candidate,
            )));
        }
        // No prekey yet → defer (never static-seal content).
        Ok(None)
    }

    /// Durable KV key for a peer's forward-secret session (DESIGN.md §25).
    fn session_kv_key(peer: &PubKeyBytes) -> String {
        format!("session/{}", bs58::encode(peer).into_string())
    }

    /// Record session activity only after the host supplies a real clock. Zero-time sends and
    /// receives remain unanchored so the first epoch tick establishes their idle-GC baseline.
    fn touch_session(&mut self, peer: PubKeyBytes) {
        if self.now_ms == 0 {
            self.unanchored_sessions.insert(peer);
            return;
        }
        self.session_touch.insert(peer, self.now_ms);
        self.unanchored_sessions.remove(&peer);
    }

    /// GC forward-secret sessions idle past [`SESSION_MAX_IDLE_MS`] — drop them from memory AND the
    /// persisted `session/` store, so a device that meets many peers once doesn't grow that store
    /// forever (D6). A pruned session just re-establishes (with a fresh prekey) if the peer returns.
    fn gc_idle_sessions(&mut self) {
        let now = self.now_ms;
        let stale: Vec<PubKeyBytes> = self
            .sessions
            .keys()
            .filter(|p| {
                now.saturating_sub(*self.session_touch.get(*p).unwrap_or(&now))
                    > SESSION_MAX_IDLE_MS
            })
            .copied()
            .collect();
        for p in stale {
            let _ = self.delete_session(&p);
        }
    }

    /// Durably write a candidate ratchet before replacing the live in-memory session. Once this
    /// succeeds the old send state must never be restored, even if later bundle storage fails.
    fn commit_session(&mut self, peer: PubKeyBytes, candidate: PeerSession) -> Result<()> {
        let bytes = postcard::to_allocvec(&candidate)?;
        self.store
            .put_kv_critical(&Self::session_kv_key(&peer), bytes)
            .map_err(|e| Error::Other(format!("session persistence failed: {e}")))?;
        self.sessions.insert(peer, candidate);
        self.touch_session(peer);
        Ok(())
    }

    /// Delete the durable session first. A failed delete leaves the live ratchet and its idle-GC
    /// bookkeeping untouched, so restart and in-process state cannot diverge.
    fn delete_session(&mut self, peer: &PubKeyBytes) -> Result<()> {
        self.store
            .remove_kv_critical(&Self::session_kv_key(peer))
            .map_err(|e| Error::Other(format!("session deletion failed: {e}")))?;
        self.sessions.remove(peer);
        self.session_touch.remove(peer);
        self.unanchored_sessions.remove(peer);
        Ok(())
    }

    /// Publish (and gossip) this node's signed prekey so peers can open forward-secret
    /// sessions to it without a live round-trip (DESIGN.md §25). Re-publish
    /// periodically to stay within the advert TTL. Returns the advert id.
    pub fn publish_prekey(&mut self) -> Result<AdvertId> {
        self.advert_seq += 1;
        let advert = Advert::publish(
            &self.identity,
            AdvertKind::PreKey {
                spk_pub: self.prekey.public,
                spk_sig: self.prekey.sig.to_vec(),
            },
            self.now_ms,
            PREKEY_TTL_MS,
            self.advert_seq,
        )?;
        let id = advert.id;
        self.publish(advert);
        Ok(id)
    }

    /// core-03: rotate the signed prekey when the clock crosses into a new epoch. The new epoch's
    /// deterministic SPK becomes the published one; its secret is added to `spk_secrets` and the
    /// current epoch's is retained. Secrets older than [`PREKEY_EPOCH_WINDOW`] past epochs are wiped,
    /// so a leaked SPK secret only decrypts sessions bootstrapped within a bounded recent window
    /// instead of for the identity's life. Re-publishes the new prekey advert so peers adopt it.
    /// Deterministic derivation means a restart re-derives the same per-epoch secrets, so a peer that
    /// cached an in-window advert can still open a session. No-op until the epoch actually advances.
    fn rotate_prekey_if_due(&mut self) {
        let cur = prekey_epoch(self.now_ms);
        if cur == self.prekey_epoch {
            return;
        }
        // Adopt the current epoch's prekey and retain its secret alongside the old one.
        let fresh = self.identity.derive_prekey_epoch(cur);
        self.spk_secrets
            .insert(fresh.public, zeroize::Zeroizing::new(fresh.secret_bytes()));
        self.prekey = fresh;
        self.prekey_epoch = cur;
        // Rebuild the retained set from exactly the in-window epochs, dropping anything older so a
        // compromised past secret can't decrypt sessions indefinitely. Re-deriving is cheap and keeps
        // the map an exact function of the current epoch (no unbounded growth across many rotations).
        let mut keep: HashMap<XPubKeyBytes, zeroize::Zeroizing<[u8; 32]>> = HashMap::new();
        // Always retain epoch 0 (the base prekey) so pre-rotation cached adverts still resolve.
        for back in 0..=PREKEY_EPOCH_WINDOW {
            let e = cur.saturating_sub(back);
            let pk = self.identity.derive_prekey_epoch(e);
            keep.insert(pk.public, zeroize::Zeroizing::new(pk.secret_bytes()));
        }
        let base = self.identity.derive_prekey_epoch(0);
        keep.insert(base.public, zeroize::Zeroizing::new(base.secret_bytes()));
        self.spk_secrets = keep;
        // Peers must learn the new SPK to open fresh sessions to us.
        let _ = self.publish_prekey();
    }

    /// §39 P4: publish (and gossip) this node's signed **receiver-beacon** so peers lay a
    /// gradient toward our mailbox-tag and route private bundles to us instead of blind-flooding.
    /// Call this when in "route-to-me" mode (a recipient that wants to be reachable deep in the
    /// mesh / across a relay→BLE bridge); a passive recipient skips it for max privacy and just
    /// recognizes whatever floods past. Re-published on a short interval from [`Node::tick`] so the
    /// gradient stays fresh + tracks a mobile recipient. Returns the advert id.
    pub fn publish_recv_beacon(&mut self) -> Result<AdvertId> {
        // F-06: beacon the current mailbox epoch AND the past window, so a private bundle addressed
        // or spooled under a just-rotated tag (sender a bit behind, or spooled before the boundary)
        // is still routed and pulled. The current-epoch beacon's id is returned.
        let addr = self.identity.address();
        let cur = mailbox_epoch(self.now_ms);
        let mut first_id = None;
        for back in 0..=MAILBOX_EPOCH_WINDOW {
            let epoch = cur.saturating_sub(back);
            self.advert_seq += 1;
            let advert = Advert::publish(
                &self.identity,
                AdvertKind::RecvBeacon {
                    mailbox: crypto::mailbox_tag(&addr, epoch),
                },
                self.now_ms,
                RECV_BEACON_TTL_MS,
                self.advert_seq,
            )?;
            let id = advert.id;
            self.publish(advert);
            if first_id.is_none() {
                first_id = Some(id);
            }
            if epoch == 0 {
                break; // no older epochs exist
            }
        }
        first_id.ok_or(Error::Crypto("no beacon emitted"))
    }

    /// Whether we hold a forward-secret session with `addr` — i.e. messages to/from
    /// it are ratchet-encrypted rather than static-sealed (DESIGN.md §25).
    pub fn has_session(&self, addr: &PubKeyBytes) -> bool {
        self.sessions.contains_key(addr)
    }

    /// Decrypt a bundle addressed to this node (e.g. an inbox item), raw payload.
    pub fn open(&self, bundle: &Bundle) -> Result<Payload> {
        bundle.open(&self.identity)
    }

    /// §39: does any prekey we still hold the secret for recognize this private bundle as
    /// ours? One DH + one hash per prekey — the cost of "is this mine?" as the bundle floods
    /// past. (We keep retired prekey secrets in `spk_secrets`, so a message in flight when we
    /// rotated is still recognized.)
    fn recognizes(&self, bundle: &Bundle) -> bool {
        self.spk_secrets
            .values()
            .any(|secret| bundle.recognized_by(secret))
    }

    /// The recognition token (ephemeral·SPK DH `shared`) for a private bundle we recognize — the value
    /// revealed in a delivery vaccine so relays can verify + drop their copy. `None` if not ours.
    fn vaccine_token_for(&self, bundle: &Bundle) -> Option<[u8; 32]> {
        let ph = bundle.inner.private.as_ref()?;
        self.spk_secrets
            .values()
            .find(|secret| bundle.recognized_by(secret))
            .map(|secret| crypto::recognition_shared(secret, &ph.ephemeral))
    }

    /// sec-priv-07: recover which held private bundle a token-only delivery vaccine clears. The
    /// anti-packet no longer names a bundle id, so we test the revealed token against each held private
    /// bundle's own recognition tag: `recognition_tag_from_shared(token, held_id) == held_tag` holds iff
    /// this token is the recipient's DH for that exact bundle. A forged/foreign token matches nothing.
    /// Bounded by the held-private-bundle count (the relay eviction cap), and run at most once per
    /// unique vaccine (the flood is id-deduped upstream), so it is not a hot-path cost. Returns the
    /// matched bundle id, or `None` if we hold no bundle this vaccine clears.
    fn resolve_vaccine_target(&self, token: &[u8; 32]) -> Option<BundleId> {
        for id in self.store.have().ids {
            let Some(b) = self.store.get(&id) else {
                continue;
            };
            // r13-01: the tag keys on the content id, not the wire id — match against content_id.
            let (Some(tag), Some(content_id)) = (
                b.inner.private.as_ref().map(|p| p.tag),
                b.private_content_id(),
            ) else {
                continue;
            };
            if crypto::recognition_tag_from_shared(token, &content_id) == tag {
                return Some(id);
            }
        }
        None
    }

    /// core-protocol-r3-02: remember a delivery-vaccine token whose target we don't hold yet, so a
    /// later-arriving target is purged on first store. Capped at [`MAX_SEEN_VACCINE_TOKENS`]
    /// (oldest-evicted on overflow) and TTL-pruned in [`Node::tick`], so a distinct-token flood can
    /// neither grow it without bound nor pin it forever. Storing a forged/foreign token is harmless: it
    /// clears no real bundle, so `already_vaccinated_by_token` will never match it.
    fn remember_vaccine_token(&mut self, token: [u8; 32]) {
        if self.seen_vaccine_tokens.len() >= MAX_SEEN_VACCINE_TOKENS
            && !self.seen_vaccine_tokens.contains_key(&token)
        {
            if let Some(oldest) = self
                .seen_vaccine_tokens
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(k, _)| *k)
            {
                self.seen_vaccine_tokens.remove(&oldest);
            }
        }
        self.seen_vaccine_tokens.insert(token, self.now_ms);
    }

    /// core-protocol-r3-02: true iff a remembered vaccine token (one that raced ahead of its target)
    /// clears this private bundle (i.e. the bundle is already delivered and should be dropped on first
    /// store instead of re-flooded to TTL. Only a real recipient's CDH token satisfies
    /// `recognition_tag_from_shared(token, id) == tag`, so this can only fire for a genuinely-delivered
    /// bundle (identical forgery-resistance to the live vaccine path).
    fn already_vaccinated_by_token(&self, bundle: &Bundle) -> bool {
        if self.seen_vaccine_tokens.is_empty() {
            return false;
        }
        let Some(tag) = bundle.inner.private.as_ref().map(|p| p.tag) else {
            return false;
        };
        // r13-01: the tag keys on the content id, not the wire id.
        let Some(content_id) = bundle.private_content_id() else {
            return false;
        };
        self.seen_vaccine_tokens
            .keys()
            .any(|token| crypto::recognition_tag_from_shared(token, &content_id) == tag)
    }

    /// core-protocol-r2-04: verify a private delivery-ACK's recipient-only CDH proof against the ORIGINAL
    /// bundle we still hold. `proof` is the recognition token `recognition_shared(recipient_spk_secret,
    /// original.ephemeral)`; it is valid iff `recognition_tag_from_shared(proof, for_bundle_id)` equals
    /// the original bundle's own `private.tag`. Only a holder of the recipient's SPK secret can compute a
    /// token that satisfies this (identical to the vaccine's forgery-resistance), so an ACK forged by an
    /// address-knower who lacks that secret fails here. Returns false if the proof is absent, the original
    /// is no longer held (nothing to authenticate a mutation against), or the tag doesn't match.
    fn private_ack_proof_ok(&self, for_bundle_id: &BundleId, proof: Option<[u8; 32]>) -> bool {
        let Some(token) = proof else {
            return false; // an unproven private ACK never mutates send state
        };
        let Some(orig) = self.store.get(for_bundle_id) else {
            return false; // original already cleared (state is settled) — no mutation to authorize
        };
        // r13-01: the original's tag keys on ITS content id, not its wire id.
        let (Some(tag), Some(content_id)) = (
            orig.inner.private.as_ref().map(|p| p.tag),
            orig.private_content_id(),
        ) else {
            return false;
        };
        crypto::recognition_tag_from_shared(&token, &content_id) == tag
    }

    fn outstanding_requests_mutation(
        requests: &HashMap<BundleId, OutstandingRequest>,
    ) -> Result<KvMutation> {
        if requests.is_empty() {
            return Ok(KvMutation::Remove {
                key: "outstanding_requests".into(),
            });
        }
        let persisted: Vec<(BundleId, OutstandingRequest)> = requests
            .iter()
            .map(|(id, request)| (*id, request.clone()))
            .collect();
        Ok(KvMutation::Put {
            key: "outstanding_requests".into(),
            value: postcard::to_allocvec(&persisted)?,
        })
    }

    /// A response may consume a request only when its signed outer source and payload kind match the
    /// durable authorization context recorded when that exact request id was created.
    fn response_authorized(&self, id: &BundleId, signer: &PubKeyBytes, kind: RequestKind) -> bool {
        self.outstanding_requests.get(id).is_some_and(|request| {
            !self.unanchored_outstanding_requests.contains(id)
                && request.responder == *signer
                && request.kind == kind
                && request.expires_at_ms > self.now_ms
        })
    }

    fn expire_outstanding_requests(&mut self) -> Result<()> {
        let expired: Vec<BundleId> = self
            .outstanding_requests
            .iter()
            .filter(|(_, request)| request.expires_at_ms <= self.now_ms)
            .map(|(id, _)| *id)
            .collect();
        if expired.is_empty() {
            return Ok(());
        }
        let mut candidate = self.outstanding_requests.clone();
        let mut custody = Vec::new();
        for id in &expired {
            if let Some(request) = candidate.remove(id) {
                custody.extend(request.custody_ids);
            }
        }
        let mut mutations = vec![Self::outstanding_requests_mutation(&candidate)?];
        mutations.extend(expired.iter().map(|id| KvMutation::Remove {
            key: Self::outgoing_carrier_key(id),
        }));
        mutations.extend(
            custody
                .iter()
                .copied()
                .map(|id| KvMutation::RemoveBundle { id }),
        );
        self.store
            .apply_kv_batch(&mutations)
            .map_err(|e| Error::Other(format!("request expiry persistence failed: {e}")))?;
        self.outstanding_requests = candidate;
        for id in expired {
            self.unanchored_outstanding_requests.remove(&id);
            self.outgoing_carriers.remove(&id);
            self.tx.remove(&id);
        }
        for id in custody {
            self.pending.remove(&id);
            self.carrier_owner.remove(&id);
        }
        Ok(())
    }

    /// Atomically commit response authorization with the exact custody records that carry its request.
    /// No live send state, success return, or bearer output is exposed until this batch succeeds.
    fn deliver_authorized_request(
        &mut self,
        bundle: Bundle,
        responder: PubKeyBytes,
        kind: RequestKind,
    ) -> Result<BundleId> {
        if !self.clock_anchored {
            return Err(Error::Other(
                "response-bearing request requires a real clock anchor".into(),
            ));
        }
        self.expire_outstanding_requests()?;
        if self.outstanding_requests.len() >= MAX_OUTSTANDING_REQUESTS {
            return Err(Error::Other("outstanding request limit reached".into()));
        }
        let lifetime_ms = bundle.inner.lifetime_ms;
        let (id, custody, carrier) = self.prepare_delivery_custody(bundle)?;
        let custody_ids: Vec<BundleId> = custody.iter().map(Bundle::id).collect();
        let mut candidate = self.outstanding_requests.clone();
        candidate.insert(
            id,
            OutstandingRequest {
                responder,
                kind,
                expires_at_ms: self.now_ms.saturating_add(lifetime_ms as u64),
                custody_ids: custody_ids.clone(),
            },
        );
        let mut mutations = Vec::with_capacity(custody.len() + 2);
        mutations.push(Self::outstanding_requests_mutation(&candidate)?);
        if let Some(carrier) = &carrier {
            mutations.push(KvMutation::Put {
                key: Self::outgoing_carrier_key(&id),
                value: postcard::to_allocvec(carrier)?,
            });
        }
        mutations.extend(custody.iter().cloned().map(|bundle| KvMutation::PutBundle {
            bundle: Box::new(bundle),
            now_ms: self.now_ms,
        }));
        self.store
            .apply_kv_batch(&mutations)
            .map_err(|e| Error::Other(format!("request persistence failed: {e}")))?;

        self.outstanding_requests = candidate;
        self.unanchored_outstanding_requests.remove(&id);
        self.tx.entry(id).or_default();
        self.forwarded
            .insert(id, (self.identity.address(), responder, self.now_ms));
        let stored = self.activate_delivery_custody(id, &custody, carrier);
        for custody_id in stored {
            self.offer_bundle_to_all_except(custody_id, LOCAL_LINK);
        }
        Ok(id)
    }

    /// §39 (sec-priv-07): flood a delivery vaccine revealing only `token`, so every node carrying a copy
    /// recovers the delivered bundle itself (`recognition_tag_from_shared(token, held_id) == held_tag`)
    /// and drops it. No plaintext delivered id on the wire. Outlives the message to chase the tail.
    fn emit_vaccine(&mut self, token: [u8; 32], lifetime_ms: u32) {
        let bundle = Bundle::create_vaccine(
            token,
            BundleOpts {
                created_at: self.now_ms,
                lifetime_ms,
                ..Default::default()
            },
        );
        self.submit(bundle);
    }

    /// Handle a private (§39) bundle we've recognized as ours. Opens the seal to route on the
    /// inner payload: a delivery ACK flips our send to "Delivered"; user content is delivered
    /// to the inbox (once) and, if asked, ACKed back to the sender we just learned from inside
    /// the seal. Recognition runs on every flooded copy, so we deliver/handle only on the
    /// first sighting but may re-ACK a duplicate (throttled) to cover a lost first ACK.
    ///
    /// core-protocol-r12-01: "first" is tracked in `delivered_private` (populated only by RECOGNIZED
    /// copies here), NOT off `store.seen`. `store.seen` is marked by ANY copy on the relay/flood path,
    /// including a same-id chimera whose recognition header was rewritten (the id binds only the sealed
    /// payload). Gating on `seen` let such a chimera mark the id seen, so the genuine copy saw
    /// `first == false` and its `inbox.push` was skipped — a silent delivery denial plus a false ACK.
    fn deliver_private(&mut self, bundle: &Bundle, id: &BundleId) -> bool {
        let first = !self.delivered_private.contains(id);
        let (sender, inner) = match bundle.open(&self.identity) {
            Ok(Payload::Private { sender, inner }) => (sender, inner),
            _ => return false, // recognized but not a well-formed private payload
        };
        match *inner {
            // A private delivery ACK for one of OUR sends: stop carrying/tracking it and mark
            // it Delivered. (No relay vaccine — the acked id can't ride in cleartext without
            // linking, so other relays drop their copy by TTL; the §39 storage cost.)
            Payload::Ack {
                for_bundle_id,
                delivery_hops,
                delivery_ms,
                proof,
                ..
            } if first => {
                // core-protocol-r2-04: a private ACK is unsigned and recognized only by our SPK (whose
                // PUBLIC half is published), and the acked bundle is sealed to our PUBLIC address — so
                // recognition alone does NOT prove the real recipient sent this. Require the recipient-
                // only CDH proof: `recognition_tag_from_shared(proof, for_bundle_id)` must equal the
                // ORIGINAL bundle's own recognition tag, which only a party holding the recipient's SPK
                // secret can produce. An attacker who knows our address + an in-flight id can forge the
                // envelope but NOT this token. If the proof is absent or wrong, refuse to mutate send
                // state (don't flip Delivered, don't remove from store/pending) so a forged ACK cannot
                // strand a real message on a false "Delivered". A genuine ACK whose original we already
                // cleared (e.g. the vaccine beat it) is idempotent — nothing left to mutate.
                if !self.private_ack_proof_ok(&for_bundle_id, proof) {
                    return false;
                }
                // r12-01: only a proof-valid ACK counts as handled — a bad-proof forgery returns above
                // without marking the id, so a genuine ACK that arrives later is still treated as first.
                self.delivered_private.insert(*id);
                self.pending.remove(&for_bundle_id);
                self.store.remove(&for_bundle_id);
                let display = self.display_id(&for_bundle_id);
                let newly = self.tx.get(&display).is_some_and(|i| !i.delivered);
                if let Some(info) = self.tx.get_mut(&display) {
                    info.delivered = true;
                    info.delivered_hops = delivery_hops;
                    info.delivered_ms = delivery_ms;
                }
                // Observability: record that WE (the sender) just learned this send was delivered, from the
                // returning ACK — the only way the sender knows. Lets a UI show the sender's real status.
                if newly && self.observe {
                    self.sends_delivered.push(display);
                }
                true
            }
            Payload::Ack { .. } => true, // a duplicate ACK, already handled
            // sec-priv-01/core-01: a bare PeerMessage inside an unsigned Private seal is a sender
            // spoof (no ratchet proves `sender`). Drop it here so we neither inbox nor ACK it —
            // read_message would refuse to surface it anyway, but not inboxing avoids emitting a
            // private ACK to the impersonated address.
            Payload::PeerMessage { .. } => false,
            // Ratcheted content authenticates the claimed private sender. Decrypt and atomically
            // stage it now; persistence/authentication failure stops this copy before ACK or seen.
            payload @ (Payload::SessionInit { .. } | Payload::SessionMessage { .. }) => self
                .stage_inbound_message(bundle, sender, payload, false, true)
                .is_ok(),
            _ => true,
        }
    }

    /// §39: seal a delivery ACK back to `to` (whom we learned from inside the message's seal)
    /// for `for_bundle_id`, reporting the forward path length + the A→B latency we observed. It
    /// floods and is recognized only by `to`. Needs `to`'s prekey; without it we can't ACK
    /// privately and the sender stays "Sent" (a documented §39 limitation — both ends normally
    /// publish prekeys).
    fn emit_private_ack(
        &mut self,
        to: PubKeyBytes,
        for_bundle_id: BundleId,
        delivery_hops: u8,
        delivery_ms: u32,
        proof: Option<[u8; 32]>,
        lifetime_ms: u32,
    ) -> bool {
        let spk_pub = match self.directory.prekey(&to) {
            Some(b) => b.spk_pub,
            None => return false,
        };
        let ack = Payload::Ack {
            for_bundle_id,
            status: 0,
            delivery_hops,
            delivery_ms,
            // core-protocol-r2-04: the recipient-only CDH proof for `for_bundle_id`.
            proof,
        };
        let wrapped = Payload::Private {
            sender: self.identity.address(),
            inner: Box::new(ack),
        };
        if let Ok(b) = Bundle::create_private(
            &to,
            &spk_pub,
            &wrapped,
            // §39 P4: ride `to`'s gradient back (F-06); core-protocol-r2-02: prefix only on the wire.
            Some(crypto::mailbox_route(&crypto::mailbox_tag(
                &to,
                mailbox_epoch(self.now_ms),
            ))),
            BundleOpts {
                // ADV18-08: coarsen the ACK's cleartext created_at too, so a relay on both legs cannot
                // tie the ACK to its forward message by a matched pair of millisecond stamps.
                created_at: private_created_at(self.now_ms),
                lifetime_ms,
                ..Default::default()
            },
        ) {
            self.submit(b);
            true
        } else {
            false
        }
    }

    /// Emit a persisted inbox item's deferred ACK and private vaccine, throttling duplicate-copy
    /// re-ACKs exactly as the old immediate-receipt path did.
    fn emit_inbox_ack(&mut self, acknowledgement: &InboxAcknowledgement) {
        let for_bundle_id = match acknowledgement {
            InboxAcknowledgement::None => return,
            InboxAcknowledgement::Traced { for_bundle_id, .. }
            | InboxAcknowledgement::Private { for_bundle_id, .. } => *for_bundle_id,
        };
        if self
            .last_ack
            .get(&for_bundle_id)
            .is_some_and(|last| self.now_ms.saturating_sub(*last) < REACK_MIN_INTERVAL_MS)
        {
            return;
        }

        let emitted = match acknowledgement {
            InboxAcknowledgement::None => false,
            InboxAcknowledgement::Traced {
                to,
                for_bundle_id,
                delivery_hops,
                delivery_ms,
                lifetime_ms,
                priority,
            } => {
                let ack = Bundle::create(
                    &self.identity,
                    Destination::AckTo(*to, *for_bundle_id),
                    to,
                    &Payload::Ack {
                        for_bundle_id: *for_bundle_id,
                        status: 0,
                        delivery_hops: *delivery_hops,
                        delivery_ms: *delivery_ms,
                        proof: None,
                    },
                    BundleOpts {
                        created_at: self.now_ms,
                        lifetime_ms: *lifetime_ms,
                        priority: *priority,
                        flags: BundleFlags {
                            is_ack: true,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                );
                if let Ok(ack) = ack {
                    self.ack_replicate.entry(ack.id()).or_default();
                    self.submit(ack);
                    true
                } else {
                    false
                }
            }
            InboxAcknowledgement::Private {
                to,
                for_bundle_id,
                delivery_hops,
                delivery_ms,
                proof,
                vaccine,
                lifetime_ms,
            } => {
                let acked = self.emit_private_ack(
                    *to,
                    *for_bundle_id,
                    *delivery_hops,
                    *delivery_ms,
                    *proof,
                    *lifetime_ms,
                );
                if let Some(token) = vaccine {
                    self.emit_vaccine(*token, *lifetime_ms);
                }
                acked || vaccine.is_some()
            }
        };
        if emitted {
            self.last_ack.insert(for_bundle_id, self.now_ms);
        }
    }

    fn inbox_kv_key(id: &BundleId) -> String {
        format!("inbox/{}", bs58::encode(id).into_string())
    }

    fn receiver_seen_kv_key(id: &BundleId) -> String {
        format!("inbox-seen/{}", bs58::encode(id).into_string())
    }

    fn inbox_acknowledgement(
        &self,
        bundle: &Bundle,
        from: PubKeyBytes,
        private: bool,
    ) -> InboxAcknowledgement {
        if !bundle.inner.flags.request_ack {
            return InboxAcknowledgement::None;
        }
        let delivery_ms = forward_ms(self.now_ms, bundle.inner.created_at);
        if private {
            let token = self.vaccine_token_for(bundle);
            InboxAcknowledgement::Private {
                to: from,
                for_bundle_id: bundle.id(),
                delivery_hops: bundle.env.hops,
                delivery_ms,
                proof: token,
                vaccine: token,
                lifetime_ms: self.default_lifetime_ms,
            }
        } else {
            InboxAcknowledgement::Traced {
                to: from,
                for_bundle_id: bundle.id(),
                delivery_hops: bundle.env.hops,
                delivery_ms,
                lifetime_ms: bundle.inner.lifetime_ms.min(MAX_ACK_LIFETIME_MS),
                priority: bundle.inner.priority.saturating_add(1),
            }
        }
    }

    /// Decrypt, authenticate, and durably stage one inbound user payload. Any receive-session
    /// advance, the decrypted inbox row, and receiver-only dedup are one atomic Store commit. The
    /// live ratchet and host-visible queue change only after that commit succeeds.
    fn stage_inbound_message(
        &mut self,
        bundle: &Bundle,
        from: PubKeyBytes,
        payload: Payload,
        authenticated: bool,
        private: bool,
    ) -> Result<()> {
        if !self.app_payload_policy.supports(AppQueueKind::PeerInbox) {
            return Err(Error::Other(
                "peer inbox disabled for this node role".into(),
            ));
        }
        let id = bundle.id();
        if let Some(seen) = self.receiver_seen.get(&id).cloned() {
            if !self.durable_inbox.contains_key(&id) {
                self.emit_inbox_ack(&seen.acknowledgement);
            }
            return Ok(());
        }

        let prepared = self.prepare_inbound_message(from, payload, authenticated)?;
        let acknowledgement = self.inbox_acknowledgement(bundle, from, private);
        let seen = ReceiverSeen {
            expires_at_ms: self
                .now_ms
                .saturating_add((bundle.inner.lifetime_ms as u64).min(MAX_SEEN_LIFETIME_MS)),
            acknowledgement: acknowledgement.clone(),
        };
        let item = prepared.message.as_ref().map(|message| InboxItem {
            id,
            from: message.from,
            content_type: message.content_type.clone(),
            body: message.body.clone(),
            hops: bundle.env.hops,
            created_at: bundle.inner.created_at,
            trace: bundle.trace().to_vec(),
            received_at: self.now_ms,
            acknowledgement: acknowledgement.clone(),
            original: bundle.clone(),
        });
        let item_charge = if let Some(item) = &item {
            let wire_bytes = bundle.to_bytes()?.len();
            Some(
                self.reserve_app_queue(
                    AppQueueKind::PeerInbox,
                    Some(item.from),
                    Self::inbox_item_bytes(item).saturating_add(wire_bytes),
                )
                .ok_or_else(|| Error::Other("peer inbox admission limit reached".into()))?,
            )
        } else {
            None
        };

        let mut mutations = Vec::with_capacity(3);
        if let Some(candidate) = &prepared.session {
            mutations.push(KvMutation::Put {
                key: Self::session_kv_key(&from),
                value: postcard::to_allocvec(candidate)?,
            });
        }
        mutations.push(KvMutation::Put {
            key: Self::receiver_seen_kv_key(&id),
            value: postcard::to_allocvec(&(id, seen.clone()))?,
        });
        if let Some(item) = &item {
            mutations.push(KvMutation::Put {
                key: Self::inbox_kv_key(&id),
                value: postcard::to_allocvec(item)?,
            });
        }
        if let Err(error) = self.store.apply_kv_batch(&mutations) {
            if let Some(charge) = item_charge {
                self.release_app_queue(charge);
            }
            return Err(Error::Other(format!("inbox persistence failed: {error}")));
        }

        if let Some(candidate) = prepared.session {
            self.sessions.insert(from, candidate);
            self.touch_session(from);
        }
        self.receiver_seen.insert(id, seen);
        if let Some(item) = item {
            self.inbox.push(bundle.clone());
            self.inbox_order.push(id);
            self.durable_inbox.insert(id, item);
            self.durable_inbox_charges.insert(
                id,
                item_charge.expect("durable inbox item has an admission charge"),
            );
        } else {
            // The authenticated session-establishment ping is protocol control, not host content.
            // Once its session+seen commit succeeds there is no host acceptance to wait for.
            self.emit_inbox_ack(&acknowledgement);
        }
        if prepared.flush_pending {
            self.flush_pending_content();
        }
        Ok(())
    }

    /// Read a user message addressed to this node. Network ingress already decrypted and staged it;
    /// this legacy low-level seam returns that durable plaintext without accepting it. Hosts must call
    /// [`Self::accept_inbox`] explicitly. Direct unit-test bundles that bypass ingress retain the old
    /// one-shot decrypt behavior.
    pub fn read_message(&mut self, bundle: &Bundle) -> Result<Option<ReadMessage>> {
        let id = bundle.id();
        if let Some(item) = self.durable_inbox.get(&id).cloned() {
            let message = ReadMessage {
                from: item.from,
                content_type: item.content_type,
                body: item.body,
            };
            return Ok(Some(message));
        }
        match bundle.open(&self.identity)? {
            // §39 untraceable: the *real* sender rode inside the seal (the envelope src is
            // zeroed). The seal is NOT identity-signed, so `sender` is an unauthenticated claim
            // here — only a ratcheted inner (SessionInit/SessionMessage, which X3DH/Double-Ratchet
            // authenticate) may attribute a message to it. `authenticated=false` enforces that.
            Payload::Private { sender, inner } => self.read_inner_message(sender, *inner, false),
            // Normal path: the envelope is Ed25519-signed and verify() checked `src`, so a bare
            // PeerMessage attributed to `src` is authenticated.
            other => self.read_inner_message(bundle.inner.src, other, true),
        }
    }

    /// Decrypt a user-message payload attributed to `from` — shared by the normal path (where
    /// `from` is the cleartext, envelope-signed src) and the §39 private path (where it came from
    /// inside the *unsigned* seal). `authenticated` is true only when `from` is proven by the
    /// envelope signature; when false, a bare `PeerMessage` carries NO proof of `from` and must
    /// not be surfaced (sender spoofing, sec-priv-01/core-01) — only ratcheted payloads, which
    /// authenticate the sender cryptographically, may attribute a message on the private path.
    /// Establishes the responder side of a session on first `SessionInit`.
    fn read_inner_message(
        &mut self,
        from: PubKeyBytes,
        payload: Payload,
        authenticated: bool,
    ) -> Result<Option<ReadMessage>> {
        let prepared = self.prepare_inbound_message(from, payload, authenticated)?;
        if let Some(candidate) = prepared.session {
            self.commit_session(from, candidate)?;
        }
        if prepared.flush_pending {
            self.flush_pending_content();
        }
        Ok(prepared.message)
    }

    /// Build a candidate receive state without mutating the live ratchet. Ingress persists this
    /// candidate together with the decrypted inbox record; the legacy direct-read path commits it
    /// afterward through `commit_session`.
    fn prepare_inbound_message(
        &mut self,
        from: PubKeyBytes,
        payload: Payload,
        authenticated: bool,
    ) -> Result<PreparedInbound> {
        match payload {
            Payload::PeerMessage { content_type, body } => {
                if !authenticated {
                    // A bare PeerMessage inside an unsigned Private seal: anyone knowing the
                    // recipient's public address + published prekey could forge this "from
                    // <victim>". Device-to-device content is always forward-secret (a send
                    // without a ratchet is an error), so a private static PeerMessage is never
                    // legitimate — drop it rather than attribute it.
                    return Ok(PreparedInbound {
                        message: None,
                        session: None,
                        flush_pending: false,
                    });
                }
                Ok(PreparedInbound {
                    message: Some(ReadMessage {
                        from,
                        content_type,
                        body,
                    }),
                    session: None,
                    flush_pending: false,
                })
            }
            Payload::SessionInit {
                ek_pub,
                spk_pub,
                msg,
            } => {
                // Build (or rebuild) a candidate responder session off-map. A private envelope's
                // `from` is only a claim until this AEAD succeeds, so a forged fresh ephemeral must
                // neither replace an established ratchet nor trigger control traffic at the victim.
                // (ADV18-01 / core-protocol-r18-01: the same off-map-until-authenticated property this
                // review called for; main landed this restructure independently, so we adopt it.)
                let fresh = match self.sessions.get(&from) {
                    None => true,
                    Some(ps) => ps.established_by != Some(ek_pub),
                };
                let mut candidate = if fresh {
                    let secret = self
                        .spk_secrets
                        .get(&spk_pub)
                        .ok_or(Error::Crypto("unknown prekey"))?
                        .clone();
                    let root = crypto::x3dh_respond(&self.identity, &secret, &from, &ek_pub)?;
                    let session = Session::init_responder(root, *secret, spk_pub);
                    PeerSession {
                        session,
                        init_material: None,
                        established_by: Some(ek_pub),
                    }
                } else {
                    self.sessions.get(&from).expect("existing session").clone()
                };
                candidate.init_material = None;
                let decrypted = candidate.session.decrypt(&msg);
                match decrypted {
                    Ok(inner) => {
                        let message = self.surface_session_inner(from, &inner)?;
                        Ok(PreparedInbound {
                            message,
                            session: Some(candidate),
                            // A peer initiating to us establishes a session both ways, so content
                            // deferred to them can ratchet immediately after the atomic commit.
                            flush_pending: true,
                        })
                    }
                    Err(e) => {
                        if authenticated {
                            self.request_session_reset(from); // signed sender can safely be asked to reset
                        }
                        Err(e)
                    }
                }
            }
            Payload::SessionMessage { msg } => {
                let mut candidate = match self.sessions.get(&from).cloned() {
                    Some(ps) => ps,
                    // We lost our session (uninstall / lost p2p data) but they kept theirs:
                    // ask them to reset so a fresh handshake re-syncs the ratchet.
                    None => {
                        if authenticated {
                            self.request_session_reset(from);
                        }
                        return Err(Error::Crypto("no session for peer"));
                    }
                };
                candidate.init_material = None;
                let decrypted = candidate.session.decrypt(&msg);
                match decrypted {
                    Ok(inner) => {
                        let message = self.surface_session_inner(from, &inner)?;
                        Ok(PreparedInbound {
                            message,
                            session: Some(candidate),
                            flush_pending: false,
                        })
                    }
                    Err(e) => {
                        if authenticated {
                            self.request_session_reset(from);
                        }
                        Err(e)
                    }
                }
            }
            _ => Ok(PreparedInbound {
                message: None,
                session: None,
                flush_pending: false,
            }),
        }
    }

    /// Decode a decrypted session inner into a user message — unless it's a re-establishment
    /// ping (a content-less handshake we send to heal a desynced ratchet), which has done its
    /// job by rebuilding the session and isn't surfaced (DESIGN.md §25).
    fn surface_session_inner(
        &self,
        from: PubKeyBytes,
        inner: &[u8],
    ) -> Result<Option<ReadMessage>> {
        let si: SessionInner = postcard::from_bytes(inner)?;
        if si.content_type == SESSION_ESTABLISH_CT {
            return Ok(None);
        }
        Ok(Some(ReadMessage {
            from,
            content_type: si.content_type,
            body: si.body,
        }))
    }

    /// Tell `peer` our ratchet with them is broken so it drops its session and re-initiates
    /// (DESIGN.md §25). A control message (statically sealed, no content). Throttled so a
    /// burst of undecryptable messages can't cause a reset storm.
    fn request_session_reset(&mut self, peer: PubKeyBytes) {
        let due = match self.last_reset_req.get(&peer) {
            Some(&t) => self.now_ms.saturating_sub(t) >= REACK_MIN_INTERVAL_MS,
            None => true,
        };
        if !due {
            return;
        }
        self.last_reset_req.insert(peer, self.now_ms);
        if let Ok(b) = Bundle::create(
            &self.identity,
            Destination::Device(peer),
            &peer,
            &Payload::SessionReset,
            BundleOpts {
                created_at: self.now_ms,
                ..Default::default()
            },
        ) {
            self.submit(b);
        }
    }

    /// Handle an inbound [`Payload::SessionReset`]: drop our (stale) session with `peer` and
    /// proactively re-establish so the ratchet heals immediately — even before the next user
    /// message. The next `SessionInit` rebuilds the peer's side too (DESIGN.md §25).
    fn handle_session_reset(&mut self, peer: PubKeyBytes) {
        if self.delete_session(&peer).is_err() {
            return;
        }
        // Re-establish now if we know their prekey; otherwise the next content send re-inits.
        // A directed control ping to heal the ratchet with a peer who already knows us uses the
        // traced path (not the §39 default), so it's a unicast, not a flood.
        if self.directory.prekey(&peer).is_some() {
            let _ =
                self.send_message_traced(peer, SESSION_ESTABLISH_CT.to_string(), Vec::new(), false);
        }
    }

    /// Send a `hops://` request to a specific endpoint (DESIGN.md §30): a normal HTTP
    /// request sealed and addressed to the endpoint's Hop address — opaque to the mesh,
    /// indistinguishable from any other peer message (there is no mesh-visible "internet
    /// bound" destination). The endpoint executes it against its own backend and the reply
    /// arrives as an [`HttpRespItem`] via [`Node::take_http_responses`]. Returns the
    /// request id (the response correlates by it).
    #[allow(clippy::too_many_arguments)] // an HTTP request is inherently many fields
    pub fn send_hops_request(
        &mut self,
        endpoint: PubKeyBytes,
        host: String,
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        max_resp: u32,
    ) -> Result<BundleId> {
        let bundle = Bundle::create(
            &self.identity,
            Destination::Device(endpoint),
            &endpoint,
            &Payload::HttpRequest {
                host,
                method,
                url,
                headers,
                body,
                max_resp_bytes: max_resp,
            },
            BundleOpts {
                created_at: self.now_ms,
                ..Default::default()
            },
        )?;
        self.ensure_delivery_within_limits(&bundle)?;
        self.deliver_authorized_request(bundle, endpoint, RequestKind::Http)
    }

    // ---- HNS: the Hop Name System (DESIGN.md §30) ----------------------------------------
    //
    // HNS maps a domain to its hops endpoint address via a self-certifying reach record the
    // domain serves at `https://<domain>/.well-known/hop`. The host does the HTTPS fetch (its
    // TLS cert proves the domain); core verifies the record's signature (it proves the address)
    // and caches `domain -> address` for the record's TTL. Resolution needs the resolving node's
    // OWN internet — there is deliberately no relayed/mesh-assisted lookup.

    /// Declare whether this node can reach the public internet (and thus fetch a domain's
    /// well-known). When on, the node resolves HNS itself, surfacing the domains to fetch via
    /// [`Node::take_dns_lookups`]; the host feeds each reach record back via
    /// [`Node::provide_reach_record`].
    pub fn set_internet(&mut self, on: bool) {
        let gained = on && !self.internet;
        self.internet = on;
        // Just got internet → resolve anything that was waiting on it, ourselves.
        if gained {
            for key in self.pending_resolves.iter().cloned().collect::<Vec<_>>() {
                self.queue_dns_lookup(&key);
            }
        }
    }

    /// Whether this node is internet-connected (see [`Node::set_internet`]).
    pub fn is_internet(&self) -> bool {
        self.internet
    }

    /// A fresh cached HNS record for `domain`, if any: `Some(Some(addr))` resolved,
    /// `Some(None)` a cached negative, `None` not cached (or expired).
    pub fn cached_hns(&self, domain: &str) -> Option<Option<PubKeyBytes>> {
        let key = normalize_domain(domain);
        self.hns_cache
            .get(&key)
            .filter(|e| e.expires_at_ms > self.now_ms)
            .map(|e| e.address)
    }

    /// Resolve `domain` to its hops endpoint address (DESIGN.md §30). Serves from cache when
    /// fresh; otherwise, if this node is internet-connected, kicks off a name lookup: the host
    /// fetches `https://<domain>/.well-known/hop` (drained via [`Node::take_dns_lookups`]) and
    /// feeds the reach record back through [`Node::provide_reach_record`]. Without internet a name
    /// cannot be resolved (name lookup needs a TLS fetch this device must make itself), so it
    /// returns [`HnsLookup::NeedsResolver`] and is retried when internet arrives. Results arrive on
    /// [`Node::take_hns_results`].
    pub fn resolve_hns(&mut self, domain: &str) -> HnsLookup {
        let key = normalize_domain(domain);
        if let Some(addr) = self.cached_hns(&key) {
            return HnsLookup::Cached(addr);
        }
        if !self.internet {
            // Reach records are fetched over the domain's own TLS-authenticated well-known, which
            // only THIS device can do trustlessly. There is no mesh-assisted resolution anymore, so
            // without internet the name stays pending and resolves when internet arrives.
            self.pending_resolves.insert(key);
            return HnsLookup::NeedsResolver;
        }
        self.pending_resolves.insert(key.clone());
        self.attempt_resolve(&key);
        HnsLookup::Pending
    }

    /// Queue a name lookup for the host if this device is internet-connected. A no-op without
    /// internet (the domain stays in `pending_resolves` for a retry when internet arrives).
    fn attempt_resolve(&mut self, key: &str) {
        if self.internet {
            self.queue_dns_lookup(key);
        }
    }

    /// Persisted records that failed to decode during startup rehydrate (F-03), clearing the
    /// tally. A non-empty result means an upgrade changed a struct's on-disk layout and dropped
    /// state; the host should log it (e.g. "3 sessions, 1 pending send lost on upgrade") so a
    /// silent wipe is observable. Empty on a clean start.
    pub fn take_rehydrate_report(&mut self) -> RehydrateReport {
        std::mem::take(&mut self.rehydrate_report)
    }

    /// Domains the host must resolve by fetching `https://<domain>/.well-known/hop`, clearing the
    /// queue. The host feeds each fetched reach record back via [`Node::provide_reach_record`].
    pub fn take_dns_lookups(&mut self) -> Vec<String> {
        let lookups = std::mem::take(&mut self.dns_lookups);
        for charge in std::mem::take(&mut self.dns_lookup_charges) {
            self.release_app_queue(charge);
        }
        lookups
    }

    /// §39 P5: mailbox-tags that just received a want-beacon (a recipient's [`AdvertKind::RecvBeacon`]
    /// newly accepted here), clearing the queue. The host reloads each mailbox's durable blind spool
    /// and re-ingests the held private bundles, which P4's freshly-laid gradient then steers to the
    /// recipient. The node does no durable I/O itself — it only surfaces the tags (cf. DNS lookups).
    pub fn take_wanted_mailboxes(&mut self) -> Vec<Tag> {
        std::mem::take(&mut self.wanted_mailboxes)
    }

    /// Feed back the reach-record bytes the host fetched from `https://<domain>/.well-known/hop`
    /// (DESIGN.md §30). The host proved the DOMAIN by validating the TLS certificate on that fetch
    /// (its own trust boundary); core proves the ADDRESS by verifying the self-certifying reach
    /// record against the address it carries (no external anchor, see [`crate::reach`]). Together:
    /// the entity controlling `domain`'s TLS asserts this address. A verify failure (bad signature,
    /// expired, malformed) caches a short negative.
    pub fn provide_reach_record(&mut self, domain: &str, record: Vec<u8>) {
        let key = normalize_domain(domain);
        let now_ms = self.now_ms;
        let (address, expires_at_ms) =
            match crate::reach::ReachRecord::verify(&record, Some(now_ms / 1000)) {
                Some(rec) => {
                    // reach-A audit: trust the address until the record's OWN absolute expiry
                    // (issued_at + ttl), NOT now + ttl. Caching for a full ttl from FETCH time would keep a
                    // record fetched just before its expiry alive for up to ~2x ttl, so a publisher's
                    // revocation-by-expiry could linger past the window the record itself declares (and past
                    // what reach.rs documents). verify() already ensured now <= issued_at + ttl, so the
                    // absolute expiry is >= now; cap the horizon at MAX_HNS_TTL from now against a bogus
                    // far-future ttl.
                    let abs = rec
                        .claim
                        .issued_at
                        .saturating_add(rec.claim.ttl_secs as u64)
                        .saturating_mul(1000);
                    (
                        Some(rec.claim.address),
                        abs.min(now_ms.saturating_add(MAX_HNS_TTL_MS)),
                    )
                }
                None => (None, now_ms.saturating_add(60_000)), // unverifiable → short (60s) negative cache
            };
        let Some(charge) =
            self.reserve_app_queue(AppQueueKind::HnsResult, None, key.len().saturating_add(40))
        else {
            self.dns_inflight.remove(&key);
            return;
        };
        self.dns_inflight.remove(&key);
        self.pending_resolves.remove(&key);
        self.hns_cache.insert(
            key.clone(),
            HnsEntry {
                address,
                expires_at_ms,
            },
        );
        self.hns_results.push(HnsResult {
            domain: key.clone(),
            address,
        });
        self.hns_result_charges.push(charge);
    }

    /// Test-only: inject a pre-trusted resolution result, bypassing the reach-record fetch +
    /// signature check, to drive the resolution state machine (cache/waiters/pending) in unit
    /// tests. Production always goes through [`Node::provide_reach_record`].
    #[cfg(test)]
    pub fn provide_dns_answer(
        &mut self,
        domain: &str,
        address: Option<PubKeyBytes>,
        ttl_secs: u32,
    ) {
        let key = normalize_domain(domain);
        let Some(charge) =
            self.reserve_app_queue(AppQueueKind::HnsResult, None, key.len().saturating_add(40))
        else {
            self.dns_inflight.remove(&key);
            return;
        };
        self.dns_inflight.remove(&key);
        self.pending_resolves.remove(&key); // resolved (positive or negative) — stop retrying
        let ttl_ms = (ttl_secs as u64).clamp(MIN_HNS_TTL_MS / 1000, MAX_HNS_TTL_MS / 1000) * 1000;
        self.hns_cache.insert(
            key.clone(),
            HnsEntry {
                address,
                expires_at_ms: self.now_ms.saturating_add(ttl_ms),
            },
        );
        self.hns_results.push(HnsResult {
            domain: key.clone(),
            address,
        });
        self.hns_result_charges.push(charge);
    }

    /// Finished HNS resolutions (positive or negative), clearing the queue.
    pub fn take_hns_results(&mut self) -> Vec<HnsResult> {
        let results = std::mem::take(&mut self.hns_results);
        for charge in std::mem::take(&mut self.hns_result_charges) {
            self.release_app_queue(charge);
        }
        results
    }

    /// Sign a self-certifying reachability record for THIS node's address, binding it to `endpoint`
    /// (e.g. `wss://myaddress.com/_hop` or `1.2.3.4:9944`) for `ttl_secs`. Serve it from
    /// `/.well-known/hop` or gossip it; anyone verifies it against the address it carries, no trust
    /// anchor needed (see [`crate::reach`]).
    pub fn sign_reach_record(&self, endpoint: String, ttl_secs: u32) -> crate::reach::ReachRecord {
        crate::reach::ReachRecord::sign(&self.identity, endpoint, ttl_secs, self.now_ms / 1000)
    }

    // ---- hps:// pub/sub: services & channels (DESIGN.md §32) -----------------------------

    /// Register a `hps://` topic at `path` that this node hosts, minting its keys. `access`
    /// governs key handoff (Open/RequestToJoin/Invite) and `visibility` whether it's advertised
    /// for discovery (DESIGN.md §32). Returns the service public key for a `Service` (`None` for
    /// a `Channel`). Re-registering replaces it.
    pub fn register_service(
        &mut self,
        path: &str,
        kind: hps::ServiceKind,
        access: hps::AccessMode,
        visibility: hps::Visibility,
    ) -> Option<[u8; 32]> {
        let cfg = hps::ServiceConfig::new_with(kind, access, visibility);
        let pk = cfg.service_pubkey();
        if visibility == hps::Visibility::Discoverable {
            self.publish_topic_advert(path, &cfg);
        }
        self.persist_service(path, &cfg);
        self.services.insert(path.to_string(), cfg);
        pk
    }

    /// Current join-proof time bucket (DESIGN.md §32 app isolation).
    fn join_bucket(&self) -> u64 {
        self.now_ms / crate::app::JOIN_EPOCH_MS
    }

    /// Proof that we hold the app secret, bound to `path` + `who` for the current bucket.
    fn hps_proof(&self, path: &str, who: &PubKeyBytes) -> [u8; 32] {
        self.app.join_proof(path, who, self.join_bucket())
    }

    /// Verify an inbound hps proof from `sender`, and that the bundle is on our app.
    fn hps_authorized(&self, bundle: &Bundle, path: &str, proof: &[u8; 32]) -> bool {
        bundle.inner.app == self.app.id
            && self
                .app
                .verify_join_proof(proof, path, &bundle.inner.src, self.join_bucket())
    }

    fn expire_hps_subscribe_pending(&mut self) -> Result<()> {
        let stale: Vec<String> = self
            .hps_subscribe_pending
            .iter()
            .filter(|(_, pending)| pending.expires_at_ms <= self.now_ms)
            .map(|(path, _)| path.clone())
            .collect();
        if stale.is_empty() {
            return Ok(());
        }
        let mutations: Vec<KvMutation> = stale
            .iter()
            .map(|path| KvMutation::Remove {
                key: Self::hps_subscribe_pending_key(path),
            })
            .collect();
        self.store
            .apply_kv_batch(&mutations)
            .map_err(|e| Error::Other(format!("subscription expiry persistence failed: {e}")))?;
        for path in stale {
            self.hps_subscribe_pending.remove(&path);
            self.unanchored_hps_subscribe_pending.remove(&path);
        }
        Ok(())
    }

    fn enforce_hps_subscribe_pending_limit(&mut self) -> Result<()> {
        let excess = self
            .hps_subscribe_pending
            .len()
            .saturating_sub(MAX_HPS_SUBSCRIBE_PENDING);
        if excess == 0 {
            return Ok(());
        }
        let mut by_expiry: Vec<(String, u64)> = self
            .hps_subscribe_pending
            .iter()
            .map(|(path, pending)| (path.clone(), pending.expires_at_ms))
            .collect();
        by_expiry.sort_by_key(|(_, expiry)| *expiry);
        let victims: Vec<String> = by_expiry
            .into_iter()
            .take(excess)
            .map(|(path, _)| path)
            .collect();
        let mutations: Vec<KvMutation> = victims
            .iter()
            .map(|path| KvMutation::Remove {
                key: Self::hps_subscribe_pending_key(path),
            })
            .collect();
        self.store
            .apply_kv_batch(&mutations)
            .map_err(|e| Error::Other(format!("subscription cap persistence failed: {e}")))?;
        for victim in victims {
            self.hps_subscribe_pending.remove(&victim);
            self.unanchored_hps_subscribe_pending.remove(&victim);
        }
        Ok(())
    }

    fn expect_hps_keys(&mut self, host: PubKeyBytes, path: &str) -> Result<()> {
        if path.len() > MAX_HPS_PATH_BYTES {
            return Err(Error::Other("subscription path exceeds limit".into()));
        }
        self.expire_hps_subscribe_pending()?;
        if self.subscriptions.contains_key(path) {
            return Err(Error::Other("already subscribed to this path".into()));
        }
        if let Some(expected) = self.hps_subscribe_pending.get(path) {
            if expected.host != host {
                return Err(Error::Other(
                    "subscription path is already pending from another host".into(),
                ));
            }
        }
        let pending = PendingHpsSubscription {
            host,
            expires_at_ms: self.now_ms.saturating_add(HPS_SUBSCRIBE_PENDING_TTL_MS),
        };
        let mut mutations = vec![KvMutation::Put {
            key: Self::hps_subscribe_pending_key(path),
            value: postcard::to_allocvec(&pending)?,
        }];
        let victim = if !self.hps_subscribe_pending.contains_key(path)
            && self.hps_subscribe_pending.len() >= MAX_HPS_SUBSCRIBE_PENDING
        {
            self.hps_subscribe_pending
                .iter()
                .min_by_key(|(_, candidate)| candidate.expires_at_ms)
                .map(|(candidate, _)| candidate.clone())
        } else {
            None
        };
        if let Some(victim) = &victim {
            mutations.push(KvMutation::Remove {
                key: Self::hps_subscribe_pending_key(victim),
            });
        }
        self.store.apply_kv_batch(&mutations).map_err(|e| {
            Error::Other(format!("subscription expectation persistence failed: {e}"))
        })?;
        if let Some(victim) = victim {
            self.hps_subscribe_pending.remove(&victim);
            self.unanchored_hps_subscribe_pending.remove(&victim);
        }
        self.hps_subscribe_pending.insert(path.to_string(), pending);
        self.unanchored_hps_subscribe_pending.remove(path);
        Ok(())
    }

    /// Subscribe to `hps://{host}/{path}`: send a sealed, proof-carrying join request to `host`.
    /// For an Open topic the keys come straight back; RequestToJoin queues for host approval;
    /// Invite topics can't be self-joined (wait for an invite).
    pub fn hps_subscribe(&mut self, host: PubKeyBytes, path: &str) -> Result<BundleId> {
        self.expect_hps_keys(host, path)?;
        let proof = self.hps_proof(path, &self.identity.address());
        self.send_to_host(
            host,
            Payload::HpsJoinRequest {
                path: path.to_string(),
                proof,
            },
        )
    }

    /// Host → destination: invite an address to a topic we host (Invite mode). The destination
    /// accepts to receive keys.
    pub fn hps_invite(&mut self, path: &str, dest: PubKeyBytes) -> Result<BundleId> {
        let cfg = self
            .services
            .get(path)
            .ok_or_else(|| Error::Other("not a topic we host".into()))?;
        let kind = cfg.kind;
        let proof = self.hps_proof(path, &self.identity.address());
        self.hps_invites_out
            .insert((path.to_string(), dest), self.now_ms);
        self.persist_invites();
        self.send_to_host(
            dest,
            Payload::HpsInvite {
                path: path.to_string(),
                kind,
                proof,
            },
        )
    }

    /// Member → host: accept an invite we received, which prompts the host to seal us the keys.
    pub fn hps_accept_invite(&mut self, host: PubKeyBytes, path: &str) -> Result<BundleId> {
        self.expect_hps_keys(host, path)?;
        self.remove_hps_invite_item(host, path);
        self.persist_invites();
        let proof = self.hps_proof(path, &self.identity.address());
        self.send_to_host(
            host,
            Payload::HpsInviteAccept {
                path: path.to_string(),
                proof,
            },
        )
    }

    /// Member → host: leave a topic (drop from the retained set so we're not re-keyed).
    pub fn hps_leave(&mut self, path: &str) -> Result<Option<BundleId>> {
        let Some(sub) = self.subscriptions.get(path).cloned() else {
            return Ok(None);
        };
        let proof = self.hps_proof(path, &self.identity.address());
        let bundle = Bundle::create(
            &self.identity,
            Destination::Device(sub.host),
            &sub.host,
            &Payload::HpsLeave {
                path: path.to_string(),
                proof,
            },
            BundleOpts {
                app: self.app.id,
                created_at: self.now_ms,
                ..Default::default()
            },
        )?;
        self.ensure_delivery_within_limits(&bundle)?;
        let (id, custody, carrier) = self.prepare_delivery_custody(bundle)?;

        let replay_topics: Vec<_> = self
            .hps_replays
            .keys()
            .copied()
            .filter(|(topic_tag, _)| *topic_tag == sub.topic_tag)
            .collect();
        let inbox_ids: Vec<_> = self
            .hps_inbox
            .iter()
            .filter(|message| message.path == path)
            .map(|message| message.id)
            .collect();
        let mut mutations = Vec::with_capacity(
            2 + replay_topics.len()
                + inbox_ids.len()
                + custody.len()
                + usize::from(carrier.is_some()),
        );
        mutations.push(KvMutation::Remove {
            key: Self::hps_sub_key(path),
        });
        mutations.extend(
            replay_topics
                .iter()
                .map(|(topic_tag, epoch)| KvMutation::Remove {
                    key: Self::hps_replay_key(topic_tag, *epoch),
                }),
        );
        mutations.extend(inbox_ids.iter().map(|message_id| KvMutation::Remove {
            key: Self::hps_inbox_key(message_id),
        }));
        if let Some(carrier) = &carrier {
            mutations.push(KvMutation::Put {
                key: Self::outgoing_carrier_key(&id),
                value: postcard::to_allocvec(carrier)?,
            });
        }
        mutations.extend(custody.iter().cloned().map(|bundle| KvMutation::PutBundle {
            bundle: Box::new(bundle),
            now_ms: self.now_ms,
        }));
        self.store
            .apply_kv_batch(&mutations)
            .map_err(|e| Error::Other(format!("leave persistence failed: {e}")))?;

        self.subscriptions.remove(path);
        self.directory.unsubscribe(path);
        for topic in replay_topics {
            self.hps_replays.remove(&topic);
        }
        self.hps_acked
            .retain(|(topic_tag, _), _| *topic_tag != sub.topic_tag);
        let messages = std::mem::take(&mut self.hps_inbox);
        let charges = std::mem::take(&mut self.hps_inbox_charges);
        for (message, charge) in messages.into_iter().zip(charges) {
            if message.path == path {
                self.hps_inbox_expires.remove(&message.id);
                self.release_app_queue(charge);
            } else {
                self.hps_inbox.push(message);
                self.hps_inbox_charges.push(charge);
            }
        }

        self.tx.entry(id).or_default();
        self.forwarded
            .insert(id, (self.identity.address(), sub.host, self.now_ms));
        let stored = self.activate_delivery_custody(id, &custody, carrier);
        for custody_id in stored {
            self.offer_bundle_to_all_except(custody_id, LOCAL_LINK);
        }
        Ok(Some(id))
    }

    /// Host: pending join requests for a RequestToJoin topic.
    pub fn hps_pending(&self, path: &str) -> Vec<PubKeyBytes> {
        self.hps_pending.get(path).cloned().unwrap_or_default()
    }

    /// Host: approve a pending requester, sealing them the topic keys.
    pub fn hps_approve(&mut self, path: &str, requester: PubKeyBytes) -> Result<BundleId> {
        if let Some(q) = self.hps_pending.get_mut(path) {
            q.retain(|a| *a != requester);
        }
        self.persist_pending(path);
        self.record_member(path, requester);
        self.send_keys(path, requester)
    }

    /// Host: deny/drop a pending requester (no keys).
    pub fn hps_deny(&mut self, path: &str, requester: PubKeyBytes) {
        if let Some(q) = self.hps_pending.get_mut(path) {
            q.retain(|a| *a != requester);
        }
        self.persist_pending(path);
    }

    /// Host: unique acking addresses for a topic (its reach / sense of delivery, DESIGN.md §32).
    pub fn hps_reach(&self, path: &str) -> usize {
        self.hps_reach.get(path).map(|s| s.len()).unwrap_or(0)
    }

    /// Host: the retained-member set (joined/approved/accepted/acked), used for rekey.
    pub fn hps_members(&self, path: &str) -> Vec<PubKeyBytes> {
        self.hps_members
            .get(path)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Member: invites we've received and not yet accepted (DESIGN.md §32 Invite mode).
    pub fn take_hps_invites(&mut self) -> Vec<HpsInviteItem> {
        // Drain the in-memory display queue but DON'T touch the durable copy — an unaccepted
        // invite must survive a restart (persistence updates only on arrival / accept / decline).
        let invites = std::mem::take(&mut self.hps_invites_in);
        for charge in std::mem::take(&mut self.hps_invite_charges) {
            self.release_app_queue(charge);
        }
        invites
    }

    /// Decline an invite (member side) — drop it from the durable set so it doesn't reappear.
    pub fn hps_decline_invite(&mut self, host: PubKeyBytes, path: &str) {
        self.remove_hps_invite_item(host, path);
        self.persist_invites();
    }

    fn remove_hps_invite_item(&mut self, host: PubKeyBytes, path: &str) {
        let mut kept_items = Vec::with_capacity(self.hps_invites_in.len());
        let mut kept_charges = Vec::with_capacity(self.hps_invite_charges.len());
        let items = std::mem::take(&mut self.hps_invites_in);
        let charges = std::mem::take(&mut self.hps_invite_charges);
        for (item, charge) in items.into_iter().zip(charges) {
            if item.path == path && item.host == host {
                self.release_app_queue(charge);
            } else {
                kept_items.push(item);
                kept_charges.push(charge);
            }
        }
        self.hps_invites_in = kept_items;
        self.hps_invite_charges = kept_charges;
    }

    /// Host: selective forward rotation (revocation, DESIGN.md §32). Mint a fresh key (and,
    /// optionally, move the topic to `new_path`), re-key every retained member except those in
    /// `remove`, tombstone the old discovery advert, and re-advertise. Removed members keep the
    /// dead key (forward-only). Returns the rekey bundle ids.
    pub fn hps_rekey(
        &mut self,
        path: &str,
        new_path: Option<&str>,
        remove: &[PubKeyBytes],
    ) -> Result<Vec<BundleId>> {
        self.expire_hps_subscribe_pending()?;
        let new_path = new_path.unwrap_or(path).to_string();
        if new_path != path
            && (self.services.contains_key(&new_path)
                || self.subscriptions.contains_key(&new_path)
                || self.hps_members.contains_key(&new_path)
                || self.hps_pending.contains_key(&new_path)
                || self.hps_subscribe_pending.contains_key(&new_path))
        {
            return Err(Error::Other("rekey destination path already exists".into()));
        }
        let mut cfg = self
            .services
            .get(path)
            .cloned()
            .ok_or_else(|| Error::Other("not a topic we host".into()))?;
        cfg.rotate();
        let svc_pk = cfg.service_pubkey();
        let epoch = cfg.epoch;
        let discoverable = cfg.visibility == hps::Visibility::Discoverable;

        // Retained = current members + reach acks, minus the removed set.
        let removed: std::collections::HashSet<PubKeyBytes> = remove.iter().copied().collect();
        let mut retained: std::collections::HashSet<PubKeyBytes> =
            self.hps_members.get(path).cloned().unwrap_or_default();
        if let Some(r) = self.hps_reach.get(path) {
            retained.extend(r.iter().copied());
        }
        retained.retain(|a| !removed.contains(a) && *a != self.identity.address());

        // Commit the new generation, reduced member set, and every old-path deletion in one Store
        // transaction. A crash or injected failure can expose either the old complete generation or
        // the new complete generation, never a mix that resurrects a revoked member on restart.
        let members: Vec<PubKeyBytes> = retained.iter().copied().collect();
        let mut mutations = vec![
            KvMutation::Put {
                key: Self::hps_svc_key(&new_path),
                value: postcard::to_allocvec(&cfg)?,
            },
            KvMutation::Put {
                key: Self::hps_members_key(&new_path),
                value: postcard::to_allocvec(&members)?,
            },
        ];
        if path != new_path {
            mutations.extend([
                KvMutation::Remove {
                    key: Self::hps_svc_key(path),
                },
                KvMutation::Remove {
                    key: Self::hps_members_key(path),
                },
                KvMutation::Remove {
                    key: Self::hps_pending_key(path),
                },
            ]);
        }
        self.store
            .apply_kv_batch(&mutations)
            .map_err(|e| Error::Other(format!("hps generation persistence failed: {e}")))?;

        // Tombstone old discovery advert and clear reach for the fresh epoch.
        if let Some(old_id) = self.hps_adverts.remove(path) {
            self.tombstone_advert(old_id);
        }
        self.hps_reach.remove(path);

        // Move state to the new path.
        if path != new_path {
            self.services.remove(path);
            self.hps_members.remove(path);
            self.hps_pending.remove(path);
        }
        let content_key = cfg.content_key;
        self.services.insert(new_path.clone(), cfg);
        self.hps_members.insert(new_path.clone(), retained.clone());
        if discoverable {
            let cfg = self.services[&new_path].clone();
            self.publish_topic_advert(&new_path, &cfg);
        }

        // Re-key each retained member.
        let mut ids = Vec::new();
        let me = self.identity.address();
        for m in retained {
            let proof = self.hps_proof(path, &me);
            let payload = Payload::HpsRekey {
                old_path: path.to_string(),
                new_path: new_path.clone(),
                epoch,
                content_key,
                service_pubkey: svc_pk,
                proof,
            };
            if let Ok(id) = self.send_to_host(m, payload) {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// Publish a message to a topic we can write to — a `Service` we host (signed by the
    /// service key) or a `Channel` we belong to (signed by our own identity). Floods to all
    /// subscribers via [`Destination::Broadcast`].
    /// Register an `hps://` topic with a caller-supplied pre-shared **content key**, so a group that
    /// already agrees on the key (endpoint replicas deriving it from a shared secret, say) can read
    /// and write the topic with NO host/join handshake. Behaves like a channel subscription: each
    /// publish is signed by the sender's identity and verified against `src` on receipt. Idempotent
    /// per `path`. This is a general pre-shared-key primitive; it knows nothing about clusters.
    pub fn hps_register_keyed(&mut self, path: &str, content_key: [u8; 32]) {
        let sub = HpsSubscription {
            content_key,
            service_pubkey: None, // channel-style: members sign with their own identity
            host: self.identity.address(), // no distinct host in a pre-shared-key group
            epoch: 0,
            topic_tag: self.app.topic_tag(path),
        };
        self.subscriptions.insert(path.to_string(), sub);
    }

    pub fn hps_publish(&mut self, path: &str, plaintext: &[u8]) -> Result<BundleId> {
        let app = self.app.id;
        let sender = self.identity.address();
        let topic_tag = self.app.topic_tag(path);
        let (content_key, epoch) = if let Some(cfg) = self.services.get(path) {
            let content_key = cfg.content_key;
            let epoch = cfg.epoch;
            let (nonce, ct) = hps::seal_content(&content_key, plaintext);
            let sig = match cfg.signing_seed {
                Some(seed) => {
                    hps::sign_publish(&seed, &app, &sender, &topic_tag, epoch, &nonce, &ct).to_vec()
                }
                None => self
                    .identity
                    .sign(&hps::publish_signing_bytes(
                        &app, &sender, &topic_tag, epoch, &nonce, &ct,
                    ))
                    .to_vec(),
            };
            return self.broadcast_publish(topic_tag, epoch, nonce, ct, sig);
        } else if let Some(sub) = self.subscriptions.get(path) {
            if sub.service_pubkey.is_some() {
                return Err(Error::Other(
                    "cannot publish to a service you don't host".into(),
                ));
            }
            (sub.content_key, sub.epoch)
        } else {
            return Err(Error::Other("not a registered or subscribed topic".into()));
        };
        // Channel member path: sign with our own identity.
        let (nonce, ct) = hps::seal_content(&content_key, plaintext);
        let signature = self
            .identity
            .sign(&hps::publish_signing_bytes(
                &app, &sender, &topic_tag, epoch, &nonce, &ct,
            ))
            .to_vec();
        self.broadcast_publish(topic_tag, epoch, nonce, ct, signature)
    }

    /// Seal an [`Payload::HpsPublish`] to the shared broadcast key and flood it. The wire form
    /// carries the opaque `topic_tag` (not the path) so a foreign app can't tell which topic.
    fn broadcast_publish(
        &mut self,
        topic_tag: [u8; 16],
        epoch: u32,
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
        sig: Vec<u8>,
    ) -> Result<BundleId> {
        let bundle = Bundle::create(
            &self.identity,
            Destination::Broadcast,
            &hps::broadcast_identity().address(),
            &Payload::HpsPublish {
                topic_tag,
                epoch,
                nonce: nonce.to_vec(),
                ciphertext,
                sig,
            },
            BundleOpts {
                app: self.app.id,
                created_at: self.now_ms,
                ..Default::default()
            },
        )?;
        self.ensure_delivery_within_limits(&bundle)?;
        let id = bundle.id();
        self.submit_checked(bundle)?;
        Ok(id)
    }

    /// Poll received pub/sub messages without consuming them. Stable publication ids are returned
    /// until [`Self::accept_hps_message`] durably removes each row.
    pub fn take_hps_messages(&self) -> Vec<HpsMessage> {
        self.hps_inbox
            .iter()
            .filter(|message| {
                self.hps_inbox_expires
                    .get(&message.id)
                    .is_some_and(|expiry| *expiry > self.now_ms)
            })
            .cloned()
            .collect()
    }

    /// Explicitly accept one host-persisted HPS publication. A failed critical delete leaves the
    /// row live and pollable, so a crash or storage fault cannot turn replay protection into loss.
    pub fn accept_hps_message(&mut self, id: &BundleId) -> Result<bool> {
        let Some(index) = self.hps_inbox.iter().position(|message| &message.id == id) else {
            return Ok(false);
        };
        self.store
            .remove_kv_critical(&Self::hps_inbox_key(id))
            .map_err(|e| Error::Other(format!("hps inbox acceptance failed: {e}")))?;
        self.hps_inbox.remove(index);
        self.hps_inbox_expires.remove(id);
        let charge = self.hps_inbox_charges.remove(index);
        self.release_app_queue(charge);
        Ok(true)
    }

    /// Process a broadcast `HpsPublish`: match its `topic_tag` to a subscription, verify the
    /// sender's signature against the known path, decrypt, surface it, and reach-ack the host.
    /// Drops stale-epoch messages (post-rekey) and anything we can't verify/decrypt.
    fn process_broadcast(&mut self, bundle: &Bundle) -> bool {
        if bundle.inner.app != self.app.id {
            return true;
        }
        let Ok(Payload::HpsPublish {
            topic_tag,
            epoch,
            nonce,
            ciphertext,
            sig,
        }) = bundle.open(&hps::broadcast_identity())
        else {
            return true;
        };
        let (Ok(nonce12), Ok(sig64)) = (
            <[u8; 12]>::try_from(nonce.as_slice()),
            <[u8; 64]>::try_from(sig.as_slice()),
        ) else {
            return true;
        };
        // Match the tag to a topic we follow (subscription) OR a channel we host. The host must
        // receive members' posts too — a channel is group chat, and the host keeps it in
        // `services`, not `subscriptions`. A *service* we host never receives others' posts
        // (only the owner writes).
        let sub = self
            .subscriptions
            .iter()
            .find(|(_, s)| s.topic_tag == topic_tag)
            .map(|(p, s)| (p.clone(), s.clone()));
        let (path, content_key, service_pubkey, my_epoch, host) = if let Some((p, s)) = sub {
            (p, s.content_key, s.service_pubkey, s.epoch, Some(s.host))
        } else if let Some((p, cfg)) = self
            .services
            .iter()
            .find(|(p, c)| {
                c.kind == hps::ServiceKind::Channel && self.app.topic_tag(p) == topic_tag
            })
            .map(|(p, c)| (p.clone(), c.clone()))
        {
            (p, cfg.content_key, None, cfg.epoch, None) // None host = we are the host
        } else {
            return true; // not a topic we follow or host (or another app's broadcast)
        };
        if epoch != my_epoch {
            return true; // only the exact installed generation may be opened
        }
        if service_pubkey.is_some() && host != Some(bundle.inner.src) {
            return true; // a service publication must come from the host stored with the subscription
        }
        // Service → verify against the service key; channel → against the sender's address.
        let signer = service_pubkey.unwrap_or(bundle.inner.src);
        if !hps::verify_publish(
            &signer,
            &bundle.inner.app,
            &bundle.inner.src,
            &topic_tag,
            epoch,
            &nonce12,
            &ciphertext,
            &sig64,
        ) {
            return true;
        }
        let Some(body) = hps::open_content(&content_key, &nonce12, &ciphertext) else {
            return true;
        };
        let publication_id = hps::publication_id(
            &bundle.inner.app,
            &bundle.inner.src,
            &topic_tag,
            epoch,
            &nonce12,
            &ciphertext,
            &sig64,
        );
        let replay_expires_at = self
            .now_ms
            .saturating_add((bundle.inner.lifetime_ms as u64).min(MAX_SEEN_LIFETIME_MS));
        if self.hps_publication_recorded(&topic_tag, epoch, &publication_id) {
            return true;
        }
        if !self.app_payload_policy.supports(AppQueueKind::HpsMessage) {
            return true;
        }
        let Some(charge) = self.reserve_app_queue(
            AppQueueKind::HpsMessage,
            Some(bundle.inner.src),
            path.len().saturating_add(body.len()).saturating_add(64),
        ) else {
            return false;
        };
        let message = HpsMessage {
            id: publication_id,
            path: path.clone(),
            sender: bundle.inner.src,
            body,
        };
        match self.accept_hps_publication(topic_tag, epoch, message, replay_expires_at, charge) {
            Ok(true) => {}
            Ok(false) => {
                self.release_app_queue(charge);
                return true;
            }
            Err(_) => {
                self.release_app_queue(charge);
                return false;
            }
        }
        match host {
            Some(h) => {
                // We're a member: reach-ack the host once per (topic, epoch) so it tallies us.
                if self.record_hps_ack((topic_tag, epoch), replay_expires_at) {
                    let member = self.identity.address();
                    let mac =
                        hps::reach_ack_mac(&content_key, &self.app.id, &member, &topic_tag, epoch);
                    let _ = self.send_to_host(
                        h,
                        Payload::HpsReachAck {
                            topic_tag,
                            epoch,
                            mac,
                        },
                    );
                }
            }
            None => {
                // We're the host: a member posting is direct evidence of membership.
                self.record_member(&path, bundle.inner.src);
                self.hps_reach
                    .entry(path)
                    .or_default()
                    .insert(bundle.inner.src);
            }
        }
        true
    }

    // --- hps internal helpers --------------------------------------------------------------

    /// Seal a directed hps control payload to `to` (sealed + app-stamped) and deliver it.
    fn send_to_host(&mut self, to: PubKeyBytes, payload: Payload) -> Result<BundleId> {
        let bundle = Bundle::create(
            &self.identity,
            Destination::Device(to),
            &to,
            &payload,
            BundleOpts {
                app: self.app.id,
                created_at: self.now_ms,
                ..Default::default()
            },
        )?;
        self.ensure_delivery_within_limits(&bundle)?;
        let id = bundle.id();
        self.tx.entry(id).or_default();
        self.forwarded
            .insert(id, (self.identity.address(), to, self.now_ms));
        self.deliver(bundle)?;
        Ok(id)
    }

    /// Host: seal the current keys for `path` to a member.
    fn send_keys(&mut self, path: &str, to: PubKeyBytes) -> Result<BundleId> {
        let cfg = self
            .services
            .get(path)
            .ok_or_else(|| Error::Other("no such topic".into()))?;
        let payload = Payload::HpsKeys {
            path: path.to_string(),
            content_key: cfg.content_key,
            service_pubkey: cfg.service_pubkey(),
            epoch: cfg.epoch,
        };
        self.send_to_host(to, payload)
    }

    /// Host: remember a member for reach/rekey.
    fn record_member(&mut self, path: &str, who: PubKeyBytes) {
        let added = self
            .hps_members
            .entry(path.to_string())
            .or_default()
            .insert(who);
        if added {
            self.persist_members(path);
        }
    }

    /// Store a subscription we've been handed (Open keys, invite/approve keys, or a rekey).
    #[cfg(test)]
    fn install_subscription(
        &mut self,
        path: &str,
        host: PubKeyBytes,
        content_key: [u8; 32],
        service_pubkey: Option<[u8; 32]>,
        epoch: u32,
    ) {
        let sub = HpsSubscription {
            content_key,
            service_pubkey,
            host,
            epoch,
            topic_tag: self.app.topic_tag(path),
        };
        self.directory.subscribe(path.to_string());
        self.persist_subscription(path, &sub);
        self.subscriptions.insert(path.to_string(), sub);
    }

    /// Build + gossip a Discoverable topic's advert (descriptor encrypted under the app key).
    fn publish_topic_advert(&mut self, path: &str, cfg: &hps::ServiceConfig) {
        let Some(disc_key) = self.app.disc_key else {
            return;
        }; // fabric: no discovery isolation
        let (nonce, ct) = hps::seal_meta(&disc_key, &cfg.meta(path));
        self.advert_seq += 1;
        if let Ok(advert) = crate::discover::Advert::publish_in(
            self.app.id,
            &self.identity,
            crate::discover::AdvertKind::HpsTopic { nonce, ct },
            self.now_ms,
            HPS_TOPIC_TTL_MS,
            self.advert_seq,
        ) {
            self.hps_adverts.insert(path.to_string(), advert.id);
            self.publish(advert);
        }
    }

    /// Tombstone a previously published advert id (revocation / rekey).
    fn tombstone_advert(&mut self, revokes: crate::discover::AdvertId) {
        self.advert_seq += 1;
        if let Ok(tomb) = crate::discover::Advert::publish_in(
            self.app.id,
            &self.identity,
            crate::discover::AdvertKind::Tombstone { revokes },
            self.now_ms,
            HPS_TOPIC_TTL_MS,
            self.advert_seq,
        ) {
            self.publish(tomb);
        }
    }

    /// The topics this node hosts or follows, so the app can rebuild its channel list after a
    /// restart (topics persist in the store; the app's in-memory list doesn't, DESIGN.md §32).
    pub fn hps_my_topics(&self) -> Vec<HpsTopicState> {
        let me = self.identity.address();
        let mut out = Vec::new();
        for (path, cfg) in &self.services {
            out.push(HpsTopicState {
                host: me,
                path: path.clone(),
                kind: cfg.kind,
                hosting: true,
                access: cfg.access,
            });
        }
        for (path, sub) in &self.subscriptions {
            out.push(HpsTopicState {
                host: sub.host,
                path: path.clone(),
                kind: if sub.service_pubkey.is_some() {
                    hps::ServiceKind::Service
                } else {
                    hps::ServiceKind::Channel
                },
                hosting: false,
                access: hps::AccessMode::Open,
            });
        }
        out
    }

    /// Same-app discoverable topics we can see (decrypted descriptors + host address).
    pub fn browse_discoverable(&self, tag: Option<&str>) -> Vec<(PubKeyBytes, hps::TopicMeta)> {
        let Some(disc_key) = self.app.disc_key else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for advert in self.directory.hps_topics() {
            if let crate::discover::AdvertKind::HpsTopic { nonce, ct } = &advert.body.kind {
                if let Some(meta) = hps::open_meta(&disc_key, nonce, ct) {
                    if tag.is_none_or(|t| meta.tags.iter().any(|x| x == t)) {
                        out.push((advert.body.publisher, meta));
                    }
                }
            }
        }
        out
    }

    fn hps_svc_key(path: &str) -> String {
        format!("hps/svc/{path}")
    }
    fn hps_sub_key(path: &str) -> String {
        format!("hps/sub/{path}")
    }
    fn hps_subscribe_pending_key(path: &str) -> String {
        format!("hps/sub-pending/{path}")
    }

    fn hps_pending_key(path: &str) -> String {
        format!("hps/pending/{path}")
    }
    fn hps_members_key(path: &str) -> String {
        format!("hps/members/{path}")
    }
    fn hps_replay_key(topic_tag: &[u8; 16], epoch: u32) -> String {
        format!(
            "hps/replay/{}/{epoch:010}",
            bs58::encode(topic_tag).into_string()
        )
    }
    fn hps_inbox_key(id: &BundleId) -> String {
        format!("hps/inbox/{}", bs58::encode(id).into_string())
    }
    fn http_response_key(id: &BundleId) -> String {
        format!("response/http/{}", bs58::encode(id).into_string())
    }
    fn service_response_key(id: &BundleId) -> String {
        format!("response/service/{}", bs58::encode(id).into_string())
    }
    fn outgoing_carrier_key(id: &BundleId) -> String {
        format!("carrier-out/{}", bs58::encode(id).into_string())
    }

    fn hps_publication_recorded(
        &self,
        topic_tag: &[u8; 16],
        epoch: u32,
        publication_id: &BundleId,
    ) -> bool {
        self.hps_inbox
            .iter()
            .any(|message| &message.id == publication_id)
            || self
                .hps_replays
                .get(&(*topic_tag, epoch))
                .is_some_and(|entries| {
                    entries
                        .iter()
                        .any(|(id, expiry)| id == publication_id && *expiry > self.now_ms)
                })
    }

    fn record_hps_ack(&mut self, topic: ([u8; 16], u32), expires_at: u64) -> bool {
        self.hps_acked.retain(|_, expiry| *expiry > self.now_ms);
        if self.hps_acked.contains_key(&topic) {
            return false;
        }
        if self.hps_acked.len() >= MAX_HPS_ACKED {
            if let Some(victim) = self
                .hps_acked
                .iter()
                .min_by_key(|(_, expiry)| **expiry)
                .map(|(topic, _)| *topic)
            {
                self.hps_acked.remove(&victim);
            }
        }
        self.hps_acked.insert(topic, expires_at);
        true
    }

    fn expire_outgoing_carriers(&mut self) {
        let expired: Vec<BundleId> = self
            .outgoing_carriers
            .iter()
            .filter(|(_, carrier)| {
                let lifetime_ended = carrier
                    .original
                    .inner
                    .created_at
                    .saturating_add(carrier.original.inner.lifetime_ms as u64)
                    <= self.now_ms;
                let unacked_transfer_finished = !carrier.original.inner.flags.request_ack
                    && carrier
                        .chunks
                        .iter()
                        .all(|chunk| !self.store.contains(chunk));
                lifetime_ended || unacked_transfer_finished
            })
            .map(|(id, _)| *id)
            .collect();
        if expired.is_empty() {
            return;
        }
        let mutations: Vec<KvMutation> = expired
            .iter()
            .map(|id| KvMutation::Remove {
                key: Self::outgoing_carrier_key(id),
            })
            .collect();
        if self.store.apply_kv_batch(&mutations).is_err() {
            return;
        }
        for id in expired {
            self.outgoing_carriers.remove(&id);
        }
    }

    fn accept_hps_publication(
        &mut self,
        topic_tag: [u8; 16],
        epoch: u32,
        message: HpsMessage,
        expires_at: u64,
        charge: AppQueueCharge,
    ) -> Result<bool> {
        let publication_id = message.id;
        let topic = (topic_tag, epoch);
        if self.hps_publication_recorded(&topic_tag, epoch, &publication_id) {
            return Ok(false);
        }
        if self.hps_inbox.len() >= MAX_DURABLE_HPS_MESSAGES {
            return Err(Error::Other("durable hps inbox limit reached".into()));
        }
        let mut candidate = self.hps_replays.clone();
        let mut protected: HashSet<BundleId> =
            self.hps_inbox.iter().map(|message| message.id).collect();
        protected.insert(publication_id);
        let entries = candidate.entry(topic).or_default();
        entries.retain(|(id, expiry)| *expiry > self.now_ms || protected.contains(id));
        entries.push((publication_id, expires_at));
        entries.sort_by_key(|(_, expiry)| *expiry);
        while entries.len() > MAX_HPS_REPLAYS_PER_TOPIC {
            let Some(index) = entries.iter().position(|(id, _)| !protected.contains(id)) else {
                return Err(Error::Other(
                    "hps replay topic limit is fully retained".into(),
                ));
            };
            entries.remove(index);
        }
        while candidate.values().map(Vec::len).sum::<usize>() > MAX_HPS_REPLAYS_GLOBAL {
            let victim = candidate
                .iter()
                .flat_map(|(candidate_topic, entries)| {
                    entries
                        .iter()
                        .enumerate()
                        .filter(|(_, (id, _))| !protected.contains(id))
                        .map(move |(index, (_, expiry))| (*expiry, *candidate_topic, index))
                })
                .min_by_key(|(expiry, _, _)| *expiry);
            let Some((_, victim_topic, victim_index)) = victim else {
                return Err(Error::Other(
                    "global hps replay limit is fully retained".into(),
                ));
            };
            if let Some(entries) = candidate.get_mut(&victim_topic) {
                entries.remove(victim_index);
            }
        }
        candidate.retain(|_, entries| !entries.is_empty());

        let inbox = PersistedHpsInbox {
            message: message.clone(),
            topic_tag,
            epoch,
            received_at_ms: self.now_ms,
            expires_at_ms: expires_at,
        };
        let mut changed_topics: HashSet<_> = self.hps_replays.keys().copied().collect();
        changed_topics.extend(candidate.keys().copied());
        let mut changed_topics: Vec<_> = changed_topics
            .into_iter()
            .filter(|topic| self.hps_replays.get(topic) != candidate.get(topic))
            .collect();
        changed_topics.sort_unstable();
        let mut mutations = Vec::with_capacity(changed_topics.len() + 1);
        for (changed_tag, changed_epoch) in changed_topics {
            match candidate.get(&(changed_tag, changed_epoch)) {
                Some(entries) => mutations.push(KvMutation::Put {
                    key: Self::hps_replay_key(&changed_tag, changed_epoch),
                    value: postcard::to_allocvec(&PersistedHpsReplay {
                        topic_tag: changed_tag,
                        epoch: changed_epoch,
                        entries: entries.clone(),
                    })?,
                }),
                None => mutations.push(KvMutation::Remove {
                    key: Self::hps_replay_key(&changed_tag, changed_epoch),
                }),
            }
        }
        mutations.push(KvMutation::Put {
            key: Self::hps_inbox_key(&publication_id),
            value: postcard::to_allocvec(&inbox)?,
        });
        self.store
            .apply_kv_batch(&mutations)
            .map_err(|e| Error::Other(format!("hps replay persistence failed: {e}")))?;
        self.hps_replays = candidate;
        self.hps_inbox_expires.insert(publication_id, expires_at);
        self.hps_inbox.push(message);
        self.hps_inbox_charges.push(charge);
        Ok(true)
    }

    fn expire_hps_replays(&mut self) {
        let topics: Vec<_> = self.hps_replays.keys().copied().collect();
        for (topic_tag, epoch) in topics {
            let Some(current) = self.hps_replays.get(&(topic_tag, epoch)) else {
                continue;
            };
            let entries: Vec<_> = current
                .iter()
                .copied()
                .filter(|(id, expiry)| {
                    *expiry > self.now_ms || self.hps_inbox.iter().any(|message| message.id == *id)
                })
                .collect();
            if entries.len() == current.len() {
                continue;
            }
            let key = Self::hps_replay_key(&topic_tag, epoch);
            let mutation = if entries.is_empty() {
                KvMutation::Remove { key }
            } else {
                let persisted = PersistedHpsReplay {
                    topic_tag,
                    epoch,
                    entries: entries.clone(),
                };
                let Ok(value) = postcard::to_allocvec(&persisted) else {
                    continue;
                };
                KvMutation::Put { key, value }
            };
            if self.store.apply_kv_batch(&[mutation]).is_ok() {
                if entries.is_empty() {
                    self.hps_replays.remove(&(topic_tag, epoch));
                } else {
                    self.hps_replays.insert((topic_tag, epoch), entries);
                }
            }
        }
    }

    fn expire_hps_inbox(&mut self) {
        let expired: HashSet<BundleId> = self
            .hps_inbox_expires
            .iter()
            .filter(|(_, expiry)| **expiry <= self.now_ms)
            .map(|(id, _)| *id)
            .collect();
        if expired.is_empty() {
            return;
        }
        let mutations: Vec<KvMutation> = expired
            .iter()
            .map(|id| KvMutation::Remove {
                key: Self::hps_inbox_key(id),
            })
            .collect();
        if self.store.apply_kv_batch(&mutations).is_err() {
            return;
        }
        let messages = std::mem::take(&mut self.hps_inbox);
        let charges = std::mem::take(&mut self.hps_inbox_charges);
        for (message, charge) in messages.into_iter().zip(charges) {
            if expired.contains(&message.id) {
                self.hps_inbox_expires.remove(&message.id);
                self.release_app_queue(charge);
            } else {
                self.hps_inbox.push(message);
                self.hps_inbox_charges.push(charge);
            }
        }
    }

    fn expire_durable_responses(&mut self) {
        let expired_http: HashSet<BundleId> = self
            .http_response_expires
            .iter()
            .filter(|(_, expiry)| **expiry <= self.now_ms)
            .map(|(id, _)| *id)
            .collect();
        let expired_service: HashSet<BundleId> = self
            .service_response_expires
            .iter()
            .filter(|(_, expiry)| **expiry <= self.now_ms)
            .map(|(id, _)| *id)
            .collect();
        if expired_http.is_empty() && expired_service.is_empty() {
            return;
        }
        let mut mutations = Vec::with_capacity(expired_http.len() + expired_service.len());
        mutations.extend(expired_http.iter().map(|id| KvMutation::Remove {
            key: Self::http_response_key(id),
        }));
        mutations.extend(expired_service.iter().map(|id| KvMutation::Remove {
            key: Self::service_response_key(id),
        }));
        if self.store.apply_kv_batch(&mutations).is_err() {
            return;
        }
        self.http_responses
            .retain(|item| !expired_http.contains(&item.id));
        self.service_responses
            .retain(|item| !expired_service.contains(&item.id));
        for id in expired_http {
            self.http_response_expires.remove(&id);
            if let Some(charge) = self.http_response_charges.remove(&id) {
                self.release_app_queue(charge);
            }
        }
        for id in expired_service {
            self.service_response_expires.remove(&id);
            if let Some(charge) = self.service_response_charges.remove(&id) {
                self.release_app_queue(charge);
            }
        }
    }

    fn persist_service(&mut self, path: &str, cfg: &hps::ServiceConfig) {
        if let Ok(bytes) = postcard::to_allocvec(cfg) {
            self.store.put_kv(&Self::hps_svc_key(path), bytes);
        }
    }
    #[cfg(test)]
    fn persist_subscription(&mut self, path: &str, sub: &HpsSubscription) {
        if let Ok(bytes) = postcard::to_allocvec(sub) {
            self.store.put_kv(&Self::hps_sub_key(path), bytes);
        }
    }
    fn persist_pending(&mut self, path: &str) {
        let q: Vec<PubKeyBytes> = self.hps_pending.get(path).cloned().unwrap_or_default();
        if let Ok(bytes) = postcard::to_allocvec(&q) {
            self.store.put_kv(&Self::hps_pending_key(path), bytes);
        }
    }
    fn persist_members(&mut self, path: &str) {
        let members = self.hps_members.get(path).cloned().unwrap_or_default();
        self.persist_member_set(path, &members);
    }
    fn persist_member_set(&mut self, path: &str, members: &HashSet<PubKeyBytes>) {
        let m: Vec<PubKeyBytes> = members.iter().copied().collect();
        if let Ok(bytes) = postcard::to_allocvec(&m) {
            self.store.put_kv(&Self::hps_members_key(path), bytes);
        }
    }

    /// Persist the deferred-content queue (messages the user sent that are waiting on a prekey)
    /// so a restart before the prekey arrives doesn't silently drop them (DESIGN.md §25).
    fn persist_pending_content(&mut self, pending: &[PendingContent]) -> Result<()> {
        let bytes = postcard::to_allocvec(&pending)?;
        self.store
            .put_kv_critical("pending_content", bytes)
            .map_err(|e| Error::Other(format!("deferred content persistence failed: {e}")))
    }

    /// Persist received + outstanding `hps://` invites so they survive a restart (§32).
    fn persist_invites(&mut self) {
        let inc: Vec<(String, PubKeyBytes, bool)> = self
            .hps_invites_in
            .iter()
            .map(|i| (i.path.clone(), i.host, i.kind == hps::ServiceKind::Channel))
            .collect();
        if let Ok(b) = postcard::to_allocvec(&inc) {
            self.store.put_kv("hps/invites_in", b);
        }
        let out: Vec<(String, PubKeyBytes)> = self.hps_invites_out.keys().cloned().collect();
        if let Ok(b) = postcard::to_allocvec(&out) {
            self.store.put_kv("hps/invites_out", b);
        }
    }

    /// A diagnostic snapshot of the live HNS cache: `(domain, address?, remaining_ttl_ms)`
    /// for each fresh entry (DESIGN.md §30). `None` address is a cached negative. The
    /// remaining TTL ticks down as the node's clock advances and the entry is pruned at zero.
    pub fn hns_cache_snapshot(&self) -> Vec<(String, Option<PubKeyBytes>, u64)> {
        let mut out: Vec<_> = self
            .hns_cache
            .iter()
            .filter(|(_, e)| e.expires_at_ms > self.now_ms)
            .map(|(d, e)| (d.clone(), e.address, e.expires_at_ms - self.now_ms))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Queue a real-DNS lookup for the host, deduped while one is in flight.
    fn queue_dns_lookup(&mut self, key: &str) {
        if self.dns_inflight.contains(key) {
            return;
        }
        let Some(charge) =
            self.reserve_app_queue(AppQueueKind::HnsLookup, None, key.len().saturating_add(16))
        else {
            return;
        };
        if self.dns_inflight.insert(key.to_string()) {
            self.dns_lookups.push(key.to_string());
            self.dns_lookup_charges.push(charge);
        } else {
            self.release_app_queue(charge);
        }
    }

    /// Seal an HTTP response back to a requester (gateway side).
    pub fn send_http_response(
        &mut self,
        to: PubKeyBytes,
        for_id: BundleId,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<BundleId> {
        let bundle = Bundle::create(
            &self.identity,
            Destination::Device(to),
            &to,
            &Payload::HttpResponse {
                status,
                headers,
                body,
                for_bundle_id: for_id,
            },
            BundleOpts {
                created_at: self.now_ms,
                ..Default::default()
            },
        )?;
        self.ensure_delivery_within_limits(&bundle)?;
        let id = bundle.id();
        self.deliver(bundle)?;
        Ok(id)
    }

    fn finish_outstanding_response(&mut self, request_id: BundleId, request: &OutstandingRequest) {
        self.outstanding_requests.remove(&request_id);
        self.unanchored_outstanding_requests.remove(&request_id);
        for custody_id in &request.custody_ids {
            self.pending.remove(custody_id);
            self.carrier_owner.remove(custody_id);
            self.relay_order.retain(|queued| queued != custody_id);
            self.forwarded.remove(custody_id);
        }
        self.outgoing_carriers.remove(&request_id);
        self.pending.remove(&request_id);
        self.relay_order.retain(|queued| *queued != request_id);
        self.forwarded.remove(&request_id);
        self.immune.insert(request_id, self.now_ms);
        self.tx.remove(&request_id);
    }

    fn commit_http_response(&mut self, bundle: &Bundle, item: HttpRespItem) -> Result<()> {
        if !self.app_payload_policy.supports(AppQueueKind::HttpResponse)
            || self.http_responses.len() + self.service_responses.len() >= MAX_DURABLE_RESPONSES
        {
            return Err(Error::Other("durable response inbox limit reached".into()));
        }
        let request = self
            .outstanding_requests
            .get(&item.for_id)
            .cloned()
            .ok_or_else(|| Error::Other("response authorization disappeared".into()))?;
        let wire_bytes = bundle.to_bytes()?.len();
        let charge = self
            .reserve_app_queue(
                AppQueueKind::HttpResponse,
                Some(item.from),
                Self::http_response_bytes(&item).saturating_add(wire_bytes),
            )
            .ok_or_else(|| Error::Other("http response admission limit reached".into()))?;
        let expires_at_ms = self.now_ms.saturating_add(DURABLE_HOST_DELIVERY_TTL_MS);
        let persisted = PersistedHttpResponse {
            item: item.clone(),
            received_at_ms: self.now_ms,
            expires_at_ms,
        };
        let mut candidate = self.outstanding_requests.clone();
        candidate.remove(&item.for_id);
        let mut mutations = vec![
            KvMutation::Put {
                key: Self::http_response_key(&item.id),
                value: postcard::to_allocvec(&persisted)?,
            },
            Self::outstanding_requests_mutation(&candidate)?,
            KvMutation::Remove {
                key: Self::outgoing_carrier_key(&item.for_id),
            },
        ];
        mutations.extend(
            request
                .custody_ids
                .iter()
                .copied()
                .map(|id| KvMutation::RemoveBundle { id }),
        );
        if let Err(error) = self.store.apply_kv_batch(&mutations) {
            self.release_app_queue(charge);
            return Err(Error::Other(format!(
                "http response persistence failed: {error}"
            )));
        }
        self.finish_outstanding_response(item.for_id, &request);
        self.http_response_expires.insert(item.id, expires_at_ms);
        self.http_response_charges.insert(item.id, charge);
        self.http_responses.push(item);
        Ok(())
    }

    fn commit_service_response(&mut self, bundle: &Bundle, item: ServiceRespItem) -> Result<()> {
        if !self
            .app_payload_policy
            .supports(AppQueueKind::ServiceResponse)
            || self.http_responses.len() + self.service_responses.len() >= MAX_DURABLE_RESPONSES
        {
            return Err(Error::Other("durable response inbox limit reached".into()));
        }
        let request = self
            .outstanding_requests
            .get(&item.for_id)
            .cloned()
            .ok_or_else(|| Error::Other("response authorization disappeared".into()))?;
        let wire_bytes = bundle.to_bytes()?.len();
        let charge = self
            .reserve_app_queue(
                AppQueueKind::ServiceResponse,
                Some(item.from),
                Self::service_response_bytes(&item).saturating_add(wire_bytes),
            )
            .ok_or_else(|| Error::Other("service response admission limit reached".into()))?;
        let expires_at_ms = self.now_ms.saturating_add(DURABLE_HOST_DELIVERY_TTL_MS);
        let persisted = PersistedServiceResponse {
            item: item.clone(),
            received_at_ms: self.now_ms,
            expires_at_ms,
        };
        let mut candidate = self.outstanding_requests.clone();
        candidate.remove(&item.for_id);
        let mut mutations = vec![
            KvMutation::Put {
                key: Self::service_response_key(&item.id),
                value: postcard::to_allocvec(&persisted)?,
            },
            Self::outstanding_requests_mutation(&candidate)?,
            KvMutation::Remove {
                key: Self::outgoing_carrier_key(&item.for_id),
            },
        ];
        mutations.extend(
            request
                .custody_ids
                .iter()
                .copied()
                .map(|id| KvMutation::RemoveBundle { id }),
        );
        if let Err(error) = self.store.apply_kv_batch(&mutations) {
            self.release_app_queue(charge);
            return Err(Error::Other(format!(
                "service response persistence failed: {error}"
            )));
        }
        self.finish_outstanding_response(item.for_id, &request);
        self.service_response_expires.insert(item.id, expires_at_ms);
        self.service_response_charges.insert(item.id, charge);
        self.service_responses.push(item);
        Ok(())
    }

    /// Drain egress HTTP requests we (as a gateway) should fulfill.
    pub fn take_http_requests(&mut self) -> Vec<HttpReqItem> {
        let pending = self.take_http_requests_deferred();
        let mut accepted = Vec::with_capacity(pending.len());
        for item in pending {
            if self.complete_app_delivery(&item.id) {
                accepted.push(item);
            } else {
                self.http_requests.push(item);
            }
        }
        accepted
    }

    /// Move HTTP requests into a higher-level admission gate without ACKing or consuming dedup.
    pub fn take_http_requests_deferred(&mut self) -> Vec<HttpReqItem> {
        std::mem::take(&mut self.http_requests)
    }

    /// Poll durable HTTP responses. Repeated calls return the same stable response ids until the host
    /// explicitly accepts each row.
    pub fn take_http_responses(&self) -> Vec<HttpRespItem> {
        self.http_responses
            .iter()
            .filter(|item| {
                self.http_response_expires
                    .get(&item.id)
                    .is_some_and(|expiry| *expiry > self.now_ms)
            })
            .cloned()
            .collect()
    }

    pub fn accept_http_response(&mut self, id: &BundleId) -> Result<bool> {
        let Some(index) = self.http_responses.iter().position(|item| &item.id == id) else {
            return Ok(false);
        };
        self.store
            .remove_kv_critical(&Self::http_response_key(id))
            .map_err(|e| Error::Other(format!("http response acceptance failed: {e}")))?;
        self.http_responses.remove(index);
        self.http_response_expires.remove(id);
        if let Some(charge) = self.http_response_charges.remove(id) {
            self.release_app_queue(charge);
        }
        Ok(true)
    }

    // --- service calls (DESIGN.md §29) ----------------------------------------

    /// Set this node's display name (returned by `hop.identify`). `None` clears it.
    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }

    /// Configure host-facing queue admission. Lowering limits does not discard already admitted
    /// durable inbox work; it only rejects new work until usage falls below the new bounds.
    pub fn set_app_queue_limits(&mut self, limits: AppQueueLimits) {
        self.app_queue_limits = limits;
    }

    fn reserve_app_queue(
        &mut self,
        kind: AppQueueKind,
        source: Option<PubKeyBytes>,
        bytes: usize,
    ) -> Option<AppQueueCharge> {
        let index = kind as usize;
        let limits = self.app_queue_limits;
        if bytes > limits.max_item_bytes
            || self.app_queue_usage.items >= limits.max_total_items
            || self.app_queue_usage.bytes.saturating_add(bytes) > limits.max_total_bytes
            || self.app_queue_usage.counts[index] >= limits.max_items_per_queue
            || self.app_queue_usage.queue_bytes[index].saturating_add(bytes)
                > limits.max_bytes_per_queue
        {
            return None;
        }
        if let Some(source) = source {
            let usage = self
                .app_queue_usage
                .senders
                .get(&source)
                .copied()
                .unwrap_or_default();
            if usage.items >= limits.max_sender_items
                || usage.bytes.saturating_add(bytes) > limits.max_sender_bytes
            {
                return None;
            }
            self.app_queue_usage.senders.insert(
                source,
                AppSenderUsage {
                    items: usage.items + 1,
                    bytes: usage.bytes + bytes,
                },
            );
        }
        self.app_queue_usage.items += 1;
        self.app_queue_usage.bytes += bytes;
        self.app_queue_usage.counts[index] += 1;
        self.app_queue_usage.queue_bytes[index] += bytes;
        Some(AppQueueCharge {
            kind,
            source,
            bytes,
        })
    }

    fn release_app_queue(&mut self, charge: AppQueueCharge) {
        let index = charge.kind as usize;
        self.app_queue_usage.items = self.app_queue_usage.items.saturating_sub(1);
        self.app_queue_usage.bytes = self.app_queue_usage.bytes.saturating_sub(charge.bytes);
        self.app_queue_usage.counts[index] = self.app_queue_usage.counts[index].saturating_sub(1);
        self.app_queue_usage.queue_bytes[index] =
            self.app_queue_usage.queue_bytes[index].saturating_sub(charge.bytes);
        if let Some(source) = charge.source {
            if let Some(usage) = self.app_queue_usage.senders.get_mut(&source) {
                usage.items = usage.items.saturating_sub(1);
                usage.bytes = usage.bytes.saturating_sub(charge.bytes);
                if usage.items == 0 {
                    self.app_queue_usage.senders.remove(&source);
                }
            }
        }
    }

    fn admit_app_delivery(
        &mut self,
        kind: AppQueueKind,
        bundle: &Bundle,
        item_bytes: usize,
    ) -> bool {
        if !self.app_payload_policy.supports(kind) {
            return false;
        }
        let id = bundle.id();
        if self.pending_app_deliveries.contains_key(&id) {
            return false;
        }
        let Ok(wire) = bundle.to_bytes() else {
            return false;
        };
        let Some(charge) = self.reserve_app_queue(
            kind,
            Some(bundle.inner.src),
            item_bytes.saturating_add(wire.len()),
        ) else {
            return false;
        };
        self.pending_app_deliveries.insert(
            id,
            PendingAppDelivery {
                bundle: bundle.clone(),
                charge,
            },
        );
        true
    }

    /// Commit one deferred app delivery. The dedup row and ACK are created only after host or held
    /// queue admission. Returns false if durable dedup admission failed, leaving the item pending.
    pub fn complete_app_delivery(&mut self, id: &BundleId) -> bool {
        let Some(pending) = self.pending_app_deliveries.get(id) else {
            return false;
        };
        let bundle = pending.bundle.clone();
        self.store.put(bundle.clone(), self.now_ms);
        if !self.store.seen(id) {
            return false;
        }
        self.store.remove(id);
        let pending = self
            .pending_app_deliveries
            .remove(id)
            .expect("pending app delivery still present");
        self.release_app_queue(pending.charge);
        if bundle.inner.flags.request_ack {
            self.emit_ack(&bundle);
        }
        true
    }

    /// Reject deferred app work without ACK or dedup consumption so a retransmission can retry.
    pub fn reject_app_delivery(&mut self, id: &BundleId) -> bool {
        let Some(pending) = self.pending_app_deliveries.remove(id) else {
            return false;
        };
        self.release_app_queue(pending.charge);
        true
    }

    fn header_bytes(headers: &[(String, String)]) -> usize {
        headers.iter().fold(0usize, |total, (name, value)| {
            total.saturating_add(name.len()).saturating_add(value.len())
        })
    }

    fn http_request_bytes(item: &HttpReqItem) -> usize {
        item.host
            .len()
            .saturating_add(item.method.len())
            .saturating_add(item.url.len())
            .saturating_add(Self::header_bytes(&item.headers))
            .saturating_add(item.body.len())
            .saturating_add(80)
    }

    fn http_response_bytes(item: &HttpRespItem) -> usize {
        Self::header_bytes(&item.headers)
            .saturating_add(item.body.len())
            .saturating_add(72)
    }

    fn service_request_bytes(item: &ServiceReqItem) -> usize {
        item.service
            .len()
            .saturating_add(item.method.len())
            .saturating_add(item.args.len())
            .saturating_add(72)
    }

    fn service_response_bytes(item: &ServiceRespItem) -> usize {
        item.body.len().saturating_add(72)
    }

    fn hps_message_bytes(item: &HpsMessage) -> usize {
        item.path
            .len()
            .saturating_add(item.body.len())
            .saturating_add(96)
    }

    fn inbox_item_bytes(item: &InboxItem) -> usize {
        item.content_type
            .len()
            .saturating_add(item.body.len())
            .saturating_add(160)
    }

    /// This node's display name, if set.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Set what kind of node this is (returned by `hop.identify`).
    pub fn set_kind(&mut self, kind: NodeKind) {
        self.kind = kind;
        self.app_payload_policy = AppPayloadPolicy::for_kind(kind);
        self.discard_unsupported_app_queues();
    }

    fn discard_unsupported_app_queues(&mut self) {
        let rejected: Vec<BundleId> = self
            .pending_app_deliveries
            .iter()
            .filter(|(_, pending)| !self.app_payload_policy.supports(pending.charge.kind))
            .map(|(id, _)| *id)
            .collect();
        for id in rejected {
            self.reject_app_delivery(&id);
        }
        if !self.app_payload_policy.supports(AppQueueKind::HttpRequest) {
            self.http_requests.clear();
        }
        if !self.app_payload_policy.supports(AppQueueKind::HttpResponse) {
            self.http_responses.clear();
            self.http_response_expires.clear();
            let charges: Vec<_> = self.http_response_charges.drain().map(|(_, c)| c).collect();
            for charge in charges {
                self.release_app_queue(charge);
            }
        }
        if !self
            .app_payload_policy
            .supports(AppQueueKind::ServiceRequest)
        {
            self.service_requests.clear();
        }
        if !self
            .app_payload_policy
            .supports(AppQueueKind::ServiceResponse)
        {
            self.service_responses.clear();
            self.service_response_expires.clear();
            let charges: Vec<_> = self
                .service_response_charges
                .drain()
                .map(|(_, charge)| charge)
                .collect();
            for charge in charges {
                self.release_app_queue(charge);
            }
        }
        if !self.app_payload_policy.supports(AppQueueKind::Telemetry) {
            self.telemetry_in.clear();
            let charges = std::mem::take(&mut self.telemetry_charges);
            for charge in charges {
                self.release_app_queue(charge);
            }
        }
        if !self.app_payload_policy.supports(AppQueueKind::PeerInbox) {
            let charges: Vec<_> = self
                .durable_inbox_charges
                .drain()
                .map(|(_, charge)| charge)
                .collect();
            for charge in charges {
                self.release_app_queue(charge);
            }
            self.durable_inbox.clear();
            self.inbox_order.clear();
            self.inbox.clear();
        }
        if !self.app_payload_policy.supports(AppQueueKind::HpsMessage) {
            self.hps_inbox.clear();
            self.hps_inbox_expires.clear();
            let charges = std::mem::take(&mut self.hps_inbox_charges);
            for charge in charges {
                self.release_app_queue(charge);
            }
        }
        if !self.app_payload_policy.supports(AppQueueKind::HpsInvite) {
            self.hps_invites_in.clear();
            let charges = std::mem::take(&mut self.hps_invite_charges);
            for charge in charges {
                self.release_app_queue(charge);
            }
        }
        if !self.app_payload_policy.supports(AppQueueKind::HnsLookup) {
            self.dns_lookups.clear();
            let charges = std::mem::take(&mut self.dns_lookup_charges);
            for charge in charges {
                self.release_app_queue(charge);
            }
        }
        if !self.app_payload_policy.supports(AppQueueKind::HnsResult) {
            self.hns_results.clear();
            let charges = std::mem::take(&mut self.hns_result_charges);
            for charge in charges {
                self.release_app_queue(charge);
            }
        }
    }

    /// This node's identity record, as the built-in `hop.identify` service reports it.
    pub fn identity_record(&self) -> IdentityRecord {
        IdentityRecord {
            name: self.name.clone(),
            kind: self.kind,
            address: self.address(),
        }
    }

    /// Call a service/command on `dst` (DESIGN.md §29). `service` is namespaced
    /// (`hop.identify` and other `hop.` names are answered by the destination node
    /// itself; anything else is dispatched to its app). The reply arrives as a
    /// [`ServiceRespItem`] via [`Node::take_service_responses`]. Returns the request id.
    pub fn send_service_request(
        &mut self,
        dst: PubKeyBytes,
        service: String,
        method: String,
        args: Vec<u8>,
    ) -> Result<BundleId> {
        let bundle = Bundle::create(
            &self.identity,
            Destination::Device(dst),
            &dst,
            &Payload::ServiceRequest {
                service,
                method,
                args,
            },
            BundleOpts {
                created_at: self.now_ms,
                ..Default::default()
            },
        )?;
        self.ensure_delivery_within_limits(&bundle)?;
        self.deliver_authorized_request(bundle, dst, RequestKind::Service)
    }

    /// Seal a service response back to a caller (app side, for a custom service). Reply
    /// to a [`ServiceReqItem`] using its `from` (as `to`) and `id` (as `for_id`).
    pub fn send_service_response(
        &mut self,
        to: PubKeyBytes,
        for_id: BundleId,
        status: u16,
        body: Vec<u8>,
    ) -> Result<BundleId> {
        let bundle = Bundle::create(
            &self.identity,
            Destination::Device(to),
            &to,
            &Payload::ServiceResponse {
                for_bundle_id: for_id,
                status,
                body,
            },
            BundleOpts {
                created_at: self.now_ms,
                ..Default::default()
            },
        )?;
        self.ensure_delivery_within_limits(&bundle)?;
        let id = bundle.id();
        self.deliver(bundle)?;
        Ok(id)
    }

    /// Drain custom service requests addressed to us (built-in `hop.` services are
    /// answered by the node and never appear here).
    pub fn take_service_requests(&mut self) -> Vec<ServiceReqItem> {
        let pending = self.take_service_requests_deferred();
        let mut accepted = Vec::with_capacity(pending.len());
        for item in pending {
            if self.complete_app_delivery(&item.id) {
                accepted.push(item);
            } else {
                self.service_requests.push(item);
            }
        }
        accepted
    }

    /// Move service requests into a higher-level admission gate without ACKing or consuming dedup.
    pub fn take_service_requests_deferred(&mut self) -> Vec<ServiceReqItem> {
        std::mem::take(&mut self.service_requests)
    }

    /// Poll durable service responses without consuming them.
    pub fn take_service_responses(&self) -> Vec<ServiceRespItem> {
        self.service_responses
            .iter()
            .filter(|item| {
                self.service_response_expires
                    .get(&item.id)
                    .is_some_and(|expiry| *expiry > self.now_ms)
            })
            .cloned()
            .collect()
    }

    pub fn accept_service_response(&mut self, id: &BundleId) -> Result<bool> {
        let Some(index) = self
            .service_responses
            .iter()
            .position(|item| &item.id == id)
        else {
            return Ok(false);
        };
        self.store
            .remove_kv_critical(&Self::service_response_key(id))
            .map_err(|e| Error::Other(format!("service response acceptance failed: {e}")))?;
        self.service_responses.remove(index);
        self.service_response_expires.remove(id);
        if let Some(charge) = self.service_response_charges.remove(id) {
            self.release_app_queue(charge);
        }
        Ok(true)
    }

    /// Export a [`TelemetryBatch`](crate::telemetry::TelemetryBatch) to a collector's address over
    /// the mesh (OTel-over-Hop, §40). The batch rides an addressed, statically sealed
    /// `hop.telemetry` bundle, so it is delay-tolerant: if the collector is unreachable it spools
    /// and delivers when a path opens. Fire-and-forget; there is no service response. Returns the
    /// bundle id.
    pub fn send_telemetry(
        &mut self,
        collector: PubKeyBytes,
        batch: &TelemetryBatch,
    ) -> Result<BundleId> {
        let bundle = Bundle::create(
            &self.identity,
            Destination::Device(collector),
            &collector,
            &Payload::ServiceRequest {
                service: SERVICE_TELEMETRY.into(),
                method: "export".into(),
                args: batch.to_bytes(),
            },
            BundleOpts {
                created_at: self.now_ms,
                ..Default::default()
            },
        )?;
        self.ensure_delivery_within_limits(&bundle)?;
        let id = bundle.id();
        self.deliver(bundle)?;
        Ok(id)
    }

    /// Drain telemetry batches received from devices (as a collector). Each was decoded and
    /// bounds-checked on receipt; malformed or oversized batches were dropped.
    pub fn take_telemetry(&mut self) -> Vec<TelemetryIn> {
        let batches = std::mem::take(&mut self.telemetry_in);
        let charges = std::mem::take(&mut self.telemetry_charges);
        for charge in charges {
            self.release_app_queue(charge);
        }
        batches
    }

    // --- transparent carrier streaming (DESIGN.md §20) ------------------------

    /// A fresh stream id, unique per this node.
    fn next_stream_id(&mut self) -> StreamId {
        self.stream_seq += 1;
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&self.stream_seq.to_be_bytes());
        id[8..].copy_from_slice(&short_addr(&self.identity.address()));
        id
    }

    fn ensure_delivery_within_limits(&self, bundle: &Bundle) -> Result<()> {
        let encoded_len = bundle.to_bytes()?.len();
        let chunk_bytes = self.carrier_limits.chunk_bytes.max(1);
        let addressed = matches!(
            bundle.inner.dst,
            Destination::Device(_) | Destination::AckTo(_, _)
        );
        if addressed
            && encoded_len > chunk_bytes
            && (encoded_len > self.carrier_limits.stream_bytes
                || encoded_len.div_ceil(chunk_bytes) > self.carrier_limits.stream_chunks)
        {
            return Err(Error::Other("bundle exceeds carrier stream limit".into()));
        }
        Ok(())
    }

    /// Build the exact custody set for one outgoing bundle without exposing it to any bearer. Large
    /// addressed bundles become a bounded set of carrier chunks plus a durable original transaction.
    fn prepare_delivery_custody(
        &mut self,
        mut bundle: Bundle,
    ) -> Result<(BundleId, Vec<Bundle>, Option<OutgoingCarrier>)> {
        if bundle.is_private() {
            bundle.env.trace.clear();
        }
        self.stamp_originated_bundle(&mut bundle);
        self.ensure_delivery_within_limits(&bundle)?;
        let chunk_bytes = self.carrier_limits.chunk_bytes.max(1);
        let encoded = bundle.to_bytes()?;
        let original_id = bundle.id();
        let addressed = matches!(
            bundle.inner.dst,
            Destination::Device(_) | Destination::AckTo(_, _)
        );
        if encoded.len() <= chunk_bytes || !addressed {
            return Ok((original_id, vec![bundle], None));
        }
        let destination = match bundle.inner.dst {
            Destination::Device(destination) | Destination::AckTo(destination, _) => destination,
            Destination::Broadcast | Destination::Vaccine(..) => unreachable!("addressed above"),
        };
        let stream_id = self.next_stream_id();
        let chunks: Vec<&[u8]> = encoded.chunks(chunk_bytes).collect();
        let count = chunks.len();
        let opts = BundleOpts {
            created_at: self.now_ms,
            flags: BundleFlags {
                request_ack: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut custody = Vec::with_capacity(count);
        for (index, chunk) in chunks.into_iter().enumerate() {
            let mut carrier_chunk = Bundle::create(
                &self.identity,
                Destination::Device(destination),
                &destination,
                &Payload::Carrier {
                    stream_id,
                    seq: index as u64,
                    bytes: chunk.to_vec(),
                    fin: index + 1 == count,
                },
                opts,
            )?;
            self.stamp_originated_bundle(&mut carrier_chunk);
            custody.push(carrier_chunk);
        }
        let carrier = OutgoingCarrier {
            original: bundle,
            chunks: custody.iter().map(Bundle::id).collect(),
        };
        Ok((original_id, custody, Some(carrier)))
    }

    fn activate_delivery_custody(
        &mut self,
        original_id: BundleId,
        custody: &[Bundle],
        carrier: Option<OutgoingCarrier>,
    ) -> Vec<BundleId> {
        if let Some(carrier) = carrier {
            for chunk in &carrier.chunks {
                self.carrier_owner.insert(*chunk, original_id);
            }
            self.outgoing_carriers.insert(original_id, carrier);
        }
        let mut ids = Vec::with_capacity(custody.len());
        for stored in custody {
            let id = stored.id();
            if stored.inner.flags.request_ack && !stored.inner.flags.is_ack {
                self.pending.insert(
                    id,
                    PendingTx {
                        copies: stored.env.copies,
                        created_at: stored.inner.created_at,
                        lifetime_ms: stored.inner.lifetime_ms,
                        next_retx_at: self.now_ms.saturating_add(self.retx_interval_ms),
                        retx_interval: self.retx_interval_ms,
                    },
                );
            }
            ids.push(id);
        }
        ids
    }

    /// Commit a prepared send ratchet together with the exact custody records it produced. For a
    /// large addressed bundle those records are every carrier chunk; for all other sends it is the
    /// bundle itself. Nothing is offered and the live ratchet is untouched until the whole Store
    /// batch succeeds.
    fn store_session_delivery(
        &mut self,
        peer: PubKeyBytes,
        session: PeerSession,
        bundle: Bundle,
    ) -> Result<Vec<BundleId>> {
        let (original, custody, carrier) = self.prepare_delivery_custody(bundle)?;

        let mut mutations = Vec::with_capacity(custody.len() + 2);
        mutations.push(KvMutation::Put {
            key: Self::session_kv_key(&peer),
            value: postcard::to_allocvec(&session)?,
        });
        if let Some(carrier) = &carrier {
            mutations.push(KvMutation::Put {
                key: Self::outgoing_carrier_key(&original),
                value: postcard::to_allocvec(carrier)?,
            });
        }
        mutations.extend(custody.iter().cloned().map(|bundle| KvMutation::PutBundle {
            bundle: Box::new(bundle),
            now_ms: self.now_ms,
        }));
        self.store
            .apply_kv_batch(&mutations)
            .map_err(|e| Error::Other(format!("outbound persistence failed: {e}")))?;

        self.sessions.insert(peer, session);
        self.touch_session(peer);
        Ok(self.activate_delivery_custody(original, &custody, carrier))
    }

    /// Submit a locally-originated bundle, **auto-streaming if it's too large**. Small
    /// bundles go as one (the common case). A large one (e.g. an image message, or a big
    /// service request/response) is split into ordered `StreamData` chunks carrying its
    /// raw bytes, each sealed to the destination and ACK-tracked for reliable transport;
    /// the receiver reassembles and processes the original bundle as if it arrived whole —
    /// so id, request_ack, delivery status and dedup are all preserved. Transparent: every
    /// `send_*` path funnels through here, so any payload type streams when needed.
    fn deliver(&mut self, bundle: Bundle) -> Result<()> {
        let (original, custody, carrier) = self.prepare_delivery_custody(bundle)?;
        if carrier.is_none() {
            self.submit_checked(
                custody
                    .into_iter()
                    .next()
                    .expect("non-carrier custody contains its original bundle"),
            )?;
            return Ok(());
        }
        let carrier_ref = carrier.as_ref().expect("checked above");
        let mut mutations = Vec::with_capacity(custody.len() + 1);
        mutations.push(KvMutation::Put {
            key: Self::outgoing_carrier_key(&original),
            value: postcard::to_allocvec(carrier_ref)?,
        });
        mutations.extend(custody.iter().cloned().map(|bundle| KvMutation::PutBundle {
            bundle: Box::new(bundle),
            now_ms: self.now_ms,
        }));
        self.store
            .apply_kv_batch(&mutations)
            .map_err(|e| Error::Other(format!("carrier custody persistence failed: {e}")))?;
        let stored = self.activate_delivery_custody(original, &custody, carrier);
        for id in stored {
            self.offer_bundle_to_all_except(id, LOCAL_LINK);
        }
        Ok(())
    }

    fn continue_carrier_rehydrate(&mut self) -> Result<bool> {
        let Some(mut state) = self.carrier_rehydrate.take() else {
            return Ok(true);
        };
        let result = self.run_carrier_rehydrate_round(&mut state);
        match result {
            Ok(true) => Ok(true),
            Ok(false) => {
                self.carrier_rehydrate = Some(state);
                Ok(false)
            }
            Err(error) => {
                self.carrier_rehydrate = Some(state);
                Err(error)
            }
        }
    }

    fn run_carrier_rehydrate_round(&mut self, state: &mut CarrierRehydrateState) -> Result<bool> {
        let mut round = CarrierRehydrateUsage::default();
        self.drain_carrier_rehydrate_cleanup(state, &mut round)?;
        if !state.cleanup.is_empty() {
            return Ok(false);
        }

        while round.rows < CARRIER_REHYDRATE_MAX_ROWS
            && round.bytes < CARRIER_REHYDRATE_MAX_BYTES
            && round.pages < CARRIER_REHYDRATE_MAX_PAGES
        {
            let row_limit = CARRIER_PERSISTED_PAGE_ROWS
                .min(CARRIER_REHYDRATE_MAX_ROWS.saturating_sub(round.rows));
            let byte_limit = CARRIER_REHYDRATE_MAX_BYTES.saturating_sub(round.bytes);
            let page = self
                .store
                .list_kv_page_bounded("strm/", state.cursor.as_deref(), row_limit, byte_limit)
                .map_err(|error| Error::Other(format!("carrier rehydrate page failed: {error}")))?;
            if page.rows.len() > row_limit
                || page.scanned_bytes > byte_limit
                || page.scanned_pages == 0
                || page.scanned_pages > CARRIER_REHYDRATE_MAX_PAGES.saturating_sub(round.pages)
            {
                return Err(Error::Other(
                    "carrier rehydrate backend exceeded its page budget".into(),
                ));
            }
            round.rows += page.rows.len();
            round.bytes += page.scanned_bytes;
            round.pages += page.scanned_pages;
            self.carrier_rehydrate_usage.rows = self
                .carrier_rehydrate_usage
                .rows
                .saturating_add(page.rows.len());
            self.carrier_rehydrate_usage.bytes = self
                .carrier_rehydrate_usage
                .bytes
                .saturating_add(page.scanned_bytes);
            self.carrier_rehydrate_usage.pages = self
                .carrier_rehydrate_usage
                .pages
                .saturating_add(page.scanned_pages);
            if page.rows.is_empty() {
                return Ok(true);
            }

            for row in page.rows {
                if state
                    .cursor
                    .as_deref()
                    .is_some_and(|cursor| cursor >= row.key.as_str())
                {
                    return Err(Error::Other(
                        "carrier rehydrate cursor did not advance".into(),
                    ));
                }
                state.cursor = Some(row.key.clone());
                let Some((from, stream_id, seq)) = parse_stream_key(&row.key) else {
                    Self::queue_carrier_cleanup(state, row);
                    continue;
                };
                if state.rejected_stream != Some((from, stream_id)) {
                    state.rejected_stream = None;
                }
                if state.rejected_stream == Some((from, stream_id)) {
                    Self::queue_carrier_cleanup(state, row);
                    continue;
                }
                if !row.canonical {
                    self.reject_rehydrated_stream(state, row, from, stream_id);
                    continue;
                }
                let Some(value) = row.value.as_deref() else {
                    self.reject_rehydrated_stream(state, row, from, stream_id);
                    continue;
                };
                let Ok(chunk) = postcard::from_bytes::<PersistedCarrierChunk>(value) else {
                    self.reject_rehydrated_stream(state, row, from, stream_id);
                    continue;
                };
                let invalid_time = chunk.started_at != 0
                    && (chunk.received_at < chunk.started_at
                        || chunk.received_at.saturating_sub(chunk.started_at)
                            >= CARRIER_STREAM_LIFETIME_MS);
                if invalid_time {
                    self.reject_rehydrated_stream(state, row, from, stream_id);
                    continue;
                }
                match self.accept_stream_chunk_at(
                    from,
                    stream_id,
                    seq,
                    CarrierChunkInput {
                        bytes: chunk.bytes,
                        fin: chunk.fin,
                        origin: CarrierChunkOrigin::Persisted {
                            started_at: chunk.started_at,
                            received_at: chunk.received_at,
                        },
                    },
                ) {
                    StreamChunkAcceptance::Retained => {}
                    StreamChunkAcceptance::Complete(inner_bytes) => {
                        let _ = self.process_reconstructed_bundle(LOCAL_LINK, from, &inner_bytes);
                        self.reject_rehydrated_stream(state, row, from, stream_id);
                    }
                    StreamChunkAcceptance::Rejected => {
                        self.reject_rehydrated_stream(state, row, from, stream_id);
                    }
                }
            }

            self.drain_carrier_rehydrate_cleanup(state, &mut round)?;
            if !state.cleanup.is_empty() {
                return Ok(false);
            }
        }
        Ok(false)
    }

    fn drain_carrier_rehydrate_cleanup(
        &mut self,
        state: &mut CarrierRehydrateState,
        round: &mut CarrierRehydrateUsage,
    ) -> Result<()> {
        while !state.cleanup.is_empty()
            && round.cleanup_operations < CARRIER_REHYDRATE_MAX_CLEANUP_OPERATIONS
        {
            let count = CARRIER_CLEANUP_BATCH_ROWS.min(state.cleanup.len()).min(
                CARRIER_REHYDRATE_MAX_CLEANUP_OPERATIONS.saturating_sub(round.cleanup_operations),
            );
            let batch: Vec<_> = state.cleanup.iter().take(count).cloned().collect();
            round.cleanup_operations += count;
            self.carrier_rehydrate_usage.cleanup_operations = self
                .carrier_rehydrate_usage
                .cleanup_operations
                .saturating_add(count);
            self.store
                .remove_kv_rows_critical(&batch)
                .map_err(|error| {
                    Error::Other(format!("carrier rehydrate cleanup failed: {error}"))
                })?;
            state.cleanup.drain(..count);
        }
        Ok(())
    }

    fn reject_rehydrated_stream(
        &mut self,
        state: &mut CarrierRehydrateState,
        row: KvPageRow,
        from: PubKeyBytes,
        stream_id: StreamId,
    ) {
        if let Some(stream) = self.remove_incoming_stream(&from, &stream_id) {
            for seq in stream.chunks.keys() {
                Self::queue_carrier_cleanup(
                    state,
                    KvPageRow::removal(stream_chunk_key(&from, &stream_id, *seq)),
                );
            }
        }
        Self::queue_carrier_cleanup(state, row);
        state.rejected_stream = Some((from, stream_id));
    }

    fn queue_carrier_cleanup(state: &mut CarrierRehydrateState, row: KvPageRow) {
        if state
            .cleanup
            .iter()
            .any(|existing| existing.key == row.key && existing.storage_id == row.storage_id)
        {
            return;
        }
        if row.storage_id.is_none()
            && state
                .cleanup
                .iter()
                .any(|existing| existing.key == row.key && existing.canonical)
        {
            return;
        }
        if row.canonical {
            if let Some(existing) = state.cleanup.iter_mut().find(|existing| {
                existing.key == row.key && existing.canonical && existing.storage_id.is_none()
            }) {
                *existing = row;
                return;
            }
        }
        state.cleanup.push_back(row);
    }

    /// Feed one inbound carrier chunk into reassembly. Rejected chunks were not retained and must
    /// not be deduped or ACKed by the caller.
    fn accept_stream_chunk(
        &mut self,
        from: PubKeyBytes,
        stream_id: StreamId,
        seq: u64,
        bytes: Vec<u8>,
        fin: bool,
    ) -> StreamChunkAcceptance {
        if self.carrier_rehydrate.is_some() {
            return StreamChunkAcceptance::Rejected;
        }
        self.accept_stream_chunk_at(
            from,
            stream_id,
            seq,
            CarrierChunkInput {
                bytes,
                fin,
                origin: CarrierChunkOrigin::Live,
            },
        )
    }

    fn anchor_incoming_stream(
        &mut self,
        from: &PubKeyBytes,
        stream_id: &StreamId,
        now_ms: u64,
    ) -> bool {
        let prefix = stream_prefix(from, stream_id);
        let Some((key, bytes)) = self.store.list_kv_page(&prefix, None, 1).into_iter().next()
        else {
            return false;
        };
        let Ok(mut chunk) = postcard::from_bytes::<PersistedCarrierChunk>(&bytes) else {
            return false;
        };
        chunk.started_at = now_ms;
        if chunk.received_at == 0 {
            chunk.received_at = now_ms;
        }
        let Ok(value) = postcard::to_allocvec(&chunk) else {
            return false;
        };
        self.store.put_kv_critical(&key, value).is_ok()
    }

    /// Parse and authenticate a completed carrier without consuming its spool. Only the original
    /// authenticated sender may carry an addressed bundle to this recipient, and nested carriers are
    /// refused. `on_bundle` reports true only after the normal receive path has durable custody.
    fn process_reconstructed_bundle(
        &mut self,
        from_link: LinkId,
        carrier_sender: PubKeyBytes,
        bytes: &[u8],
    ) -> bool {
        let Ok(bundle) = Bundle::from_bytes(bytes) else {
            return false;
        };
        if bundle.verify().is_err()
            || bundle.inner.src != carrier_sender
            || !is_for(&bundle, &self.address())
            || matches!(bundle.open(&self.identity), Ok(Payload::Carrier { .. }))
        {
            return false;
        }
        self.process_bundle(from_link, bundle)
    }

    fn accept_stream_chunk_at(
        &mut self,
        from: PubKeyBytes,
        stream_id: StreamId,
        seq: u64,
        input: CarrierChunkInput,
    ) -> StreamChunkAcceptance {
        let CarrierChunkInput { bytes, fin, origin } = input;
        let (persisted_times, cleanup_on_reject) = match origin {
            CarrierChunkOrigin::Live => (None, true),
            CarrierChunkOrigin::Persisted {
                started_at,
                received_at,
            } => (Some((started_at, received_at)), false),
        };
        let activity_at = persisted_times.map_or(self.now_ms, |(_, received_at)| received_at);
        let hinted_start = persisted_times.map_or(self.now_ms, |(started_at, _)| started_at);
        let key = (from, stream_id);
        if bytes.is_empty()
            || bytes.len() > self.carrier_limits.chunk_bytes
            || self.carrier_limits.stream_chunks == 0
            || seq >= self.carrier_limits.stream_chunks as u64
        {
            if cleanup_on_reject {
                let _ = self.abort_incoming_stream(&from, &stream_id);
            }
            return StreamChunkAcceptance::Rejected;
        }

        let hash = *blake3::hash(&bytes).as_bytes();
        if let Some(existing) = self
            .incoming_streams
            .get(&key)
            .and_then(|stream| stream.chunks.get(&seq))
            .copied()
        {
            let stream = &self.incoming_streams[&key];
            let mismatched_start = persisted_times.is_some()
                && hinted_start != 0
                && stream.started_at != 0
                && hinted_start != stream.started_at;
            let expired = stream.started_at != 0
                && activity_at.saturating_sub(stream.started_at) >= CARRIER_STREAM_LIFETIME_MS;
            if mismatched_start || expired {
                if cleanup_on_reject {
                    let _ = self.abort_incoming_stream(&from, &stream_id);
                }
                return StreamChunkAcceptance::Rejected;
            }
            if existing.hash == hash && existing.fin == fin {
                if let Some(stream) = self.incoming_streams.get_mut(&key) {
                    stream.at = stream.at.max(activity_at);
                }
                if self
                    .incoming_streams
                    .get(&key)
                    .is_some_and(|stream| stream.reassembler.is_finished())
                {
                    return StreamChunkAcceptance::Complete(
                        self.incoming_streams[&key].data.clone(),
                    );
                }
                return StreamChunkAcceptance::Retained;
            }
            if cleanup_on_reject {
                let _ = self.abort_incoming_stream(&from, &stream_id);
            }
            return StreamChunkAcceptance::Rejected;
        }

        let (is_new, stream_bytes, stream_chunks, terminal_seq, has_later_chunk, mut started_at) =
            self.incoming_streams
                .get(&key)
                .map(|stream| {
                    (
                        false,
                        stream.bytes,
                        stream.chunks.len(),
                        stream
                            .chunks
                            .iter()
                            .find_map(|(chunk_seq, chunk)| chunk.fin.then_some(*chunk_seq)),
                        stream.chunks.keys().any(|chunk_seq| *chunk_seq > seq),
                        stream.started_at,
                    )
                })
                .unwrap_or((true, 0, 0, None, false, hinted_start));
        if started_at == 0 && hinted_start != 0 {
            started_at = hinted_start;
        }
        if (started_at != 0 && activity_at.saturating_sub(started_at) >= CARRIER_STREAM_LIFETIME_MS)
            || (persisted_times.is_some()
                && !is_new
                && hinted_start != 0
                && started_at != 0
                && hinted_start != started_at)
        {
            if cleanup_on_reject {
                let _ = self.abort_incoming_stream(&from, &stream_id);
            }
            return StreamChunkAcceptance::Rejected;
        }
        let next_stream_bytes = match stream_bytes.checked_add(bytes.len()) {
            Some(total) => total,
            None => {
                if cleanup_on_reject {
                    let _ = self.abort_incoming_stream(&from, &stream_id);
                }
                return StreamChunkAcceptance::Rejected;
            }
        };
        let impossible_order =
            terminal_seq.is_some_and(|terminal| seq > terminal || fin) || (fin && has_later_chunk);
        if impossible_order
            || stream_chunks.saturating_add(1) > self.carrier_limits.stream_chunks
            || next_stream_bytes > self.carrier_limits.stream_bytes
        {
            if cleanup_on_reject {
                let _ = self.abort_incoming_stream(&from, &stream_id);
            }
            return StreamChunkAcceptance::Rejected;
        }

        let sender_usage = self
            .incoming_sender_usage
            .get(&from)
            .copied()
            .unwrap_or_default();
        let exceeds_stream_pressure = is_new
            && (self.incoming_streams.len() >= self.carrier_limits.global_streams
                || sender_usage.streams >= self.carrier_limits.sender_streams);
        let exceeds_byte_pressure = sender_usage
            .bytes
            .checked_add(bytes.len())
            .is_none_or(|total| total > self.carrier_limits.sender_bytes)
            || self
                .incoming_stream_bytes
                .checked_add(bytes.len())
                .is_none_or(|total| total > self.carrier_limits.global_bytes);
        if exceeds_stream_pressure || exceeds_byte_pressure {
            // Aggregate pressure is temporary. Keep every previously retained chunk and do not
            // persist, dedup, or ACK this one, so retransmission can succeed after cleanup.
            return StreamChunkAcceptance::Rejected;
        }

        let persisted = PersistedCarrierChunk {
            started_at,
            received_at: activity_at,
            fin,
            bytes: bytes.clone(),
        };
        if persisted_times.is_none() {
            let storage_key = stream_chunk_key(&from, &stream_id, seq);
            let Ok(value) = postcard::to_allocvec(&persisted) else {
                return StreamChunkAcceptance::Rejected;
            };
            if self.store.put_kv_critical(&storage_key, value).is_err() {
                return StreamChunkAcceptance::Rejected;
            }
        }

        if is_new {
            self.incoming_streams.insert(
                key,
                IncomingStream {
                    reassembler: StreamReassembler::new(),
                    data: Vec::new(),
                    chunks: HashMap::new(),
                    bytes: 0,
                    started_at,
                    at: activity_at,
                },
            );
            self.incoming_sender_usage.entry(from).or_default().streams += 1;
        }
        let entry = self
            .incoming_streams
            .get_mut(&key)
            .expect("admitted carrier stream exists");
        entry.at = entry.at.max(activity_at);
        if entry.started_at == 0 && hinted_start != 0 {
            entry.started_at = hinted_start;
        }
        entry.bytes += bytes.len();
        entry.chunks.insert(seq, IncomingChunk { hash, fin });
        for chunk in entry.reassembler.accept(seq, bytes, fin) {
            entry.data.extend_from_slice(&chunk);
        }
        self.incoming_stream_bytes += persisted.bytes.len();
        self.incoming_sender_usage.entry(from).or_default().bytes += persisted.bytes.len();

        if self
            .incoming_streams
            .get(&key)
            .is_some_and(|stream| stream.reassembler.is_finished())
        {
            StreamChunkAcceptance::Complete(self.incoming_streams[&key].data.clone())
        } else {
            StreamChunkAcceptance::Retained
        }
    }

    fn remove_incoming_stream(
        &mut self,
        from: &PubKeyBytes,
        stream_id: &StreamId,
    ) -> Option<IncomingStream> {
        let stream = self.incoming_streams.remove(&(*from, *stream_id))?;
        self.incoming_stream_bytes = self.incoming_stream_bytes.saturating_sub(stream.bytes);
        let remove_sender = if let Some(usage) = self.incoming_sender_usage.get_mut(from) {
            usage.streams = usage.streams.saturating_sub(1);
            usage.bytes = usage.bytes.saturating_sub(stream.bytes);
            usage.streams == 0 && usage.bytes == 0
        } else {
            false
        };
        if remove_sender {
            self.incoming_sender_usage.remove(from);
        }
        Some(stream)
    }

    fn finalize_incoming_stream(&mut self, from: &PubKeyBytes, stream_id: &StreamId) -> bool {
        if self.clear_persisted_stream(from, stream_id).is_err() {
            return false;
        }
        self.remove_incoming_stream(from, stream_id);
        true
    }

    fn abort_incoming_stream(&mut self, from: &PubKeyBytes, stream_id: &StreamId) -> bool {
        self.finalize_incoming_stream(from, stream_id)
    }

    /// Remove all persisted chunks of a completed or abandoned carrier stream (DESIGN.md §20).
    fn clear_persisted_stream(&mut self, from: &PubKeyBytes, stream_id: &StreamId) -> Result<()> {
        let prefix = stream_prefix(from, stream_id);
        let mut after: Option<String> = None;
        loop {
            let page = self
                .store
                .list_kv_page_bounded(
                    &prefix,
                    after.as_deref(),
                    CARRIER_PERSISTED_PAGE_ROWS,
                    CARRIER_REHYDRATE_MAX_BYTES,
                )
                .map_err(|error| Error::Other(format!("carrier cleanup page failed: {error}")))?;
            if page.rows.is_empty() {
                break;
            }
            if page.rows.len() > CARRIER_PERSISTED_PAGE_ROWS
                || page.scanned_bytes > CARRIER_REHYDRATE_MAX_BYTES
                || page.scanned_pages == 0
            {
                return Err(Error::Other(
                    "carrier cleanup backend exceeded its page budget".into(),
                ));
            }
            let next = page.rows.last().map(|row| row.key.clone());
            if next == after {
                return Err(Error::Other(
                    "carrier cleanup cursor did not advance".into(),
                ));
            }
            self.store
                .remove_kv_rows_critical(&page.rows)
                .map_err(|error| {
                    Error::Other(format!("carrier cleanup persistence failed: {error}"))
                })?;
            after = next;
        }
        Ok(())
    }

    /// Publish (and gossip) a signed service advert so others discover it across the
    /// mesh — even multiple hops away via relays (§15–§16). Returns the advert id so
    /// the caller can later revoke it with a tombstone. The advert carries this node's
    /// address as `publisher`, so a discoverer can seal a message straight back.
    ///
    /// Apps build presence and contacts on top of this: a chat app publishes a
    /// "presence" service whose `title` is the user's chosen display name, browses for
    /// it, and ties name↔address locally (DESIGN.md §4, §23).
    pub fn publish_service(
        &mut self,
        service: String,
        title: String,
        summary: String,
        tags: Vec<String>,
        ttl_ms: u32,
    ) -> Result<AdvertId> {
        self.advert_seq += 1;
        let advert = Advert::publish(
            &self.identity,
            AdvertKind::Service {
                service,
                title,
                summary,
                tags,
            },
            self.now_ms,
            ttl_ms,
            self.advert_seq,
        )?;
        let id = advert.id;
        self.publish(advert);
        Ok(id)
    }

    /// Browse a service namespace (optionally filtered by tag) for adverts discovered
    /// across the mesh. Returns the live [`Advert`]s; `publisher` is the address to
    /// message, `hops` the closest known distance.
    pub fn browse(&self, service: &str, tag: Option<&str>) -> Vec<Advert> {
        self.directory.browse(service, tag)
    }

    /// Delivery status of a message we sent: `(peers_relayed_to, delivered,
    /// delivery_hops)`. Maps to Sending (0, false, _) / Sent N (N, false, _) /
    /// Delivered (_, true, hops). `delivery_hops` is the forward path length the
    /// destination observed (0 until delivered).
    pub fn message_status(&self, id: &BundleId) -> Option<(u32, bool, u8, u32)> {
        self.tx.get(id).map(|i| {
            (
                i.relayed.len() as u32,
                i.delivered,
                i.delivered_hops,
                i.delivered_ms,
            )
        })
    }

    /// The relay queue for display: our messages awaiting send (pinned) and peer
    /// messages awaiting relay (subject to decay). Newest first.
    pub fn queue(&self) -> Vec<QueuedMessage> {
        let mut items: Vec<QueuedMessage> = self
            .store
            .have()
            .ids
            .iter()
            .filter_map(|id| self.store.get(id))
            .map(|b| QueuedMessage {
                id: b.id(),
                own: self.tx.contains_key(&b.id()) || self.carrier_owner.contains_key(&b.id()),
                to: match b.inner.dst {
                    Destination::Device(a) | Destination::AckTo(a, _) => Some(a),
                    Destination::Broadcast | Destination::Vaccine(..) => None,
                },
                priority: b.inner.priority,
                hops: b.env.hops,
            })
            .collect();
        // Own (pinned) first, then by priority desc.
        items.sort_by(|a, b| b.own.cmp(&a.own).then(b.priority.cmp(&a.priority)));
        items
    }

    /// For the cloud backbone's cross-partition handoff (DESIGN.md §28): the
    /// device-addressed bundles we're holding whose destination is **not** currently
    /// connected to us, as `(id, dst, sealed bytes, expires_at_ms)`. The relay hands
    /// these into the destination region's Firestore mailbox so an offline device
    /// collects them when it next checks in (or that region cold-starts). Returns the
    /// sealed wire bytes untouched — the relay never opens what it forwards.
    /// stores-r3-01: the durable `expireAt` a relay must stamp when it hands off or spools a bundle
    /// into another region's Firestore mailbox. Anchor it to the store's RECEIVER-clamped dedup
    /// deadline (`seen_expiry`, from stores-r2-01) — the same clock the durable mirror uses — NOT to
    /// the sender's advisory `created_at`. A hostile or non-node sender (or the wire/BundleOpts
    /// default) can stamp `created_at = 0`, which would make `created_at + lifetime` land in ~1970,
    /// so the TTL policy would sweep a still-live handed-off/spooled message and an offline recipient
    /// would silently lose it. Fall back to `now + lifetime` only when the store doesn't track the
    /// id (e.g. a backend without dedup-expiry), so every durable write is receiver-anchored.
    fn durable_expiry(&self, id: &BundleId, b: &Bundle) -> u64 {
        self.store
            .seen_expiry(id)
            .unwrap_or_else(|| self.now_ms.saturating_add(b.inner.lifetime_ms as u64))
    }

    pub fn undeliverable_device_bundles(&self) -> Vec<(BundleId, PubKeyBytes, Vec<u8>, u64)> {
        let connected: HashSet<PubKeyBytes> = self.peers().into_iter().collect();
        let mut out = Vec::new();
        for id in self.store.have().ids {
            let Some(b) = self.store.get(&id) else {
                continue;
            };
            // Both user messages (Device) and delivery-ACKs (AckTo) are addressed to a
            // specific node, so both ride the handoff — otherwise an ACK back to an
            // offline cross-region sender would never arrive (no live peering, §28).
            let dst = match b.inner.dst {
                Destination::Device(d) | Destination::AckTo(d, _) => d,
                Destination::Broadcast | Destination::Vaccine(..) => continue,
            };
            if connected.contains(&dst) {
                continue; // deliverable directly on this node — no handoff needed
            }
            if let Ok(bytes) = b.to_bytes() {
                let expires = self.durable_expiry(&id, &b);
                out.push((id, dst, bytes, expires));
            }
        }
        out
    }

    /// §39 P5: private bundles we should DURABLY spool by mailbox-tag — so an offline / cross-partition
    /// recipient (whom P4's live gradient can't reach right now) collects it via a later want-beacon pull.
    /// A bundle qualifies iff it's private and carries a mailbox-tag. core-protocol-r2-01: we intentionally
    /// spool even when a live gradient exists for the route, because the gradient keys on a 2-byte PREFIX
    /// and a live next-hop may be a prefix-COLLIDING different recipient — suppressing the spool then
    /// black-holes the true (passive) recipient. When the recipient later beacons, the host reloads the
    /// spool and P4 steers the reloaded copy down the freshly-laid gradient. The relay never opens the
    /// envelope — sealed bytes verbatim. Returns (id, mailbox-route-prefix, sealed bytes, expires_at).
    ///
    /// core-protocol-r3-01: ACK spooling is INTENTIONAL, not a leak. A private delivery-ACK
    /// (`emit_private_ack`) is itself a private bundle carrying a mailbox toward the ORIGINAL sender
    /// (§39 P4 return path), so it qualifies here and is durably spooled just like forward content.
    /// This is deliberate: the ACK makes the SAME dormant round-trip as the message, so an offline or
    /// cross-partition sender collects its delivery confirmation via a later want-beacon pull instead
    /// of stranding on "Sending…". It is also the ONLY safe choice: the relay never opens the seal, so
    /// forward-content and ACK payloads are byte-indistinguishable to it, so trying to spool one but not
    /// the other would require peeking inside the seal (defeating §39) or trusting an in-the-clear
    /// type hint (a metadata leak). The extra storage is bounded by the same eviction cap + TTL as any
    /// spooled bundle (and ACKs clamp to `MAX_ACK_LIFETIME_MS`), so this is a small, bounded
    /// storage-efficiency cost that buys delivery-confirmation resilience, never a correctness defect.
    pub fn spoolable_private_bundles(&self) -> Vec<(BundleId, Tag, Vec<u8>, u64)> {
        let mut out = Vec::new();
        for id in self.store.have().ids {
            let Some(b) = self.store.get(&id) else {
                continue;
            };
            if !b.is_private() {
                continue;
            }
            let Some(prefix) = b.inner.private.as_ref().and_then(|p| p.mailbox) else {
                continue;
            };
            // sec-priv-04 / core-protocol-r2-02: the header already carries ONLY the routing prefix, so
            // the relay's spool key is an anonymity set an address-knower can't resolve to one recipient.
            let route = route_key_from_prefix(&prefix);
            // core-protocol-r2-01: DO NOT suppress the spool just because a live gradient exists for this
            // route. The gradient keys on the 2-byte PREFIX, so a live next-hop may be a DIFFERENT
            // recipient that merely collides on the prefix with this bundle's intended recipient. The old
            // "live ⇒ don't spool" rule black-holed the passive/offline colliding recipient: the forward
            // gate steered the copy only down the colliding recipient's link (which drops it on the
            // recognition check) AND the spool refused, so the intended recipient — who is passive and
            // never on the live gradient — could receive it via NEITHER path. We now ALWAYS spool a
            // private bundle carrying a mailbox. If the live route happens to be the true recipient, the
            // spooled copy is merely redundant (the recipient dedups by id and the vaccine/TTL reclaims
            // it); if it is a prefix collision, the spool is the ONLY path that reaches the real
            // recipient's later want-beacon. Correctness (never black-hole) outranks the storage saving.
            if let Ok(bytes) = b.to_bytes() {
                let expires = self.durable_expiry(&id, &b);
                out.push((id, route, bytes, expires));
            }
        }
        out
    }

    /// Ingest a foreign (relayed) bundle pulled from durable storage — e.g. a
    /// cross-partition handoff written into our Firestore partition while we were
    /// already warm (DESIGN.md §28). Stores it for onward relay and offers it to live
    /// links, exactly as if a peer had handed it over. A cold-started node gets the same
    /// bundles for free via [`Node::with_store`]'s rehydrate.
    pub fn ingest(&mut self, bundle: Bundle) {
        // relay-F (pass-5 audit): re-inject via LOCAL_LINK, NOT a phantom `LinkId::MAX`. Both match no
        // real connection (so the bundle is offered to every live link, the offer step skips only the
        // arrival link), but ONLY LOCAL_LINK is exempt from the F-07 per-link private-ingest flood cap.
        // This IS our own re-injection from durable storage (a mailbox pull or a cross-partition handoff),
        // so it must not be capped: relayd's `process_mailbox` deletes each spool copy BEFORE re-ingest,
        // and a beacon that pulls > MAX_PRIV_BUNDLES_PER_WINDOW bundles (a real backlog, or an attacker
        // co-locating spam under a shared mailbox prefix) would otherwise overflow the cap and silently
        // drop the overflow AFTER the durable copy is gone: permanent loss of offline messages.
        self.on_bundle(LOCAL_LINK, bundle);
    }

    /// Drop everything we're currently holding: our own undelivered messages (stop
    /// retransmitting them) and any bundles we're relaying for peers. Clears the relay
    /// queue shown in the UI. Delivery-status history (`tx`) is kept so already-sent
    /// messages still render their last state; sessions/directory are untouched.
    pub fn clear_queue(&mut self) {
        for id in self.store.have().ids {
            self.store.remove(&id);
        }
        self.relay_order.clear();
        self.relay_fwd.clear();
        self.ack_replicate.clear();
        self.pending.clear();
    }

    /// Addresses of currently-connected, authenticated peers (handshake complete).
    pub fn peers(&self) -> Vec<PubKeyBytes> {
        self.links
            .values()
            .filter_map(|s| match s {
                LinkState::Up(e) => Some(e.peer),
                _ => None,
            })
            .collect()
    }

    /// `(peer address, link id)` for every live link — lets the host map a direct
    /// neighbour to the transport(s) carrying it (the bearer owns the link-id → medium
    /// mapping). A peer may appear more than once if reachable over multiple bearers.
    pub fn peer_links(&self) -> Vec<(PubKeyBytes, LinkId)> {
        self.links
            .iter()
            .filter_map(|(id, s)| match s {
                LinkState::Up(e) => Some((e.peer, *id)),
                _ => None,
            })
            .collect()
    }

    /// Send a message to a directly-connected peer. Returns the bundle id, or `None`
    /// if not connected to that address. (Any address can be reached with
    /// [`Node::send_message`]; this just gates on a live link.)
    pub fn send_to(
        &mut self,
        address: &PubKeyBytes,
        content_type: String,
        body: Vec<u8>,
        request_ack: bool,
    ) -> Result<Option<BundleId>> {
        let connected = self
            .links
            .values()
            .any(|s| matches!(s, LinkState::Up(e) if e.peer == *address));
        if !connected {
            return Ok(None);
        }
        // Directly-connected fast path: the peer already knows our identity (the link
        // authenticated it), so untraceability vs them is moot — send a directed unicast
        // rather than flooding. Reach any *non*-adjacent address untraceably via send_message.
        Ok(Some(self.send_message_traced(
            *address,
            content_type,
            body,
            request_ack,
        )?))
    }

    /// Advance time: expire stale adverts and retransmit unacked bundles whose
    /// retry timer is due, giving up on any past their lifetime (§7, §8).
    pub fn tick(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        self.clock_anchored |= now_ms != 0;
        // §35: roll the keyed-access hint tables when the epoch advances (no-op under Open, cheap
        // when the epoch is stable). Keeps admission an O(1) hint lookup instead of a per-bundle scan.
        self.access_policy.refresh(now_ms);
        // Cold-start carrier recovery is intentionally not an unbounded constructor operation. One
        // bounded round runs per tick, retaining its cursor and cleanup queue on exhaustion/failure.
        let _ = self.continue_carrier_rehydrate();
        // §35: drop pending attribution for any bundle no longer HELD. A delivered bundle already
        // removed its own entry (via meter_delivered) synchronously; what remains here for a
        // no-longer-held id is an evicted or TTL-expired bundle that never delivered, and is
        // therefore never billed as carriage (decision 2). Cheap: only runs when non-empty.
        if !self.metered_attribution.is_empty() {
            self.metered_attribution
                .retain(|id, _| self.store.contains(id));
        }
        // Persisted PeerSession intentionally has no wall-clock field. Rehydrate marks restored
        // sessions unanchored, so their first real tick establishes an idle-GC baseline instead of
        // comparing an epoch-scale timestamp against zero and deleting them immediately.
        if now_ms != 0 {
            for peer in self.unanchored_sessions.iter().copied().collect::<Vec<_>>() {
                if self.sessions.contains_key(&peer) {
                    self.touch_session(peer);
                } else {
                    self.unanchored_sessions.remove(&peer);
                }
            }
        }
        let _ = self.expire_outstanding_requests();
        let _ = self.expire_hps_subscribe_pending();
        if now_ms != 0 {
            self.unanchored_outstanding_requests.retain(|id| {
                self.outstanding_requests
                    .get(id)
                    .is_some_and(|request| request.expires_at_ms <= now_ms)
            });
            self.unanchored_hps_subscribe_pending.retain(|path| {
                self.hps_subscribe_pending
                    .get(path)
                    .is_some_and(|pending| pending.expires_at_ms <= now_ms)
            });
        }
        self.expire_hps_inbox();
        self.expire_durable_responses();
        self.expire_hps_replays();
        self.hps_acked.retain(|_, expiry| *expiry > now_ms);
        self.directory.expire(now_ms);
        self.forget_evicted_adverts();
        self.prune_peer_sent();
        // §39 P4 (+ sec-priv-04): drop stale next-hops — a recipient that stopped beaconing (moved or
        // went passive) stops attracting bundles down its link within one TTL (no permanent black-hole).
        // Prune expired links per bucket, then drop any bucket left with no live next-hop.
        self.recv_gradient.retain(|_, e| {
            e.links.retain(|(_, gl)| gl.expires_at > now_ms);
            !e.links.is_empty()
        });
        // Re-advertise hosted Discoverable topics we don't currently have a live advert for —
        // e.g. after a restart, where the topic persists but the in-memory directory/advert do
        // not. Runs with the real clock set (above), so created_at is valid; once published the
        // path is in hps_adverts and this skips it. This is what makes a hosted channel
        // discoverable again after the host relaunches (DESIGN.md §32).
        if self.app.disc_key.is_some() {
            let stale: Vec<String> = self
                .services
                .iter()
                .filter(|(p, c)| {
                    c.visibility == hps::Visibility::Discoverable
                        && !self.hps_adverts.contains_key(*p)
                })
                .map(|(p, _)| p.clone())
                .collect();
            for path in stale {
                if let Some(cfg) = self.services.get(&path).cloned() {
                    self.publish_topic_advert(&path, &cfg);
                }
            }
        }
        self.store.prune(now_ms);
        self.expire_outgoing_carriers();
        // Accepted receiver dedup expires with the bundle window. Unaccepted inbox rows never expire:
        // host acceptance, not sender TTL, owns their retention and redelivery lifecycle.
        let expired_received: Vec<BundleId> = self
            .receiver_seen
            .iter()
            .filter(|(id, seen)| {
                seen.expires_at_ms <= now_ms && !self.durable_inbox.contains_key(*id)
            })
            .map(|(id, _)| *id)
            .collect();
        if !expired_received.is_empty() {
            let removals: Vec<KvMutation> = expired_received
                .iter()
                .map(|id| KvMutation::Remove {
                    key: Self::receiver_seen_kv_key(id),
                })
                .collect();
            if self.store.apply_kv_batch(&removals).is_ok() {
                for id in expired_received {
                    self.receiver_seen.remove(&id);
                }
            }
        }
        // Drop relay-queue entries whose bundles have been delivered or expired.
        self.relay_order.retain(|id| self.store.contains(id));
        self.relay_fwd.retain(|id, _| self.store.contains(id));
        // Expire vaccine immunity after a bundle could no longer be live (1h).
        self.immune
            .retain(|_, t| now_ms.saturating_sub(*t) < 3_600_000);
        // core-protocol-r12-01: forget the §39 private-delivery marks once the store stops deduping the
        // id (the same window the old `seen`-based gate used), so a still-live duplicate is deduped but
        // an expired id can't pin the set. Reading `seen` only to bound retention is safe — a chimera
        // that marks `seen` can widen this window slightly but can never make the set CONTAIN an id it
        // never delivered, which is the property that closes the suppression. Also retain while the id is
        // `immune`: a delivery vaccine can race AHEAD of the bundle, so `on_bundle` returns at the immune
        // check before `store.put` marks `seen` — without this the mark would be pruned and a later
        // duplicate would re-deliver. `immune` is on the same 1h horizon, so this cannot pin the set open.
        self.delivered_private
            .retain(|id| self.store.seen(id) || self.immune.contains_key(id));
        // core-protocol-r3-02: forget raced-ahead vaccine tokens on the same 1h horizon (a target
        // that hasn't arrived within an hour is past any live window; if it arrives later it just
        // falls back to TTL reclamation, never a black-hole).
        self.seen_vaccine_tokens
            .retain(|_, t| now_ms.saturating_sub(*t) < 3_600_000);
        // D6: GC forward-secret sessions idle past SESSION_MAX_IDLE_MS (memory + persisted store).
        self.gc_idle_sessions();
        // Forget forwarded-route memory for bundles that can no longer ACK back (§27).
        self.forwarded
            .retain(|_, (_, _, t)| now_ms.saturating_sub(*t) < 3_600_000);
        // A stream accepted before the host established a real clock gets one absolute anchor on
        // the first real tick. Later arrivals may refresh idle activity, never this lifetime anchor.
        if now_ms != 0 {
            let unanchored: Vec<(PubKeyBytes, StreamId)> = self
                .incoming_streams
                .iter()
                .filter(|(_, stream)| stream.started_at == 0)
                .map(|(key, _)| *key)
                .collect();
            for (from, stream_id) in unanchored {
                if self.anchor_incoming_stream(&from, &stream_id, now_ms) {
                    if let Some(stream) = self.incoming_streams.get_mut(&(from, stream_id)) {
                        stream.started_at = now_ms;
                        if stream.at == 0 {
                            stream.at = now_ms;
                        }
                    }
                }
            }
        }
        // Drop abandoned half-received carrier streams (sender vanished mid-transfer), releasing
        // sender/global accounting and persisted chunks through the same cleanup path.
        let dropped: Vec<(PubKeyBytes, StreamId)> = self
            .incoming_streams
            .iter()
            .filter(|(_, stream)| {
                (stream.at != 0 && now_ms.saturating_sub(stream.at) >= CARRIER_STREAM_IDLE_MS)
                    || (stream.started_at != 0
                        && now_ms.saturating_sub(stream.started_at) >= CARRIER_STREAM_LIFETIME_MS)
            })
            .map(|(k, _)| *k)
            .collect();
        for (from, sid) in dropped {
            let _ = self.abort_incoming_stream(&from, &sid);
        }
        // Forget carrier→original links once the carrier is no longer held (delivered/expired).
        self.carrier_owner.retain(|cid, _| self.store.contains(cid));
        // Forget deferred-content aliases once their real bundle is gone (delivered/expired).
        self.tx_alias
            .retain(|real, _| self.store.contains(real) || self.pending.contains_key(real));
        // Periodically RE-gossip adverts to every live link. Adverts (presence, and crucially
        // prekeys, §25) are otherwise offered only once per link — at link-up — so a node that
        // didn't have a peer's prekey at connect time could never open a forward-secret session to
        // it until a RECONNECT forced a fresh gossip. That's the "you have to move out of range and
        // back to send a message" bug — and it's transport-agnostic (BLE, Wi-Fi, relay alike). This
        // re-offers over stable links so the prekey arrives without churning the connection; the
        // receiver dedups unchanged adverts, so it's cheap. (DESIGN.md §16/§25.)
        if now_ms.saturating_sub(self.last_regossip_ms) >= REGOSSIP_INTERVAL_MS {
            self.last_regossip_ms = now_ms;
            // Re-gossip ONLY our OWN prekey/presence to every live link (NOT the whole directory).
            // Re-flooding the whole directory was O(directory × links) every interval — the multi-peer
            // resource-exhaustion bug (tx >> rx, real messages starve). But re-offering just our own
            // securing adverts is cheap (~2-3 adverts × links) and lets a peer that silently lost state
            // on a STABLE link (no flap to trigger the link-up re-offer) re-secure within the interval.
            // The foreign bulk stays per-peer-deduped; newly published/ingested adverts still propagate
            // immediately via on_advert/publish → offer_adverts_to_all.
            let own = self
                .directory
                .advert_ids_by_publisher(&self.identity.address());
            if !own.is_empty() {
                for state in self.links.values_mut() {
                    if let LinkState::Up(est) = state {
                        for id in &own {
                            est.sent_adverts.remove(id);
                        }
                    }
                }
                self.offer_adverts_to_all();
            }
        }
        // core-03: rotate our signed prekey on epoch boundaries so a compromised SPK secret only
        // exposes a bounded recent window of sessions, then re-publish the new one.
        self.rotate_prekey_if_due();
        // §39 P4: keep our receiver-beacon fresh (short interval ≪ its TTL) so the gradient toward
        // us stays alive and re-points if we move. Passive (max-privacy) recipients skip this.
        if self.route_to_me
            && now_ms.saturating_sub(self.last_recv_beacon_ms) >= RECV_BEACON_REFRESH_MS
        {
            self.last_recv_beacon_ms = now_ms;
            // F-06: the mailbox is now bound to our address + epoch (not the prekey), so the beacon is
            // self-verifying at the relay — no prekey coordination needed. Emits current + window epochs.
            let _ = self.publish_recv_beacon();
            self.beaconed_tick = true; // observability: emitted a recv-beacon this tick (see drain_beaconed)
        }
        // Retry any content still waiting on a prekey (it gossips, §25).
        self.flush_pending_content();
        // ACK bookkeeping: forget replication tracking for ACKs no longer held, and age
        // out the re-ACK throttle map.
        self.ack_replicate.retain(|id, _| self.store.contains(id));
        self.last_ack
            .retain(|_, t| now_ms.saturating_sub(*t) < 3_600_000);
        // Expired HNS records leave the device entirely (DESIGN.md §30): once a cached
        // endpoint's DNS-derived TTL lapses it's dropped, so the next request re-resolves
        // all the way back to DNS rather than reusing a stale address.
        self.hns_cache.retain(|_, e| e.expires_at_ms > now_ms);
        // Delay-tolerant resolution: periodically re-attempt anything still unresolved, so a
        // query placed while offline eventually completes once internet/a peer appears (§30).
        if !self.pending_resolves.is_empty()
            && now_ms.saturating_sub(self.last_resolve_retry_ms) >= HNS_RETRY_INTERVAL_MS
        {
            self.last_resolve_retry_ms = now_ms;
            for key in self.pending_resolves.iter().cloned().collect::<Vec<_>>() {
                // reach-A audit: clear the in-flight guard before re-attempting. A domain still in
                // pending_resolves never got a provide_reach_record callback (an answer removes it), so
                // its prior lookup either is still in flight or was DROPPED by the host. Without this
                // remove, queue_dns_lookup's `dns_inflight.insert` returns false and the retry emits
                // nothing, wedging the name forever on a single dropped callback. Re-emitting once per
                // HNS_RETRY_INTERVAL is exactly the delay-tolerant retry this loop is for.
                self.dns_inflight.remove(&key);
                self.attempt_resolve(&key);
            }
        }

        let mut retransmit = false;
        for id in self.pending.keys().copied().collect::<Vec<_>>() {
            let p = self.pending[&id];
            if now_ms >= p.created_at.saturating_add(p.lifetime_ms as u64) {
                self.pending.remove(&id); // lifetime exhausted — give up
                self.store.remove(&id);
                continue;
            }
            if now_ms >= p.next_retx_at {
                // Refresh the copy budget and re-offer along every link.
                if !self.store.contains(&id) {
                    self.pending.remove(&id);
                    continue;
                }
                self.store.set_copies(&id, p.copies);
                for state in self.links.values_mut() {
                    if let LinkState::Up(est) = state {
                        est.sent_bundles.remove(&id);
                    }
                }
                if let Some(p) = self.pending.get_mut(&id) {
                    // Exponential backoff so a long-lived bundle retries a handful of
                    // times over its lifetime, not every 30s for days.
                    p.retx_interval = p.retx_interval.saturating_mul(2).min(MAX_RETX_INTERVAL_MS);
                    p.next_retx_at = now_ms.saturating_add(p.retx_interval);
                }
                retransmit = true;
            }
        }
        if retransmit {
            self.offer_bundles_to_all();
        }
    }

    /// Publish a locally-originated advert; gossips it to live links.
    pub fn publish(&mut self, advert: Advert) {
        let accepted = self.directory.ingest(advert, self.now_ms).unwrap_or(false);
        self.forget_evicted_adverts();
        if accepted {
            self.offer_adverts_to_all();
        }
    }

    /// Legacy raw-bundle test seam. Public hosts use [`Self::inbox_items`] so polling is
    /// non-destructive and cannot consume a ratchet twice after a crash.
    pub fn take_inbox(&mut self) -> Vec<Bundle> {
        let queued = std::mem::take(&mut self.inbox);
        let mut accepted = Vec::with_capacity(queued.len());
        for bundle in queued {
            let id = bundle.id();
            if !self.pending_app_deliveries.contains_key(&id) || self.complete_app_delivery(&id) {
                accepted.push(bundle);
            } else {
                self.inbox.push(bundle);
            }
        }
        accepted
    }

    /// Decrypted, authenticated messages awaiting synchronous host acceptance. Repeated calls return
    /// the same stable ids until [`Self::accept_inbox`] durably removes each item.
    pub fn inbox_items(&self) -> Vec<InboxItem> {
        self.inbox_order
            .iter()
            .filter_map(|id| self.durable_inbox.get(id).cloned())
            .collect()
    }

    /// Accept one host-persisted inbox item. The durable row is removed before in-memory state changes
    /// or an ACK/vaccine is emitted. A failed delete leaves the item available for redelivery.
    pub fn accept_inbox(&mut self, id: &BundleId) -> Result<bool> {
        let Some(item) = self.durable_inbox.get(id).cloned() else {
            return Ok(false);
        };
        self.store
            .apply_kv_batch(&[KvMutation::Remove {
                key: Self::inbox_kv_key(id),
            }])
            .map_err(|e| Error::Other(format!("inbox acceptance persistence failed: {e}")))?;
        self.durable_inbox.remove(id);
        if let Some(charge) = self.durable_inbox_charges.remove(id) {
            self.release_app_queue(charge);
        }
        self.inbox_order.retain(|queued| queued != id);
        self.inbox.retain(|bundle| bundle.id() != *id);
        self.emit_inbox_ack(&item.acknowledgement);
        Ok(true)
    }

    /// Opaque bytes to ship over the bearer, paired with their connection.
    pub fn drain_outgoing(&mut self) -> Vec<(LinkId, Vec<u8>)> {
        std::mem::take(&mut self.outgoing)
    }

    /// Observability: enable recording of which bundle crosses which link (see [`Self::drain_transfers`]).
    pub fn set_observe(&mut self, on: bool) {
        self.observe = on;
    }

    /// Observability: take the `(link, bundle_id, is_final_delivery)` transfers recorded since the last
    /// call. Lets a caller attribute each hop to the real bundle that crossed it. Empty unless
    /// [`Self::set_observe`]`(true)` was called.
    pub fn drain_transfers(&mut self) -> Vec<(LinkId, BundleId, bool)> {
        // Report DISPLAY ids: a deferred send (queued while the recipient's prekey gossips over, §25)
        // flushes later under a fresh wire id, the caller tracked the id `send` returned, so without
        // this mapping a deferred message's flood is invisible to an observer.
        std::mem::take(&mut self.transfers)
            .into_iter()
            .map(|(l, id, d)| (l, self.display_id(&id), d))
            .collect()
    }

    /// Observability: take the ids of our OWN sends that were confirmed delivered (by a returning ACK)
    /// since the last call. A sender only learns delivery this way — never from the recipient directly
    /// — so a per-device UI can show the sender "delivered" only once its ACK is home.
    pub fn drain_delivered(&mut self) -> Vec<BundleId> {
        std::mem::take(&mut self.sends_delivered)
    }

    /// Set the lifetime stamped on new messages/ACKs this node originates. A real per-bundle sender
    /// choice (`BundleOpts::lifetime_ms`); the store's own prune enforces it on tick. A short
    /// lifetime makes relay copies of a delivered message expire quickly (§39 has no relay vaccine,
    /// so relays clean up by TTL); production leaves it at the 24h default.
    pub fn set_default_lifetime_ms(&mut self, ms: u32) {
        self.default_lifetime_ms = ms;
    }

    /// Observability: the §39 P4 recv-gradient as `(route_key, inbound_link, hops)` — the reachable mailbox
    /// **routing prefixes** (sec-priv-04, right-padded into a Tag) this node can steer a private bundle
    /// toward, and the next hop for each. Read-only view of the distributed routing tree (each node
    /// holds a slice). Keys match [`Node::current_mailbox_tag`] (also projected).
    pub fn recv_gradient_view(&self) -> Vec<(Tag, LinkId, u8)> {
        // sec-priv-04: a bucket may hold several next-hops (an anonymity set); emit one row per
        // (route-prefix, next-hop) so a caller sees every steer-able link.
        self.recv_gradient
            .iter()
            .flat_map(|(tag, e)| e.links.iter().map(move |(l, gl)| (*tag, *l, gl.hops)))
            .collect()
    }

    /// Observability: this node's current mailbox **routing key** — its full tag `H(address ‖ epoch)`
    /// projected onto the sec-priv-04 routing prefix (right-padded into a Tag), i.e. the exact key a
    /// relay's gradient buckets under. Projected (not the raw full tag) so it lines up against
    /// [`Node::recv_gradient_view`] keys now that routing decisions key on the prefix.
    pub fn current_mailbox_tag(&self) -> Tag {
        route_key(&crypto::mailbox_tag(
            &self.identity.address(),
            mailbox_epoch(self.now_ms),
        ))
    }

    /// Observability: did this node emit a §39 recv-beacon since the last call? Surfaces when a node
    /// as it advertises its reachability (the presence signal that lays the gradient tree).
    pub fn drain_beaconed(&mut self) -> bool {
        std::mem::take(&mut self.beaconed_tick)
    }

    /// Observability: do we currently hold `addr`'s prekey (i.e. could we seal a private send to them now)?
    pub fn knows_prekey(&self, addr: &PubKeyBytes) -> bool {
        self.directory.prekey(addr).is_some()
    }

    /// Observability: send status for each message we originated — `(display id, distinct peers we've handed
    /// it to, delivered)`. Mirrors the debug app's "Sending / Sent · N / Delivered" (peers==0 = Sending,
    /// N>0 = Sent·N, delivered = ACK home). Read-only.
    pub fn sends_status(&self) -> Vec<(BundleId, u16, bool)> {
        self.tx
            .iter()
            .map(|(id, info)| {
                (
                    *id,
                    info.relayed.len().min(u16::MAX as usize) as u16,
                    info.delivered,
                )
            })
            .collect()
    }

    /// Observability: ids of the bundles this node currently holds, lets a caller show which
    /// devices still have a copy (they drop it as the delivery-ACK/vaccine reaches them). Read-only;
    /// storage lifecycle stays entirely with the core + its `Store` (real TTL, real prune).
    pub fn held_bundle_ids_display(&self) -> Vec<BundleId> {
        self.held_bundle_ids()
            .into_iter()
            .map(|id| self.display_id(&id))
            .collect()
    }

    pub fn held_bundle_ids(&self) -> Vec<BundleId> {
        self.store.have().ids
    }

    /// Feed one bearer event into the loop.
    pub fn handle(&mut self, event: BearerEvent) {
        match event {
            BearerEvent::Connected(link, role) => self.on_connected(link, role),
            BearerEvent::Disconnected(link) => {
                // Snapshot what we've already gossiped to this PEER so a reconnect doesn't re-flood
                // the whole directory (the flapping-link resource-exhaustion bug). Keyed by peer, not
                // by link instance — the link id changes on every reconnect, the peer address doesn't.
                if let Some(LinkState::Up(est)) = self.links.remove(&link) {
                    self.peer_sent.insert(
                        est.peer,
                        PeerSent {
                            adverts: est.sent_adverts,
                            bundles: est.sent_bundles,
                            last_seen_ms: self.now_ms,
                        },
                    );
                    self.prune_peer_sent();
                }
                self.priv_ingest.remove(&link); // F-07: drop the rate-limit counter for a dead link
                self.advert_ingest.remove(&link);
            }
            BearerEvent::Data(link, bytes) => self.on_data(link, bytes),
        }
    }

    // --- connection lifecycle -------------------------------------------------

    fn auth_payload(&self) -> Vec<u8> {
        let auth = LinkAuth {
            address: self.identity.address(),
        };
        postcard::to_allocvec(&auth).expect("auth encode")
    }

    fn on_connected(&mut self, link: LinkId, role: Role) {
        // core-05: LinkId 0 is the RESERVED local/no-link sentinel. It marks our own re-injection
        // path (rehydrate, stream reassembly) and the "no link to skip" arg to offer helpers, and it
        // is exempt from the F-07 private-ingest rate limit. A real bearer must never assign it, or an
        // attacker on that connection would bypass the unsigned-private flood cap. Refuse to admit a
        // link 0 rather than trust bearer id allocation.
        if link == LOCAL_LINK {
            // A real bearer must never assign the reserved sentinel; refuse to admit it as a
            // connection rather than let its traffic inherit the LOCAL_LINK rate-limit exemption.
            return;
        }
        // Idempotent: a spurious Connected for a link we already hold must not tear down its live
        // Noise session (a re-handshake would reset dedup + re-flood). Real reconnects are preceded
        // by Disconnected (bearer contract), which removes the entry and snapshots its dedup per-peer.
        if self.links.contains_key(&link) {
            return;
        }
        let Ok(mut hs) = (match role {
            Role::Initiator => LinkHandshake::initiator(&self.identity),
            Role::Responder => LinkHandshake::responder(&self.identity),
        }) else {
            return;
        };

        // The initiator sends the first handshake message immediately.
        if role == Role::Initiator {
            if let Ok(msg) = hs.write(&self.auth_payload()) {
                self.send_packet(link, LinkPacket::Handshake(msg));
            }
        }
        self.links.insert(
            link,
            LinkState::Handshaking(Box::new(Handshaking { hs, verified: None })),
        );
    }

    fn on_data(&mut self, link: LinkId, bytes: Vec<u8>) {
        let Some(packet) = decode_link_packet(&bytes) else {
            return;
        };
        match packet {
            LinkPacket::Handshake(msg) => self.on_handshake_msg(link, &msg),
            LinkPacket::Data(ct) => self.on_record(link, &ct),
            LinkPacket::DataFrag { idx, cnt, ct } => self.on_record_frag(link, idx, cnt, &ct),
        }
    }

    fn on_handshake_msg(&mut self, link: LinkId, msg: &[u8]) {
        // Take the handshake out so we can both write and (later) consume it.
        let Some(LinkState::Handshaking(boxed)) = self.links.remove(&link) else {
            return; // unknown link or already established
        };
        let mut state = *boxed;

        let Ok(payload) = state.hs.read(msg) else {
            return; // drop link on bad handshake
        };

        // Bind the peer's claimed address to the Noise-authenticated static key:
        // they match iff the address's derived X25519 key equals `remote_static`.
        if let Some(remote_static) = state.hs.remote_static() {
            match postcard::from_bytes::<LinkAuth>(&payload) {
                Ok(auth) if crypto::address_to_x(&auth.address) == Some(remote_static) => {
                    state.verified = Some(auth.address);
                }
                Ok(_) => return, // address doesn't match the link key → drop
                Err(_) => {}     // no claim in this message (e.g. m1) → keep going
            }
        }

        if !state.hs.is_finished() {
            if let Ok(out) = state.hs.write(&self.auth_payload()) {
                self.send_packet(link, LinkPacket::Handshake(out));
            }
        }

        if state.hs.is_finished() {
            let (Some(peer), Ok(session)) = (state.verified, state.hs.into_session()) else {
                return; // finished without an authenticated peer → drop
            };
            // Restore the per-peer dedup so a reconnect to a peer we've already synced doesn't
            // re-flood the directory; a brand-new peer has no entry → empty sets → full first sync
            // (prekey + presence + bundle handoff) still happens exactly once (DESIGN.md §16/§25/§27).
            let prior = self.peer_sent.remove(&peer).unwrap_or_default();
            self.links.insert(
                link,
                LinkState::Up(Box::new(Established {
                    session,
                    peer,
                    sent_bundles: prior.bundles,
                    sent_adverts: prior.adverts,
                    peer_has: HashSet::new(),
                    frag_buf: Vec::new(),
                    frag_next: 0,
                })),
            );
            // ALWAYS re-offer our OWN adverts (prekey/presence) on link-up: clear them from the
            // restored per-peer dedup so they go out again. A peer that lost state (restart / data-
            // wipe / cache-evict) must be able to re-secure to us — it needs our prekey. The FOREIGN
            // directory bulk stays deduped (no reflood), so this re-offers only ~2-3 small adverts.
            let own = self
                .directory
                .advert_ids_by_publisher(&self.identity.address());
            // Our own UNDELIVERED messages (awaiting an ACK): re-offer them on link-up too, so a
            // reconnect re-sends them IMMEDIATELY instead of waiting out the exponential-backoff
            // retransmit timer (30s → 15min). A bundle "sent" on a link that then dropped sits in the
            // restored per-peer dedup marked already-sent — which is what made delivery take minutes
            // on a flaky BLE link even after securing succeeded.
            let pending_ids: Vec<BundleId> = self.pending.keys().copied().collect();
            // Generalize that to EVERYTHING we still hold: delivery-ACKs and vaccines have no
            // retransmit timer of their own, so a copy lost to a link flap (marked sent, never
            // received) would otherwise be stranded against this peer FOREVER — the stuck-"Sending…"
            // sender bug. If we still hold a bundle it is still relevant; the receiver
            // dedups duplicates by `seen`, so re-offering on a fresh contact costs only bandwidth.
            let held_ids = self.store.have().ids;
            if let Some(LinkState::Up(est)) = self.links.get_mut(&link) {
                for id in &own {
                    est.sent_adverts.remove(id);
                }
                for id in &pending_ids {
                    est.sent_bundles.remove(id);
                }
                for id in &held_ids {
                    est.sent_bundles.remove(id);
                }
            }
            // §35 custody beacon: if enabled (relays), tell this peer what we already hold so it
            // stops re-offering those to us, cutting duplicate-ingress COGS. Mode-1 (over the
            // authenticated link with the peer it constrains): the peer's own truthful claim, no
            // forgery surface. Sent BEFORE our offers so the peer's first offer pass to us is
            // already filtered by what we hold (symmetric: each side beacons its holdings).
            if self.emit_have {
                let mut ids = self.store.have().ids;
                ids.truncate(MAX_HAVE_ADVERTISE);
                self.send_record(link, &Wire::Have(crate::store::HaveSet { ids }));
            }
            // Adverts (prekeys + presence) FIRST, then bulk bundles: a peer needs our prekey to
            // open a forward-secret session to us, so it must not sit behind a burst of relay-bundle
            // offers on a rate-limited BLE link (that head-of-line blocking delayed "Securing").
            self.offer_adverts_to_link(link);
            self.offer_bundles_to_link(link);
        } else {
            self.links
                .insert(link, LinkState::Handshaking(Box::new(state)));
        }
    }

    /// §35 custody beacon inbound: this peer told us (over the authenticated link) which ids it
    /// already holds, so we suppress re-offering them on this link. Mode-1: the claim constrains
    /// only this peer's own link, so a dishonest claim just denies the peer a bundle it said it
    /// had (self-harm), never censors delivery to anyone else. Bounded by [`MAX_HAVE_ADVERTISE`]
    /// via a truncating merge.
    fn on_have(&mut self, link: LinkId, have: crate::store::HaveSet) {
        if let Some(LinkState::Up(est)) = self.links.get_mut(&link) {
            for id in have.ids.into_iter().take(MAX_HAVE_ADVERTISE) {
                if est.peer_has.len() >= MAX_HAVE_ADVERTISE {
                    break;
                }
                est.peer_has.insert(id);
            }
        }
    }

    // --- inbound records ------------------------------------------------------

    fn on_record(&mut self, link: LinkId, ct: &[u8]) {
        let Some(LinkState::Up(est)) = self.links.get_mut(&link) else {
            return;
        };
        let Ok(plaintext) = est.session.decrypt(ct) else {
            return;
        };
        let peer = est.peer;
        if advert_record_exceeds_limit(&plaintext) {
            return;
        }
        match postcard::from_bytes::<Wire>(&plaintext) {
            Ok(Wire::Bundle(b)) => {
                self.on_bundle(link, b);
            }
            Ok(Wire::Advert(a)) => self.on_advert(link, peer, a),
            Ok(Wire::Have(hs)) => self.on_have(link, hs),
            Err(_) => {}
        }
    }

    /// Receive one fragment of an oversized record (DESIGN.md §20). Each fragment is its own
    /// Noise message, so decrypt in arrival order (the bearer is ordered) and concatenate the
    /// plaintext; on the final fragment, decode and dispatch the whole [`Wire`]. An
    /// out-of-order fragment means loss/corruption — drop the partial record and resync.
    fn on_record_frag(&mut self, link: LinkId, idx: u16, cnt: u16, ct: &[u8]) {
        let ready = {
            let Some(LinkState::Up(est)) = self.links.get_mut(&link) else {
                return;
            };
            // Decrypt now: the Noise ratchet must advance in lockstep with arrivals.
            let Ok(piece) = est.session.decrypt(ct) else {
                return;
            };
            // A valid advert is at most 8 KiB and therefore never needs record fragmentation. Reject
            // its discriminant on the first fragment before accumulating a large attacker record.
            if piece.is_empty() || (idx == 0 && piece.first() == Some(&1)) {
                est.frag_buf.clear();
                est.frag_next = 0;
                return;
            }
            if usize::from(cnt) > MAX_RECORD_FRAGMENTS
                || piece.len() > MAX_RECORD_PLAINTEXT
                || est.frag_buf.len().saturating_add(piece.len()) > MAX_REASSEMBLED_RECORD
            {
                est.frag_buf.clear();
                est.frag_next = 0;
                return;
            }
            if cnt == 0 || idx >= cnt || idx != est.frag_next {
                // Stray or reordered fragment: reset. Only a fresh idx 0 starts a new record.
                est.frag_buf.clear();
                est.frag_next = 0;
                if idx != 0 {
                    return;
                }
            }
            est.frag_buf.extend_from_slice(&piece);
            est.frag_next += 1;
            if est.frag_next == cnt {
                let plaintext = std::mem::take(&mut est.frag_buf);
                est.frag_next = 0;
                Some((plaintext, est.peer))
            } else {
                None
            }
        };
        if let Some((plaintext, peer)) = ready {
            if advert_record_exceeds_limit(&plaintext) {
                return;
            }
            match postcard::from_bytes::<Wire>(&plaintext) {
                Ok(Wire::Bundle(b)) => {
                    self.on_bundle(link, b);
                }
                Ok(Wire::Advert(a)) => self.on_advert(link, peer, a),
                Ok(Wire::Have(hs)) => self.on_have(link, hs),
                Err(_) => {}
            }
        }
    }

    /// F-07: fixed-window per-link rate limit for unsigned §39 private bundles. Returns false
    /// (drop) when this link has exceeded [`MAX_PRIV_BUNDLES_PER_WINDOW`] in the current window.
    /// `from_link == LOCAL_LINK` is our own re-injection path (rehydrate / stream reassembly), never
    /// limited. A real bearer never assigns [`LOCAL_LINK`] ([`Node::on_connected`] enforces this), so
    /// this exemption cannot be reached from a remote connection (core-05).
    fn allow_private_ingest(&mut self, from_link: LinkId) -> bool {
        if from_link == LOCAL_LINK {
            return true;
        }
        let now = self.now_ms;
        let (start, count) = self.priv_ingest.entry(from_link).or_insert((now, 0));
        if now.saturating_sub(*start) >= PRIV_INGEST_WINDOW_MS {
            *start = now;
            *count = 0;
        }
        *count += 1;
        *count <= MAX_PRIV_BUNDLES_PER_WINDOW
    }

    fn on_bundle(&mut self, from_link: LinkId, bundle: Bundle) {
        let _ = self.process_bundle(from_link, bundle);
    }

    fn process_bundle(&mut self, from_link: LinkId, mut bundle: Bundle) -> bool {
        if bundle.verify().is_err() {
            return false; // never store/relay unverifiable bundles
        }
        if bundle.is_private() {
            // Provenance is mutable envelope metadata and is never valid on the untraceable path.
            // Clear injected values without rejecting an otherwise valid private bundle.
            bundle.env.trace.clear();
        }
        let _ = self.expire_hps_subscribe_pending();
        // F-07: throttle a flood of unsigned private bundles from a single link before it can
        // touch the store, dedup table, or flood path. Signed (attributable) traffic is exempt.
        //
        // core-protocol-r2-03 / security-privacy-r2-01: a §39 delivery vaccine is ALSO unsigned and
        // freely mintable (its id self-verifies as `H(domain‖token)` for any attacker-chosen token),
        // yet it is not `is_private()` so the original gate missed it — a peer could flood unique-token
        // vaccines uncapped, each forcing a store scan (bounded now by the `seen` gate, but still work).
        // Subject Vaccine bundles to the SAME per-link limit as private bundles, so a single hostile
        // link cannot mint vaccines faster than [`MAX_PRIV_BUNDLES_PER_WINDOW`].
        let rate_limited =
            bundle.is_private() || matches!(bundle.inner.dst, Destination::Vaccine(_));
        if rate_limited && !self.allow_private_ingest(from_link) {
            return false;
        }
        let id = bundle.id();
        if self.pending_app_deliveries.contains_key(&id) {
            // Local app work is admitted but not accepted yet. A duplicate neither grows the queue
            // nor receives an ACK before the host or higher-level holding gate accepts the first copy.
            return false;
        }
        let mut locally_accepted = false;

        // A broadcast is processed by everyone and relayed by everyone, then falls through to
        // the store+offer flood below — we never short-circuit, since halting the flood at the
        // recipient would out it.
        if matches!(bundle.inner.dst, Destination::Broadcast) {
            if bundle.is_private() {
                // §39 "is this mine?": trial-match against our prekeys on EVERY arrival (a
                // cheap DH+hash) — so a flooded duplicate can re-ACK if our first ACK was
                // lost. deliver_private delivers/handles the inner payload only once.
                if self.recognizes(&bundle) {
                    if !self.deliver_private(&bundle, &id) {
                        return false;
                    }
                    locally_accepted = true;
                }
            } else if !self.store.seen(&id) && !self.process_broadcast(&bundle) {
                return false;
            }
        }

        if is_for(&bundle, &self.address()) {
            if let Some(seen) = self.receiver_seen.get(&id).cloned() {
                // A staged item is not accepted yet, so duplicates stay silent. Once the inbox row
                // is gone, the durable seen metadata permits the existing throttled re-ACK behavior.
                if !self.durable_inbox.contains_key(&id) {
                    self.emit_inbox_ack(&seen.acknowledgement);
                }
                return true;
            }
            if self.store.seen(&id) {
                // A duplicate of something we already delivered. If it wanted an ACK, our
                // ACK may have been lost — re-emit it (throttled) so the sender can stop
                // retransmitting. Never re-deliver to the inbox.
                let is_user_content = matches!(
                    bundle.open(&self.identity),
                    Ok(Payload::PeerMessage { .. })
                        | Ok(Payload::SessionInit { .. })
                        | Ok(Payload::SessionMessage { .. })
                );
                if !is_user_content && !bundle.inner.flags.is_ack && bundle.inner.flags.request_ack
                {
                    let due = match self.last_ack.get(&id) {
                        Some(&t) => self.now_ms.saturating_sub(t) >= REACK_MIN_INTERVAL_MS,
                        None => true,
                    };
                    if due {
                        self.emit_ack(&bundle);
                    }
                }
                return true;
            }
            if bundle.inner.flags.is_ack {
                // An ACK for one of our sent bundles: stop tracking & carrying it,
                // and mark it Delivered for the UI.
                if let Ok(Payload::Ack {
                    for_bundle_id,
                    delivery_hops,
                    delivery_ms,
                    ..
                }) = bundle.open(&self.identity)
                {
                    // core-protocol-r7/r8/r9-01: AUTHORIZE the acker, do not merely authenticate it.
                    // verify() proves WHO signed the ack, not that they are the destination, so honor a
                    // traced ACK ONLY when we hold the acked bundle AND it was sent TRACED, i.e. its
                    // plaintext dst is Device(d) with d == the ack's signer, AND the ack is itself
                    // identity-signed (so its src is authenticated; a private bundle's src is
                    // attacker-chosen because verify() binds only the sealed payload to the id). All
                    // three forgery vectors the audits found collapse to this positive check:
                    //   (r7) a signed ack from a NON-destination: d != src, refused.
                    //   (r8) a private "chimera" (is_ack, dst=AckTo(us), attacker-set src): is_private,
                    //        refused.
                    //   (r9) a genuine signed traced ACK naming a DEFAULT §39 PRIVATE send's cleartext
                    //        id: that send is held as dst=Broadcast, not Device, so it does not match and
                    //        is refused. Private sends are acked ONLY via the recipient-only CDH proof on
                    //        the Broadcast/deliver_private path (r2-04), never here.
                    // A legit traced ACK from the real destination for a still-held Device send matches
                    // and is honored. The only thing this gives up vs blind honoring is a re-ack or an
                    // ack for a store-evicted bundle (store.get None -> no match): delivered is not
                    // (re-)set and retransmit continues until lifetime, which is safe and self-correcting.
                    let carrier_progress = self.carrier_owner.get(&for_bundle_id).copied();
                    let completed_unacked_carrier = carrier_progress.filter(|original_id| {
                        self.outgoing_carriers
                            .get(original_id)
                            .is_some_and(|carrier| {
                                !carrier.original.inner.flags.request_ack
                                    && carrier.chunks.iter().all(|chunk| {
                                        *chunk == for_bundle_id || !self.store.contains(chunk)
                                    })
                            })
                    });
                    let authorized_bundle = self.store.get(&for_bundle_id).or_else(|| {
                        self.outgoing_carriers
                            .get(&for_bundle_id)
                            .map(|carrier| carrier.original.clone())
                    });
                    let authorized = !bundle.is_private()
                        && matches!(
                            authorized_bundle
                                .filter(|original| !original.is_private())
                                .map(|original| original.inner.dst),
                            Some(Destination::Device(d)) if d == bundle.inner.src
                        );
                    if authorized {
                        if carrier_progress.is_some() {
                            let mut removals = vec![KvMutation::RemoveBundle { id: for_bundle_id }];
                            if let Some(original_id) = completed_unacked_carrier {
                                removals.push(KvMutation::Remove {
                                    key: Self::outgoing_carrier_key(&original_id),
                                });
                            }
                            if self.store.apply_kv_batch(&removals).is_err() {
                                return false;
                            }
                            self.pending.remove(&for_bundle_id);
                            self.carrier_owner.remove(&for_bundle_id);
                            self.forwarded.remove(&for_bundle_id);
                            if let Some(original_id) = completed_unacked_carrier {
                                self.outgoing_carriers.remove(&original_id);
                            }
                        } else {
                            if let Some(carrier) =
                                self.outgoing_carriers.get(&for_bundle_id).cloned()
                            {
                                let mut removals = vec![KvMutation::Remove {
                                    key: Self::outgoing_carrier_key(&for_bundle_id),
                                }];
                                removals.extend(
                                    carrier
                                        .chunks
                                        .iter()
                                        .copied()
                                        .map(|id| KvMutation::RemoveBundle { id }),
                                );
                                if self.store.apply_kv_batch(&removals).is_err() {
                                    return false;
                                }
                                for chunk in &carrier.chunks {
                                    self.pending.remove(chunk);
                                    self.carrier_owner.remove(chunk);
                                    self.forwarded.remove(chunk);
                                }
                                self.outgoing_carriers.remove(&for_bundle_id);
                            } else {
                                self.store.remove(&for_bundle_id);
                            }
                            self.pending.remove(&for_bundle_id);
                            // Carrier ACKs are transfer progress only. Only this original-bundle ACK
                            // reaches the transaction row and marks the user message Delivered.
                            let display = self.display_id(&for_bundle_id);
                            if let Some(info) = self.tx.get_mut(&display) {
                                info.delivered = true;
                                info.delivered_hops = delivery_hops;
                                info.delivered_ms = delivery_ms;
                            }
                            // Our message reached its destination: learn the route (§27).
                            if let Some((s, d, _)) = self.forwarded.remove(&for_bundle_id) {
                                self.routes.learn(&s, &d, self.now_ms);
                            }
                        }
                    }
                }
            } else {
                let mut ack_after_processing = true;
                // Route by payload. User content decrypts and commits its durable inbox state here;
                // every other addressed protocol payload keeps its existing immediate processing.
                match bundle.open(&self.identity) {
                    Ok(payload @ Payload::PeerMessage { .. })
                    | Ok(payload @ Payload::SessionInit { .. })
                    | Ok(payload @ Payload::SessionMessage { .. }) => {
                        if !self.app_payload_policy.supports(AppQueueKind::PeerInbox) {
                            return false;
                        }
                        if self
                            .stage_inbound_message(&bundle, bundle.inner.src, payload, true, false)
                            .is_err()
                        {
                            return false;
                        }
                        ack_after_processing = false;
                    }
                    Ok(Payload::HttpResponse {
                        status,
                        headers,
                        body,
                        for_bundle_id,
                    }) => {
                        if self
                            .unanchored_outstanding_requests
                            .contains(&for_bundle_id)
                        {
                            return false;
                        }
                        // r18-07: the request id, authenticated signer, and response kind must all match
                        // before any request, store, immunity, UI, or response-queue state is changed.
                        if self.response_authorized(
                            &for_bundle_id,
                            &bundle.inner.src,
                            RequestKind::Http,
                        ) {
                            let item = HttpRespItem {
                                from: bundle.inner.src,
                                id,
                                for_id: for_bundle_id,
                                status,
                                headers,
                                body,
                            };
                            return self.commit_http_response(&bundle, item).is_ok();
                        }
                    }
                    // A hops:// request sealed to us (we're a hop-endpoint, §30): surface
                    // it for the operator's translator to execute against its backend.
                    Ok(Payload::HttpRequest {
                        host,
                        method,
                        url,
                        headers,
                        body,
                        max_resp_bytes,
                    }) => {
                        let item = HttpReqItem {
                            from: bundle.inner.src,
                            id,
                            host,
                            method,
                            url,
                            headers,
                            body,
                            max_resp: max_resp_bytes,
                        };
                        if !self.admit_app_delivery(
                            AppQueueKind::HttpRequest,
                            &bundle,
                            Self::http_request_bytes(&item),
                        ) {
                            return false;
                        }
                        self.http_requests.push(item);
                        return false;
                    }
                    Ok(Payload::ServiceResponse {
                        for_bundle_id,
                        status,
                        body,
                    }) => {
                        if self
                            .unanchored_outstanding_requests
                            .contains(&for_bundle_id)
                        {
                            return false;
                        }
                        // A response is the return-path "delete" for our request: service
                        // calls carry no ACK-vaccine of their own, so without this the
                        // request bundle would sit pinned in our store forever. Drop it
                        // everywhere and vaccinate so any in-flight copy is dropped too.
                        // r18-07: the request id, authenticated signer, and response kind must all match
                        // before any request/store/immunity/UI/response-queue state is changed.
                        if self.response_authorized(
                            &for_bundle_id,
                            &bundle.inner.src,
                            RequestKind::Service,
                        ) {
                            let item = ServiceRespItem {
                                from: bundle.inner.src,
                                id,
                                for_id: for_bundle_id,
                                status,
                                body,
                            };
                            return self.commit_service_response(&bundle, item).is_ok();
                        }
                    }
                    Ok(Payload::ServiceRequest {
                        service,
                        method,
                        args,
                    }) => {
                        let from = bundle.inner.src;
                        if service == SERVICE_IDENTIFY {
                            // Built-in: the node answers with its own identity record.
                            let body =
                                postcard::to_allocvec(&self.identity_record()).unwrap_or_default();
                            let _ = self.send_service_response(from, id, 0, body);
                        } else if service == SERVICE_TELEMETRY {
                            // Built-in OTel-over-Hop sink (§40): decode + bounds-check, attribute the
                            // tenant from the carriage stamp (§35, the SAME verified attribution as
                            // billing; any-epoch since telemetry is delay-tolerant and may carry a
                            // legitimately-old spooled stamp), then surface it. Fire-and-forget (no
                            // response); a malformed or oversized batch is dropped rather than trusted.
                            if let Some(batch) = TelemetryBatch::from_bytes(&args) {
                                if !self.app_payload_policy.supports(AppQueueKind::Telemetry) {
                                    return false;
                                }
                                let tenant = bundle
                                    .env
                                    .access
                                    .as_deref()
                                    .and_then(|stamp| self.access_policy.attribute(stamp, &id));
                                let Some(charge) = self.reserve_app_queue(
                                    AppQueueKind::Telemetry,
                                    Some(from),
                                    args.len().saturating_add(40),
                                ) else {
                                    return false;
                                };
                                self.telemetry_in.push(TelemetryIn {
                                    from,
                                    batch,
                                    tenant,
                                });
                                self.telemetry_charges.push(charge);
                            }
                        } else {
                            // Custom service: hand to the embedding app to fulfill.
                            let item = ServiceReqItem {
                                from,
                                id,
                                service,
                                method,
                                args,
                            };
                            if !self.admit_app_delivery(
                                AppQueueKind::ServiceRequest,
                                &bundle,
                                Self::service_request_bytes(&item),
                            ) {
                                return false;
                            }
                            self.service_requests.push(item);
                            return false;
                        }
                    }
                    // A join request for a topic we host (§32). Verify app+proof, then branch on
                    // access: Open → seal keys now; RequestToJoin → queue for approval; Invite →
                    // ignore (members can't self-join, they must be invited).
                    Ok(Payload::HpsJoinRequest { path, proof }) => {
                        if self.hps_authorized(&bundle, &path, &proof) {
                            let who = bundle.inner.src;
                            match self.services.get(&path).map(|c| c.access) {
                                Some(hps::AccessMode::Open) => {
                                    self.record_member(&path, who);
                                    let _ = self.send_keys(&path, who);
                                }
                                Some(hps::AccessMode::RequestToJoin) => {
                                    let q = self.hps_pending.entry(path.clone()).or_default();
                                    if !q.contains(&who) {
                                        q.push(who);
                                        self.persist_pending(&path);
                                    }
                                }
                                _ => {} // Invite-only or unregistered → ignore
                            }
                        }
                    }
                    // Host → us: an invite. Verify it's a same-app invite, then surface it for
                    // the user to accept.
                    Ok(Payload::HpsInvite { path, kind, proof }) => {
                        if self.hps_authorized(&bundle, &path, &proof) {
                            let host = bundle.inner.src;
                            if !self
                                .hps_invites_in
                                .iter()
                                .any(|i| i.path == path && i.host == host)
                            {
                                if !self.app_payload_policy.supports(AppQueueKind::HpsInvite) {
                                    return false;
                                }
                                let Some(charge) = self.reserve_app_queue(
                                    AppQueueKind::HpsInvite,
                                    Some(host),
                                    path.len().saturating_add(64),
                                ) else {
                                    return false;
                                };
                                self.hps_invites_in.push(HpsInviteItem { path, host, kind });
                                self.hps_invite_charges.push(charge);
                                self.persist_invites();
                            }
                        }
                    }
                    // Destination → host: an invite was accepted; seal them the keys.
                    Ok(Payload::HpsInviteAccept { path, proof }) => {
                        let who = bundle.inner.src;
                        if self.hps_authorized(&bundle, &path, &proof)
                            && self.hps_invites_out.remove(&(path.clone(), who)).is_some()
                        {
                            self.persist_invites();
                            self.record_member(&path, who);
                            let _ = self.send_keys(&path, who);
                        }
                    }
                    // Member → host: leaving; drop them from retained set + reach tally.
                    Ok(Payload::HpsLeave { path, proof }) => {
                        if self.hps_authorized(&bundle, &path, &proof) {
                            let who = bundle.inner.src;
                            if self
                                .hps_members
                                .get(&path)
                                .is_some_and(|members| members.contains(&who))
                                && self.hps_rekey(&path, None, &[who]).is_ok()
                            {
                                if let Some(r) = self.hps_reach.get_mut(&path) {
                                    r.remove(&who);
                                }
                            }
                        }
                    }
                    // Member → host: reach ack — tally unique acking addresses (§32).
                    Ok(Payload::HpsReachAck {
                        topic_tag,
                        epoch,
                        mac,
                    }) => {
                        let who = bundle.inner.src;
                        // Map the opaque tag back to a path we host, then require this exact
                        // generation and a MAC under its current content key before mutating reach.
                        let topic = self
                            .services
                            .iter()
                            .find(|(path, _)| self.app.topic_tag(path) == topic_tag)
                            .map(|(path, cfg)| (path.clone(), cfg.epoch, cfg.content_key));
                        if let Some((path, current_epoch, content_key)) = topic {
                            let authorized = bundle.inner.app == self.app.id
                                && epoch == current_epoch
                                && hps::verify_reach_ack_mac(
                                    &content_key,
                                    &self.app.id,
                                    &who,
                                    &topic_tag,
                                    epoch,
                                    &mac,
                                );
                            if authorized {
                                self.hps_reach.entry(path.clone()).or_default().insert(who);
                                self.record_member(&path, who);
                            }
                        }
                    }
                    // Host → us: rotate to a new key generation (revocation, §32).
                    Ok(Payload::HpsRekey {
                        old_path,
                        new_path,
                        epoch,
                        content_key,
                        service_pubkey,
                        proof,
                    }) => {
                        if let Some(old) = self.subscriptions.get(&old_path).cloned() {
                            let collision = old_path != new_path
                                && (self.subscriptions.contains_key(&new_path)
                                    || self.services.contains_key(&new_path)
                                    || self.hps_subscribe_pending.contains_key(&new_path));
                            if self.hps_authorized(&bundle, &old_path, &proof)
                                && bundle.inner.src == old.host
                                && epoch > old.epoch
                                && !collision
                            {
                                let host = old.host;
                                let replacement = HpsSubscription {
                                    content_key,
                                    service_pubkey,
                                    host,
                                    epoch,
                                    topic_tag: self.app.topic_tag(&new_path),
                                };
                                let mut mutations = vec![KvMutation::Put {
                                    key: Self::hps_sub_key(&new_path),
                                    value: match postcard::to_allocvec(&replacement) {
                                        Ok(value) => value,
                                        Err(_) => return false,
                                    },
                                }];
                                if old_path != new_path {
                                    mutations.push(KvMutation::Remove {
                                        key: Self::hps_sub_key(&old_path),
                                    });
                                }
                                if self.store.apply_kv_batch(&mutations).is_ok() {
                                    if old_path != new_path {
                                        self.subscriptions.remove(&old_path);
                                        self.directory.unsubscribe(&old_path);
                                    }
                                    self.directory.subscribe(new_path.clone());
                                    self.subscriptions.insert(new_path, replacement);
                                }
                            }
                        }
                    }
                    // The keys for a topic we subscribed to (§32): remember them so we can
                    // decrypt + verify its broadcasts.
                    Ok(Payload::HpsKeys {
                        path,
                        content_key,
                        service_pubkey,
                        epoch,
                    }) => {
                        let host = bundle.inner.src;
                        let expected = self.hps_subscribe_pending.get(&path).copied();
                        if expected.is_some()
                            && self.unanchored_hps_subscribe_pending.contains(&path)
                        {
                            return false;
                        }
                        if bundle.inner.app == self.app.id
                            && !self.subscriptions.contains_key(&path)
                            && expected.is_some_and(|pending| {
                                !self.unanchored_hps_subscribe_pending.contains(&path)
                                    && pending.host == host
                                    && pending.expires_at_ms > self.now_ms
                            })
                        {
                            let subscription = HpsSubscription {
                                content_key,
                                service_pubkey,
                                host,
                                epoch,
                                topic_tag: self.app.topic_tag(&path),
                            };
                            let Ok(value) = postcard::to_allocvec(&subscription) else {
                                return false;
                            };
                            let mutations = [
                                KvMutation::Put {
                                    key: Self::hps_sub_key(&path),
                                    value,
                                },
                                KvMutation::Remove {
                                    key: Self::hps_subscribe_pending_key(&path),
                                },
                            ];
                            if self.store.apply_kv_batch(&mutations).is_ok() {
                                self.directory.subscribe(path.clone());
                                self.subscriptions.insert(path.clone(), subscription);
                                self.hps_subscribe_pending.remove(&path);
                                self.unanchored_hps_subscribe_pending.remove(&path);
                            }
                        }
                    }
                    // A transport carrier chunk: reassemble (§20); once complete, reconstruct
                    // the original bundle and process it as if it had arrived whole.
                    // (Application streams use StreamData and are delivered progressively.)
                    Ok(Payload::Carrier {
                        stream_id,
                        seq,
                        bytes,
                        fin,
                    }) => {
                        let from = bundle.inner.src;
                        match self.accept_stream_chunk(from, stream_id, seq, bytes, fin) {
                            StreamChunkAcceptance::Retained => {}
                            StreamChunkAcceptance::Complete(inner_bytes) => {
                                if !self.process_reconstructed_bundle(from_link, from, &inner_bytes)
                                    || !self.finalize_incoming_stream(&from, &stream_id)
                                {
                                    return false;
                                }
                            }
                            StreamChunkAcceptance::Rejected => {
                                // The chunk was not durably retained. Do not mark it seen or ACK it;
                                // sender retransmission is the recovery path after pressure clears.
                                return false;
                            }
                        }
                    }
                    // A peer says our ratchet desynced: drop our session and re-establish so
                    // a fresh handshake re-syncs it (DESIGN.md §25). Not surfaced to the app.
                    Ok(Payload::SessionReset) => self.handle_session_reset(bundle.inner.src),
                    _ => {
                        let item_bytes = bundle
                            .to_bytes()
                            .map(|bytes| bytes.len())
                            .unwrap_or(usize::MAX);
                        if !self.admit_app_delivery(AppQueueKind::GenericInbox, &bundle, item_bytes)
                        {
                            return false;
                        }
                        self.inbox.push(bundle.clone());
                        return false;
                    }
                }
                if ack_after_processing && bundle.inner.flags.request_ack {
                    self.emit_ack(&bundle);
                }
            }
            // Mark seen (dedup) but don't hold — we never relay what's addressed to us.
            let stored = self.store.put(bundle, self.now_ms);
            self.store.remove(&id);
            return stored || self.store.seen(&id);
        }

        // A passing ACK vaccinates us: the bundle it acknowledges is delivered, so
        // drop our copy and remember to drop any future copy (epidemic recovery). The
        // acked id rides in the *unsealed* AckTo destination, so relays can read it.
        if bundle.inner.flags.is_ack {
            match bundle.inner.dst {
                Destination::AckTo(_, delivered) => {
                    // core-protocol-r7/r8/r9/r10: authorize before purging. Purge + immune ONLY when we
                    // hold the acked bundle, it was sent TRACED (a NON-private Device(dst) bundle), the
                    // held dst == the ack's signer, and the ack is itself identity-signed. A relay that
                    // does not hold the bundle (store.get None) authorizes nothing, so it never
                    // immune-poisons an unheld id. A §39 private bundle we carry is Broadcast (r10-01
                    // rejects a Device-dst private replay at the gate) and is never purged here; it is
                    // vaccinated only by the token Vaccine on its own recognition tag. So no forged or
                    // chimera ack can deny a real message's delivery via this path.
                    // core-protocol-r8-01: only an identity-signed ack has an authenticated src (see the
                    // origin path). A private-flagged AckTo chimera has an attacker-chosen src, so never
                    // let it purge a relay's held bundle; require the ack be identity-signed.
                    // core-protocol-r9-01: purge on a traced ACK ONLY when we hold the acked bundle, it
                    // was sent TRACED (dst == Device(signer)), and the ack is identity-signed. A private
                    // (Broadcast-dst) bundle we are carrying is NEVER purged by a traced AckTo: it is
                    // vaccinated only by the token Vaccine on its own recognition tag (sec-priv-07). This
                    // closes the network-wide DoS where a genuine signed AckTo naming a private send's
                    // cleartext id purged + immune-poisoned the real §39 message mid-carry.
                    let authorized = !bundle.is_private()
                        && matches!(
                            self.store.get(&delivered).filter(|b| !b.is_private()).map(|b| b.inner.dst),
                            Some(Destination::Device(d)) if d == bundle.inner.src
                        );
                    if authorized {
                        // §35: a returning ACK proves this relay carried the bundle to delivery.
                        self.meter_delivered(&delivered);
                        self.store.remove(&delivered);
                        self.relay_order.retain(|x| *x != delivered);
                        self.immune.insert(delivered, self.now_ms);
                        // The ACK for a bundle we forwarded is passing back through us — we're
                        // on a working path between its endpoints, in both directions (§27).
                        if let Some((s, d, _)) = self.forwarded.remove(&delivered) {
                            self.routes.learn(&s, &d, self.now_ms);
                        }
                    }
                }
                // §39 delivery vaccine (sec-priv-07): the anti-packet carries ONLY the revealed token,
                // no plaintext delivered id. We recover which held private bundle it clears by testing
                // the token against each held bundle's own recognition tag; a forged token matches
                // nothing and purges nothing. If we hold no match we just relay it onward (below) so
                // real holders can act on it.
                //
                // core-protocol-r2-03 / security-privacy-r2-01: `resolve_vaccine_target` is an
                // O(held-private-bundles) DH+hash scan, and a vaccine is `is_ack` so it is EXEMPT from
                // the F-07 per-link private-ingest limit. Without a dedup gate here, EVERY flooded
                // duplicate copy of the SAME vaccine (all sharing one id = H(domain‖token)) would
                // re-run the whole scan — CPU amplification an attacker triggers by re-injecting one
                // vaccine. Short-circuit on the store's `seen` set: the first copy scans + resolves
                // once, subsequent copies (same id) are skipped before the scan. A forged random-token
                // vaccine still scans at most once per unique id, and the per-link rate limit on
                // Vaccine ingest (see `allow_private_ingest` call site) bounds the mint rate.
                Destination::Vaccine(token) if !self.store.seen(&id) => {
                    if let Some(delivered) = self.resolve_vaccine_target(&token) {
                        // The SENDER treats a verified vaccine as PROOF OF DELIVERY. Its private ACK
                        // can be lost (a throttled link, a single-carrier contact) — and once the
                        // vaccine has immunized the mesh, retransmits can never trigger a re-ACK, so
                        // a lost ack would strand the sender on "Sending…" forever. The vaccine floods
                        // network-wide and carries the same CDH token only the true recipient can
                        // compute, so it is exactly as trustworthy as the ACK (minus hop/latency
                        // metadata, which stays at its last-known values).
                        let display = self.display_id(&delivered);
                        if let Some(info) = self.tx.get_mut(&display) {
                            if !info.delivered {
                                info.delivered = true;
                                self.pending.remove(&delivered);
                                self.pending.remove(&display);
                                if self.observe {
                                    self.sends_delivered.push(display);
                                }
                            }
                        }
                        // §35: a §39 delivery vaccine proves this relay's held private bundle was
                        // delivered (the same delivery-justified atom, on the untraceable path).
                        self.meter_delivered(&delivered);
                        self.store.remove(&delivered);
                        self.relay_order.retain(|x| *x != delivered);
                        self.immune.insert(delivered, self.now_ms);
                    } else {
                        // core-protocol-r3-02: we hold no bundle this vaccine clears YET. It may be
                        // racing ahead of its target (a relay that saw the vaccine first). Remember the
                        // token so that when the target private bundle is first stored (below), the
                        // vaccine purges it immediately instead of it lingering to TTL. Bounded + TTL'd.
                        self.remember_vaccine_token(token);
                    }
                }
                _ => {}
            }
        } else if self.immune.contains_key(&id) {
            return true; // already delivered elsewhere — don't re-store or re-flood it
        }

        // core-protocol-r3-02: a delivery vaccine may have raced ahead of this private bundle and
        // already passed through us (its `resolve_vaccine_target` scan found nothing to clear because
        // the target (this bundle) hadn't arrived yet). If a remembered token clears THIS bundle,
        // it is already delivered elsewhere: drop it now (mark immune so a re-flood is refused too)
        // rather than storing + re-flooding it until its clamped TTL. `already_vaccinated_by_token`
        // is O(seen-tokens) only for private bundles and only over the small, TTL'd token set, run
        // once per unique bundle id at first store, not a hot path.
        if bundle.is_private() && self.already_vaccinated_by_token(&bundle) {
            self.immune.insert(id, self.now_ms);
            return true;
        }
        if self.max_relayed == 0 {
            return locally_accepted;
        }
        // Not ours: store for onward relay, then offer to every other live link.
        //
        // §35 carriage gate: under a `Keyed` policy, custody of a foreign bundle requires a stamp
        // whose signer is in the keyserver; `admit` VERIFIES the rotating-hint signature against
        // the current/previous epoch and returns the attributable tenant. We record that verified
        // tenant now (metering itself is DELIVERY-justified, below) so a delay-tolerant delivery
        // after the stamp epoch rolls still bills, and the mutable stamp is never re-read later.
        // LOCAL_LINK re-injections (durable re-ingest: warm reload, mailbox pulls, rehydrate) are
        // trusted first-accepts (they were gated on live arrival); re-gating them would lose
        // spooled mail (process_mailbox deletes the durable copy after the custody ack).
        // Vaccines are §39 anti-packets, not billable carriage: they MUST propagate freely to
        // purge delivered copies fleet-wide, and stamping one would leak the recipient. Exempt
        // them from the gate and the meter entirely (decision: vaccine exemption).
        let is_vaccine = matches!(bundle.inner.dst, Destination::Vaccine(_));
        let metered_tenant = if is_vaccine {
            None
        } else if from_link == LOCAL_LINK {
            // Durable re-ingest (a spooled bundle pulled back for offline delivery, or a warm
            // reload of our own partition): a trusted first-accept, NOT gated. But if it carries a
            // stamp, attribute it now (any-epoch, since a spooled stamp is legitimately old) so the
            // eventual mesh delivery bills the OFFLINE-delivery path, which is otherwise silent
            // because the origin relay's in-memory attribution was pruned when it evicted the copy.
            bundle
                .env
                .access
                .as_deref()
                .and_then(|s| self.access_policy.attribute(s, &id))
        } else {
            match self
                .access_policy
                .admit(bundle.env.access.as_deref(), &id, self.now_ms)
            {
                Admit::Granted(tenant) => tenant,
                Admit::Refused => {
                    self.access_refused = self.access_refused.saturating_add(1);
                    return false;
                }
            }
        };
        let metered_bytes = bundle.inner.payload.ciphertext.len() as u64;
        let relay_src = bundle.inner.src;
        let relay_dst = match bundle.inner.dst {
            Destination::Device(d) => Some(d),
            _ => None,
        };
        // relay-A audit: a trusted re-injection from our own durable storage (Node::ingest, from_link ==
        // LOCAL_LINK) of a bundle we already `seen` but EVICTED from held (max_relayed pressure dropped
        // the held copy while the durable mailbox copy + dedup row survived) must RE-HOLD it, not be
        // refused by the surviving dedup entry. Otherwise process_mailbox's delete-before-ingest loses
        // the message permanently on a same-relay re-pull. Live traffic and never-evicted stores take the
        // ordinary `put` path (rehydrate defaults to put). Delivered bundles never reach here (the
        // immune / vaccine checks above return early).
        let rehydrating =
            from_link == LOCAL_LINK && self.store.seen(&id) && !self.store.contains(&id);
        let stored = if rehydrating {
            self.store.rehydrate(bundle, self.now_ms)
        } else {
            self.store.put(bundle, self.now_ms)
        };
        if stored {
            // §35: record the VERIFIED attribution for this held bundle, but do NOT bill yet.
            // Billing is DELIVERY-justified (decision 2): we charge this tenant only if/when we
            // later see proof the bundle was delivered (an ACK or §39 vaccine purges our copy,
            // `meter_delivered`). A bundle we hold that never delivers (evicts or TTL-expires) is
            // never billed as carriage; its durable-storage occupancy is priced by the separate
            // storage floor. `tick` prunes attribution for any bundle no longer held.
            if let Some(tenant) = metered_tenant {
                if self.metered_attribution.len() < MAX_METERED_ATTRIBUTION
                    || self.metered_attribution.contains_key(&id)
                {
                    self.metered_attribution.insert(id, (tenant, metered_bytes));
                } else {
                    // Cap hit: carried but unattributed. Count the drop so the host can surface it.
                    self.usage_dropped = self.usage_dropped.saturating_add(1);
                }
            }
            self.relay_order.push(id);
            // Remember we're carrying this toward `dst` so a returning ACK teaches the
            // route (§27). `or_insert` keeps our own-send record if we have one.
            if let Some(d) = relay_dst {
                self.forwarded
                    .entry(id)
                    .or_insert((relay_src, d, self.now_ms));
                self.prune_forwarded_if_needed();
            }
            self.evict_relayed_if_needed();
            // F-09: offer just the bundle we accepted to the other links, not the whole store.
            self.offer_bundle_to_all_except(id, from_link);
        }
        stored
    }

    /// Keep relayed (not-ours) bundles within `max_relayed`. Custody policy (DESIGN.md §6):
    /// **never drop a bundle we haven't relayed at least once if we can avoid it** — so a
    /// flood of big transfers can't evict legitimate, not-yet-forwarded messages, and so
    /// the cap acts as a *sliding window* (chunks flow through: relayed, then evicted after
    /// a grace window) rather than a hard limit on transfer size. Eviction therefore
    /// prefers already-relayed, past-grace bundles, and only falls back to dropping a
    /// not-yet-relayed (or in-grace) bundle when nothing else can be freed (to bound
    /// memory). Within a tier the victim is the lowest-utility (priority, then route,
    /// then oldest). Our own messages are never here.
    fn evict_relayed_if_needed(&mut self) {
        let now = self.now_ms;
        while self.relay_order.len() > self.max_relayed {
            let victim = self
                .pick_evict_victim(now, true)
                .or_else(|| self.pick_evict_victim(now, false));
            let Some((idx, id)) = victim else { break };
            self.relay_order.remove(idx);
            self.store.remove(&id);
            self.relay_fwd.remove(&id);
            self.forwarded.remove(&id);
            for state in self.links.values_mut() {
                if let LinkState::Up(established) = state {
                    established.sent_bundles.remove(&id);
                }
            }
            for sent in self.peer_sent.values_mut() {
                sent.bundles.remove(&id);
            }
        }
    }

    /// Choose an eviction victim by lowest utility (priority, route, oldest). When
    /// `settled_only`, consider only bundles we've already relayed once and held past
    /// [`EVICT_GRACE_MS`] — the preferred, safe-to-drop set.
    fn pick_evict_victim(&self, now: u64, settled_only: bool) -> Option<(usize, BundleId)> {
        self.relay_order
            .iter()
            .enumerate()
            .filter(|(_, id)| {
                !settled_only
                    || self
                        .relay_fwd
                        .get(*id)
                        .is_some_and(|t| now.saturating_sub(*t) >= EVICT_GRACE_MS)
            })
            .min_by(|(ia, a), (ib, b)| {
                self.bundle_utility(a, now)
                    .partial_cmp(&self.bundle_utility(b, now))
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(ia.cmp(ib))
            })
            .map(|(idx, id)| (idx, *id))
    }

    /// Bound the forwarded-route memory (§27): drop the oldest entries past the cap.
    fn prune_forwarded_if_needed(&mut self) {
        if self.forwarded.len() <= DEFAULT_MAX_FORWARDED {
            return;
        }
        let drop_n = self.forwarded.len() - DEFAULT_MAX_FORWARDED;
        let mut by_age: Vec<(BundleId, u64)> =
            self.forwarded.iter().map(|(k, v)| (*k, v.2)).collect();
        by_age.sort_by_key(|(_, t)| *t);
        for (k, _) in by_age.into_iter().take(drop_n) {
            self.forwarded.remove(&k);
        }
    }

    /// Emit an ACK bundle back to the origin of `orig`, sealed to its address.
    fn emit_ack(&mut self, orig: &Bundle) {
        let acknowledgement = self.inbox_acknowledgement(orig, orig.inner.src, false);
        self.emit_inbox_ack(&acknowledgement);
    }

    fn allow_advert_ingest(&mut self, link: LinkId) -> bool {
        let now = self.now_ms;
        if now.saturating_sub(self.advert_ingest_global.0) >= ADVERT_VERIFY_WINDOW_MS {
            self.advert_ingest_global = (now, 0);
        }
        let per_link = self.advert_ingest.entry(link).or_insert((now, 0));
        if now.saturating_sub(per_link.0) >= ADVERT_VERIFY_WINDOW_MS {
            *per_link = (now, 0);
        }
        if per_link.1 >= MAX_ADVERTS_PER_LINK_WINDOW
            || self.advert_ingest_global.1 >= MAX_ADVERTS_GLOBAL_WINDOW
        {
            return false;
        }
        per_link.1 += 1;
        self.advert_ingest_global.1 += 1;
        true
    }

    fn forget_evicted_adverts(&mut self) {
        let evicted = self.directory.take_evicted();
        if evicted.is_empty() {
            return;
        }
        for id in evicted {
            for state in self.links.values_mut() {
                if let LinkState::Up(established) = state {
                    established.sent_adverts.remove(&id);
                }
            }
            for sent in self.peer_sent.values_mut() {
                sent.adverts.remove(&id);
            }
        }
    }

    fn prune_peer_sent(&mut self) {
        let now = self.now_ms;
        self.peer_sent.retain(|_, sent| {
            sent.adverts.retain(|id| self.directory.contains(id));
            sent.bundles.retain(|id| self.store.contains(id));
            now.saturating_sub(sent.last_seen_ms) < PEER_SENT_TTL_MS
        });
        while self.peer_sent.len() > MAX_PEER_SENT {
            let victim = self
                .peer_sent
                .iter()
                .min_by_key(|(_, sent)| sent.last_seen_ms)
                .map(|(peer, _)| *peer);
            let Some(victim) = victim else { break };
            self.peer_sent.remove(&victim);
        }
    }

    fn on_advert(&mut self, from_link: LinkId, peer: PubKeyBytes, advert: Advert) {
        let _ = peer; // reserved for finer-grained relay scoring (DESIGN.md §18)
        if !self.allow_advert_ingest(from_link) {
            return;
        }
        // Service adverts flood the directory (subscribed → full retention, else the
        // bounded relay cache). Re-gossip only when newly accepted.
        let is_prekey = matches!(advert.body.kind, AdvertKind::PreKey { .. });
        // §39 P4: a signed receiver-beacon lays/refreshes a gradient toward its mailbox via the
        // link we heard it on. Read its fields (and the publisher) before `ingest` consumes it.
        let beacon = match advert.body.kind {
            AdvertKind::RecvBeacon { mailbox, .. } => Some((
                mailbox,
                advert.body.publisher,
                advert.hops,
                advert.body.created_at,
                advert.body.ttl_ms,
                advert.body.seq,
            )),
            _ => None,
        };
        let accepted = self.directory.ingest(advert, self.now_ms).unwrap_or(false);
        self.forget_evicted_adverts();
        if accepted {
            self.offer_adverts_to_all();
            // A newly-learned prekey may unblock content we were holding to ratchet (§25).
            if is_prekey {
                self.flush_pending_content();
            }
            if let Some((mailbox, publisher, hops, created_at, ttl_ms, seq)) = beacon {
                // F-05 + F-06: bind the beacon to its owner before laying a gradient. The mailbox tag
                // is `H(address ‖ epoch)`, and a beacon is identity-signed by that address, so a node
                // can only beacon a mailbox it can compute for ITS OWN address — an attacker can't
                // forge a victim's mailbox because it can't sign an advert as the victim (`directory
                // .ingest` already verified the signature, so `publisher` is authentic here). Accept
                // the current epoch and the recent window, so a just-rotated tag still routes.
                let cur = mailbox_epoch(self.now_ms);
                let owns_mailbox = (0..=MAILBOX_EPOCH_WINDOW).any(|back| {
                    crypto::mailbox_tag(&publisher, cur.saturating_sub(back)) == mailbox
                });
                if owns_mailbox {
                    // sec-priv-04: the beacon carried (and we authenticated against) the FULL tag, but
                    // the gradient/want-beacon keys on the routing PREFIX so an address-knower who sees
                    // this gradient only learns an anonymity-set membership, not the exact recipient.
                    self.record_gradient(
                        route_key(&mailbox),
                        from_link,
                        hops,
                        created_at,
                        ttl_ms,
                        seq,
                    );
                }
            }
        }
    }

    /// §39 P4 (+ sec-priv-04): record/refresh a routing next-hop from a verified receiver-beacon — a
    /// recipient in `mailbox`'s prefix anonymity set is reachable via `from_link`. Per link the freshest
    /// (higher `seq`, then fewer hops) beacon wins; a moved recipient re-points its own link, and a
    /// DISTINCT colliding recipient on another link adds a second next-hop (both are then served, so a
    /// collision can't starve either). After recording, immediately re-offer any already-HELD private
    /// bundles down the new link — without this, a bundle parked before the gradient existed waits
    /// forever (the relay already deduped it on the bridge link at link-up).
    fn record_gradient(
        &mut self,
        // sec-priv-04: this is the ROUTING KEY (a `route_key`-projected mailbox prefix), NOT the full
        // tag. The caller authenticated the full tag against the beacon publisher before projecting.
        mailbox: Tag,
        from_link: LinkId,
        hops: u8,
        created_at: u64,
        ttl_ms: u32,
        seq: u64,
    ) {
        let expires_at = created_at.saturating_add(ttl_ms as u64);
        if expires_at <= self.now_ms {
            return; // already stale on arrival
        }
        let fresh = GradientLink {
            hops,
            expires_at,
            seq,
            last_seen: self.now_ms,
        };
        // Would this beacon actually change the bucket? (Fresher than the same link's current entry, or
        // a brand-new link.) If not, skip so a bare refresh doesn't re-queue the want-beacon / re-offer.
        let changes = match self.recv_gradient.get(&mailbox) {
            Some(e) => match e.links.iter().find(|(l, _)| *l == from_link) {
                Some((_, cur)) => seq > cur.seq || (seq == cur.seq && hops < cur.hops),
                None => true,
            },
            None => true,
        };
        if !changes {
            return;
        }
        if self.recv_gradient.len() >= MAX_RECV_GRADIENT
            && !self.recv_gradient.contains_key(&mailbox)
        {
            // Bound the table (Sybil): evict the bucket whose soonest-expiring link is nearest to expiry.
            if let Some(victim) = self
                .recv_gradient
                .iter()
                .min_by_key(|(_, e)| e.links.iter().map(|(_, l)| l.expires_at).min().unwrap_or(0))
                .map(|(k, _)| *k)
            {
                self.recv_gradient.remove(&victim);
            }
        }
        let entry = self.recv_gradient.entry(mailbox).or_default();
        match entry.links.iter_mut().find(|(l, _)| *l == from_link) {
            Some((_, cur)) => *cur = fresh, // freshen this next-hop in place
            None => {
                // A new next-hop in the anonymity set. Bound the per-bucket fan-out (Sybil): if full,
                // evict the LEAST-RECENTLY-SEEN existing link before adding this one (security-privacy-
                // r2-04). Using recency, not nearest-to-expiry, means a prefix-grinding Sybil cannot crowd
                // out a legitimately re-beaconing recipient: that recipient refreshes on a short interval,
                // so its link is always among the most-recently-seen, while a Sybil that merely parks a
                // slot with a far-future TTL goes stale-seen and is the one evicted. The newcomer we are
                // adding is by definition the most-recently-seen (last_seen == now), so this never evicts
                // a link fresher than the one we admit.
                if entry.links.len() >= MAX_GRADIENT_LINKS_PER_BUCKET {
                    if let Some(idx) = entry
                        .links
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, (_, l))| l.last_seen)
                        .map(|(i, _)| i)
                    {
                        entry.links.remove(idx);
                    }
                }
                entry.links.push((from_link, fresh));
            }
        }
        // §39 P5: a newly-accepted beacon IS a want-beacon — surface the mailbox so the host reloads
        // its durable blind spool (an offline-deposited bundle is pulled the moment we hear from the
        // recipient). Bounded so a beacon storm can't grow this unboundedly; a dropped tag just waits
        // for the next periodic re-beacon. (Deduped against the tail to avoid a refresh re-queuing it.)
        if self.wanted_mailboxes.last() != Some(&mailbox) {
            if self.wanted_mailboxes.len() >= MAX_RECV_GRADIENT {
                self.wanted_mailboxes.remove(0);
            }
            self.wanted_mailboxes.push(mailbox);
        }
        // The fix for the live "held=95 never drains" bug: a freshly-laid gradient is a NEW
        // trigger to push parked private bundles toward the recipient, not just at link-up.
        self.offer_bundles_to_link(from_link);
    }

    // --- outbound offers ------------------------------------------------------

    fn offer_bundles_to_all(&mut self) {
        let links: Vec<LinkId> = self.links.keys().copied().collect();
        for l in links {
            self.offer_bundles_to_link(l);
        }
    }

    fn offer_adverts_to_all(&mut self) {
        let links: Vec<LinkId> = self.links.keys().copied().collect();
        for l in links {
            self.offer_adverts_to_link(l);
        }
    }

    /// Utility of a stored bundle for transmit-ordering and eviction (DESIGN.md §27):
    /// service priority dominates (×100 keeps priority bands separate), and learned
    /// reachability toward the destination orders bundles *within* a band — so a bundle
    /// toward a destination we have a route to beats one toward an unknown destination.
    fn bundle_utility(&self, id: &BundleId, now: u64) -> f64 {
        let Some(b) = self.store.get(id) else {
            return 0.0;
        };
        self.bundle_utility_of(&b, now)
    }

    /// Utility from an ALREADY-loaded bundle — avoids a `store.get` per call. `offer_bundles_to_link`
    /// uses this so its transmit-order sort does O(N) reads (load once), not O(N log N) (one read per
    /// sort comparison), which under the held node Mutex was starving link handshakes.
    fn bundle_utility_of(&self, b: &Bundle, now: u64) -> f64 {
        let route = match b.inner.dst {
            Destination::Device(d) => self.routes.utility(&d, now),
            _ => 0.0,
        };
        b.inner.priority as f64 * 100.0 + route
    }

    /// Offer stored bundles to one link, applying binary spray-and-wait.
    fn offer_bundles_to_link(&mut self, link: LinkId) {
        // Provenance privacy (§27): a DEVICE relay leaves its address OUT of the trace (stamps a
        // zeroed short-addr) so the recipient learns only the hop count + carrier type ("device"),
        // never WHICH devices carried it. Infra relays self-identify (their address is public) so a
        // recipient can still see "via Hop Relay". A device's own address is in the bundle `src`
        // anyway, so hiding it in the trace loses nothing — it only protects intermediate relays.
        let me_short = if self.trace_app == FABRIC_APP {
            ShortAddr::default()
        } else {
            short_addr(&self.identity.address())
        };
        let me_app = short_app(&self.trace_app);
        let now = self.now_ms;
        // Snapshot ids, ordered by utility so the most-likely-to-deliver bundles go
        // first during a short contact (DESIGN.md §27).
        // Load each bundle ONCE, compute its utility, then sort by the precomputed value — O(N)
        // store reads, not the O(N log N) the per-comparison bundle_utility(id) used to do. Under
        // the held node Mutex that read storm (×fsync from synchronous=FULL) starved link Noise
        // handshakes and prekey gossip, which is what made messages hang "Securing" under load.
        let mut loaded: Vec<(BundleId, Bundle, f64)> = self
            .store
            .have()
            .ids
            .into_iter()
            .filter_map(|id| {
                let b = self.store.get(&id)?;
                let u = self.bundle_utility_of(&b, now);
                Some((id, b, u))
            })
            .collect();
        loaded.sort_by(|x, y| y.2.partial_cmp(&x.2).unwrap_or(std::cmp::Ordering::Equal));
        for (id, b, _) in loaded {
            self.offer_one_to_link(link, id, b, me_short, me_app, now);
        }
    }

    /// F-09: offer a SINGLE just-arrived bundle to every link (except `except`, usually the link
    /// it arrived on), instead of rescanning the whole store per link per arrival. The old relay
    /// hot path did `store.have()` + a `store.get` per id per link on every accepted bundle, which
    /// under the one node Mutex was the read-storm that starved Noise handshakes ("Securing
    /// forever"). Same spray/gradient/dedup decisions, just scoped to the one new bundle.
    fn offer_bundle_to_all_except(&mut self, id: BundleId, except: LinkId) {
        let Some(b) = self.store.get(&id) else { return };
        let me_short = if self.trace_app == FABRIC_APP {
            ShortAddr::default()
        } else {
            short_addr(&self.identity.address())
        };
        let me_app = short_app(&self.trace_app);
        let now = self.now_ms;
        let links: Vec<LinkId> = self
            .links
            .keys()
            .copied()
            .filter(|l| *l != except)
            .collect();
        for l in links {
            self.offer_one_to_link(l, id, b.clone(), me_short, me_app, now);
        }
    }

    /// Offer ONE already-loaded stored bundle to a single link, applying binary spray-and-wait,
    /// §39 gradient steering, and per-link dedup. Extracted from `offer_bundles_to_link` so a
    /// just-arrived bundle can be offered without a full-store rescan (F-09).
    fn offer_one_to_link(
        &mut self,
        link: LinkId,
        id: BundleId,
        b: Bundle,
        me_short: ShortAddr,
        me_app: ShortApp,
        now: u64,
    ) {
        // A prior link's offer in this same pass may have removed it (custody release / drop).
        if !self.store.contains(&id) {
            return;
        }
        let Some(LinkState::Up(est)) = self.links.get(&link) else {
            return;
        };
        // Already sent this bundle on this link, OR the peer's custody beacon said it already holds
        // it: either way, do not re-offer (§35 duplicate-ingress suppression). Mode-1 exact set, so
        // no false positives; a recipient-gradient bundle still floods on links where the peer did
        // NOT claim it, so no flood floor is needed.
        if est.sent_bundles.contains(&id) || est.peer_has.contains(&id) {
            return;
        }
        let peer = est.peer;
        // §39 P4 (+ sec-priv-04): route a private bundle DOWN its gradient (toward the recipient)
        // instead of blind-flooding. The gradient keys on the tag's routing PREFIX (an anonymity set),
        // so a bucket may hold SEVERAL live next-hops (colliding recipients on different links); the
        // directed copy rides ALL of them and NO other link. A far end that isn't the intended
        // recipient just fails the per-message recognition tag and drops its copy. No live next-hop
        // (cold start / passive recipient / all flapping) → fall through to the epidemic flood fallback.
        //
        // security-privacy-r3-02 (documented scope): the bucket is a PREFIX anonymity set that may hold
        // >1 recipient, so a live next-hop can be a prefix-COLLIDING DECOY (an ACTIVE recipient B1) while
        // the TRUE recipient is a PASSIVE B2 that never beacons and so is in NO gradient. Suppressing the
        // flood here steers B2's copy only down B1's link (dropped on the recognition check). Recovery is
        // the durable want-beacon SPOOL (`spoolable_private_bundles` + `take_wanted_mailboxes` + `ingest`,
        // all public `Node` APIs): when B2 later beacons, its carrier reloads the spool and P4 steers the
        // reloaded copy to B2. Those core APIs are transport-agnostic, so a PURE-P2P carrier can run the
        // same reload loop as `hop-relayd`, but a partition with NO node running that loop cannot recover
        // a passive colliding recipient off-relay. We deliberately do NOT drop the P4 anti-flood guarantee
        // (never flooding a private bundle to non-recipient leaf links, which the decoy-privacy test
        // pins) to paper over that: the node cannot distinguish a passive RECIPIENT leaf from a passive
        // DECOY leaf without opening the seal, so flooding "just in case" would leak the very traffic P4
        // hides. The fix is a driver one (run the spool-reload loop on P2P carriers, not only relays); the
        // relay-dependency of the black-hole recovery is called out in DESIGN.md §39.
        if b.is_private() {
            if let Some(prefix) = b.inner.private.as_ref().and_then(|p| p.mailbox) {
                if let Some(entry) = self.recv_gradient.get(&route_key_from_prefix(&prefix)) {
                    let mut any_live = false;
                    let mut this_link_is_a_next_hop = false;
                    for (l, gl) in &entry.links {
                        let live = gl.expires_at > now
                            && matches!(self.links.get(l), Some(LinkState::Up(_)));
                        if live {
                            any_live = true;
                            if *l == link {
                                this_link_is_a_next_hop = true;
                            }
                        }
                    }
                    // If the bucket has ANY live next-hop but THIS link isn't one of them, skip it: the
                    // directed copy rides only the anonymity-set's links, never a leaf's.
                    if any_live && !this_link_is_a_next_hop {
                        return;
                    }
                }
            }
        }
        {
            let meta = BundleMeta::from(&b);
            let direct = is_for(&b, &peer);
            // If we can reach the destination directly right now, don't spray copies
            // to relays — direct delivery on the destination's own link completes it.
            let dest_here = self.dest_is_connected(&b);

            // Our own originated messages: keep until the delivery ACK arrives (or
            // they expire), so we can re-flood if undelivered — don't release on a
            // mere handoff (DESIGN.md §6, §7).
            let own = self.tx.contains_key(&id);

            let to_send: Option<Bundle> = match self.router.should_forward(&meta, &peer) {
                ForwardDecision::Drop => {
                    self.store.remove(&id);
                    None
                }
                ForwardDecision::Hold => None,
                ForwardDecision::Forward if direct => {
                    let mut copy = b.clone();
                    if copy.forwarded() {
                        copy.add_hop(me_short, me_app); // provenance (§27)
                                                        // Release custody only for fire-and-forget bundles. For request_ack
                                                        // ones (carrier chunks, messages), keep custody until the delivery
                                                        // ACK confirms receipt — handing to the destination is optimistic, and
                                                        // a chunk it misses in a brief background window must be re-offerable
                                                        // on its next wake, not deleted here (the ACK vaccine removes it for
                                                        // real). Without this, a large transfer to a backgrounded device can
                                                        // lose chunks the relay already dropped, and dedup blocks re-injection.
                        if !own && !b.inner.flags.request_ack {
                            self.store.remove(&id);
                        }
                        Some(copy)
                    } else {
                        None
                    }
                }
                // Destination is directly reachable on its own link — deliver there,
                // don't also flood it to relays (the dest would just dedup the copies).
                ForwardDecision::Forward if dest_here => None,
                ForwardDecision::Forward => {
                    // Epidemic flood: hand a full copy to this neighbour and keep ours
                    // so we keep flooding to other/future neighbours. Copies are bounded
                    // by the hop limit and reclaimed by the delivery-ACK vaccine.
                    let mut copy = b.clone();
                    if copy.forwarded() {
                        copy.add_hop(me_short, me_app); // provenance (§27)
                        Some(copy)
                    } else {
                        None
                    }
                }
            };

            if let Some(copy) = to_send {
                self.send_record(link, &Wire::Bundle(copy));
                if self.observe {
                    self.transfers.push((link, id, direct));
                }
                if let Some(LinkState::Up(est)) = self.links.get_mut(&link) {
                    est.sent_bundles.insert(id);
                }
                // Record the first handoff of a not-ours bundle so eviction can prefer
                // already-relayed, settled bundles over ones we haven't relayed yet (§6).
                if !own {
                    self.relay_fwd.entry(id).or_insert(now);
                }
                // A delivery-ACK we originated: count distinct peers it's reached; once it
                // has spread to ACK_REPLICATION_TARGET, it's done — drop it so it stops
                // riding to every contact (DESIGN.md §7).
                if let Some(peers) = self.ack_replicate.get_mut(&id) {
                    peers.insert(peer);
                    if peers.len() >= ACK_REPLICATION_TARGET {
                        self.ack_replicate.remove(&id);
                        self.store.remove(&id);
                    }
                }
                // "Sent N peers" counts relay handoffs only — not direct delivery to
                // the destination itself (that shows as Delivered once the ACK is back).
                if !direct {
                    // Attribute to the UI-facing message (carrier chunk → original; deferred
                    // content → its handle) so "Sent N" lands on the right row.
                    let owner = self.display_id(&id);
                    if let Some(info) = self.tx.get_mut(&owner) {
                        info.relayed.insert(peer);
                    }
                }
            }
        }
    }

    /// Gossip directory adverts to one link, ranked by relay utility isn't wired
    /// here yet (needs a scorer); plain offer for now (DESIGN.md §16, §18).
    fn offer_adverts_to_link(&mut self, link: LinkId) {
        let already: HashSet<crate::discover::AdvertId> = match self.links.get(&link) {
            Some(LinkState::Up(est)) => est.sent_adverts.clone(),
            _ => return,
        };
        let offer = self.directory.gossip_offer(&already);
        for advert in offer {
            let aid = advert.id;
            // Increment hop distance so receivers can show "N hops away".
            let mut fwd = advert;
            fwd.hops = fwd.hops.saturating_add(1);
            self.send_record(link, &Wire::Advert(fwd));
            if let Some(LinkState::Up(est)) = self.links.get_mut(&link) {
                est.sent_adverts.insert(aid);
            }
        }
    }

    // --- wire helpers ---------------------------------------------------------

    fn send_packet(&mut self, link: LinkId, packet: LinkPacket) {
        if let Ok(bytes) = postcard::to_allocvec(&packet) {
            self.outgoing.push((link, bytes));
        }
    }

    fn send_record(&mut self, link: LinkId, record: &Wire) {
        let Some(LinkState::Up(est)) = self.links.get_mut(&link) else {
            return;
        };
        let Ok(plaintext) = postcard::to_allocvec(record) else {
            return;
        };
        // Fits one Noise message: send as a single Data record (the common case).
        if plaintext.len() <= MAX_RECORD_PLAINTEXT {
            let Ok(ct) = est.session.encrypt(&plaintext) else {
                return;
            };
            if let Ok(bytes) = postcard::to_allocvec(&LinkPacket::Data(ct)) {
                self.outgoing.push((link, bytes));
            }
            return;
        }
        // Too large for one Noise message — fragment across several so it isn't silently
        // dropped. Each piece is independently encrypted; the peer reassembles (§20).
        let pieces: Vec<&[u8]> = plaintext.chunks(MAX_RECORD_PLAINTEXT).collect();
        if pieces.len() > MAX_RECORD_FRAGMENTS {
            return;
        }
        let cnt = pieces.len() as u16;
        for (i, piece) in pieces.into_iter().enumerate() {
            let Ok(ct) = est.session.encrypt(piece) else {
                return; // ratchet would desync; abandon the rest of this record
            };
            if let Ok(bytes) = postcard::to_allocvec(&LinkPacket::DataFrag {
                idx: i as u16,
                cnt,
                ct,
            }) {
                self.outgoing.push((link, bytes));
            }
        }
    }
}

fn decode_link_packet(bytes: &[u8]) -> Option<LinkPacket> {
    if bytes.len() > MAX_LINK_PACKET_BYTES {
        return None;
    }
    let packet = postcard::from_bytes::<LinkPacket>(bytes).ok()?;
    let valid = match &packet {
        LinkPacket::Handshake(message) => message.len() <= MAX_HANDSHAKE_MESSAGE_BYTES,
        LinkPacket::Data(ciphertext) => ciphertext.len() <= MAX_RECORD_PLAINTEXT + 16,
        LinkPacket::DataFrag { idx, cnt, ct } => {
            *cnt > 0
                && usize::from(*cnt) <= MAX_RECORD_FRAGMENTS
                && *idx < *cnt
                && ct.len() <= MAX_RECORD_PLAINTEXT + 16
        }
    };
    valid.then_some(packet)
}

/// Feature-scoped parser entry point for cargo-fuzz. Production receives the same checks through
/// [`Node::on_data`], while the private packet enum remains outside the public protocol API.
#[cfg(feature = "fuzzing")]
pub fn fuzz_link_packet(bytes: &[u8]) {
    if let Some(packet) = decode_link_packet(bytes) {
        match packet {
            LinkPacket::Handshake(message) | LinkPacket::Data(message) => {
                std::hint::black_box(message.len());
            }
            LinkPacket::DataFrag { idx, cnt, ct } => {
                std::hint::black_box((idx, cnt, ct.len()));
            }
        }
    }
}

impl<S: Store> Node<S> {
    /// Is the bundle's destination one of our currently-connected, authenticated
    /// peers? If so we can deliver directly and need not spray copies to relays.
    fn dest_is_connected(&self, bundle: &Bundle) -> bool {
        let dst = match bundle.inner.dst {
            Destination::Device(a) | Destination::AckTo(a, _) => a,
            Destination::Broadcast | Destination::Vaccine(..) => return false,
        };
        self.links
            .values()
            .any(|s| matches!(s, LinkState::Up(e) if e.peer == dst))
    }
}

/// Durable KV key for one persisted carrier chunk (DESIGN.md §20). Zero-padded seq keeps
/// keys lexically ordered; both addresses base58-encode without a `/`, so the key splits
/// cleanly back apart.
fn stream_chunk_key(from: &PubKeyBytes, sid: &StreamId, seq: u64) -> String {
    format!(
        "strm/{}/{}/{:020}",
        bs58::encode(from).into_string(),
        bs58::encode(sid).into_string(),
        seq
    )
}

/// KV prefix for all of one carrier stream's persisted chunks.
fn stream_prefix(from: &PubKeyBytes, sid: &StreamId) -> String {
    format!(
        "strm/{}/{}/",
        bs58::encode(from).into_string(),
        bs58::encode(sid).into_string()
    )
}

/// Parse a persisted-chunk key back into `(from, stream_id, seq)`.
fn parse_stream_key(key: &str) -> Option<(PubKeyBytes, StreamId, u64)> {
    let rest = key.strip_prefix("strm/")?;
    let mut parts = rest.split('/');
    let from = parts.next()?;
    let sid = parts.next()?;
    let seq = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let from = <PubKeyBytes>::try_from(bs58::decode(from).into_vec().ok()?.as_slice()).ok()?;
    let sid = <StreamId>::try_from(bs58::decode(sid).into_vec().ok()?.as_slice()).ok()?;
    Some((from, sid, seq.parse().ok()?))
}

/// Canonicalize a domain for HNS cache keys/lookups: lowercase, no trailing dot, no
/// surrounding whitespace. (DNS is case-insensitive; the root dot is implicit.)
fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Is this bundle destined for `addr` (direct delivery)?
fn is_for(bundle: &Bundle, addr: &PubKeyBytes) -> bool {
    use crate::bundle::Destination::*;
    match &bundle.inner.dst {
        Device(d) => d == addr,
        AckTo(d, _) => d == addr,
        Broadcast | Vaccine(..) => false,
    }
}

/// Forward-path latency (ms) a receiver reports in its ACK: its receive time `now` minus the
/// message's `created_at` (the sender's send time). Saturating + clamped to `u32` — a negative
/// value (clock skew where the receiver's clock trails the sender's) reads as 0, and anything
/// beyond ~49 days clamps rather than wrapping.
fn forward_ms(now: u64, created_at: u64) -> u32 {
    now.saturating_sub(created_at).min(u32::MAX as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{BundleOpts, Destination, Payload};
    use crate::discover::AdvertKind;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn malformed_link_packet_bytes_never_panic(
            bytes in prop::collection::vec(any::<u8>(), 0..(MAX_LINK_PACKET_BYTES + 64))
        ) {
            let parsed = std::panic::catch_unwind(|| decode_link_packet(&bytes));
            prop_assert!(parsed.is_ok(), "link packet parser panicked");
            if let Some(packet) = parsed.unwrap() {
                let canonical = postcard::to_allocvec(&packet).expect("decoded packet re-encodes");
                prop_assert_eq!(decode_link_packet(&canonical), Some(packet));
            }
        }
    }

    // --- F-03: rehydrate counts (does not silently drop) undecodable persisted state --------
    #[test]
    fn rehydrate_reports_undecodable_records_instead_of_silently_dropping() {
        let mut store = MemoryStore::new();
        // Simulate a post-upgrade layout mismatch: bytes that are not a valid encoding of the
        // struct the current build expects for these keys.
        store.put_kv("pending_content", vec![0xff, 0xff, 0xff, 0xff]);
        store.put_kv(
            &format!("session/{}", bs58::encode([7u8; 32]).into_string()),
            vec![0xde, 0xad, 0xbe, 0xef],
        );
        let mut node = Node::with_store(Identity::generate(), store);
        let report = node.take_rehydrate_report();
        assert_eq!(
            report.total(),
            2,
            "both undecodable records must be counted, not dropped silently"
        );
        assert!(report.dropped.iter().any(|(k, _)| *k == "pending_content"));
        assert!(report.dropped.iter().any(|(k, _)| *k == "session"));
        // Draining clears it.
        assert!(node.take_rehydrate_report().is_empty());
    }

    #[test]
    fn rehydrate_report_is_empty_on_a_clean_store() {
        let mut node = Node::new(Identity::generate());
        assert!(node.take_rehydrate_report().is_empty());
    }

    /// In-memory test fabric: pump nodes until quiescent, routing each node's
    /// outgoing bytes to the peer on the matching link id.
    struct Wire2 {
        // For a connection between node A and node B: A uses link `ab`, B uses `ba`.
        // map: (node_index, link_id) -> (other_node_index, other_link_id)
        routes: HashMap<(usize, LinkId), (usize, LinkId)>,
    }

    impl Wire2 {
        fn new() -> Self {
            Self {
                routes: HashMap::new(),
            }
        }

        /// Connect nodes `a` and `b` with the given link ids and run the handshake.
        fn connect(&mut self, nodes: &mut [Node], a: usize, la: LinkId, b: usize, lb: LinkId) {
            self.routes.insert((a, la), (b, lb));
            self.routes.insert((b, lb), (a, la));
            nodes[a].handle(BearerEvent::Connected(la, Role::Initiator));
            nodes[b].handle(BearerEvent::Connected(lb, Role::Responder));
            self.pump(nodes);
        }

        /// Deliver all queued bytes until the network is quiescent.
        fn pump(&mut self, nodes: &mut [Node]) {
            for _ in 0..1000 {
                let mut any = false;
                for i in 0..nodes.len() {
                    for (link, bytes) in nodes[i].drain_outgoing() {
                        any = true;
                        if let Some(&(j, jl)) = self.routes.get(&(i, link)) {
                            nodes[j].handle(BearerEvent::Data(jl, bytes));
                        }
                    }
                }
                if !any {
                    break;
                }
            }
        }
    }

    fn accept_all<S: Store>(node: &mut Node<S>) {
        let ids: Vec<BundleId> = node.inbox_items().into_iter().map(|item| item.id).collect();
        for id in ids {
            assert!(node.accept_inbox(&id).unwrap());
        }
    }

    fn take_hps_and_accept<S: Store>(node: &mut Node<S>) -> Vec<HpsMessage> {
        let messages = node.take_hps_messages();
        for message in &messages {
            assert!(node.accept_hps_message(&message.id).unwrap());
        }
        messages
    }

    fn msg(from: &Node, to: &Node, body: &[u8]) -> Bundle {
        Bundle::create(
            &from.identity,
            Destination::Device(to.address()),
            &to.identity.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: body.to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap()
    }

    fn custom_service_request<S: Store>(
        from: &Identity,
        to: &Node<S>,
        sequence: u8,
        request_ack: bool,
    ) -> Bundle {
        Bundle::create(
            from,
            Destination::Device(to.address()),
            &to.address(),
            &Payload::ServiceRequest {
                service: "app.queue".into(),
                method: "run".into(),
                args: vec![sequence],
            },
            BundleOpts {
                flags: BundleFlags {
                    request_ack,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn carrier<S: Store>(
        from: &Identity,
        to: &Node<S>,
        stream_id: StreamId,
        seq: u64,
        bytes: Vec<u8>,
        fin: bool,
    ) -> Bundle {
        Bundle::create(
            from,
            Destination::Device(to.address()),
            &to.address(),
            &Payload::Carrier {
                stream_id,
                seq,
                bytes,
                fin,
            },
            BundleOpts {
                flags: BundleFlags {
                    request_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap()
    }

    /// Publish + gossip prekeys so `send_message` can open forward-secret sessions — content is
    /// never static-sealed now, so a test that sends via `send_message` must do this first (§25).
    fn exchange_prekeys(net: &mut Wire2, nodes: &mut [Node]) {
        for n in nodes.iter_mut() {
            n.publish_prekey().unwrap();
        }
        net.pump(nodes);
    }

    /// Inject `who`'s (epoch-0) prekey straight into `node`'s directory via a genuine signed PreKey
    /// advert — the same thing gossip would deliver, but without wiring a live link. Lets a test send a
    /// §39 private message to an OFFLINE recipient (the sender only needs the recipient's published SPK).
    fn inject_prekey<S: Store>(node: &mut Node<S>, who: &Identity) {
        let spk = who.derive_prekey();
        let advert = Advert::publish(
            who,
            AdvertKind::PreKey {
                spk_pub: spk.public,
                spk_sig: spk.sig.to_vec(),
            },
            node.now_ms,
            60_000,
            1,
        )
        .unwrap();
        node.directory.ingest(advert, node.now_ms).unwrap();
    }

    /// Pair pump for tests whose nodes use different Store implementations.
    fn pump_pair<A: Store, B: Store>(
        a: &mut Node<A>,
        a_link: LinkId,
        b: &mut Node<B>,
        b_link: LinkId,
    ) {
        for _ in 0..1000 {
            let mut any = false;
            for (link, bytes) in a.drain_outgoing() {
                any = true;
                if link == a_link {
                    b.handle(BearerEvent::Data(b_link, bytes));
                }
            }
            for (link, bytes) in b.drain_outgoing() {
                any = true;
                if link == b_link {
                    a.handle(BearerEvent::Data(a_link, bytes));
                }
            }
            if !any {
                break;
            }
        }
    }

    #[derive(Clone, Default)]
    struct FaultStore {
        inner: MemoryStore,
        fail_bundle_puts: usize,
        fail_bundle_removes: usize,
        evict_bundle_puts: usize,
        bundle_put_calls: usize,
        bundle_remove_calls: usize,
        fail_critical_put_prefix: Option<String>,
        fail_critical_remove_prefix: Option<String>,
        fail_batch_after: Option<usize>,
        enforce_firestore_carrier_limits: bool,
        fail_carrier_cleanup_at: Option<usize>,
        carrier_cleanup_batches: Vec<(usize, usize)>,
        carrier_page_calls: std::cell::RefCell<Vec<(Option<String>, usize, usize)>>,
    }

    impl Store for FaultStore {
        fn put(&mut self, bundle: Bundle, now_ms: u64) -> bool {
            self.bundle_put_calls += 1;
            if self.fail_bundle_puts > 0 {
                self.fail_bundle_puts -= 1;
                return false;
            }
            if self.evict_bundle_puts > 0 {
                self.evict_bundle_puts -= 1;
                return true;
            }
            self.inner.put(bundle, now_ms)
        }
        fn rehydrate(&mut self, bundle: Bundle, now_ms: u64) -> bool {
            self.inner.rehydrate(bundle, now_ms)
        }
        fn get(&self, id: &BundleId) -> Option<Bundle> {
            self.inner.get(id)
        }
        fn remove(&mut self, id: &BundleId) -> Option<Bundle> {
            self.bundle_remove_calls += 1;
            if self.fail_bundle_removes > 0 {
                self.fail_bundle_removes -= 1;
                return None;
            }
            self.inner.remove(id)
        }
        fn seen(&self, id: &BundleId) -> bool {
            self.inner.seen(id)
        }
        fn contains(&self, id: &BundleId) -> bool {
            self.inner.contains(id)
        }
        fn have(&self) -> crate::store::HaveSet {
            self.inner.have()
        }
        fn prune(&mut self, now_ms: u64) {
            self.inner.prune(now_ms)
        }
        fn split_copies(&mut self, id: &BundleId) -> u16 {
            self.inner.split_copies(id)
        }
        fn set_copies(&mut self, id: &BundleId, copies: u16) {
            self.inner.set_copies(id, copies)
        }
        fn seen_expiry(&self, id: &BundleId) -> Option<u64> {
            self.inner.seen_expiry(id)
        }
        fn put_kv(&mut self, key: &str, value: Vec<u8>) {
            self.inner.put_kv(key, value)
        }
        fn apply_kv_batch(&mut self, mutations: &[KvMutation]) -> std::result::Result<(), String> {
            let carrier_cleanup = !mutations.is_empty()
                && mutations.iter().all(
                    |mutation| matches!(mutation, KvMutation::Remove { key } if key.starts_with("strm/")),
                );
            if carrier_cleanup && self.enforce_firestore_carrier_limits {
                let encoded_bytes =
                    mutations
                        .iter()
                        .fold(0usize, |total, mutation| match mutation {
                            KvMutation::Remove { key } => total.saturating_add(key.len() + 8),
                            _ => total,
                        });
                if mutations.len() >= 400 || encoded_bytes >= 512 * 1024 {
                    return Err("modeled Firestore critical-batch limit exceeded".into());
                }
                let attempt = self.carrier_cleanup_batches.len();
                self.carrier_cleanup_batches
                    .push((mutations.len(), encoded_bytes));
                if self.fail_carrier_cleanup_at == Some(attempt) {
                    self.fail_carrier_cleanup_at = None;
                    return Err("injected Firestore carrier cleanup failure".into());
                }
            }
            for (index, mutation) in mutations.iter().enumerate() {
                if self
                    .fail_batch_after
                    .is_some_and(|boundary| index >= boundary)
                {
                    return Err(format!("injected batch failure at mutation {index}"));
                }
                match mutation {
                    KvMutation::Put { key, .. }
                        if self
                            .fail_critical_put_prefix
                            .as_ref()
                            .is_some_and(|prefix| key.starts_with(prefix)) =>
                    {
                        return Err(format!("injected critical put failure for {key}"));
                    }
                    KvMutation::Remove { key }
                        if self
                            .fail_critical_remove_prefix
                            .as_ref()
                            .is_some_and(|prefix| key.starts_with(prefix)) =>
                    {
                        return Err(format!("injected critical remove failure for {key}"));
                    }
                    KvMutation::PutBundle { .. } if self.fail_bundle_puts > 0 => {
                        self.fail_bundle_puts -= 1;
                        return Err("injected critical bundle put failure".into());
                    }
                    KvMutation::RemoveBundle { .. } if self.fail_bundle_removes > 0 => {
                        self.fail_bundle_removes -= 1;
                        return Err("injected critical bundle remove failure".into());
                    }
                    _ => {}
                }
            }
            self.inner.apply_kv_batch(mutations)
        }
        fn put_kv_critical(
            &mut self,
            key: &str,
            value: Vec<u8>,
        ) -> std::result::Result<(), String> {
            if self
                .fail_critical_put_prefix
                .as_ref()
                .is_some_and(|prefix| key.starts_with(prefix))
            {
                return Err(format!("injected critical put failure for {key}"));
            }
            self.inner.put_kv_critical(key, value)
        }
        fn get_kv(&self, key: &str) -> Option<Vec<u8>> {
            self.inner.get_kv(key)
        }
        fn remove_kv(&mut self, key: &str) {
            self.inner.remove_kv(key)
        }
        fn remove_kv_critical(&mut self, key: &str) -> std::result::Result<(), String> {
            if self
                .fail_critical_remove_prefix
                .as_ref()
                .is_some_and(|prefix| key.starts_with(prefix))
            {
                return Err(format!("injected critical remove failure for {key}"));
            }
            self.inner.remove_kv_critical(key)
        }
        fn list_kv(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
            self.inner.list_kv(prefix)
        }
        fn list_kv_page(
            &self,
            prefix: &str,
            after: Option<&str>,
            limit: usize,
        ) -> Vec<(String, Vec<u8>)> {
            self.inner.list_kv_page(prefix, after, limit)
        }
        fn list_kv_page_bounded(
            &self,
            prefix: &str,
            after: Option<&str>,
            limit: usize,
            max_bytes: usize,
        ) -> std::result::Result<crate::store::KvPage, String> {
            if prefix.starts_with("strm/") {
                self.carrier_page_calls.borrow_mut().push((
                    after.map(str::to_string),
                    limit,
                    max_bytes,
                ));
            }
            self.inner
                .list_kv_page_bounded(prefix, after, limit, max_bytes)
        }
    }

    fn established_fault_pair() -> (Node<FaultStore>, Node, LinkId, LinkId) {
        let mut alice = Node::with_store(Identity::generate(), FaultStore::default());
        let mut bob = Node::new(Identity::generate());
        let (alice_link, bob_link) = (91, 92);
        alice.handle(BearerEvent::Connected(alice_link, Role::Initiator));
        bob.handle(BearerEvent::Connected(bob_link, Role::Responder));
        pump_pair(&mut alice, alice_link, &mut bob, bob_link);
        alice.publish_prekey().unwrap();
        bob.publish_prekey().unwrap();
        pump_pair(&mut alice, alice_link, &mut bob, bob_link);

        alice
            .send_message_traced(bob.address(), "t".into(), b"establish".to_vec(), false)
            .unwrap();
        pump_pair(&mut alice, alice_link, &mut bob, bob_link);
        for bundle in bob.take_inbox() {
            let id = bundle.id();
            bob.read_message(&bundle).unwrap();
            bob.accept_inbox(&id).unwrap();
        }
        bob.send_message_traced(alice.address(), "t".into(), b"confirm".to_vec(), false)
            .unwrap();
        pump_pair(&mut alice, alice_link, &mut bob, bob_link);
        for bundle in alice.take_inbox() {
            let id = bundle.id();
            alice.read_message(&bundle).unwrap();
            alice.accept_inbox(&id).unwrap();
        }
        alice.clear_queue();
        bob.clear_queue();
        assert!(alice.drain_outgoing().is_empty());
        assert!(bob.drain_outgoing().is_empty());
        assert!(alice.has_session(&bob.address()));
        assert!(bob.has_session(&alice.address()));
        (alice, bob, alice_link, bob_link)
    }

    fn ratchet_message(bundle: &Bundle, recipient: &Identity) -> crate::session::RatchetMessage {
        match bundle.open(recipient).unwrap() {
            Payload::SessionInit { msg, .. } | Payload::SessionMessage { msg } => msg,
            _ => panic!("expected ratcheted payload"),
        }
    }

    #[test]
    fn undecryptable_session_message_is_neither_receiver_seen_nor_acked() {
        let (mut alice, mut bob, alice_link, bob_link) = established_fault_pair();
        let alice_addr = alice.address();
        let before = postcard::to_allocvec(&alice.sessions[&bob.address()]).unwrap();
        let genuine_id = bob
            .send_message_traced(alice_addr, "t".into(), b"tamper".to_vec(), true)
            .unwrap();
        let genuine = bob.store.get(&genuine_id).unwrap();
        let mut payload = genuine.open(&alice.identity).unwrap();
        match &mut payload {
            Payload::SessionInit { msg, .. } | Payload::SessionMessage { msg } => {
                msg.ciphertext[0] ^= 0x80;
            }
            _ => panic!("expected ratcheted payload"),
        }
        let bad = Bundle::create(
            &bob.identity,
            Destination::Device(alice_addr),
            &alice_addr,
            &payload,
            BundleOpts {
                flags: BundleFlags {
                    request_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        let bad_id = bad.id();
        alice.ingest(bad);

        assert!(alice.inbox_items().is_empty());
        assert!(!alice.receiver_seen.contains_key(&bad_id));
        assert!(!alice.store.seen(&bad_id));
        assert_eq!(
            postcard::to_allocvec(&alice.sessions[&bob.address()]).unwrap(),
            before,
            "failed authentication leaves the previous receive ratchet usable"
        );
        assert!(!alice.last_ack.contains_key(&bad_id));
        assert!(alice.store.have().ids.into_iter().all(|id| {
            alice.store.get(&id).is_none_or(|held| {
                !held.inner.flags.is_ack && !matches!(held.inner.dst, Destination::Vaccine(_))
            })
        }));

        // The genuine next message still decrypts with the untouched session.
        bob.send_message_traced(alice_addr, "t".into(), b"still usable".to_vec(), false)
            .unwrap();
        pump_pair(&mut alice, alice_link, &mut bob, bob_link);
        assert!(alice
            .inbox_items()
            .iter()
            .any(|item| item.body == b"still usable"));
    }

    #[test]
    fn inbox_batch_failure_advances_neither_session_seen_nor_ack() {
        let (mut alice, mut bob, alice_link, bob_link) = established_fault_pair();
        let peer = bob.address();
        let before_live = postcard::to_allocvec(&alice.sessions[&peer]).unwrap();
        let session_key = Node::<FaultStore>::session_kv_key(&peer);
        let before_durable = alice.store.get_kv(&session_key).unwrap();
        alice.store.fail_critical_put_prefix = Some("inbox/".into());

        let id = bob
            .send_message_traced(alice.address(), "t".into(), b"retry me".to_vec(), true)
            .unwrap();
        let bundle = bob.store.get(&id).unwrap();
        pump_pair(&mut alice, alice_link, &mut bob, bob_link);

        assert!(alice.inbox_items().is_empty());
        assert!(!alice.receiver_seen.contains_key(&id));
        assert!(!alice.store.seen(&id));
        assert_eq!(
            postcard::to_allocvec(&alice.sessions[&peer]).unwrap(),
            before_live
        );
        assert_eq!(alice.store.get_kv(&session_key), Some(before_durable));
        assert!(alice.drain_outgoing().is_empty());

        alice.store.fail_critical_put_prefix = None;
        alice.ingest(bundle);
        let staged = alice.inbox_items();
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].id, id);
        assert_eq!(staged[0].body, b"retry me");
    }

    #[test]
    fn private_inbox_persistence_failure_emits_neither_ack_nor_vaccine() {
        let (mut alice, mut bob, alice_link, bob_link) = established_fault_pair();
        alice.store.fail_critical_put_prefix = Some("inbox/".into());
        let id = bob
            .send_message(alice.address(), "t".into(), b"private".to_vec(), true)
            .unwrap();
        pump_pair(&mut alice, alice_link, &mut bob, bob_link);

        assert!(alice.inbox_items().is_empty());
        assert!(!alice.receiver_seen.contains_key(&id));
        assert!(!alice.store.seen(&id));
        assert!(
            alice.drain_outgoing().is_empty(),
            "failed private staging emits neither private ACK nor vaccine"
        );
    }

    #[test]
    fn staged_inbox_survives_restart_and_next_message_uses_persisted_ratchet() {
        let (mut alice, mut bob, alice_link, bob_link) = established_fault_pair();
        let secret = alice.identity_secret();
        let first_id = bob
            .send_message_traced(
                alice.address(),
                "t".into(),
                b"before restart".to_vec(),
                true,
            )
            .unwrap();
        pump_pair(&mut alice, alice_link, &mut bob, bob_link);
        assert_eq!(alice.inbox_items()[0].id, first_id);

        let mut restarted = Node::with_store(
            Identity::from_secret_bytes(&secret),
            FaultStore {
                inner: alice.store.inner.clone(),
                ..Default::default()
            },
        );
        let restored = restarted.inbox_items();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].id, first_id);
        assert_eq!(restored[0].body, b"before restart");

        let second_id = bob
            .send_message_traced(
                restarted.address(),
                "t".into(),
                b"after restart".to_vec(),
                false,
            )
            .unwrap();
        let second = bob.store.get(&second_id).unwrap();
        restarted.ingest(second);
        assert!(restarted
            .inbox_items()
            .iter()
            .any(|item| item.id == second_id && item.body == b"after restart"));
    }

    #[test]
    fn inbox_repeats_until_durable_acceptance_then_stops() {
        let (mut alice, mut bob, alice_link, bob_link) = established_fault_pair();
        let id = bob
            .send_message_traced(alice.address(), "t".into(), b"persist first".to_vec(), true)
            .unwrap();
        pump_pair(&mut alice, alice_link, &mut bob, bob_link);

        assert_eq!(alice.inbox_items()[0].id, id);
        assert_eq!(alice.inbox_items()[0].id, id, "polling is non-destructive");
        alice.store.fail_critical_remove_prefix = Some("inbox/".into());
        assert!(alice.accept_inbox(&id).is_err());
        assert_eq!(alice.inbox_items()[0].id, id);
        assert!(alice.drain_outgoing().is_empty());

        alice.store.fail_critical_remove_prefix = None;
        assert!(alice.accept_inbox(&id).unwrap());
        assert!(alice.inbox_items().is_empty());
        assert!(!alice.drain_outgoing().is_empty());

        let restarted = Node::with_store(
            Identity::from_secret_bytes(&alice.identity_secret()),
            FaultStore {
                inner: alice.store.inner.clone(),
                ..Default::default()
            },
        );
        assert!(restarted.inbox_items().is_empty());
    }

    #[test]
    fn failed_session_write_preserves_live_state_and_emits_nothing() {
        let (mut alice, bob, _, _) = established_fault_pair();
        let peer = bob.address();
        let key = Node::<FaultStore>::session_kv_key(&peer);
        let old_live = postcard::to_allocvec(&alice.sessions[&peer]).unwrap();
        let old_durable = alice.store.get_kv(&key).unwrap();
        let old_have = alice.store.have().ids.len();
        let old_tx = alice.tx.len();
        alice.store.fail_critical_put_prefix = Some("session/".into());

        let result = alice.send_message_traced(peer, "t".into(), b"must fail".to_vec(), false);

        assert!(result.is_err());
        assert_eq!(
            postcard::to_allocvec(&alice.sessions[&peer]).unwrap(),
            old_live,
            "the live ratchet must not advance when its durable write fails"
        );
        assert_eq!(alice.store.get_kv(&key).unwrap(), old_durable);
        assert_eq!(alice.store.have().ids.len(), old_have);
        assert_eq!(alice.tx.len(), old_tx, "no delivery state was created");
        assert!(
            alice.drain_outgoing().is_empty(),
            "no ciphertext was offered"
        );
    }

    #[test]
    fn failed_initial_session_write_does_not_establish_or_emit() {
        let mut alice = Node::with_store(Identity::generate(), FaultStore::default());
        let bob = Identity::generate();
        inject_prekey(&mut alice, &bob);
        alice.store.fail_critical_put_prefix = Some("session/".into());

        let result =
            alice.send_message_traced(bob.address(), "t".into(), b"first message".to_vec(), false);

        assert!(result.is_err());
        assert!(!alice.has_session(&bob.address()));
        assert!(alice.store.list_kv("session/").is_empty());
        assert!(alice.store.have().ids.is_empty());
        assert!(alice.tx.is_empty());
        assert!(alice.drain_outgoing().is_empty());
    }

    #[test]
    fn failed_deferred_queue_write_is_not_reported_as_a_send() {
        let mut alice = Node::with_store(Identity::generate(), FaultStore::default());
        alice.store.fail_critical_put_prefix = Some("pending_content".into());

        let result = alice.send_message_traced(
            Identity::generate().address(),
            "t".into(),
            b"must remain unaccepted".to_vec(),
            false,
        );

        assert!(result.is_err());
        assert!(alice.pending_content.is_empty());
        assert!(alice.store.get_kv("pending_content").is_none());
        assert!(alice.tx.is_empty());
    }

    #[test]
    fn restart_after_successful_send_never_reuses_a_message_key() {
        let (mut alice, mut bob, _, _) = established_fault_pair();
        let bob_addr = bob.address();
        let alice_secret = alice.identity_secret();

        let first_id = alice
            .send_message_traced(bob_addr, "t".into(), b"before restart".to_vec(), false)
            .unwrap();
        let first_bundle = alice.store.get(&first_id).unwrap();
        let first_ratchet = ratchet_message(&first_bundle, &bob.identity);
        let first = bob
            .read_message(&first_bundle)
            .unwrap()
            .expect("first message decrypts");
        assert_eq!(first.body, b"before restart");

        let persisted = alice.store.inner.clone();
        let mut restarted = Node::with_store(
            Identity::from_secret_bytes(&alice_secret),
            FaultStore {
                inner: persisted,
                ..Default::default()
            },
        );
        let second_id = restarted
            .send_message_traced(bob_addr, "t".into(), b"after restart".to_vec(), false)
            .unwrap();
        let second_bundle = restarted.store.get(&second_id).unwrap();
        let second_ratchet = ratchet_message(&second_bundle, &bob.identity);

        assert_ne!(
            (first_ratchet.header.dh, first_ratchet.header.n),
            (second_ratchet.header.dh, second_ratchet.header.n),
            "a restart must resume after the durably committed send key"
        );
        assert_ne!(first_ratchet.ciphertext, second_ratchet.ciphertext);
        let second = bob
            .read_message(&second_bundle)
            .unwrap()
            .expect("post-restart message decrypts");
        assert_eq!(second.body, b"after restart");
    }

    #[test]
    fn deferred_flush_session_write_failure_retains_the_queue() {
        let mut alice = Node::with_store(Identity::generate(), FaultStore::default());
        let bob = Identity::generate();
        let handle = alice
            .send_message_traced(bob.address(), "t".into(), b"queued".to_vec(), false)
            .unwrap();
        assert_eq!(alice.pending_content.len(), 1);
        inject_prekey(&mut alice, &bob);
        alice.store.fail_critical_put_prefix = Some("session/".into());

        alice.flush_pending_content();

        assert_eq!(alice.pending_content.len(), 1);
        assert_eq!(alice.pending_content[0].display_id, handle);
        let durable: Vec<PendingContent> =
            postcard::from_bytes(&alice.store.get_kv("pending_content").unwrap()).unwrap();
        assert_eq!(durable.len(), 1, "the durable deferred queue is unchanged");
        assert!(alice.store.have().ids.is_empty());
        assert!(alice.drain_outgoing().is_empty());
    }

    #[test]
    fn failed_session_delete_preserves_reset_and_idle_gc_state() {
        let (mut alice, bob, _, _) = established_fault_pair();
        let peer = bob.address();
        let key = Node::<FaultStore>::session_kv_key(&peer);
        let durable = alice.store.get_kv(&key).unwrap();
        alice.store.fail_critical_remove_prefix = Some("session/".into());

        alice.handle_session_reset(peer);
        assert!(alice.has_session(&peer));
        assert_eq!(alice.store.get_kv(&key), Some(durable.clone()));
        assert!(alice.drain_outgoing().is_empty());

        alice.tick(1);
        alice.tick(SESSION_MAX_IDLE_MS + 2);
        assert!(
            alice.has_session(&peer),
            "idle GC keeps live state on delete failure"
        );
        assert_eq!(alice.store.get_kv(&key), Some(durable));
    }

    #[test]
    fn bundle_store_failure_rolls_back_ratchet_and_emits_nothing() {
        let (mut alice, mut bob, alice_link, bob_link) = established_fault_pair();
        let peer = bob.address();
        let key = Node::<FaultStore>::session_kv_key(&peer);
        let old_session = alice.store.get_kv(&key).unwrap();
        let old_live = postcard::to_allocvec(&alice.sessions[&peer]).unwrap();
        let old_have = alice.store.have().ids.len();
        let old_tx = alice.tx.len();
        alice.store.fail_bundle_puts = 1;

        let failed = alice.send_message(peer, "t".into(), b"not emitted".to_vec(), false);
        assert!(failed.is_err());
        assert_eq!(
            alice.store.get_kv(&key).unwrap(),
            old_session,
            "the durable ratchet and custody record are one failed transaction"
        );
        assert_eq!(
            postcard::to_allocvec(&alice.sessions[&peer]).unwrap(),
            old_live
        );
        assert_eq!(alice.store.have().ids.len(), old_have);
        assert_eq!(alice.tx.len(), old_tx);
        assert!(alice.drain_outgoing().is_empty());

        alice
            .send_message(peer, "t".into(), b"after failure".to_vec(), false)
            .unwrap();
        pump_pair(&mut alice, alice_link, &mut bob, bob_link);
        let delivered = bob
            .take_inbox()
            .iter()
            .find_map(|bundle| bob.read_message(bundle).ok().flatten())
            .expect("the next send decrypts from the unchanged ratchet state");
        assert_eq!(delivered.body, b"after failure");
    }

    /// Build a §39 private delivery-ACK sealed to `to` for `for_bundle_id`, carrying `proof`
    /// (core-protocol-r2-04). Models both a genuine recipient ACK (valid proof) and an attacker's
    /// forgery (no / wrong proof) — the sender recognizes either, but only accepts one.
    fn make_private_ack(
        to: &PubKeyBytes,
        to_spk_pub: &XPubKeyBytes,
        for_bundle_id: BundleId,
        proof: Option<[u8; 32]>,
    ) -> Bundle {
        let wrapped = Payload::Private {
            sender: [0u8; 32], // the attacker/recipient can claim any sender inside the seal
            inner: Box::new(Payload::Ack {
                for_bundle_id,
                status: 0,
                delivery_hops: 1,
                delivery_ms: 1,
                proof,
            }),
        };
        Bundle::create_private(
            to,
            to_spk_pub,
            &wrapped,
            Some(crypto::mailbox_route(&crypto::mailbox_tag(to, 0))),
            BundleOpts {
                created_at: 0,
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn ingest_holds_offline_device_bundle_for_handoff() {
        // A relay ingests a foreign alice→bob bundle from durable storage. With neither
        // endpoint connected it reports the bundle as undeliverable (so the backbone can
        // hand it into bob's region's mailbox, §28), preserving the sealed bytes verbatim.
        let mut relay = Node::new(Identity::generate());
        let alice = Identity::generate();
        let bob = Identity::generate();
        let b = Bundle::create(
            &alice,
            Destination::Device(bob.address()),
            &bob.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"hi".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap();
        let id = b.id();

        relay.ingest(b.clone());
        let u = relay.undeliverable_device_bundles();
        assert_eq!(
            u.len(),
            1,
            "the held device bundle is undeliverable while bob is offline"
        );
        assert_eq!(u[0].0, id);
        assert_eq!(u[0].1, bob.address());
        let round = Bundle::from_bytes(&u[0].2).expect("sealed bytes round-trip");
        assert_eq!(round.id(), id);

        // Re-ingesting the same bundle is a no-op (dedup), not a duplicate.
        relay.ingest(b);
        assert_eq!(relay.undeliverable_device_bundles().len(), 1);
    }

    #[test]
    fn handoff_and_spool_expiry_are_receiver_anchored_not_sender_created_at() {
        // stores-r3-01: a relay's durable handoff/spool `expireAt` must be anchored to the store's
        // RECEIVER-clamped dedup deadline (seen_expiry, stores-r2-01), NOT recomputed from the
        // sender's advisory created_at. The wire/BundleOpts default is created_at=0 (and a hostile
        // or non-node sender can stamp it), so the OLD `created_at + lifetime` landed at ~1970 —
        // a durable expireAt in the PAST, which the TTL policy sweeps, silently losing a still-live
        // handed-off/spooled message to an offline recipient. Assert both paths now use now+lifetime.
        let now_ms = 1_700_000_000_000u64; // a real 2023 wall clock, far past created_at=0
        let lifetime_ms = 86_400_000u64; // 24h default

        // --- handoff (device-addressed) ---
        let mut relay = Node::new(Identity::generate());
        relay.set_time(now_ms);
        let alice = Identity::generate();
        let bob = Identity::generate();
        let dev = Bundle::create(
            &alice,
            Destination::Device(bob.address()),
            &bob.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"hi".to_vec(),
            },
            BundleOpts::default(), // created_at = 0 (the wire default a hostile sender can also set)
        )
        .unwrap();
        assert_eq!(
            dev.inner.created_at, 0,
            "precondition: sender created_at is 0"
        );
        relay.ingest(dev);
        let u = relay.undeliverable_device_bundles();
        assert_eq!(u.len(), 1);
        let handoff_expiry = u[0].3;
        assert_eq!(
            handoff_expiry,
            now_ms + lifetime_ms,
            "handoff expireAt is receiver-anchored (now+lifetime), not created_at(0)+lifetime"
        );
        assert!(
            handoff_expiry > now_ms,
            "the durable expiry is in the FUTURE, so the TTL sweep can't reap a live message"
        );

        // --- spool (private, mailbox-tagged) ---
        let mut relay2 = Node::new(Identity::generate());
        relay2.set_time(now_ms);
        let recipient = Identity::generate();
        let mailbox = crypto::mailbox_tag(&recipient.address(), 0);
        let prefix = crypto::mailbox_route(&mailbox);
        let pb = Bundle::create_private(
            &recipient.address(),
            &recipient.derive_prekey().public,
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"secret".to_vec(),
            },
            Some(prefix),
            BundleOpts::default(), // created_at = 0
        )
        .unwrap();
        assert_eq!(
            pb.inner.created_at, 0,
            "precondition: private created_at is 0"
        );
        assert!(pb.is_private());
        relay2.ingest(pb);
        let s = relay2.spoolable_private_bundles();
        assert_eq!(s.len(), 1, "the private mailbox bundle is spoolable");
        let spool_expiry = s[0].3;
        assert_eq!(
            spool_expiry,
            now_ms + lifetime_ms,
            "spool expireAt is receiver-anchored (now+lifetime), not created_at(0)+lifetime"
        );
        assert!(
            spool_expiry > now_ms,
            "the durable spool expiry is in the FUTURE (not swept immediately)"
        );
    }

    #[test]
    fn identify_service_round_trips() {
        // Calling the built-in hop.identify on a peer returns its name/kind/address,
        // answered by the node itself — nothing surfaces to the responder's app (§29).
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        nodes[1].set_name(Some("Bob's Phone".into()));
        nodes[0].set_time(1);

        nodes[0]
            .send_service_request(
                nodes[1].address(),
                SERVICE_IDENTIFY.into(),
                String::new(),
                vec![],
            )
            .unwrap();
        net.pump(&mut nodes);

        assert!(
            nodes[1].take_service_requests().is_empty(),
            "built-in is auto-answered"
        );
        let resps = nodes[0].take_service_responses();
        assert_eq!(resps.len(), 1);
        assert_eq!(resps[0].status, 0);
        let rec: IdentityRecord = postcard::from_bytes(&resps[0].body).unwrap();
        assert_eq!(rec.name.as_deref(), Some("Bob's Phone"));
        assert_eq!(rec.kind, NodeKind::Device);
        assert_eq!(rec.address, nodes[1].address());
    }

    #[test]
    fn unnamed_node_identifies_with_no_name() {
        // A device with no name set returns None — the caller falls back to its short
        // address. The full address still comes back so the caller can resolve it.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        nodes[0].set_time(1);

        nodes[0]
            .send_service_request(
                nodes[1].address(),
                SERVICE_IDENTIFY.into(),
                String::new(),
                vec![],
            )
            .unwrap();
        net.pump(&mut nodes);

        let resps = nodes[0].take_service_responses();
        let rec: IdentityRecord = postcard::from_bytes(&resps[0].body).unwrap();
        assert_eq!(rec.name, None);
        assert_eq!(rec.address, nodes[1].address());
    }

    #[test]
    fn telemetry_rides_over_the_mesh() {
        // A device exports a TelemetryBatch to a collector's address. It rides an addressed,
        // statically sealed hop.telemetry bundle and surfaces (decoded + bounds-checked) via
        // take_telemetry, one-way, with no service response back to the sender.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);

        let batch = crate::telemetry::TelemetryBatch::new()
            .with_resource("platform", "ios")
            .with_resource("app", "acme.dispatch")
            .counter("hop.bundle.delivered", 1, 1000)
            .gauge("hop.delivery.latency_ms", 2100, 1000);

        nodes[0].send_telemetry(nodes[1].address(), &batch).unwrap();
        net.pump(&mut nodes);

        let got = nodes[1].take_telemetry();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].from, nodes[0].address());
        assert_eq!(got[0].batch, batch);
        assert_eq!(got[0].batch.billable_events(), 2);
        assert_eq!(
            got[0].tenant, None,
            "no stamper + Open policy: unattributed"
        );
        // Fire-and-forget: it is not surfaced as a custom service request, and no response returns.
        assert!(nodes[1].take_service_requests().is_empty());
        assert!(nodes[0].take_service_responses().is_empty());
    }

    #[test]
    fn telemetry_attributes_the_tenant_from_the_carriage_stamp() {
        // A device that stamps its bundles with its app's tenant key (§35) sends telemetry to a
        // collector running the SAME Keyed policy as the billing relays; take_telemetry recovers the
        // verified TenantId, so telemetry meters to the same tenant as billing (one attribution path).
        const TENANT: crate::access::TenantId = [7u8; 16];
        let now = 100 * crate::access::CARRIAGE_EPOCH_MS + 5;
        let stamper_key = Identity::generate();

        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        nodes[0].set_time(now);
        nodes[1].set_time(now);
        // The sender stamps everything it originates with its tenant key.
        nodes[0].set_stamper(Some(Stamper::new(
            TENANT,
            Identity::from_secret_bytes(&stamper_key.to_secret_bytes()),
        )));
        // The collector knows TENANT -> the stamper's pubkey (the same KeyServer the relays hold).
        let mut server = crate::access::KeyServer::new();
        server.insert(TENANT, stamper_key.address());
        nodes[1].set_access_policy(AccessPolicy::Keyed(crate::access::KeyedAccess::new(
            server,
            std::collections::HashSet::new(),
        )));
        nodes[1].refresh_access();

        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        let batch = crate::telemetry::TelemetryBatch::new().counter("hop.bundle.delivered", 1, now);
        nodes[0].send_telemetry(nodes[1].address(), &batch).unwrap();
        net.pump(&mut nodes);

        let got = nodes[1].take_telemetry();
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].tenant,
            Some(TENANT),
            "attributed to the tenant via the carriage stamp"
        );
    }

    #[test]
    fn large_streamed_telemetry_is_still_attributable() {
        // A batch over STREAM_CHUNK is fragmented into carriers. The stamp MUST be applied before
        // fragmentation, or the reassembled original arrives unstamped and the largest (most
        // billable) batches would silently bill nothing. Regression for that revenue bug.
        const TENANT: crate::access::TenantId = [7u8; 16];
        let now = 100 * crate::access::CARRIAGE_EPOCH_MS + 5;
        let stamper_key = Identity::generate();

        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        nodes[0].set_time(now);
        nodes[1].set_time(now);
        nodes[0].set_stamper(Some(Stamper::new(
            TENANT,
            Identity::from_secret_bytes(&stamper_key.to_secret_bytes()),
        )));
        let mut server = crate::access::KeyServer::new();
        server.insert(TENANT, stamper_key.address());
        nodes[1].set_access_policy(AccessPolicy::Keyed(crate::access::KeyedAccess::new(
            server,
            std::collections::HashSet::new(),
        )));
        nodes[1].refresh_access();

        // Max-width records: ~8.5 KB each, so a handful clears the 48 KiB STREAM_CHUNK while still
        // satisfying within_bounds (which caps COUNTS and string length, not total bytes).
        let wide = "x".repeat(crate::telemetry::MAX_STR);
        let mut batch = crate::telemetry::TelemetryBatch::new();
        for _ in 0..8 {
            let mut rec = crate::telemetry::Record::counter(&wide, 1, now).with_unit(&wide);
            for _ in 0..crate::telemetry::MAX_ATTRS {
                rec = rec.with_attr(&wide, &wide);
            }
            batch = batch.push(rec);
        }
        assert!(batch.within_bounds(), "a legal batch");
        assert!(
            batch.to_bytes().len() > STREAM_CHUNK,
            "must exercise the streamed path"
        );

        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        nodes[0].send_telemetry(nodes[1].address(), &batch).unwrap();
        for _ in 0..8 {
            net.pump(&mut nodes); // several rounds: the stream is many carriers
        }

        let got = nodes[1].take_telemetry();
        assert_eq!(got.len(), 1, "carriers reassembled into one batch");
        assert_eq!(
            got[0].tenant,
            Some(TENANT),
            "a streamed batch is still attributable (stamped before fragmentation)"
        );
    }

    #[test]
    fn custom_service_dispatches_to_app_and_replies() {
        // A non-hop. service surfaces to the responder's app, which replies; the caller
        // gets the response correlated by the request id.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        nodes[0].set_time(1);

        let req_id = nodes[0]
            .send_service_request(
                nodes[1].address(),
                "app.echo".into(),
                "say".into(),
                b"hi".to_vec(),
            )
            .unwrap();
        net.pump(&mut nodes);

        let reqs = nodes[1].take_service_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].service, "app.echo");
        assert_eq!(reqs[0].method, "say");
        assert_eq!(reqs[0].args, b"hi");
        assert_eq!(reqs[0].id, req_id);
        let (from, for_id) = (reqs[0].from, reqs[0].id);
        nodes[1]
            .send_service_response(from, for_id, 0, b"hi back".to_vec())
            .unwrap();
        net.pump(&mut nodes);

        let resps = nodes[0].take_service_responses();
        assert_eq!(resps.len(), 1);
        assert_eq!(resps[0].for_id, req_id);
        assert_eq!(resps[0].body, b"hi back");
        // The response is the return-path delete: the request no longer lingers in our
        // store (service calls carry no ACK-vaccine, so without this it would pin forever).
        assert!(
            !nodes[0].store.contains(&req_id),
            "request purged once its response arrives"
        );
    }

    #[test]
    fn app_queue_limits_cover_every_queue_and_release_exact_accounting() {
        let mut node = Node::new(Identity::generate());
        let source = [7u8; 32];
        let kinds = [
            AppQueueKind::PeerInbox,
            AppQueueKind::GenericInbox,
            AppQueueKind::HttpRequest,
            AppQueueKind::HttpResponse,
            AppQueueKind::ServiceRequest,
            AppQueueKind::ServiceResponse,
            AppQueueKind::HnsLookup,
            AppQueueKind::HnsResult,
            AppQueueKind::HpsMessage,
            AppQueueKind::HpsInvite,
            AppQueueKind::Telemetry,
        ];
        node.set_app_queue_limits(AppQueueLimits {
            max_items_per_queue: 1,
            max_bytes_per_queue: 8,
            max_total_items: APP_QUEUE_KINDS,
            max_total_bytes: APP_QUEUE_KINDS * 8,
            max_item_bytes: 8,
            max_sender_items: APP_QUEUE_KINDS,
            max_sender_bytes: APP_QUEUE_KINDS * 8,
        });
        for kind in kinds {
            let charge = node
                .reserve_app_queue(kind, Some(source), 8)
                .expect("first item in every queue is admitted");
            assert!(
                node.reserve_app_queue(kind, Some([8u8; 32]), 1).is_none(),
                "each queue enforces its own count cap"
            );
            node.release_app_queue(charge);
        }
        assert_eq!(node.app_queue_usage.items, 0);
        assert_eq!(node.app_queue_usage.bytes, 0);
        assert!(node.app_queue_usage.senders.is_empty());

        node.set_app_queue_limits(AppQueueLimits {
            max_items_per_queue: 2,
            max_bytes_per_queue: 8,
            max_total_items: 3,
            max_total_bytes: 10,
            max_item_bytes: 8,
            max_sender_items: 1,
            max_sender_bytes: 8,
        });
        assert!(
            node.reserve_app_queue(AppQueueKind::HttpRequest, Some(source), 9)
                .is_none(),
            "one oversized item is rejected before accounting"
        );
        let first = node
            .reserve_app_queue(AppQueueKind::HttpRequest, Some(source), 5)
            .unwrap();
        assert!(
            node.reserve_app_queue(AppQueueKind::HttpRequest, Some([8u8; 32]), 4)
                .is_none(),
            "per-queue bytes are bounded"
        );
        assert!(
            node.reserve_app_queue(AppQueueKind::ServiceRequest, Some(source), 1)
                .is_none(),
            "one source cannot consume another queue's share"
        );
        let second = node
            .reserve_app_queue(AppQueueKind::ServiceRequest, Some([8u8; 32]), 5)
            .unwrap();
        assert!(
            node.reserve_app_queue(AppQueueKind::HpsMessage, Some([9u8; 32]), 1)
                .is_none(),
            "the total byte cap applies across queue classes"
        );
        node.release_app_queue(first);
        let third = node
            .reserve_app_queue(AppQueueKind::HpsMessage, Some([9u8; 32]), 1)
            .expect("released capacity is reusable by another source");
        node.release_app_queue(second);
        node.release_app_queue(third);
        assert_eq!(node.app_queue_usage.items, 0);
        assert_eq!(node.app_queue_usage.bytes, 0);
        assert!(node.app_queue_usage.senders.is_empty());
    }

    #[test]
    fn app_queue_rejection_does_not_ack_or_consume_dedup() {
        let mut node = Node::new(Identity::generate());
        node.set_app_queue_limits(AppQueueLimits {
            max_items_per_queue: 3,
            max_bytes_per_queue: 1 << 20,
            max_total_items: 3,
            max_total_bytes: 1 << 20,
            max_item_bytes: 1 << 20,
            max_sender_items: 1,
            max_sender_bytes: 1 << 20,
        });
        let noisy = Identity::generate();
        let other = Identity::generate();
        let first = custom_service_request(&noisy, &node, 1, true);
        let rejected = custom_service_request(&noisy, &node, 2, true);
        let fair = custom_service_request(&other, &node, 3, true);
        let first_id = first.id();
        let rejected_id = rejected.id();
        let fair_id = fair.id();

        node.on_bundle(1, first.clone());
        node.on_bundle(1, rejected.clone());
        node.on_bundle(2, fair.clone());
        node.on_bundle(1, first.clone());
        assert_eq!(
            node.service_requests.len(),
            2,
            "duplicates do not grow the queue"
        );
        assert_eq!(node.pending_app_deliveries.len(), 2);
        for id in [first_id, rejected_id, fair_id] {
            assert!(!node.store.seen(&id));
            assert!(!node.last_ack.contains_key(&id));
        }

        let queued = node.take_service_requests_deferred();
        assert_eq!(queued.len(), 2);
        assert!(node.complete_app_delivery(&first_id));
        assert!(node.store.seen(&first_id));
        assert!(node.last_ack.contains_key(&first_id));
        assert!(node.reject_app_delivery(&fair_id));
        assert!(!node.store.seen(&fair_id));
        assert!(!node.last_ack.contains_key(&fair_id));

        node.on_bundle(2, fair);
        node.on_bundle(1, rejected);
        assert_eq!(
            node.service_requests.len(),
            2,
            "rejected work retries after capacity is released"
        );
        assert!(node.pending_app_deliveries.contains_key(&fair_id));
        assert!(node.pending_app_deliveries.contains_key(&rejected_id));
        assert!(!node.store.seen(&fair_id));
        assert!(!node.store.seen(&rejected_id));
        assert!(!node.last_ack.contains_key(&fair_id));
        assert!(!node.last_ack.contains_key(&rejected_id));
    }

    #[test]
    fn app_delivery_completion_requires_retained_dedup_before_ack() {
        let mut node = Node::with_store(Identity::generate(), FaultStore::default());
        let sender = Identity::generate();
        let request = custom_service_request(&sender, &node, 1, true);
        let id = request.id();

        node.on_bundle(1, request.clone());
        assert!(node.pending_app_deliveries.contains_key(&id));
        node.store.evict_bundle_puts = 1;
        assert!(!node.complete_app_delivery(&id));
        assert!(node.pending_app_deliveries.contains_key(&id));
        assert!(!node.store.seen(&id));
        assert!(!node.last_ack.contains_key(&id));

        assert!(node.reject_app_delivery(&id));
        node.on_bundle(1, request);
        assert!(node.complete_app_delivery(&id));
        assert!(node.store.seen(&id));
        assert!(node.last_ack.contains_key(&id));
    }

    #[test]
    fn infrastructure_roles_retain_only_their_host_payload_classes() {
        let kinds = [
            AppQueueKind::PeerInbox,
            AppQueueKind::GenericInbox,
            AppQueueKind::HttpRequest,
            AppQueueKind::HttpResponse,
            AppQueueKind::ServiceRequest,
            AppQueueKind::ServiceResponse,
            AppQueueKind::HnsLookup,
            AppQueueKind::HnsResult,
            AppQueueKind::HpsMessage,
            AppQueueKind::HpsInvite,
            AppQueueKind::Telemetry,
        ];
        for kind in kinds {
            assert!(AppPayloadPolicy::for_kind(NodeKind::Device).supports(kind));
            assert!(!AppPayloadPolicy::for_kind(NodeKind::Relay).supports(kind));
            assert_eq!(
                AppPayloadPolicy::for_kind(NodeKind::Gateway).supports(kind),
                kind == AppQueueKind::HttpRequest
            );
            assert_eq!(
                AppPayloadPolicy::for_kind(NodeKind::Endpoint).supports(kind),
                matches!(kind, AppQueueKind::HttpRequest | AppQueueKind::HpsMessage)
            );
        }

        let sender = Identity::generate();
        let mut relay = Node::new(Identity::generate());
        let queued_before_role = custom_service_request(&sender, &relay, 1, true);
        relay.on_bundle(1, queued_before_role);
        assert_eq!(relay.pending_app_deliveries.len(), 1);
        relay.set_kind(NodeKind::Relay);
        assert!(relay.pending_app_deliveries.is_empty());
        assert!(relay.service_requests.is_empty());
        assert_eq!(relay.app_queue_usage.items, 0);

        let dropped = custom_service_request(&sender, &relay, 2, true);
        let dropped_id = dropped.id();
        relay.on_bundle(1, dropped);
        assert!(relay.pending_app_deliveries.is_empty());
        assert!(!relay.store.seen(&dropped_id));
        assert!(!relay.last_ack.contains_key(&dropped_id));
    }

    #[test]
    fn response_authorization_rejects_racing_wrong_signer_and_wrong_kind() {
        let mut caller = Node::new(Identity::generate());
        caller.set_time(1);
        let expected = Identity::generate();
        let attacker = Identity::generate();
        let request_id = caller
            .send_service_request(
                expected.address(),
                "app.echo".into(),
                "say".into(),
                b"hello".to_vec(),
            )
            .unwrap();

        // A validly signed response from the wrong identity races first.
        let wrong_signer = Bundle::create(
            &attacker,
            Destination::Device(caller.address()),
            &caller.address(),
            &Payload::ServiceResponse {
                for_bundle_id: request_id,
                status: 0,
                body: b"attacker".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap();
        caller.on_bundle(1, wrong_signer);

        // The expected signer then races a response of the wrong protocol kind.
        let wrong_kind = Bundle::create(
            &expected,
            Destination::Device(caller.address()),
            &caller.address(),
            &Payload::HttpResponse {
                status: 200,
                headers: vec![],
                body: b"not service".to_vec(),
                for_bundle_id: request_id,
            },
            BundleOpts::default(),
        )
        .unwrap();
        caller.on_bundle(2, wrong_kind);

        assert!(caller.store.contains(&request_id));
        assert!(caller.outstanding_requests.contains_key(&request_id));
        assert!(!caller.immune.contains_key(&request_id));
        assert!(caller.take_service_responses().is_empty());
        assert!(caller.take_http_responses().is_empty());

        // The genuine response still wins after both adversarial racers were rejected.
        let genuine = Bundle::create(
            &expected,
            Destination::Device(caller.address()),
            &caller.address(),
            &Payload::ServiceResponse {
                for_bundle_id: request_id,
                status: 0,
                body: b"genuine".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap();
        caller.on_bundle(3, genuine);

        let responses = caller.take_service_responses();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].body, b"genuine");
        assert!(!caller.store.contains(&request_id));
        assert!(!caller.outstanding_requests.contains_key(&request_id));
    }

    #[test]
    fn response_authorization_rehydrates_and_expires_with_the_request() {
        let caller_secret = Identity::generate().to_secret_bytes();
        let endpoint = Identity::generate();
        let mut caller = Node::from_identity_secret(&caller_secret);
        caller.set_time(10_000);
        let request_id = caller
            .send_hops_request(
                endpoint.address(),
                "example.com".into(),
                "GET".into(),
                "/".into(),
                vec![],
                vec![],
                1024,
            )
            .unwrap();
        let expiry = caller.outstanding_requests[&request_id].expires_at_ms;

        let store = caller.clone_store();
        let mut caller = Node::with_store(Identity::from_secret_bytes(&caller_secret), store);
        assert_eq!(
            caller.outstanding_requests[&request_id].responder,
            endpoint.address(),
            "the expected responder survives restart"
        );
        assert_eq!(
            caller.outstanding_requests[&request_id].expires_at_ms, expiry,
            "the original request expiry survives restart"
        );
        caller.tick(10_000);

        let genuine = Bundle::create(
            &endpoint,
            Destination::Device(caller.address()),
            &caller.address(),
            &Payload::HttpResponse {
                status: 200,
                headers: vec![],
                body: b"after restart".to_vec(),
                for_bundle_id: request_id,
            },
            BundleOpts::default(),
        )
        .unwrap();
        caller.on_bundle(1, genuine);
        let responses = caller.take_http_responses();
        assert_eq!(responses.len(), 1);
        assert!(caller.accept_http_response(&responses[0].id).unwrap());
        assert!(!caller.outstanding_requests.contains_key(&request_id));

        let expiring_id = caller
            .send_hops_request(
                endpoint.address(),
                "example.com".into(),
                "GET".into(),
                "/late".into(),
                vec![],
                vec![],
                1024,
            )
            .unwrap();
        let expiring_at = caller.outstanding_requests[&expiring_id].expires_at_ms;
        caller.tick(expiring_at);
        assert!(!caller.outstanding_requests.contains_key(&expiring_id));
        assert!(caller.store.get_kv("outstanding_requests").is_none());

        let late = Bundle::create(
            &endpoint,
            Destination::Device(caller.address()),
            &caller.address(),
            &Payload::HttpResponse {
                status: 200,
                headers: vec![],
                body: b"too late".to_vec(),
                for_bundle_id: expiring_id,
            },
            BundleOpts::default(),
        )
        .unwrap();
        caller.on_bundle(2, late);
        assert!(caller.take_http_responses().is_empty());
    }

    #[test]
    fn response_bearing_requests_require_a_nonzero_clock_anchor() {
        let endpoint = Identity::generate();
        let mut caller = Node::new(Identity::generate());

        assert!(caller
            .send_service_request(
                endpoint.address(),
                "app.echo".into(),
                "run".into(),
                Vec::new(),
            )
            .is_err());
        assert!(caller
            .send_hops_request(
                endpoint.address(),
                "example.com".into(),
                "GET".into(),
                "/".into(),
                Vec::new(),
                Vec::new(),
                1024,
            )
            .is_err());
        assert!(caller.outstanding_requests.is_empty());
        assert!(caller.store.have().ids.is_empty());
        assert!(caller.drain_outgoing().is_empty());

        caller.set_time(0);
        assert!(caller
            .send_service_request(
                endpoint.address(),
                "app.echo".into(),
                "run".into(),
                Vec::new(),
            )
            .is_err());
        caller.set_time(1);
        assert!(caller
            .send_service_request(
                endpoint.address(),
                "app.echo".into(),
                "run".into(),
                Vec::new(),
            )
            .is_ok());
    }

    #[test]
    fn request_authorization_and_exact_custody_commit_atomically_before_send() {
        let endpoint = Identity::generate();
        let mut caller = Node::with_store(Identity::generate(), FaultStore::default());
        caller.set_time(1);
        caller.store.fail_critical_put_prefix = Some("outstanding_requests".into());
        assert!(caller
            .send_service_request(
                endpoint.address(),
                "app.echo".into(),
                "run".into(),
                b"one".to_vec(),
            )
            .is_err());
        assert!(caller.outstanding_requests.is_empty());
        assert!(caller.store.have().ids.is_empty());
        assert!(caller.tx.is_empty());
        assert!(caller.drain_outgoing().is_empty());

        caller.store.fail_critical_put_prefix = None;
        caller.store.fail_bundle_puts = 1;
        assert!(caller
            .send_hops_request(
                endpoint.address(),
                "example.com".into(),
                "POST".into(),
                "/".into(),
                vec![],
                b"two".to_vec(),
                1024,
            )
            .is_err());
        assert!(caller.outstanding_requests.is_empty());
        assert!(caller.store.have().ids.is_empty());
        assert!(caller.tx.is_empty());
        assert!(caller.drain_outgoing().is_empty());
    }

    #[test]
    fn response_commit_failure_keeps_authorization_then_restart_redelivers_until_accept() {
        let caller_secret = Identity::generate().to_secret_bytes();
        let endpoint = Identity::generate();
        let mut caller = Node::with_store(
            Identity::from_secret_bytes(&caller_secret),
            FaultStore::default(),
        );
        caller.set_time(1);
        let request_id = caller
            .send_service_request(
                endpoint.address(),
                "app.echo".into(),
                "run".into(),
                Vec::new(),
            )
            .unwrap();
        let response = Bundle::create(
            &endpoint,
            Destination::Device(caller.address()),
            &caller.address(),
            &Payload::ServiceResponse {
                for_bundle_id: request_id,
                status: 0,
                body: b"durable".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap();

        caller.store.fail_critical_remove_prefix = Some("outstanding_requests".into());
        caller.on_bundle(1, response.clone());
        assert!(caller.outstanding_requests.contains_key(&request_id));
        assert!(caller.store.contains(&request_id));
        assert!(caller.take_service_responses().is_empty());
        assert!(!caller.store.seen(&response.id()));

        caller.store.fail_critical_remove_prefix = None;
        caller.on_bundle(1, response);
        let polled = caller.take_service_responses();
        assert_eq!(polled.len(), 1);
        assert_eq!(caller.take_service_responses()[0].id, polled[0].id);
        assert!(!caller.outstanding_requests.contains_key(&request_id));

        let mut restarted = Node::with_store(
            Identity::from_secret_bytes(&caller_secret),
            FaultStore {
                inner: caller.store.inner.clone(),
                ..Default::default()
            },
        );
        assert_eq!(restarted.take_service_responses()[0].id, polled[0].id);
        restarted.store.fail_critical_remove_prefix = Some("response/service/".into());
        assert!(restarted.accept_service_response(&polled[0].id).is_err());
        assert_eq!(restarted.take_service_responses().len(), 1);

        let mut redelivered = Node::with_store(
            Identity::from_secret_bytes(&caller_secret),
            FaultStore {
                inner: restarted.store.inner.clone(),
                ..Default::default()
            },
        );
        assert_eq!(redelivered.take_service_responses()[0].id, polled[0].id);
        assert!(redelivered.accept_service_response(&polled[0].id).unwrap());
        assert!(redelivered.take_service_responses().is_empty());
    }

    #[test]
    fn restored_request_rejects_responses_before_clock_anchor_and_expires_stale_rows() {
        let caller_secret = Identity::generate().to_secret_bytes();
        let endpoint = Identity::generate();
        let mut caller = Node::from_identity_secret(&caller_secret);
        caller.set_time(1_000);
        let request_id = caller
            .send_service_request(
                endpoint.address(),
                "app.echo".into(),
                "run".into(),
                Vec::new(),
            )
            .unwrap();
        let expiry = caller.outstanding_requests[&request_id].expires_at_ms;
        let response = Bundle::create(
            &endpoint,
            Destination::Device(caller.address()),
            &caller.address(),
            &Payload::ServiceResponse {
                for_bundle_id: request_id,
                status: 0,
                body: b"late".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap();
        let response_id = response.id();
        let store = caller.clone_store();
        let mut caller = Node::with_store(Identity::from_secret_bytes(&caller_secret), store);
        caller.set_time(expiry + 1);
        caller.on_bundle(1, response.clone());
        assert!(caller.take_service_responses().is_empty());
        assert!(!caller.store.seen(&response_id));
        assert!(caller.outstanding_requests.contains_key(&request_id));

        caller.tick(expiry + 1);
        assert!(!caller.outstanding_requests.contains_key(&request_id));
        caller.on_bundle(1, response);
        assert!(caller.take_service_responses().is_empty());
    }

    #[test]
    fn outstanding_requests_and_durable_responses_are_bounded_and_expire() {
        let endpoint = Identity::generate();
        let mut caller = Node::new(Identity::generate());
        caller.set_time(1);
        for index in 0..MAX_OUTSTANDING_REQUESTS {
            caller
                .send_service_request(
                    endpoint.address(),
                    "app.echo".into(),
                    "run".into(),
                    vec![index as u8],
                )
                .unwrap();
        }
        assert_eq!(caller.outstanding_requests.len(), MAX_OUTSTANDING_REQUESTS);
        assert!(caller
            .send_service_request(
                endpoint.address(),
                "app.echo".into(),
                "overflow".into(),
                Vec::new(),
            )
            .is_err());
        caller.tick(1 + BundleOpts::default().lifetime_ms as u64);
        assert!(caller.outstanding_requests.is_empty());
        assert!(caller.store.have().ids.is_empty());

        let request_id = caller
            .send_service_request(
                endpoint.address(),
                "app.echo".into(),
                "response".into(),
                Vec::new(),
            )
            .unwrap();
        let response = Bundle::create(
            &endpoint,
            Destination::Device(caller.address()),
            &caller.address(),
            &Payload::ServiceResponse {
                for_bundle_id: request_id,
                status: 0,
                body: Vec::new(),
            },
            BundleOpts {
                created_at: caller.now_ms,
                ..Default::default()
            },
        )
        .unwrap();
        caller.on_bundle(1, response);
        let response_id = caller.take_service_responses()[0].id;
        caller.tick(caller.now_ms.saturating_add(DURABLE_HOST_DELIVERY_TTL_MS));
        assert!(caller.take_service_responses().is_empty());
        assert!(caller
            .store
            .get_kv(&Node::<MemoryStore>::service_response_key(&response_id))
            .is_none());
    }

    #[test]
    fn hps_register_keyed_lets_a_preshared_group_talk_without_a_handshake() {
        // The general pre-shared-key primitive the endpoint cluster is built on: two nodes that
        // already agree on a content key can read + write a topic with no host and no join.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let ck = [3u8; 32];
        let path = "_grp/x";
        nodes[0].hps_register_keyed(path, ck);
        nodes[1].hps_register_keyed(path, ck);
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);

        nodes[0].hps_publish(path, b"hello group").unwrap();
        net.pump(&mut nodes);

        let msgs = take_hps_and_accept(&mut nodes[1]);
        assert_eq!(msgs.len(), 1, "the peer received the keyed publish");
        assert_eq!(msgs[0].path, path);
        assert_eq!(msgs[0].body, b"hello group");
        assert_eq!(msgs[0].sender, nodes[0].address(), "verified against src");
    }

    #[test]
    fn idle_sessions_are_gc_d_from_memory_and_store() {
        // D6: a forward-secret session unused past the horizon is dropped from memory AND the
        // persisted `session/` store, so meeting many peers once doesn't grow storage forever.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        exchange_prekeys(&mut net, &mut nodes);
        nodes[0]
            .send_message_traced(nodes[1].address(), "t".into(), b"hi".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        for b in nodes[1].take_inbox() {
            let _ = nodes[1].read_message(&b);
        }

        let a = nodes[0].address();
        assert!(nodes[1].has_session(&a), "B established a session with A");
        let key = format!("session/{}", bs58::encode(a).into_string());
        assert!(nodes[1].store.get_kv(&key).is_some(), "session persisted");

        // A zero-time session anchors on the first real tick, then a later idle-horizon tick prunes
        // it from memory and storage.
        nodes[1].tick(1);
        nodes[1].tick(SESSION_MAX_IDLE_MS + 2);
        assert!(!nodes[1].has_session(&a), "idle session GC'd from memory");
        assert!(
            nodes[1].store.get_kv(&key).is_none(),
            "idle session cleared from the store"
        );
    }

    #[test]
    fn lost_session_data_recovers_via_reset() {
        // One side loses its ratchet (uninstall / wiped p2p data: identity survives, store
        // doesn't) while the peer keeps theirs. The peer's next message can't be decrypted →
        // a SessionReset asks it to re-establish → a fresh handshake re-syncs the ratchet and
        // subsequent messages decrypt again (DESIGN.md §25).
        let id1_secret = Identity::generate().to_secret_bytes();
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::from_identity_secret(&id1_secret),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        nodes[0].publish_prekey().unwrap();
        nodes[1].publish_prekey().unwrap();
        net.pump(&mut nodes);
        nodes[0]
            .send_message_traced(nodes[1].address(), "t".into(), b"hi".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        for b in nodes[1].take_inbox() {
            let id = b.id();
            nodes[1].read_message(&b).unwrap();
            nodes[1].accept_inbox(&id).unwrap();
        }
        nodes[1]
            .send_message_traced(nodes[0].address(), "t".into(), b"yo".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        for b in nodes[0].take_inbox() {
            let id = b.id();
            nodes[0].read_message(&b).unwrap();
            nodes[0].accept_inbox(&id).unwrap();
        }
        assert!(
            nodes[0].has_session(&nodes[1].address()),
            "n0 has a session"
        );

        // n1 uninstalls: same identity, but a fresh store (no persisted session).
        nodes[1] = Node::from_identity_secret(&id1_secret);
        assert!(
            !nodes[1].has_session(&nodes[0].address()),
            "n1 lost its session"
        );
        nodes[0].handle(BearerEvent::Disconnected(1));
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 2, 1, 2);
        nodes[1].publish_prekey().unwrap(); // re-gossip n1's (deterministic) prekey
        net.pump(&mut nodes);

        // n0 still thinks it has a session → sends a SessionMessage n1 can't read.
        nodes[0]
            .send_message_traced(
                nodes[1].address(),
                "t".into(),
                b"during desync".to_vec(),
                true,
            )
            .unwrap();
        net.pump(&mut nodes);
        // Reading the undecryptable message makes n1 ask n0 to reset.
        for b in nodes[1].take_inbox() {
            let _ = nodes[1].read_message(&b);
        }
        net.pump(&mut nodes); // reset → n0 drops + re-establishes → ping reaches n1
        for b in nodes[1].take_inbox() {
            let _ = nodes[1].read_message(&b); // process the re-establishment ping (rebuilds)
        }

        // The ratchet is healed: a fresh message now decrypts.
        nodes[0]
            .send_message_traced(nodes[1].address(), "t".into(), b"healed".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        let mut got: Vec<Vec<u8>> = Vec::new();
        for b in nodes[1].take_inbox() {
            if let Ok(Some(m)) = nodes[1].read_message(&b) {
                got.push(m.body);
            }
        }
        assert!(
            got.contains(&b"healed".to_vec()),
            "ratchet recovered after the reset"
        );
    }

    #[test]
    fn deferred_content_flushes_when_peer_initiates_session() {
        // A message sent before we know the recipient's prekey is deferred ("Securing…"). If the
        // recipient then messages US first, that establishes a session — and the deferred message
        // must ratchet + send right then, WITHOUT waiting for a tick. (The stuck-"Securing" bug:
        // flush only ran on tick/prekey-advert, so a message queued just before the app
        // backgrounded never left even though a session later formed via the inbound path.)
        let alice = Identity::generate().to_secret_bytes();
        let mut nodes = [
            Node::from_identity_secret(&alice),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        // Alice publishes her prekey so Bob can initiate; Bob does NOT, so Alice must defer.
        nodes[0].publish_prekey().unwrap();
        net.pump(&mut nodes);

        // Alice messages Bob with no prekey for him → deferred; nothing reaches Bob yet.
        nodes[0]
            .send_message_traced(nodes[1].address(), "t".into(), b"deferred".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        assert!(
            nodes[1].take_inbox().is_empty(),
            "no prekey for Bob → message defers, not sent"
        );

        // Bob messages Alice first; his SessionInit establishes a session on Alice's side.
        nodes[1]
            .send_message_traced(nodes[0].address(), "t".into(), b"hi".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        for b in nodes[0].take_inbox() {
            let _ = nodes[0].read_message(&b); // establishing the session here must flush the deferral
        }
        net.pump(&mut nodes); // shuttle the now-flushed deferred message — NO tick() anywhere

        let mut bob_got: Vec<Vec<u8>> = Vec::new();
        for b in nodes[1].take_inbox() {
            if let Ok(Some(m)) = nodes[1].read_message(&b) {
                bob_got.push(m.body);
            }
        }
        assert!(
            bob_got.contains(&b"deferred".to_vec()),
            "deferred message flushed + arrived once the inbound session formed (no tick)"
        );
    }

    #[test]
    fn out_of_order_session_messages_decrypt_at_the_node_layer() {
        // Over a multi-copy DTN, two SessionMessages can be reassembled/processed out of
        // order. read_message must recover the earlier one from the ratchet's skipped-key
        // store — not just at the Session unit level, but through the node accessor (§25).
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        nodes[0].publish_prekey().unwrap();
        nodes[1].publish_prekey().unwrap();
        net.pump(&mut nodes);
        // Establish both directions.
        nodes[0]
            .send_message_traced(nodes[1].address(), "t".into(), b"hi".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        for b in nodes[1].take_inbox() {
            let id = b.id();
            nodes[1].read_message(&b).unwrap();
            nodes[1].accept_inbox(&id).unwrap();
        }
        nodes[1]
            .send_message_traced(nodes[0].address(), "t".into(), b"yo".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        for b in nodes[0].take_inbox() {
            let id = b.id();
            nodes[0].read_message(&b).unwrap();
            nodes[0].accept_inbox(&id).unwrap();
        }

        // Two messages from 0; deliver, then process them in reverse order.
        nodes[0]
            .send_message_traced(nodes[1].address(), "t".into(), b"first".to_vec(), true)
            .unwrap();
        nodes[0]
            .send_message_traced(nodes[1].address(), "t".into(), b"second".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        let mut inbox = nodes[1].take_inbox();
        assert_eq!(inbox.len(), 2, "both arrived");
        inbox.reverse(); // process out of order

        let mut bodies: Vec<Vec<u8>> = Vec::new();
        for b in &inbox {
            bodies.push(
                nodes[1]
                    .read_message(b)
                    .unwrap()
                    .expect("decrypts out of order")
                    .body,
            );
        }
        assert!(
            bodies.contains(&b"first".to_vec()),
            "earlier message recovered from skipped keys"
        );
        assert!(bodies.contains(&b"second".to_vec()));
    }

    #[test]
    fn partial_carrier_stream_resumes_after_restart() {
        // The image-in-background bug: a receiver gets some chunks, ACKs them (relay drops
        // its copies), then iOS suspends/relaunches the app — wiping in-memory reassembly.
        // Persisted chunks let it resume on the next wake instead of stalling forever (§20).
        let secret = Identity::generate().to_secret_bytes();
        let from = Identity::generate().address();
        let sid = [7u8; 16];
        let chunks: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 100]).collect();
        let full: Vec<u8> = chunks.iter().flatten().copied().collect();

        let mut r = Node::from_identity_secret(&secret);
        // First three chunks arrive in one wake (not the final one).
        for (i, c) in chunks.iter().take(3).enumerate() {
            assert!(matches!(
                r.accept_stream_chunk(from, sid, i as u64, c.clone(), false),
                StreamChunkAcceptance::Retained
            ));
        }

        // Beacon-mode kill + relaunch: rebuild from the persisted store. In-memory reassembly
        // is gone, but rehydrate re-feeds the persisted chunks.
        let store = r.clone_store();
        let mut r = Node::with_store(Identity::from_secret_bytes(&secret), store);
        assert_eq!(r.incoming_stream_bytes, 300);
        assert_eq!(r.incoming_sender_usage[&from].bytes, 300);
        assert_eq!(r.incoming_streams[&(from, sid)].started_at, 0);

        // A real epoch clock on the first post-restart tick anchors activity instead of
        // immediately treating the restored stream as decades idle.
        r.tick(1_700_000_000_000);
        assert!(r.incoming_streams.contains_key(&(from, sid)));
        assert_eq!(
            r.incoming_streams[&(from, sid)].started_at,
            1_700_000_000_000
        );

        // Remaining chunks arrive on a later wake; the final one completes the message.
        assert!(matches!(
            r.accept_stream_chunk(from, sid, 3, chunks[3].clone(), false),
            StreamChunkAcceptance::Retained
        ));
        let done = r.accept_stream_chunk(from, sid, 4, chunks[4].clone(), true);
        let StreamChunkAcceptance::Complete(done) = done else {
            panic!("resumed stream did not complete");
        };
        assert_eq!(done, full, "resumed and completed across restart");

        // Reconstruction alone retains custody. The downstream durable receive path finalizes it.
        assert!(!r.clone_store().list_kv("strm/").is_empty());
        assert!(r.finalize_incoming_stream(&from, &sid));
        assert!(
            r.clone_store().list_kv("strm/").is_empty(),
            "persisted chunks cleared"
        );
        assert_eq!(r.incoming_stream_bytes, 0);
        assert!(!r.incoming_sender_usage.contains_key(&from));
    }

    #[test]
    fn hostile_carrier_shape_and_sequence_abort_the_stream() {
        let mut node = Node::new(Identity::generate());
        node.carrier_limits = CarrierLimits {
            chunk_bytes: 4,
            stream_bytes: 16,
            stream_chunks: 4,
            sender_streams: 2,
            sender_bytes: 32,
            global_streams: 4,
            global_bytes: 64,
        };
        let from = Identity::generate().address();
        let sid = [1u8; 16];

        assert!(matches!(
            node.accept_stream_chunk(from, sid, 0, vec![1; 4], false),
            StreamChunkAcceptance::Retained
        ));
        assert!(matches!(
            node.accept_stream_chunk(from, sid, u64::MAX, vec![2], false),
            StreamChunkAcceptance::Rejected
        ));
        assert!(!node.incoming_streams.contains_key(&(from, sid)));
        assert_eq!(node.incoming_stream_bytes, 0);
        assert!(node.store.list_kv(&stream_prefix(&from, &sid)).is_empty());

        assert!(matches!(
            node.accept_stream_chunk(from, sid, 0, vec![1; 4], false),
            StreamChunkAcceptance::Retained
        ));
        assert!(matches!(
            node.accept_stream_chunk(from, sid, 1, vec![2; 5], false),
            StreamChunkAcceptance::Rejected
        ));
        assert!(!node.incoming_streams.contains_key(&(from, sid)));

        // A terminal chunk may arrive out of order, but no sequence may appear beyond it.
        assert!(matches!(
            node.accept_stream_chunk(from, sid, 2, vec![3], true),
            StreamChunkAcceptance::Retained
        ));
        assert!(matches!(
            node.accept_stream_chunk(from, sid, 3, vec![4], false),
            StreamChunkAcceptance::Rejected
        ));
        assert!(!node.incoming_streams.contains_key(&(from, sid)));
        assert!(!node.incoming_sender_usage.contains_key(&from));
    }

    #[test]
    fn carrier_stream_count_pressure_preserves_state_and_does_not_ack() {
        let mut node = Node::new(Identity::generate());
        node.carrier_limits = CarrierLimits {
            chunk_bytes: 4,
            stream_bytes: 16,
            stream_chunks: 4,
            sender_streams: 1,
            sender_bytes: 16,
            global_streams: 2,
            global_bytes: 32,
        };
        let sender = Identity::generate();
        let other = Identity::generate();
        let third = Identity::generate();
        let sid_a = [1u8; 16];
        let sid_b = [2u8; 16];
        let sid_c = [3u8; 16];
        let sid_d = [4u8; 16];

        assert!(matches!(
            node.accept_stream_chunk(sender.address(), sid_a, 0, vec![1; 4], false),
            StreamChunkAcceptance::Retained
        ));
        let pressured = carrier(&sender, &node, sid_b, 0, vec![2; 4], false);
        let pressured_id = pressured.id();
        node.on_bundle(9, pressured.clone());
        assert!(node
            .incoming_streams
            .contains_key(&(sender.address(), sid_a)));
        assert!(!node
            .incoming_streams
            .contains_key(&(sender.address(), sid_b)));
        assert!(!node.store.seen(&pressured_id));
        assert!(!node.last_ack.contains_key(&pressured_id));
        assert!(node
            .store
            .list_kv(&stream_prefix(&sender.address(), &sid_b))
            .is_empty());

        assert!(matches!(
            node.accept_stream_chunk(other.address(), sid_c, 0, vec![3; 4], false),
            StreamChunkAcceptance::Retained
        ));
        assert!(matches!(
            node.accept_stream_chunk(third.address(), sid_d, 0, vec![4; 4], false),
            StreamChunkAcceptance::Rejected
        ));
        assert_eq!(node.incoming_streams.len(), 2, "global stream cap holds");

        node.abort_incoming_stream(&sender.address(), &sid_a);
        node.on_bundle(9, pressured);
        assert!(node
            .incoming_streams
            .contains_key(&(sender.address(), sid_b)));
        assert!(node.store.seen(&pressured_id));
        assert!(node.last_ack.contains_key(&pressured_id));
    }

    #[test]
    fn carrier_byte_pressure_is_temporary_and_timeout_releases_all_accounting() {
        let mut node = Node::new(Identity::generate());
        node.carrier_limits = CarrierLimits {
            chunk_bytes: 4,
            stream_bytes: 12,
            stream_chunks: 4,
            sender_streams: 3,
            sender_bytes: 6,
            global_streams: 4,
            global_bytes: 8,
        };
        let first = Identity::generate().address();
        let second = Identity::generate().address();
        let third = Identity::generate().address();
        let sid_a = [5u8; 16];
        let sid_b = [6u8; 16];
        let sid_c = [7u8; 16];

        assert!(matches!(
            node.accept_stream_chunk(first, sid_a, 0, vec![1; 4], false),
            StreamChunkAcceptance::Retained
        ));
        assert!(matches!(
            node.accept_stream_chunk(first, sid_a, 1, vec![2; 4], false),
            StreamChunkAcceptance::Rejected
        ));
        assert_eq!(node.incoming_streams[&(first, sid_a)].bytes, 4);
        assert_eq!(node.incoming_sender_usage[&first].bytes, 4);
        assert!(node
            .store
            .get_kv(&stream_chunk_key(&first, &sid_a, 1))
            .is_none());

        assert!(matches!(
            node.accept_stream_chunk(second, sid_b, 0, vec![3; 4], false),
            StreamChunkAcceptance::Retained
        ));
        assert!(matches!(
            node.accept_stream_chunk(third, sid_c, 0, vec![4], false),
            StreamChunkAcceptance::Rejected
        ));
        assert_eq!(node.incoming_stream_bytes, 8);
        assert_eq!(node.incoming_streams.len(), 2);

        node.tick(1);
        node.tick(1 + CARRIER_STREAM_IDLE_MS);
        assert!(node.incoming_streams.is_empty());
        assert!(node.incoming_sender_usage.is_empty());
        assert_eq!(node.incoming_stream_bytes, 0);
        assert!(node.store.list_kv("strm/").is_empty());
        assert!(matches!(
            node.accept_stream_chunk(third, sid_c, 0, vec![4], false),
            StreamChunkAcceptance::Retained
        ));
    }

    #[test]
    fn invalid_reconstructed_bundle_retains_stream_state_without_ack() {
        let sender = Identity::generate();
        let mut node = Node::new(Identity::generate());
        let sid = [8u8; 16];
        let invalid = carrier(&sender, &node, sid, 0, vec![0xff; 8], true);
        let carrier_id = invalid.id();

        node.on_bundle(7, invalid);

        assert!(node.incoming_streams.contains_key(&(sender.address(), sid)));
        assert_eq!(node.incoming_sender_usage[&sender.address()].bytes, 8);
        assert_eq!(node.incoming_stream_bytes, 8);
        assert!(!node.store.list_kv("strm/").is_empty());
        assert!(!node.store.seen(&carrier_id));
        assert!(!node.last_ack.contains_key(&carrier_id));
        assert!(node.take_inbox().is_empty());
    }

    #[test]
    fn final_carrier_cleanup_failure_retains_spool_and_restart_finishes_after_durable_receive() {
        let recipient_secret = Identity::generate().to_secret_bytes();
        let sender = Identity::generate();
        let mut recipient = Node::with_store(
            Identity::from_secret_bytes(&recipient_secret),
            FaultStore::default(),
        );
        let original = Bundle::create(
            &sender,
            Destination::Device(recipient.address()),
            &recipient.address(),
            &Payload::PeerMessage {
                content_type: "application/test".into(),
                body: vec![7u8; 512],
            },
            BundleOpts {
                flags: BundleFlags {
                    request_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        let original_id = original.id();
        let bytes = original.to_bytes().unwrap();
        let split = bytes.len() / 2;
        let stream_id = [0x31; 16];
        let first = carrier(
            &sender,
            &recipient,
            stream_id,
            0,
            bytes[..split].to_vec(),
            false,
        );
        let final_chunk = carrier(
            &sender,
            &recipient,
            stream_id,
            1,
            bytes[split..].to_vec(),
            true,
        );
        let final_id = final_chunk.id();
        recipient.on_bundle(1, first);
        recipient.drain_outgoing();
        recipient.store.fail_critical_remove_prefix = Some("strm/".into());
        recipient.on_bundle(1, final_chunk);

        assert_eq!(recipient.inbox_items()[0].id, original_id);
        assert!(recipient
            .incoming_streams
            .contains_key(&(sender.address(), stream_id)));
        assert!(!recipient.store.list_kv("strm/").is_empty());
        assert!(!recipient.store.seen(&final_id));
        assert!(!recipient.last_ack.contains_key(&final_id));

        let restarted = Node::with_store(
            Identity::from_secret_bytes(&recipient_secret),
            FaultStore {
                inner: recipient.store.inner.clone(),
                ..Default::default()
            },
        );
        assert_eq!(restarted.inbox_items()[0].id, original_id);
        assert!(restarted.incoming_streams.is_empty());
        assert!(restarted.store.list_kv("strm/").is_empty());
    }

    #[test]
    fn final_carrier_waits_for_queue_capacity_then_retries_without_losing_spool() {
        let sender = Identity::generate();
        let mut recipient = Node::new(Identity::generate());
        let original = Bundle::create(
            &sender,
            Destination::Device(recipient.address()),
            &recipient.address(),
            &Payload::PeerMessage {
                content_type: "text/plain".into(),
                body: b"retry after pressure".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap();
        let stream_id = [0x32; 16];
        let final_chunk = carrier(
            &sender,
            &recipient,
            stream_id,
            0,
            original.to_bytes().unwrap(),
            true,
        );
        let final_id = final_chunk.id();
        recipient.set_app_queue_limits(AppQueueLimits {
            max_items_per_queue: 0,
            ..AppQueueLimits::default()
        });
        recipient.on_bundle(1, final_chunk.clone());
        assert!(recipient.inbox_items().is_empty());
        assert!(recipient
            .incoming_streams
            .contains_key(&(sender.address(), stream_id)));
        assert!(!recipient.store.seen(&final_id));
        assert!(!recipient.store.list_kv("strm/").is_empty());

        recipient.set_app_queue_limits(AppQueueLimits::default());
        recipient.on_bundle(1, final_chunk);
        assert_eq!(recipient.inbox_items().len(), 1);
        assert!(recipient.incoming_streams.is_empty());
        assert!(recipient.store.list_kv("strm/").is_empty());
        assert!(recipient.store.seen(&final_id));
        assert!(recipient.last_ack.contains_key(&final_id));
    }

    #[test]
    fn carrier_stream_size_boundary_matches_bundle_parser_limit() {
        assert_eq!(MAX_CARRIER_STREAM_BYTES, MAX_BUNDLE_WIRE_BYTES);
        let sender = Identity::generate().address();
        let mut node = Node::new(Identity::generate());
        let exact_stream = [0x33; 16];
        let mut remaining = MAX_BUNDLE_WIRE_BYTES;
        let mut sequence = 0u64;
        while remaining > 0 {
            let count = remaining.min(STREAM_CHUNK);
            remaining -= count;
            let accepted = node.accept_stream_chunk(
                sender,
                exact_stream,
                sequence,
                vec![1; count],
                remaining == 0,
            );
            if remaining == 0 {
                assert!(
                    matches!(accepted, StreamChunkAcceptance::Complete(bytes) if bytes.len() == MAX_BUNDLE_WIRE_BYTES)
                );
            } else {
                assert!(matches!(accepted, StreamChunkAcceptance::Retained));
            }
            sequence += 1;
        }
        assert!(node.finalize_incoming_stream(&sender, &exact_stream));

        let oversized_stream = [0x34; 16];
        let mut remaining = MAX_BUNDLE_WIRE_BYTES;
        let mut sequence = 0u64;
        while remaining > 0 {
            let count = remaining.min(STREAM_CHUNK);
            remaining -= count;
            assert!(matches!(
                node.accept_stream_chunk(
                    sender,
                    oversized_stream,
                    sequence,
                    vec![2; count],
                    false,
                ),
                StreamChunkAcceptance::Retained
            ));
            sequence += 1;
        }
        assert!(matches!(
            node.accept_stream_chunk(sender, oversized_stream, sequence, vec![3], true),
            StreamChunkAcceptance::Rejected
        ));
        assert!(!node
            .incoming_streams
            .contains_key(&(sender, oversized_stream)));
        assert!(node
            .store
            .list_kv(&stream_prefix(&sender, &oversized_stream))
            .is_empty());
    }

    #[test]
    fn rehydrate_removes_hostile_carrier_rows_outside_the_limits() {
        let from = Identity::generate().address();
        let sid_sequence = [9u8; 16];
        let sid_chunk = [10u8; 16];
        let mut store = MemoryStore::new();
        let persisted = |bytes: Vec<u8>| {
            postcard::to_allocvec(&PersistedCarrierChunk {
                bytes,
                fin: false,
                started_at: 1,
                received_at: 1,
            })
            .unwrap()
        };
        store.put_kv(
            &stream_chunk_key(&from, &sid_sequence, 0),
            persisted(vec![1, 2, 3]),
        );
        store.put_kv(
            &stream_chunk_key(&from, &sid_sequence, MAX_CARRIER_STREAM_CHUNKS as u64),
            persisted(vec![4]),
        );
        store.put_kv(
            &stream_chunk_key(&from, &sid_chunk, 0),
            persisted(vec![5; STREAM_CHUNK + 1]),
        );
        store.put_kv("strm/not/a/valid/key", vec![0, 1]);

        let node = Node::with_store(Identity::generate(), store);

        assert!(node.incoming_streams.is_empty());
        assert!(node.incoming_sender_usage.is_empty());
        assert_eq!(node.incoming_stream_bytes, 0);
        assert!(node.store.list_kv("strm/").is_empty());
    }

    #[test]
    fn rehydrate_bounds_a_large_persisted_carrier_flood_while_paging() {
        let mut store = MemoryStore::new();
        for index in 0..1_024u64 {
            let mut from = [0u8; 32];
            from[..8].copy_from_slice(&index.to_be_bytes());
            let mut stream_id = [0u8; 16];
            stream_id[..8].copy_from_slice(&index.to_be_bytes());
            let chunk = PersistedCarrierChunk {
                started_at: 1,
                received_at: 1,
                fin: false,
                bytes: vec![index as u8],
            };
            store.put_kv(
                &stream_chunk_key(&from, &stream_id, 0),
                postcard::to_allocvec(&chunk).unwrap(),
            );
        }

        let mut node = Node::with_store(Identity::generate(), store);

        assert!(!node.carrier_startup_ready());
        for _ in 0..32 {
            if node.carrier_startup_ready() {
                break;
            }
            node.tick(1);
        }

        assert!(node.carrier_startup_ready());
        assert_eq!(node.incoming_streams.len(), MAX_CARRIER_STREAMS_GLOBAL);
        assert_eq!(node.incoming_sender_usage.len(), MAX_CARRIER_STREAMS_GLOBAL);
        assert_eq!(node.incoming_stream_bytes, MAX_CARRIER_STREAMS_GLOBAL);
        assert_eq!(
            node.store.list_kv("strm/").len(),
            MAX_CARRIER_STREAMS_GLOBAL,
            "rows rejected by admission are removed instead of surviving restart"
        );
    }

    #[test]
    fn carrier_rehydrate_respects_firestore_budgets_and_resumes_after_cleanup_failure() {
        const ROWS: u64 = 450;
        assert!(ROWS as usize > 400);
        assert!(ROWS as usize > CARRIER_REHYDRATE_MAX_ROWS);

        let from = Identity::generate().address();
        let stream_id = [0x45; 16];
        let value = postcard::to_allocvec(&PersistedCarrierChunk {
            started_at: 1,
            received_at: 1,
            fin: false,
            bytes: vec![7],
        })
        .unwrap();
        let mut inner = MemoryStore::new();
        for seq in 0..ROWS {
            inner.put_kv(&stream_chunk_key(&from, &stream_id, seq), value.clone());
        }
        let store = FaultStore {
            inner,
            enforce_firestore_carrier_limits: true,
            fail_carrier_cleanup_at: Some(0),
            ..Default::default()
        };
        let mut node = Node::with_store(Identity::generate(), store);

        assert!(!node.carrier_startup_ready());
        assert_eq!(node.carrier_rehydrate_usage.rows, 32);
        assert_eq!(node.carrier_rehydrate_usage.pages, 2);
        assert_eq!(node.store.list_kv("strm/").len(), ROWS as usize);
        let retained_cursor = stream_chunk_key(&from, &stream_id, 31);
        assert_eq!(
            node.carrier_rehydrate
                .as_ref()
                .and_then(|state| state.cursor.as_deref()),
            Some(retained_cursor.as_str())
        );

        let blocked_stream = [0x46; 16];
        assert!(matches!(
            node.accept_stream_chunk(from, blocked_stream, 0, vec![1], false),
            StreamChunkAcceptance::Rejected
        ));
        assert!(node
            .store
            .get_kv(&stream_chunk_key(&from, &blocked_stream, 0))
            .is_none());

        node.tick(1);
        let calls = node.store.carrier_page_calls.borrow();
        let first_page_cursor = stream_chunk_key(&from, &stream_id, 15);
        assert_eq!(calls[0].0, None);
        assert_eq!(calls[1].0.as_deref(), Some(first_page_cursor.as_str()));
        assert_eq!(calls[2].0.as_deref(), Some(retained_cursor.as_str()));
        assert!(calls
            .iter()
            .all(|(_, rows, bytes)| *rows <= CARRIER_PERSISTED_PAGE_ROWS
                && *bytes <= CARRIER_REHYDRATE_MAX_BYTES));
        drop(calls);

        for now in 2..32 {
            if node.carrier_startup_ready() {
                break;
            }
            node.tick(now);
        }

        assert!(node.carrier_startup_ready());
        assert!(node.store.list_kv("strm/").is_empty());
        assert!(node.incoming_streams.is_empty());
        assert!(node.carrier_rehydrate_usage.rows >= ROWS as usize);
        assert!(node.carrier_rehydrate_usage.cleanup_operations >= ROWS as usize);
        assert!(node
            .store
            .carrier_cleanup_batches
            .iter()
            .all(
                |(mutations, bytes)| *mutations <= CARRIER_CLEANUP_BATCH_ROWS
                    && *bytes < 512 * 1024
            ));
        assert_eq!(
            node.store
                .carrier_page_calls
                .borrow()
                .iter()
                .filter(|(cursor, _, _)| cursor.is_none())
                .count(),
            1,
            "continuation never restarts the carrier scan at strm/"
        );
    }

    #[test]
    fn clear_persisted_stream_pages_over_firestore_limit_and_retries_from_progress() {
        const ROWS: u64 = 450;
        let from = Identity::generate().address();
        let stream_id = [0x47; 16];
        let mut node = Node::with_store(
            Identity::generate(),
            FaultStore {
                enforce_firestore_carrier_limits: true,
                ..Default::default()
            },
        );
        node.store.carrier_page_calls.borrow_mut().clear();
        for seq in 0..ROWS {
            node.store
                .inner
                .put_kv(&stream_chunk_key(&from, &stream_id, seq), vec![seq as u8]);
        }
        node.store.fail_carrier_cleanup_at = Some(1);

        assert!(node.clear_persisted_stream(&from, &stream_id).is_err());
        assert_eq!(
            node.store.list_kv(&stream_prefix(&from, &stream_id)).len(),
            ROWS as usize - CARRIER_PERSISTED_PAGE_ROWS,
            "the first successful page remains deleted when the next page fails"
        );
        node.clear_persisted_stream(&from, &stream_id).unwrap();

        assert!(node
            .store
            .list_kv(&stream_prefix(&from, &stream_id))
            .is_empty());
        assert!(node.store.carrier_cleanup_batches.len() > 400 / CARRIER_PERSISTED_PAGE_ROWS);
        assert!(node
            .store
            .carrier_cleanup_batches
            .iter()
            .all(
                |(mutations, bytes)| *mutations <= CARRIER_PERSISTED_PAGE_ROWS
                    && *bytes < 512 * 1024
            ));
    }

    #[test]
    fn carrier_stream_absolute_lifetime_survives_arrivals_and_restart() {
        let secret = Identity::generate().to_secret_bytes();
        let from = Identity::generate().address();
        let stream_id = [11u8; 16];
        let started_at = 1_000;
        let mut node = Node::from_identity_secret(&secret);
        node.set_time(started_at);
        assert!(matches!(
            node.accept_stream_chunk(from, stream_id, 0, vec![1], false),
            StreamChunkAcceptance::Retained
        ));

        node.set_time(started_at + CARRIER_STREAM_LIFETIME_MS - 1);
        assert!(matches!(
            node.accept_stream_chunk(from, stream_id, 1, vec![2], false),
            StreamChunkAcceptance::Retained
        ));
        assert_eq!(
            node.incoming_streams[&(from, stream_id)].started_at,
            started_at
        );

        let store = node.clone_store();
        let mut restarted = Node::with_store(Identity::from_secret_bytes(&secret), store);
        assert_eq!(
            restarted.incoming_streams[&(from, stream_id)].started_at,
            started_at
        );
        restarted.tick(started_at + CARRIER_STREAM_LIFETIME_MS);
        assert!(!restarted.incoming_streams.contains_key(&(from, stream_id)));
        assert!(restarted.store.list_kv("strm/").is_empty());
    }

    #[test]
    fn carrier_stream_first_clock_anchor_survives_restart() {
        let secret = Identity::generate().to_secret_bytes();
        let from = Identity::generate().address();
        let stream_id = [12u8; 16];
        let mut node = Node::from_identity_secret(&secret);
        assert!(matches!(
            node.accept_stream_chunk(from, stream_id, 0, vec![1], false),
            StreamChunkAcceptance::Retained
        ));
        assert_eq!(node.incoming_streams[&(from, stream_id)].started_at, 0);

        let anchored_at = 5_000;
        node.tick(anchored_at);
        let persisted = node
            .store
            .list_kv(&stream_prefix(&from, &stream_id))
            .into_iter()
            .next()
            .map(|(_, value)| postcard::from_bytes::<PersistedCarrierChunk>(&value).unwrap())
            .unwrap();
        assert_eq!(persisted.started_at, anchored_at);
        assert_eq!(persisted.received_at, anchored_at);

        let store = node.clone_store();
        let mut restarted = Node::with_store(Identity::from_secret_bytes(&secret), store);
        assert_eq!(
            restarted.incoming_streams[&(from, stream_id)].started_at,
            anchored_at
        );
        restarted.tick(anchored_at + CARRIER_STREAM_LIFETIME_MS);
        assert!(!restarted.incoming_streams.contains_key(&(from, stream_id)));
        assert!(restarted.store.list_kv("strm/").is_empty());
    }

    #[test]
    fn outbound_carrier_limit_rejects_before_submitting_a_prefix() {
        assert_eq!(MAX_CARRIER_STREAM_BYTES, MAX_BUNDLE_WIRE_BYTES);
        let mut node = Node::new(Identity::generate());
        node.carrier_limits = CarrierLimits {
            chunk_bytes: 32,
            stream_bytes: 64,
            stream_chunks: 2,
            sender_streams: 1,
            sender_bytes: 64,
            global_streams: 1,
            global_bytes: 64,
        };
        let recipient = Identity::generate();
        assert!(node
            .send_service_request(
                recipient.address(),
                "test".into(),
                "large".into(),
                vec![0; 256],
            )
            .is_err());
        assert!(node.store.have().ids.is_empty());
        assert!(node.pending.is_empty());
        assert!(node.carrier_owner.is_empty());
        assert!(node.outstanding_requests.is_empty());
        assert!(node.tx.is_empty());
        assert!(node.forwarded.is_empty());
    }

    #[test]
    fn session_survives_a_restart_via_persisted_store() {
        // The beacon-mode / reinstall bug: a backgrounded app is killed mid-conversation,
        // losing its in-memory ratchet while the peer keeps theirs → every later message
        // fails to decrypt. With the session persisted to the store, a restart rehydrates it
        // and decryption resumes (DESIGN.md §25).
        let id1_secret = Identity::generate().to_secret_bytes();
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::from_identity_secret(&id1_secret),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);

        nodes[0].publish_prekey().unwrap();
        nodes[1].publish_prekey().unwrap();
        net.pump(&mut nodes);
        nodes[0]
            .send_message_traced(nodes[1].address(), "t".into(), b"hi".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        for b in nodes[1].take_inbox() {
            let id = b.id();
            nodes[1].read_message(&b).unwrap();
            nodes[1].accept_inbox(&id).unwrap();
        }
        nodes[1]
            .send_message_traced(nodes[0].address(), "t".into(), b"yo".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        for b in nodes[0].take_inbox() {
            let id = b.id();
            nodes[0].read_message(&b).unwrap();
            nodes[0].accept_inbox(&id).unwrap();
        }
        assert!(
            nodes[1].has_session(&nodes[0].address()),
            "n1 has a session before restart"
        );

        // Beacon-mode kill + relaunch of n1: rebuild it from its persisted store.
        let store = nodes[1].clone_store();
        nodes[1] = Node::with_store(Identity::from_secret_bytes(&id1_secret), store);
        assert!(
            nodes[1].has_session(&nodes[0].address()),
            "session restored from the persisted store"
        );

        // The relaunch re-establishes the bearer on a fresh link; n0 drops the stale one.
        nodes[0].handle(BearerEvent::Disconnected(1));
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 2, 1, 2);
        nodes[0]
            .send_message_traced(
                nodes[1].address(),
                "image/jpeg".into(),
                b"after restart".to_vec(),
                true,
            )
            .unwrap();
        net.pump(&mut nodes);

        let inbox = nodes[1].take_inbox();
        assert_eq!(inbox.len(), 1, "message after restart delivered");
        let m = nodes[1]
            .read_message(&inbox[0])
            .unwrap()
            .expect("decrypts with the restored ratchet");
        assert_eq!(m.body, b"after restart");
    }

    #[test]
    fn restored_session_anchors_to_first_real_tick_before_idle_gc() {
        let real_now = 1_700_000_000_000u64;
        let bob_secret = Identity::generate().to_secret_bytes();
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::from_identity_secret(&bob_secret),
        ];
        nodes[0].set_time(real_now);
        nodes[1].set_time(real_now);
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        exchange_prekeys(&mut net, &mut nodes);
        let bob = nodes[1].address();
        let alice = nodes[0].address();
        nodes[0]
            .send_message_traced(bob, "t".into(), b"before restart".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        let first = nodes[1].take_inbox();
        nodes[1].read_message(&first[0]).unwrap();
        nodes[1].accept_inbox(&first[0].id()).unwrap();
        assert!(nodes[1].has_session(&alice));

        let store = nodes[1].clone_store();
        nodes[1] = Node::with_store(Identity::from_secret_bytes(&bob_secret), store);
        assert!(nodes[1].unanchored_sessions.contains(&alice));

        // The first post-restart tick uses a real epoch timestamp far beyond the idle horizon. It
        // must establish the baseline, not interpret the restored session as decades idle.
        nodes[1].tick(0);
        assert!(nodes[1].unanchored_sessions.contains(&alice));
        nodes[1].tick(real_now + 1_000);
        assert!(nodes[1].has_session(&alice));
        assert!(nodes[1].unanchored_sessions.is_empty());

        nodes[0].handle(BearerEvent::Disconnected(1));
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 2, 1, 2);
        nodes[0]
            .send_message_traced(bob, "t".into(), b"after first tick".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        let inbox = nodes[1].take_inbox();
        let message = inbox
            .iter()
            .find_map(|bundle| nodes[1].read_message(bundle).ok().flatten())
            .expect("restored ratchet decrypts after its first real tick");
        assert_eq!(message.body, b"after first tick");
    }

    #[test]
    fn restored_session_send_before_first_real_tick_keeps_durable_ratchet() {
        let (alice, mut bob, _, _) = established_fault_pair();
        let peer = bob.address();
        let alice_secret = alice.identity_secret();
        let mut restarted = Node::with_store(
            Identity::from_secret_bytes(&alice_secret),
            FaultStore {
                inner: alice.store.inner.clone(),
                ..Default::default()
            },
        );
        let session_key = Node::<FaultStore>::session_kv_key(&peer);
        assert!(restarted.unanchored_sessions.contains(&peer));

        let sent = restarted
            .send_message_traced(peer, "t".into(), b"before clock".to_vec(), false)
            .unwrap();
        let sent_bundle = restarted.store.get(&sent).unwrap();
        let message = bob
            .read_message(&sent_bundle)
            .unwrap()
            .expect("zero-time post-restart send decrypts");
        assert_eq!(message.body, b"before clock");
        assert!(restarted.unanchored_sessions.contains(&peer));
        assert!(!restarted.session_touch.contains_key(&peer));
        assert!(restarted.store.get_kv(&session_key).is_some());

        let epoch = 1_700_000_000_000;
        restarted.tick(epoch);
        assert!(restarted.has_session(&peer));
        assert_eq!(restarted.session_touch.get(&peer), Some(&epoch));
        assert!(!restarted.unanchored_sessions.contains(&peer));
        assert!(restarted.store.get_kv(&session_key).is_some());

        let reply = bob
            .send_message_traced(
                restarted.address(),
                "t".into(),
                b"after clock".to_vec(),
                false,
            )
            .unwrap();
        let reply_bundle = bob.store.get(&reply).unwrap();
        let reply_message = restarted
            .read_message(&reply_bundle)
            .unwrap()
            .expect("ratchet remains synchronized after the epoch tick");
        assert_eq!(reply_message.body, b"after clock");
        assert!(restarted.store.get_kv(&session_key).is_some());
    }

    #[test]
    fn restored_session_decrypt_before_first_real_tick_keeps_durable_ratchet() {
        let (alice, mut bob, _, _) = established_fault_pair();
        let peer = bob.address();
        let alice_secret = alice.identity_secret();
        let mut restarted = Node::with_store(
            Identity::from_secret_bytes(&alice_secret),
            FaultStore {
                inner: alice.store.inner.clone(),
                ..Default::default()
            },
        );
        let session_key = Node::<FaultStore>::session_kv_key(&peer);
        let inbound = bob
            .send_message_traced(
                restarted.address(),
                "t".into(),
                b"before clock".to_vec(),
                false,
            )
            .unwrap();
        let inbound_bundle = bob.store.get(&inbound).unwrap();

        restarted.ingest(inbound_bundle);
        assert!(restarted
            .inbox_items()
            .iter()
            .any(|item| item.body == b"before clock"));
        assert!(restarted.unanchored_sessions.contains(&peer));
        assert!(!restarted.session_touch.contains_key(&peer));
        assert!(restarted.store.get_kv(&session_key).is_some());

        let epoch = 1_700_000_000_000;
        restarted.tick(epoch);
        assert!(restarted.has_session(&peer));
        assert_eq!(restarted.session_touch.get(&peer), Some(&epoch));
        assert!(!restarted.unanchored_sessions.contains(&peer));
        assert!(restarted.store.get_kv(&session_key).is_some());

        let sent = restarted
            .send_message_traced(peer, "t".into(), b"after clock".to_vec(), false)
            .unwrap();
        let sent_bundle = restarted.store.get(&sent).unwrap();
        let message = bob
            .read_message(&sent_bundle)
            .unwrap()
            .expect("post-tick ratchet send decrypts");
        assert_eq!(message.body, b"after clock");
        assert!(restarted.store.get_kv(&session_key).is_some());
    }

    #[test]
    fn large_message_over_established_session_arrives() {
        // The on-device scenario: a large image sent over an established forward-secret
        // session (the 🔒). session_payload ratchet-encrypts the whole body into ONE
        // SessionMessage, which deliver() then carrier-chunks. Reassembly + ratchet-decrypt
        // must yield the exact bytes. (Earlier large-message tests had no session → static
        // seal, so they never exercised the ratchet + carrier interaction.)
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);

        // Both publish prekeys and gossip them so either side can open a session.
        nodes[0].publish_prekey().unwrap();
        nodes[1].publish_prekey().unwrap();
        net.pump(&mut nodes);

        // Establish the session both ways, reading each received bundle exactly as the app
        // does (take_inbox → read_message), so the ratchet actually advances on both sides.
        nodes[0]
            .send_message_traced(nodes[1].address(), "t".into(), b"hi".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        for b in nodes[1].take_inbox() {
            nodes[1].read_message(&b).unwrap();
        }
        nodes[1]
            .send_message_traced(nodes[0].address(), "t".into(), b"yo".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        for b in nodes[0].take_inbox() {
            nodes[0].read_message(&b).unwrap();
        }
        assert!(
            nodes[0].has_session(&nodes[1].address()),
            "session established"
        );

        // Now the large image over the established session.
        let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        nodes[0]
            .send_message_traced(nodes[1].address(), "image/jpeg".into(), body.clone(), true)
            .unwrap();
        net.pump(&mut nodes);

        let inbox = nodes[1].take_inbox();
        assert_eq!(inbox.len(), 1, "large image over a session reassembled");
        let m = nodes[1]
            .read_message(&inbox[0])
            .unwrap()
            .expect("a user message");
        assert_eq!(m.content_type, "image/jpeg");
        assert_eq!(m.body, body, "ratchet-decrypted bytes match exactly");
    }

    #[test]
    fn relay_keeps_request_ack_bundle_until_acked() {
        // A relay must keep custody of a request_ack bundle until the delivery ACK confirms
        // receipt — not release it on the optimistic handoff. Otherwise a chunk the
        // destination misses in a brief background window is lost and dedup blocks
        // re-injection, so a large transfer can never complete (DESIGN.md §6, §20).
        let mut relay = Node::new(Identity::generate());
        relay.set_kind(NodeKind::Relay);
        let alice = Identity::generate();
        let bob = Node::new(Identity::generate());

        let b = Bundle::create(
            &alice,
            Destination::Device(bob.address()),
            &bob.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"hi".to_vec(),
            },
            BundleOpts {
                flags: BundleFlags {
                    request_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        let id = b.id();
        relay.ingest(b);
        assert!(relay.store.contains(&id));

        // Hand-drive the link so we can deliver to bob but DROP his ACK.
        let mut relay = relay;
        let mut bob = bob;
        relay.handle(BearerEvent::Connected(1, Role::Initiator));
        bob.handle(BearerEvent::Connected(2, Role::Responder));
        let mut got = false;
        for _ in 0..12 {
            for (l, bytes) in relay.drain_outgoing() {
                if l == 1 {
                    bob.handle(BearerEvent::Data(2, bytes));
                }
            }
            if !bob.take_inbox().is_empty() {
                got = true;
                accept_all(&mut bob);
                break; // bob has the message; its pending outgoing is the ACK — withhold it
            }
            for (l, bytes) in bob.drain_outgoing() {
                if l == 2 {
                    relay.handle(BearerEvent::Data(1, bytes));
                }
            }
        }
        assert!(got, "bob received the message");
        assert!(
            relay.store.contains(&id),
            "relay keeps custody — ACK not yet seen"
        );

        // Deliver bob's withheld ACK; the vaccine now releases the relay's copy.
        for (l, bytes) in bob.drain_outgoing() {
            if l == 2 {
                relay.handle(BearerEvent::Data(1, bytes));
            }
        }
        assert!(!relay.store.contains(&id), "ACK vaccine releases custody");
    }

    #[test]
    fn large_message_arrives_through_a_relay() {
        // The real image scenario: sender and recipient never meet directly — a relay in
        // the middle carries the carrier-chunk bundles and the recipient reassembles (§20).
        let mut nodes = [
            Node::new(Identity::generate()), // 0 sender
            Node::new(Identity::generate()), // 1 relay
            Node::new(Identity::generate()), // 2 recipient
        ];
        nodes[1].set_kind(NodeKind::Relay);
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1); // sender <-> relay
        net.connect(&mut nodes, 1, 2, 2, 2); // relay  <-> recipient
        exchange_prekeys(&mut net, &mut nodes); // content is ratcheted — need prekeys (§25)

        let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect(); // ~300KB
        let dst = nodes[2].address();
        let orig = nodes[0]
            .send_message_traced(dst, "image/jpeg".into(), body.clone(), true)
            .unwrap();
        net.pump(&mut nodes);

        // The chunked message reports real relay progress + delivery under its original id
        // (carriers travel as separate bundles but attribute back — not a stuck "Sending").
        let (relayed, delivered, _, _) = nodes[0].message_status(&orig).expect("tracked");
        assert!(
            relayed >= 1,
            "shows Sent N (carriers relayed to the relay), not 0"
        );
        assert!(
            !delivered,
            "carrier progress never marks the original Delivered before host acceptance"
        );

        let inbox = nodes[2].take_inbox();
        assert_eq!(
            inbox.len(),
            1,
            "reassembled into exactly one message through the relay"
        );
        let m = nodes[2]
            .read_message(&inbox[0])
            .unwrap()
            .expect("a user message");
        assert_eq!(m.content_type, "image/jpeg");
        assert_eq!(m.body, body, "bytes reassembled exactly, in order");
        nodes[2].accept_inbox(&inbox[0].id()).unwrap();
        net.pump(&mut nodes);
        assert!(
            nodes[0].message_status(&orig).unwrap().1,
            "the reconstructed original ACK marks it Delivered after acceptance"
        );
        assert!(!nodes[0].outgoing_carriers.contains_key(&orig));
        assert!(nodes[0]
            .store
            .get_kv(&Node::<MemoryStore>::outgoing_carrier_key(&orig))
            .is_none());
    }

    #[test]
    fn final_carrier_ack_removes_metadata_when_original_needs_no_ack() {
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);

        let original = nodes[0]
            .send_service_response(nodes[1].address(), [0x44; 32], 200, vec![0x55; 300_000])
            .unwrap();
        assert!(nodes[0].outgoing_carriers.contains_key(&original));
        assert!(nodes[0]
            .store
            .get_kv(&Node::<MemoryStore>::outgoing_carrier_key(&original))
            .is_some());

        net.pump(&mut nodes);

        assert!(!nodes[0].outgoing_carriers.contains_key(&original));
        assert!(nodes[0]
            .store
            .get_kv(&Node::<MemoryStore>::outgoing_carrier_key(&original))
            .is_none());
    }

    #[test]
    fn carrier_metadata_expires_when_delivery_never_completes() {
        let mut node = Node::new(Identity::generate());
        node.set_time(100);
        let original = node
            .send_service_response(
                Identity::generate().address(),
                [0x66; 32],
                200,
                vec![0x77; 300_000],
            )
            .unwrap();
        assert!(node.outgoing_carriers.contains_key(&original));

        node.tick(100 + BundleOpts::default().lifetime_ms as u64);

        assert!(!node.outgoing_carriers.contains_key(&original));
        assert!(node
            .store
            .get_kv(&Node::<MemoryStore>::outgoing_carrier_key(&original))
            .is_none());
    }

    // --- §39 untraceable (private) messaging ----------------------------------

    #[test]
    fn private_message_floods_anonymously_and_only_the_recipient_recognizes_it() {
        // §39: Alice → Bob with nobody in between able to see who it's for. A relay (Carol)
        // carries it but can't tell it's Bob's; Bob recognizes it ("is this mine?") and reads
        // the true sender from inside the seal even though the envelope names no one.
        let mut nodes = [
            Node::new(Identity::generate()), // 0 Alice (sender)
            Node::new(Identity::generate()), // 1 Carol (relay, not the recipient)
            Node::new(Identity::generate()), // 2 Bob   (recipient)
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1); // Alice <-> Carol
        net.connect(&mut nodes, 1, 2, 2, 2); // Carol <-> Bob
        exchange_prekeys(&mut net, &mut nodes); // content is forward-secret — need prekeys (§25)

        let alice = nodes[0].address();
        let bob = nodes[2].address();
        nodes[0]
            .send_message(bob, "text/plain".into(), b"meet at dawn".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);

        // The relay never recognized it as anyone's — it just floods past.
        assert!(
            nodes[1].take_inbox().is_empty(),
            "the relay can't tell the message is Bob's"
        );

        // Bob recognized + holds exactly one; on the wire it named no src and flooded.
        let inbox = nodes[2].take_inbox();
        assert_eq!(
            inbox.len(),
            1,
            "only the intended recipient recognizes the private bundle"
        );
        assert!(inbox[0].is_private());
        assert!(
            inbox[0].trace().is_empty(),
            "private multi-hop trace stays empty"
        );
        assert_eq!(inbox[0].env.hops, 2, "hop count remains available");
        assert_eq!(
            inbox[0].inner.src, [0u8; 32],
            "no cleartext sender on the wire"
        );
        assert!(
            matches!(inbox[0].inner.dst, Destination::Broadcast),
            "floods — no cleartext dst"
        );

        // ...and Bob reads the *real* sender (from inside the seal) plus the content.
        let m = nodes[2]
            .read_message(&inbox[0])
            .unwrap()
            .expect("a user message");
        assert_eq!(
            m.from, alice,
            "sender recovered from the seal, not the (zeroed) envelope"
        );
        assert_eq!(m.content_type, "text/plain");
        assert_eq!(m.body, b"meet at dawn");
    }

    #[test]
    fn injected_private_trace_is_cleared_without_rejecting_or_resetting_hops() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let recipient_prekey = recipient.derive_prekey();
        let mut private = Bundle::create_private(
            &recipient.address(),
            &recipient_prekey.public,
            &Payload::Private {
                sender: sender.address(),
                inner: Box::new(Payload::SessionReset),
            },
            None,
            BundleOpts::default(),
        )
        .unwrap();
        private.env.hops = 5;
        private.env.trace.push(crate::bundle::TraceHop {
            node: [7u8; 8],
            app: [8u8; 8],
        });
        assert!(private.verify().is_ok(), "trace is mutable envelope data");
        assert!(
            private.trace().is_empty(),
            "private trace is never surfaced"
        );

        let id = private.id();
        let mut relay = Node::new(Identity::generate());
        relay.ingest(private);
        let held = relay
            .store
            .get(&id)
            .expect("valid private bundle is retained");
        assert!(
            held.env.trace.is_empty(),
            "ingest strips injected provenance"
        );
        assert_eq!(held.env.hops, 5, "ingest preserves the hop count");

        let mut forwarded = held;
        assert!(forwarded.forwarded());
        forwarded.env.trace.push(crate::bundle::TraceHop {
            node: [9u8; 8],
            app: [10u8; 8],
        });
        forwarded.add_hop([11u8; 8], [12u8; 8]);
        assert!(forwarded.env.trace.is_empty(), "forward strips trace again");
        assert_eq!(forwarded.env.hops, 6, "forward still increments hops");
    }

    #[test]
    fn spoofed_private_peer_message_is_not_attributed_to_the_claimed_sender() {
        // sec-priv-01/core-01: a Private seal is NOT identity-signed, so the in-seal `sender` is an
        // unauthenticated claim. An attacker who knows only the recipient's public address + their
        // published prekey (both flood in adverts) crafts Private{ sender: <victim>, inner: bare
        // PeerMessage } sealed to the recipient. The recipient must recognize it (well-formed) but
        // must NOT surface it as a message "from <victim>" — only ratcheted inners authenticate a sender.
        let victim = Identity::generate(); // whom the attacker wants to impersonate
        let bob_id = Identity::generate(); // the recipient
        let bob_prekey = bob_id.derive_prekey(); // public: an attacker harvests this from Bob's advert
        let bob_addr = bob_id.address();

        let spoof = Payload::Private {
            sender: victim.address(),
            inner: Box::new(Payload::PeerMessage {
                content_type: "text/plain".into(),
                body: b"transfer the funds; I never said this".to_vec(),
            }),
        };
        let bundle = Bundle::create_private(
            &bob_addr,
            &bob_prekey.public,
            &spoof,
            Some(crypto::mailbox_route(&crypto::mailbox_tag(
                &bob_addr,
                mailbox_epoch(0),
            ))),
            BundleOpts::default(),
        )
        .unwrap();

        let mut bob = Node::new(bob_id);
        assert!(
            bob.recognizes(&bundle),
            "the seal is well-formed and addressed to Bob — he recognizes it"
        );
        assert!(
            bob.read_message(&bundle).unwrap().is_none(),
            "a bare PeerMessage inside an unsigned Private seal must not be attributed to the claimed sender"
        );
    }

    #[test]
    fn private_conversation_round_trips_both_ways() {
        // A full private exchange: Alice → Bob, then Bob → Alice — both untraceable and both
        // forward-secret (the reply rides the session Bob established from Alice's first message).
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        exchange_prekeys(&mut net, &mut nodes);
        let alice = nodes[0].address();
        let bob = nodes[1].address();

        nodes[0]
            .send_message(bob, "t".into(), b"hi bob".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        let inb = nodes[1].take_inbox();
        let m = nodes[1].read_message(&inb[0]).unwrap().expect("msg");
        assert_eq!((m.from, m.body.as_slice()), (alice, b"hi bob".as_slice()));
        assert!(
            nodes[1].has_session(&alice),
            "Bob established a session from the private SessionInit"
        );

        nodes[1]
            .send_message(alice, "t".into(), b"hi alice".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        let inb = nodes[0].take_inbox();
        let m = nodes[0].read_message(&inb[0]).unwrap().expect("reply");
        assert_eq!((m.from, m.body.as_slice()), (bob, b"hi alice".as_slice()));
    }

    #[test]
    fn forged_private_session_init_preserves_session_and_does_not_reflect_reset() {
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        exchange_prekeys(&mut net, &mut nodes);
        let alice = nodes[0].address();
        let bob = nodes[1].address();

        nodes[0]
            .send_message(bob, "t".into(), b"establish".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        let first = nodes[1].take_inbox();
        nodes[1].read_message(&first[0]).unwrap();
        nodes[1]
            .send_message(alice, "t".into(), b"confirm".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        let confirm = nodes[0].take_inbox();
        nodes[0].read_message(&confirm[0]).unwrap();
        let before = postcard::to_allocvec(&nodes[1].sessions[&alice]).unwrap();
        let _ = nodes[1].drain_outgoing();

        // Anyone can seal a private envelope to Bob and claim Alice as its sender. The bogus X3DH
        // candidate must authenticate its first ratchet ciphertext before replacing Alice's session.
        let attacker = Identity::generate();
        let forged_inner = Payload::Private {
            sender: alice,
            inner: Box::new(Payload::SessionInit {
                ek_pub: attacker.derive_prekey().public,
                spk_pub: nodes[1].prekey.public,
                msg: crate::session::RatchetMessage {
                    header: crate::session::Header {
                        dh: attacker.derive_prekey().public,
                        pn: 0,
                        n: 0,
                    },
                    ciphertext: vec![0u8; 16],
                },
            }),
        };
        let forged = Bundle::create_private(
            &bob,
            &nodes[1].prekey.public,
            &forged_inner,
            Some(crypto::mailbox_route(&crypto::mailbox_tag(&bob, 0))),
            BundleOpts::default(),
        )
        .unwrap();
        assert!(nodes[1].read_message(&forged).is_err());
        assert_eq!(
            postcard::to_allocvec(&nodes[1].sessions[&alice]).unwrap(),
            before,
            "failed candidate decryption must leave the established session byte-for-byte intact"
        );
        assert!(
            !nodes[1].last_reset_req.contains_key(&alice),
            "an unauthenticated private sender claim must not receive a reflected SessionReset"
        );
        assert!(nodes[1].drain_outgoing().is_empty());

        nodes[0]
            .send_message(bob, "t".into(), b"still synced".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        let inbox = nodes[1].take_inbox();
        let message = nodes[1]
            .read_message(&inbox[0])
            .unwrap()
            .expect("the genuine established session still decrypts");
        assert_eq!(message.body, b"still synced");
    }

    #[test]
    fn private_send_defers_until_prekey_then_floods() {
        // require-ratchet (§25) holds for private sends too: with no prekey for Bob yet, the
        // message is queued ("Sending…"), never static-sealed — then flushes the moment Bob's
        // prekey advert arrives, and reaches him untraceably.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        nodes[0].publish_prekey().unwrap(); // Alice's prekey out; Bob's NOT yet
        net.pump(&mut nodes);

        let bob = nodes[1].address();
        nodes[0]
            .send_message(bob, "t".into(), b"later".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        assert!(
            nodes[1].take_inbox().is_empty(),
            "no prekey for Bob → deferred, not sent"
        );

        nodes[1].publish_prekey().unwrap(); // Bob's prekey arrives → Alice can ratchet + tag
        net.pump(&mut nodes);
        let inb = nodes[1].take_inbox();
        assert_eq!(
            inb.len(),
            1,
            "deferred private message flushed once the prekey was known"
        );
        let m = nodes[1].read_message(&inb[0]).unwrap().expect("msg");
        assert_eq!(m.body, b"later");
        assert_eq!(m.from, nodes[0].address());
    }

    #[test]
    fn private_message_delivery_is_confirmed_by_a_private_ack() {
        // request_ack on the default (private) path: the recipient recognizes the message and
        // seals an Ack back to the sender it learned from inside the seal. The ack floods, the
        // sender recognizes it, and the message flips to Delivered — all without either end
        // ever appearing in cleartext on the wire.
        let mut nodes = [
            Node::new(Identity::generate()), // 0 Alice
            Node::new(Identity::generate()), // 1 Carol (relay)
            Node::new(Identity::generate()), // 2 Bob
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        net.connect(&mut nodes, 1, 2, 2, 2);
        exchange_prekeys(&mut net, &mut nodes);

        let bob = nodes[2].address();
        let id = nodes[0]
            .send_message(bob, "t".into(), b"ack me".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);

        assert_eq!(
            nodes[2].take_inbox().len(),
            1,
            "Bob received the private message"
        );
        accept_all(&mut nodes[2]);
        net.pump(&mut nodes);
        let (_, delivered, _, _) = nodes[0].message_status(&id).expect("tracked");
        assert!(
            delivered,
            "the private ACK flipped Alice's message to Delivered"
        );
        // The relay is an endpoint for neither leg — both were anonymous broadcasts.
        assert!(
            nodes[1].take_inbox().is_empty(),
            "the relay is not an endpoint for either leg"
        );
    }

    #[test]
    fn ack_reports_forward_path_latency_not_round_trip() {
        // "Delivered" should tell the sender how long A→B took (the forward leg the recipient
        // observed), not the A→B→A round trip. The recipient stamps `received − created_at`
        // into the ACK; the sender surfaces it via message_status's 4th field.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        exchange_prekeys(&mut net, &mut nodes);

        // Sender sends at a bucket-aligned t=60_000 (ADV18-08 coarsens the private created_at to a
        // 60s bucket, so aligning keeps this measuring the real forward leg rather than a bucket
        // rounding artifact); recipient's clock is 1500ms ahead → it observes a 1500ms forward leg.
        // (set_time sets the clock directly; pump shuttles bytes without ticking.)
        nodes[0].set_time(60_000);
        nodes[1].set_time(61_500);
        let bob = nodes[1].address();
        let id = nodes[0]
            .send_message(bob, "t".into(), b"time me".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        accept_all(&mut nodes[1]);
        net.pump(&mut nodes);

        let (_, delivered, _, fwd_ms) = nodes[0].message_status(&id).expect("tracked");
        assert!(delivered);
        assert_eq!(
            fwd_ms, 1_500,
            "ACK carries the A→B forward latency the recipient saw"
        );
    }

    #[test]
    fn private_bundle_created_at_is_coarsened_on_the_wire() {
        // ADV18-08: the cleartext, id-bound created_at on a private bundle must be bucketed, not the
        // exact send millisecond, so it is not a per-message sender timing fingerprint.
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let mut node = Node::new(sender);
        inject_prekey(&mut node, &recipient);
        // A send time deliberately OFF a bucket boundary; the wire stamp must round down to the bucket.
        node.set_time(60_000 + 37_123);
        let mid = node
            .send_message(recipient.address(), "t".into(), b"hi".to_vec(), true)
            .unwrap();
        let stored = node
            .store
            .get(&mid)
            .expect("sender holds its private bundle");
        assert!(stored.is_private(), "it is a §39 private bundle");
        assert_eq!(
            stored.inner.created_at, 60_000,
            "created_at is coarsened to the private time bucket, not the exact send ms"
        );
    }

    // --- §39 P4 gradient routing -----------------------------------------------

    /// 4-node A—R—B with a decoy D also hanging off R (the relay/bridge has 3 links). Models the
    /// live bug: a remote sender A reaches a recipient B only through a relay R, with other clients
    /// (D) also on R.
    fn gradient_topology() -> ([Node; 4], Wire2) {
        let mut nodes = [
            Node::new(Identity::generate()), // 0 A (sender)
            Node::new(Identity::generate()), // 1 R (relay / bridge)
            Node::new(Identity::generate()), // 2 B (recipient, no direct link to A)
            Node::new(Identity::generate()), // 3 D (decoy also on R)
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1); // A <-> R   (R link 1)
        net.connect(&mut nodes, 1, 2, 2, 2); // R <-> B   (R link 2)
        net.connect(&mut nodes, 1, 3, 3, 3); // R <-> D   (R link 3)
        exchange_prekeys(&mut net, &mut nodes); // A learns B's prekey (to seal + tag the bundle)
        (nodes, net)
    }

    #[test]
    fn private_bundle_routes_down_the_gradient_not_flooded_to_decoys() {
        // The fix for the relay-bridged regression: B advertises a receiver-beacon → R lays a
        // gradient toward B; A's private message then routes DOWN it (R→B only), reaching B
        // WITHOUT being flooded to the decoy D — directed delivery, not blind flood.
        let (mut nodes, mut net) = gradient_topology();

        nodes[2].publish_recv_beacon().unwrap(); // B in "route-to-me" mode
        net.pump(&mut nodes);

        // R laid a gradient toward B's mailbox, pointing at the R-B link (R's link 2).
        // sec-priv-04: the gradient keys on the tag's routing PREFIX, so inspect via route_key.
        let bmail = route_key(&crypto::mailbox_tag(&nodes[2].address(), 0));
        let g = nodes[1]
            .recv_gradient
            .get(&bmail)
            .expect("R holds a gradient toward B");
        assert_eq!(
            g.links.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
            vec![2],
            "gradient's sole next-hop is the R-B link, not R-A/R-D"
        );

        let bob = nodes[2].address();
        let id = nodes[0]
            .send_message(bob, "t".into(), b"routed".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);

        assert_eq!(
            nodes[2].take_inbox().len(),
            1,
            "B received it via the gradient (through R)"
        );
        assert!(
            !nodes[3].store.contains(&id),
            "decoy D never got a copy — directed, not flooded"
        );
    }

    #[test]
    fn mailbox_tag_rotates_per_epoch_and_beacon_covers_the_recent_window() {
        // F-06: the pull pseudonym rotates each epoch (a global observer can't correlate across epochs).
        let bob = Identity::generate();
        assert_ne!(
            crypto::mailbox_tag(&bob.address(), 5),
            crypto::mailbox_tag(&bob.address(), 6),
            "a recipient's mailbox-tag must differ across epochs"
        );

        // With every node advanced into epoch 1, B's beacon lays a gradient for BOTH the current
        // (epoch 1) and previous (epoch 0) mailbox tags — so a bundle addressed just before the
        // rotation boundary (sender a bit behind) still routes instead of being stranded.
        let (mut nodes, mut net) = gradient_topology(); // A, R, B, D ; prekeys already exchanged
        for n in nodes.iter_mut() {
            n.tick(MAILBOX_EPOCH_MS); // all clocks in epoch 1
        }
        let baddr = nodes[2].address();
        nodes[2].publish_recv_beacon().unwrap();
        net.pump(&mut nodes);

        // sec-priv-04: gradient keys on the tag's routing prefix (route_key).
        assert!(
            nodes[1]
                .recv_gradient
                .contains_key(&route_key(&crypto::mailbox_tag(&baddr, 1))),
            "relay holds a gradient for B's current-epoch mailbox"
        );
        assert!(
            nodes[1]
                .recv_gradient
                .contains_key(&route_key(&crypto::mailbox_tag(&baddr, 0))),
            "relay ALSO holds a gradient for B's previous-epoch mailbox (the window)"
        );
    }

    #[test]
    fn beacon_cannot_hijack_another_nodes_mailbox() {
        // F-05: a beacon signed by a NON-owner must not lay a gradient for a victim's mailbox.
        // The mailbox tag is H(SPK) and the SPK is public, so Mallory can name B's mailbox — but
        // the gradient only installs if the mailbox matches the *publisher's own* prekey.
        let (mut nodes, mut net) = gradient_topology();
        let bmail = crypto::mailbox_tag(&nodes[2].address(), 0); // B's mailbox
        let now = nodes[1].now_ms;

        // Mallory is a participant R knows (R has her legit prekey), but she is not B.
        let mallory = Identity::generate();
        let mspk = mallory.derive_prekey();
        let pk = Advert::publish(
            &mallory,
            AdvertKind::PreKey {
                spk_pub: mspk.public,
                spk_sig: mspk.sig.to_vec(),
            },
            now,
            10_000_000,
            1,
        )
        .unwrap();
        nodes[1].on_advert(3, mallory.address(), pk);

        // Mallory forges a receiver-beacon claiming B's mailbox, signed with her own identity.
        let forged = Advert::publish(
            &mallory,
            AdvertKind::RecvBeacon { mailbox: bmail },
            now,
            10_000_000,
            2,
        )
        .unwrap();
        nodes[1].on_advert(3, mallory.address(), forged);
        assert!(
            !nodes[1].recv_gradient.contains_key(&route_key(&bmail)),
            "a beacon signed by a non-owner must NOT lay a gradient for the victim's mailbox"
        );

        // Control: B's own beacon still lays the gradient (the fix doesn't break legit beacons).
        nodes[2].publish_recv_beacon().unwrap();
        net.pump(&mut nodes);
        assert!(
            nodes[1].recv_gradient.contains_key(&route_key(&bmail)),
            "B's own beacon (mailbox matches B's prekey) still lays the gradient"
        );
    }

    #[test]
    fn private_bundle_floods_as_fallback_without_a_gradient() {
        // No beacon ⇒ no gradient ⇒ R falls back to the epidemic flood, so the decoy D DOES
        // receive (+ stores) a copy it can't open. This is the contrast that proves the gradient
        // is what makes routing directed — and that delivery still works on the cold-start floor.
        let (mut nodes, mut net) = gradient_topology();

        let bmail = route_key(&crypto::mailbox_tag(&nodes[2].address(), 0));
        assert!(
            !nodes[1].recv_gradient.contains_key(&bmail),
            "no beacon → no gradient at R"
        );

        let bob = nodes[2].address();
        let id = nodes[0]
            .send_message(bob, "t".into(), b"flooded".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);

        assert_eq!(
            nodes[2].take_inbox().len(),
            1,
            "B still gets it on the flood fallback"
        );
        assert!(
            nodes[3].store.contains(&id),
            "decoy D got a copy — flooded (no gradient to steer it)"
        );
    }

    #[test]
    fn reply_ack_returns_via_intermittent_carrier() {
        // Intermittent-carrier topology (a stuck case the browser sim surfaced): `you` is BLE-only and meets a carrier only in passes; the
        // carrier and `friend` sit on a relay. m1 you→friend acks fine. friend's REPLY m2 reaches
        // `you` on a later pass — and m2's ACK must ride back on subsequent passes. Without the
        // fix this ack never comes home (friend stays "Sending…" forever).
        let mut nodes = [
            Node::new(Identity::generate()), // 0 you (intermittent)
            Node::new(Identity::generate()), // 1 carrier
            Node::new(Identity::generate()), // 2 relay
            Node::new(Identity::generate()), // 3 friend
        ];
        for n in nodes.iter_mut() {
            n.publish_prekey().unwrap();
        } // (prekey publish, as a client does on node add)
        let mut net = Wire2::new();
        net.connect(&mut nodes, 1, 51, 2, 52); // carrier <-> relay (always up)
        net.connect(&mut nodes, 2, 53, 3, 54); // relay <-> friend (always up)

        // pass 1: `you` meets the carrier; prekeys gossip everywhere (re-gossip needs TIME to fire).
        net.connect(&mut nodes, 0, 11, 1, 12);
        let mut now = 0u64;
        let settle = |nodes: &mut [Node], net: &mut Wire2, now: &mut u64, secs: u64| {
            for _ in 0..secs.div_ceil(5) {
                *now += 5_000;
                for n in nodes.iter_mut() {
                    n.tick(*now);
                }
                net.pump(nodes);
            }
        };
        settle(&mut nodes, &mut net, &mut now, 60);
        let friend = nodes[3].address();
        let you = nodes[0].address();
        assert!(nodes[0].knows_prekey(&friend), "prekeys gossiped to you");
        assert!(nodes[3].knows_prekey(&you), "prekeys gossiped to friend");

        // m1 you→friend delivers + acks while the pass is live.
        let _m1 = nodes[0]
            .send_message(friend, "t".into(), b"m1".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        assert_eq!(nodes[3].take_inbox().len(), 1, "m1 delivered");
        accept_all(&mut nodes[3]);
        net.pump(&mut nodes);

        // the pass ends: you drops off. friend replies while you is away.
        nodes[0].handle(BearerEvent::Disconnected(11));
        nodes[1].handle(BearerEvent::Disconnected(12));
        net.routes.remove(&(0, 11));
        net.routes.remove(&(1, 12));
        let m2 = nodes[3]
            .send_message(you, "t".into(), b"m2".to_vec(), true)
            .unwrap();
        settle(&mut nodes, &mut net, &mut now, 120); // m2 spreads to relay + carrier, parks there

        // pass 2: the carrier meets you again — m2 must deliver, and you's ACK must start back.
        net.connect(&mut nodes, 0, 13, 1, 14);
        settle(&mut nodes, &mut net, &mut now, 60);
        assert_eq!(
            nodes[0].take_inbox().len(),
            1,
            "m2 delivered to you on the second pass"
        );
        accept_all(&mut nodes[0]);
        settle(&mut nodes, &mut net, &mut now, 120);

        // the ACK rides the still-connected carrier→relay→friend chain: friend must see Delivered.
        let done = nodes[3]
            .sends_status()
            .iter()
            .any(|(id, _, delivered)| id == &m2 && *delivered);
        assert!(
            done,
            "friend's reply must flip to Delivered once the ACK rides back"
        );
    }

    #[test]
    fn a_verified_vaccine_is_delivery_proof_for_the_sender() {
        // The sender's private ACK can be lost, and once the vaccine immunizes the mesh a
        // retransmit can never trigger a re-ACK — so the SENDER must accept a verified vaccine
        // as proof of delivery (same CDH token, same forgery bar as the relay-purge check).
        let (mut nodes, mut net) = gradient_topology();
        let bob = nodes[2].address();
        let id = nodes[0]
            .send_message(bob, "t".into(), b"vaxproof".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        assert_eq!(nodes[2].take_inbox().len(), 1, "delivered");

        // Simulate the ACK being lost: sender still shows undelivered.
        let before = nodes[0]
            .sends_status()
            .iter()
            .any(|(i, _, d)| i == &id && *d);
        // (If the ack already made it through the pump, the point still holds — craft the vaccine
        // path explicitly against a FRESH sender copy below.)
        let eph = nodes[1]
            .store
            .get(&id)
            .map(|b| b.inner.private.unwrap().ephemeral);
        if let (false, Some(eph)) = (before, eph) {
            let token = crypto::recognition_shared(&nodes[2].prekey.secret_bytes(), &eph);
            let vax = Bundle::create_vaccine(
                token,
                BundleOpts {
                    created_at: 0,
                    ..Default::default()
                },
            );
            nodes[0].on_bundle(9, vax);
        }
        // Whether via the pumped ack or the crafted vaccine: the sender must show Delivered.
        let done = nodes[0]
            .sends_status()
            .iter()
            .any(|(i, _, d)| i == &id && *d);
        assert!(
            done,
            "a verified vaccine flips the sender's send to Delivered"
        );

        // A forged vaccine must NOT flip an undelivered send.
        let id2 = nodes[0]
            .send_message(bob, "t".into(), b"fresh".to_vec(), true)
            .unwrap();
        let forged = Bundle::create_vaccine(
            [0xEE; 32],
            BundleOpts {
                created_at: 0,
                ..Default::default()
            },
        );
        nodes[0].on_bundle(9, forged);
        let bad = nodes[0]
            .sends_status()
            .iter()
            .any(|(i, _, d)| i == &id2 && *d);
        assert!(!bad, "a forged vaccine must not mark a send delivered");
    }

    #[test]
    fn delivery_vaccine_purges_relay_copy_but_a_forged_token_cannot() {
        // §39 vaccine: on delivery the recipient reveals its recognition DH; a relay holding the
        // bundle verifies token→tag and drops its copy. A forged token (anyone who saw the flood
        // knows the id) must NOT purge it — only a real delivery can. No src/dst is ever revealed.
        let (mut nodes, mut net) = gradient_topology();

        // No-ack send ⇒ B delivers but emits NO vaccine, so R keeps its relayed copy for us to test.
        let bob = nodes[2].address();
        let id = nodes[0]
            .send_message(bob, "t".into(), b"vax".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        assert_eq!(nodes[2].take_inbox().len(), 1, "B received it");
        assert!(
            nodes[1].store.contains(&id),
            "relay R holds a copy after the flood"
        );

        // The real recognition token = B's prekey secret DH'd against the bundle's ephemeral.
        let eph = nodes[1]
            .store
            .get(&id)
            .unwrap()
            .inner
            .private
            .unwrap()
            .ephemeral;
        let real = crypto::recognition_shared(&nodes[2].prekey.secret_bytes(), &eph);

        // A forged vaccine (wrong token) is rejected — R keeps its copy.
        let forged = Bundle::create_vaccine(
            [0xAB; 32],
            BundleOpts {
                created_at: 0,
                ..Default::default()
            },
        );
        nodes[1].on_bundle(9, forged);
        assert!(
            nodes[1].store.contains(&id),
            "a forged token must NOT purge the relay's copy"
        );

        // The real vaccine drops it and marks it immune (a late copy would be dropped too).
        let vax = Bundle::create_vaccine(
            real,
            BundleOpts {
                created_at: 0,
                ..Default::default()
            },
        );
        nodes[1].on_bundle(9, vax);
        assert!(
            !nodes[1].store.contains(&id),
            "the real vaccine purges the relay's copy"
        );
        assert!(
            nodes[1].immune.contains_key(&id),
            "and marks it immune against re-flood"
        );
    }

    #[test]
    fn vaccine_arriving_before_its_target_purges_it_on_first_store() {
        // core-protocol-r3-02: a delivery vaccine can race AHEAD of the target bundle it clears,
        // reaching a relay before that relay ever sees the bundle. Before the fix, the vaccine's
        // resolve scan found nothing (bundle not held), and the later-arriving target was stored +
        // re-flooded, lingering until its clamped TTL. The fix remembers the raced-ahead token and
        // purges the target on FIRST STORE. This proves it: deliver the vaccine, THEN the bundle, to
        // a fresh relay that has never seen either. Revert-proof: without `remember_vaccine_token` +
        // `already_vaccinated_by_token`, the relay stores + floods the bundle here.
        let (mut nodes, mut net) = gradient_topology();

        // Produce a real relayable private bundle to B (ack=false ⇒ B emits no vaccine, so R keeps a
        // verbatim copy we can lift the bytes + ephemeral from).
        let bob = nodes[2].address();
        let id = nodes[0]
            .send_message(bob, "t".into(), b"racer".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        let held = nodes[1].store.get(&id).expect("R relayed a copy");
        let eph = held.inner.private.as_ref().unwrap().ephemeral;
        let bytes = held.to_bytes().unwrap();
        // The real recognition token only B can compute.
        let token = crypto::recognition_shared(&nodes[2].prekey.secret_bytes(), &eph);

        // A FRESH relay that has seen NEITHER the bundle nor the vaccine.
        let mut fresh = Node::new(Identity::generate());
        let vax = Bundle::create_vaccine(
            token,
            BundleOpts {
                created_at: 0,
                ..Default::default()
            },
        );
        // 1) Vaccine arrives FIRST, resolves nothing (target not held), token remembered.
        fresh.on_bundle(7, vax);
        assert!(
            !fresh.store.contains(&id),
            "fresh relay holds nothing yet (only the token is remembered)"
        );

        // 2) The target bundle arrives SECOND.
        let target = Bundle::from_bytes(&bytes).unwrap();
        fresh.on_bundle(8, target);

        // It must be purged on first store, not stored + re-flooded.
        assert!(
            !fresh.store.contains(&id),
            "the raced-ahead vaccine purges the target on first store"
        );
        assert!(
            fresh.immune.contains_key(&id),
            "and marks it immune so a re-flood is refused too"
        );
    }

    #[test]
    fn forged_vaccine_token_does_not_purge_a_later_arriving_bundle() {
        // core-protocol-r3-02 adversarial self-check: the remembered-token path must NOT let a forged
        // token black-hole a legitimate bundle. A random token (an attacker who saw the flood knows
        // the id but not B's CDH) is remembered, but when the real target arrives it must be stored +
        // relayed normally, because the forged token clears no real bundle.
        let (mut nodes, mut net) = gradient_topology();
        let bob = nodes[2].address();
        let id = nodes[0]
            .send_message(bob, "t".into(), b"legit".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        let bytes = nodes[1].store.get(&id).unwrap().to_bytes().unwrap();

        let mut fresh = Node::new(Identity::generate());
        let forged = Bundle::create_vaccine(
            [0x5A; 32],
            BundleOpts {
                created_at: 0,
                ..Default::default()
            },
        );
        fresh.on_bundle(7, forged); // remembered, but clears nothing real
        let target = Bundle::from_bytes(&bytes).unwrap();
        fresh.on_bundle(8, target);

        assert!(
            fresh.store.contains(&id),
            "a forged raced-ahead token must NOT black-hole the real bundle; it is stored + relayed"
        );
        assert!(
            !fresh.immune.contains_key(&id),
            "and it is not falsely marked delivered"
        );
    }

    #[test]
    fn seen_vaccine_tokens_are_pruned_and_capped() {
        // core-protocol-r3-02 DoS self-check: the remembered-token set is bounded (cap) and TTL'd, so
        // a distinct-token vaccine flood can neither grow it without bound nor pin it forever.
        let mut n = Node::new(Identity::generate());
        n.tick(1);
        for i in 0..(MAX_SEEN_VACCINE_TOKENS + 500) {
            let mut tok = [0u8; 32];
            tok[..8].copy_from_slice(&(i as u64).to_le_bytes());
            n.remember_vaccine_token(tok);
        }
        assert!(
            n.seen_vaccine_tokens.len() <= MAX_SEEN_VACCINE_TOKENS,
            "cap bounds the remembered-token set under a distinct-token flood"
        );
        // Past the 1h horizon everything is forgotten (falls back to pre-fix TTL reclamation).
        n.tick(3_600_001);
        assert!(
            n.seen_vaccine_tokens.is_empty(),
            "remembered tokens expire on the immune horizon"
        );
    }

    #[test]
    fn gradient_expires_and_falls_back_to_flood_no_black_hole() {
        // Soft state: once B stops beaconing, its gradient entry expires (no permanent black-hole).
        // A subsequent private send then falls back to flood rather than dead-ending on a stale path.
        let (mut nodes, mut net) = gradient_topology();
        nodes[2].publish_recv_beacon().unwrap();
        net.pump(&mut nodes);
        let bmail = route_key(&crypto::mailbox_tag(&nodes[2].address(), 0));
        assert!(nodes[1].recv_gradient.contains_key(&bmail), "gradient laid");

        // Advance every node past the beacon TTL with no refresh; tick prunes the dead entry.
        let t = (RECV_BEACON_TTL_MS as u64) + 1;
        for n in nodes.iter_mut() {
            n.tick(t);
        }
        assert!(
            !nodes[1].recv_gradient.contains_key(&bmail),
            "stale gradient pruned at R"
        );

        // Delivery still works (via flood), and the decoy now sees it again (no gradient to steer).
        let bob = nodes[2].address();
        let id = nodes[0]
            .send_message(bob, "t".into(), b"after expiry".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        assert_eq!(
            nodes[2].take_inbox().len(),
            1,
            "B still reachable after the gradient expired"
        );
        assert!(
            nodes[3].store.contains(&id),
            "fell back to flood (decoy got a copy)"
        );
    }

    #[test]
    fn spool_then_want_beacon_reloads() {
        // §39 P5: a private bundle reaching a relay with NO live gradient toward its recipient is
        // SPOOLABLE (durably held by mailbox-tag) and NOT on the device-handoff path. When the
        // recipient later beacons, the relay lays a gradient AND surfaces the mailbox as "wanted"
        // (the want-beacon → the host reloads the durable spool), and the bundle is no longer
        // spoolable — P4 now owns it (spool XOR live-route, no double-send).
        let bob = Identity::generate();
        let bob_mailbox = crypto::mailbox_tag(&bob.address(), 0);
        // sec-priv-04 / core-protocol-r2-02: the spool/gradient/want keys are the tag's routing PREFIX,
        // and the private-bundle header now carries ONLY that prefix (never the full tag).
        let bob_route = route_key(&bob_mailbox);
        let bob_prefix = crypto::mailbox_route(&bob_mailbox);

        // A private bundle sealed to bob + stamped with bob's mailbox ROUTING PREFIX (as dispatch_private).
        let pb = Bundle::create_private(
            &bob.address(),
            &bob.derive_prekey().public,
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"offline".to_vec(),
            },
            Some(bob_prefix),
            BundleOpts::default(),
        )
        .unwrap();
        let pid = pb.id();

        let mut relay = Node::new(Identity::generate());
        relay.ingest(pb);

        // No recipient, no beacon → spoolable by mailbox-tag; and NOT on the device handoff path.
        let s = relay.spoolable_private_bundles();
        assert_eq!(
            s.len(),
            1,
            "private bundle with no live gradient is spoolable"
        );
        assert_eq!(
            (s[0].0, s[0].1),
            (pid, bob_route),
            "keyed by bob's mailbox-tag routing prefix (sec-priv-04)"
        );
        assert!(
            relay.undeliverable_device_bundles().is_empty(),
            "a Broadcast private bundle never rides the device handoff"
        );

        // Bob comes online behind the relay and beacons (the want-beacon). He publishes his
        // prekey too (as every real node does on startup), so the relay can bind his mailbox to
        // its owner before laying a gradient (F-05 — a beacon whose owner is unknown is dropped).
        let mut nodes = [relay, Node::from_identity_secret(&bob.to_secret_bytes())];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1); // relay <-> bob
        nodes[1].publish_prekey().unwrap();
        net.pump(&mut nodes); // relay learns bob's prekey
        nodes[1].publish_recv_beacon().unwrap();
        net.pump(&mut nodes);

        // The relay laid a gradient toward bob AND surfaced his mailbox as a want-beacon (pull trigger).
        assert!(
            nodes[0].recv_gradient.contains_key(&bob_route),
            "gradient laid from the beacon"
        );
        assert!(
            nodes[0].take_wanted_mailboxes().contains(&bob_route),
            "beacon surfaced the wanted mailbox"
        );
        assert!(
            nodes[0].take_wanted_mailboxes().is_empty(),
            "wanted drains once"
        );
        // core-protocol-r2-01: the bundle STAYS spoolable even with a live gradient. The gradient keys
        // on a 2-byte prefix, so a live next-hop may be a prefix-COLLIDING different recipient — the old
        // "spool XOR route" rule black-holed the true (passive) recipient in that case. We now keep the
        // durable spool as a safety net; a redundant delivery to the genuine recipient is deduped by id.
        assert!(
            !nodes[0].spoolable_private_bundles().is_empty(),
            "still spooled even with a live gradient (no black-hole under prefix collision)"
        );
    }

    #[test]
    fn a_private_ack_is_spoolable_just_like_forward_content() {
        // core-protocol-r3-01: an ACK is itself a private bundle carrying a mailbox toward the ORIGINAL
        // sender (§39 P4 return path), so it is durably spooled exactly like forward content. This is
        // intentional and is also the only safe choice: the relay never opens the seal, so an ACK and
        // a message are byte-indistinguishable to it. This test pins BOTH halves: (a) a forward message
        // still spools (no black-hole regression), and (b) an ACK spools too (return-path resilience).
        let sender = Identity::generate();
        let sender_prefix = crypto::mailbox_route(&crypto::mailbox_tag(&sender.address(), 0));

        // (a) A forward message to the sender's mailbox: must be spoolable.
        let fwd = Bundle::create_private(
            &sender.address(),
            &sender.derive_prekey().public,
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"forward".to_vec(),
            },
            Some(sender_prefix),
            BundleOpts::default(),
        )
        .unwrap();

        // (b) An ACK shaped exactly as `emit_private_ack` builds it: a Private-wrapped Ack, addressed
        // to the sender's mailbox (the return path).
        let ack_inner = Payload::Private {
            sender: Identity::generate().address(),
            inner: Box::new(Payload::Ack {
                for_bundle_id: fwd.id(),
                status: 0,
                delivery_hops: 1,
                delivery_ms: 10,
                proof: Some([0x11; 32]),
            }),
        };
        let ack = Bundle::create_private(
            &sender.address(),
            &sender.derive_prekey().public,
            &ack_inner,
            Some(sender_prefix),
            BundleOpts::default(),
        )
        .unwrap();

        let mut relay = Node::new(Identity::generate());
        relay.ingest(fwd.clone());
        assert!(
            relay
                .spoolable_private_bundles()
                .iter()
                .any(|(bid, ..)| *bid == fwd.id()),
            "a forward message with a mailbox is spoolable (no black-hole)"
        );

        relay.ingest(ack.clone());
        assert!(
            relay
                .spoolable_private_bundles()
                .iter()
                .any(|(bid, ..)| *bid == ack.id()),
            "an ACK is spoolable too; the return path survives the same dormant round-trip"
        );
    }

    /// Find two distinct identities whose current mailbox-tags collide on the routing prefix — the
    /// anonymity set an address-knower cannot resolve. A birthday search over a 2-byte prefix finds a
    /// pair quickly; bounded so the test can never hang.
    fn colliding_recipients(epoch: u64) -> (Identity, Identity) {
        use std::collections::HashMap;
        let mut seen: HashMap<Tag, [u8; 32]> = HashMap::new();
        for _ in 0..1_000_000 {
            let id = Identity::generate();
            let secret = id.to_secret_bytes();
            let route = route_key(&crypto::mailbox_tag(&id.address(), epoch));
            if let Some(prev_secret) = seen.get(&route) {
                let prev = Identity::from_secret_bytes(prev_secret);
                if prev.address() != id.address() {
                    return (prev, id);
                }
            }
            seen.insert(route, secret);
        }
        panic!("no prefix collision found — prefix width unexpectedly large");
    }

    #[test]
    fn colliding_recipients_share_one_route_bucket_but_each_gets_only_its_own_message() {
        // sec-priv-04: two recipients whose mailbox-tags collide on the routing prefix are
        // INDISTINGUISHABLE at the routing layer (one gradient/spool bucket = an anonymity set), yet
        // delivery stays correct — each opens ONLY its own message, because the final "is this mine?"
        // test is the per-message recognition tag, which is unique and unlinkable. This proves both the
        // unlinkability property AND that delivery still works.
        let (b1, b2) = colliding_recipients(0);
        let t1 = crypto::mailbox_tag(&b1.address(), 0);
        let t2 = crypto::mailbox_tag(&b2.address(), 0);
        assert_ne!(t1, t2, "distinct pseudonyms (full tags differ)");
        assert_eq!(
            route_key(&t1),
            route_key(&t2),
            "but they collide on the routing prefix — the anonymity set"
        );

        // Stand up A—R with both recipients hanging off R, so a private send must route through R.
        let mut nodes = [
            Node::new(Identity::generate()),                   // 0 A (sender)
            Node::new(Identity::generate()),                   // 1 R (relay)
            Node::from_identity_secret(&b1.to_secret_bytes()), // 2 B1
            Node::from_identity_secret(&b2.to_secret_bytes()), // 3 B2
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1); // A <-> R
        net.connect(&mut nodes, 1, 2, 2, 2); // R <-> B1
        net.connect(&mut nodes, 1, 3, 3, 3); // R <-> B2
        exchange_prekeys(&mut net, &mut nodes);

        // Both recipients go "route-to-me". Because their tags share a prefix, R holds exactly ONE
        // gradient bucket for the pair — an observer of R's gradient sees the prefix, not which of the
        // two (or any other colliding address) is behind it.
        nodes[2].publish_recv_beacon().unwrap();
        nodes[3].publish_recv_beacon().unwrap();
        net.pump(&mut nodes);
        let bucket = route_key(&t1);
        assert!(
            nodes[1].recv_gradient.contains_key(&bucket),
            "R holds the shared route bucket"
        );
        // sec-priv-04 unlinkability: the two distinct recipients occupy exactly ONE gradient KEY (the
        // shared prefix). An address-knower reading R's gradient sees a single opaque prefix bucket, not
        // which of the (≥2) colliding addresses is behind it — that is the anonymity set.
        assert_eq!(
            nodes[1].recv_gradient.len(),
            1,
            "both colliding recipients collapse to ONE indistinguishable route bucket"
        );
        // Yet the ONE bucket fans out to BOTH next-hops, so neither colliding recipient is starved.
        assert_eq!(
            nodes[1].recv_gradient[&bucket].links.len(),
            2,
            "the shared bucket keeps a next-hop for each colliding recipient"
        );

        // A sends a distinct private message to EACH. Both stamp the same route bucket, so both ride
        // the same gradient — yet each recipient recognizes and opens only the one sealed to it.
        nodes[0]
            .send_message(b1.address(), "t".into(), b"for-b1".to_vec(), true)
            .unwrap();
        nodes[0]
            .send_message(b2.address(), "t".into(), b"for-b2".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);

        let read_bodies = |n: &mut Node| -> Vec<Vec<u8>> {
            n.take_inbox()
                .iter()
                .filter_map(|b| n.read_message(b).ok().flatten().map(|m| m.body))
                .collect()
        };
        let b1_msgs = read_bodies(&mut nodes[2]);
        let b2_msgs = read_bodies(&mut nodes[3]);
        assert_eq!(
            b1_msgs,
            vec![b"for-b1".to_vec()],
            "B1 opened only its own message"
        );
        assert_eq!(
            b2_msgs,
            vec![b"for-b2".to_vec()],
            "B2 opened only its own message"
        );
    }

    #[test]
    fn a_re_beaconing_recipient_is_not_evicted_from_its_bucket_by_parked_sybils() {
        // security-privacy-r2-04: a Sybil can grind identities colliding on a victim's 2-byte prefix and
        // beacon them from distinct links to fill the per-bucket fan-out. The OLD eviction (nearest-to-
        // expiry) let a fleet of fresher-expiry Sybil beacons crowd out the victim's own link. The fix
        // evicts the LEAST-RECENTLY-SEEN link instead: a recipient that re-beacons on its short interval
        // stays recently-seen and survives, while parked Sybils (stale last_seen) are evicted first.
        let mut relay = Node::new(Identity::generate());
        let bucket = route_key(&crypto::mailbox_tag(&Identity::generate().address(), 0));
        let victim_link: LinkId = 999;
        let ttl = 60_000u32;

        // The victim beacons FIRST (t=0), claiming its slot.
        relay.set_time(0);
        relay.record_gradient(bucket, victim_link, 1, 0, ttl, 1);

        // A Sybil fleet parks the remaining 7 slots at t=1000 with FAR-FUTURE expiry (a longer TTL) —
        // under nearest-to-expiry eviction these fresher-expiry links would outrank the victim's.
        relay.set_time(1_000);
        for i in 0..(MAX_GRADIENT_LINKS_PER_BUCKET - 1) {
            relay.record_gradient(bucket, 1_000 + i as LinkId, 3, 1_000, ttl * 10, 1);
        }
        assert_eq!(
            relay.recv_gradient[&bucket].links.len(),
            MAX_GRADIENT_LINKS_PER_BUCKET,
            "bucket is now full (victim + parked Sybils)"
        );

        // The victim RE-BEACONS on its short interval (t=2000): it is now the MOST-recently-seen link.
        relay.set_time(2_000);
        relay.record_gradient(bucket, victim_link, 1, 2_000, ttl, 2);

        // One MORE Sybil arrives on a fresh link (t=3000), overflowing the bucket → an eviction fires.
        relay.set_time(3_000);
        relay.record_gradient(bucket, 2_000 as LinkId, 3, 3_000, ttl * 10, 1);

        // The victim's link MUST survive — the evicted one is a stale-seen parked Sybil, not the victim.
        assert!(
            relay.recv_gradient[&bucket]
                .links
                .iter()
                .any(|(l, _)| *l == victim_link),
            "a re-beaconing recipient's link is retained; a parked Sybil is evicted instead"
        );
        assert_eq!(
            relay.recv_gradient[&bucket].links.len(),
            MAX_GRADIENT_LINKS_PER_BUCKET,
            "bucket stays at the fan-out cap"
        );
    }

    #[test]
    fn private_bundle_header_carries_only_the_route_prefix_not_the_full_mailbox_tag() {
        // core-protocol-r2-02: the FULL 16-byte mailbox tag = H(address ‖ epoch) is a public
        // deterministic function of a broadly-known address. If it rode verbatim in the cleartext
        // header, a bundle-capturing address-knower could recompute the target's tag and UNIQUELY
        // re-link the recipient off the header — defeating the sec-priv-04 anonymity-set claim. Assert
        // the header (and the whole serialized wire) carries only the 2-byte routing PREFIX, so the full
        // deterministic tag never appears on the wire.
        let bob = Identity::generate();
        let full_tag = crypto::mailbox_tag(&bob.address(), mailbox_epoch(0));
        let prefix = crypto::mailbox_route(&full_tag);

        let sender = Identity::generate();
        let mut node = Node::new(sender);
        inject_prekey(&mut node, &bob);
        let mid = node
            .send_message(bob.address(), "t".into(), b"secret".to_vec(), true)
            .unwrap();
        let pb = node
            .store
            .get(&mid)
            .expect("sender holds its private bundle");

        // The header field is exactly the prefix — and, being only 2 bytes, cannot be the full tag.
        let hdr_mailbox = pb.inner.private.as_ref().unwrap().mailbox;
        assert_eq!(
            hdr_mailbox,
            Some(prefix),
            "header carries the routing prefix"
        );

        // The full deterministic tag must NOT appear anywhere in the serialized bundle. (The
        // per-message recognition `tag` DOES ride in the header, but it is ephemeral+unlinkable — only
        // the address-derived mailbox tag is the linkability leak we are closing.)
        let wire = pb.to_bytes().unwrap();
        assert!(
            !wire.windows(crypto::TAG_LEN).any(|w| w == full_tag),
            "the full address-derived mailbox tag must not appear on the wire (only its 2-byte prefix)"
        );

        // Routing still works: the prefix in the header keys the same gradient bucket a beacon lays.
        assert_eq!(
            route_key_from_prefix(&prefix),
            route_key(&full_tag),
            "the header prefix maps to the same routing bucket as the beacon's full tag"
        );
    }

    #[test]
    fn a_passive_colliding_recipient_is_not_black_holed_by_an_active_one() {
        // core-protocol-r2-01 (REGRESSION): B2 is a PASSIVE (max-privacy) recipient that never beacons.
        // B1 collides with B2 on the 2-byte route prefix and IS beaconing. Before the fix, a relay
        // steered B2's private bundle ONLY down B1's (colliding) link — where B1 fails the per-message
        // recognition tag and drops it — AND the spool gate refused to spool it because a "live gradient"
        // existed for the (shared) route. Result: B2's message reached B2 via NEITHER the live route NOR
        // the durable spool: a silent black-hole. The fix ALWAYS spools a private bundle carrying a
        // mailbox, so B2 still collects it via its want-beacon pull when it later checks in.
        let (b1, b2) = colliding_recipients(0);
        assert_eq!(
            route_key(&crypto::mailbox_tag(&b1.address(), 0)),
            route_key(&crypto::mailbox_tag(&b2.address(), 0)),
            "B1 and B2 collide on the routing prefix"
        );
        let b2_route = route_key(&crypto::mailbox_tag(&b2.address(), 0));

        // A — R with the ACTIVE colliding recipient B1 behind R. B2 is offline/passive (not connected).
        let mut nodes = [
            Node::new(Identity::generate()),                   // 0 A (sender)
            Node::new(Identity::generate()),                   // 1 R (relay)
            Node::from_identity_secret(&b1.to_secret_bytes()), // 2 B1 (active, colliding decoy)
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1); // A <-> R
        net.connect(&mut nodes, 1, 2, 2, 2); // R <-> B1
                                             // A needs B2's prekey for the recognition tag + ratchet. Publish B1's prekey the normal way;
                                             // inject B2's prekey into A's directory directly (B2 is offline but published it earlier, §25).
        nodes[0].publish_prekey().unwrap();
        nodes[1].publish_prekey().unwrap();
        nodes[2].publish_prekey().unwrap();
        net.pump(&mut nodes);
        inject_prekey(&mut nodes[0], &b2);

        // Only the ACTIVE colliding recipient B1 beacons. R lays a gradient for the shared prefix bucket
        // with exactly B1's link — B2, being passive, is NOT in it.
        nodes[2].publish_recv_beacon().unwrap();
        net.pump(&mut nodes);
        assert!(
            nodes[1].recv_gradient.contains_key(&b2_route),
            "R holds the shared prefix bucket (B1 beacons into it)"
        );

        // A sends a private message to the PASSIVE recipient B2.
        nodes[0]
            .send_message(b2.address(), "t".into(), b"for-passive-b2".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);

        // B1 (the active decoy) must NOT open B2's message — the recognition tag is unique per recipient.
        let b1_bodies: Vec<Vec<u8>> = nodes[2]
            .take_inbox()
            .iter()
            .filter_map(|b| nodes[2].read_message(b).ok().flatten().map(|m| m.body))
            .collect();
        assert!(
            b1_bodies.is_empty(),
            "the colliding active decoy B1 never opens B2's message"
        );

        // THE FIX: R still spools B2's bundle even though a live gradient (B1's) exists for the route —
        // otherwise B2 would be black-holed. Before the fix this list was empty.
        let spool = nodes[1].spoolable_private_bundles();
        assert!(
            spool.iter().any(|(_, route, _, _)| *route == b2_route),
            "R spools the passive recipient's bundle despite the colliding live gradient (no black-hole)"
        );

        // Prove the spool actually delivers: B2 comes online behind R and beacons; R reloads the spool
        // and re-ingests, and P4 steers the reloaded copy to B2, who opens ONLY its own message.
        let spooled: Vec<Bundle> = spool
            .iter()
            .map(|(_, _, bytes, _)| Bundle::from_bytes(bytes).unwrap())
            .collect();
        let mut nodes2 = [
            std::mem::replace(&mut nodes[1], Node::new(Identity::generate())), // R (carries spool state)
            Node::from_identity_secret(&b2.to_secret_bytes()),                 // B2 comes online
        ];
        let mut net2 = Wire2::new();
        net2.connect(&mut nodes2, 0, 5, 1, 5); // R(node 0, link 5) <-> B2(node 1, link 5)
        nodes2[1].publish_prekey().unwrap();
        net2.pump(&mut nodes2);
        nodes2[1].publish_recv_beacon().unwrap();
        net2.pump(&mut nodes2);
        // Host reloads the durable spool for the wanted mailbox and re-ingests it (§39 P5).
        assert!(
            nodes2[0].take_wanted_mailboxes().contains(&b2_route),
            "B2's beacon surfaces its wanted mailbox so the host pulls the spool"
        );
        for b in spooled {
            nodes2[0].ingest(b);
        }
        net2.pump(&mut nodes2);
        let b2_bodies: Vec<Vec<u8>> = nodes2[1]
            .take_inbox()
            .iter()
            .filter_map(|b| nodes2[1].read_message(b).ok().flatten().map(|m| m.body))
            .collect();
        assert_eq!(
            b2_bodies,
            vec![b"for-passive-b2".to_vec()],
            "the passive recipient B2 collects its own message via the spool pull"
        );
    }

    #[test]
    fn a_plain_p2p_carrier_recovers_a_passive_colliding_recipient_off_relay() {
        // security-privacy-r3-02: the collision black-hole recovery (spool + want-beacon reload) is
        // TRANSPORT-AGNOSTIC: it lives on plain `Node`, not `hop-relayd`. This proves a pure-P2P
        // carrier (a bare Node, no relay service) running the same reload loop delivers a passive
        // colliding recipient B2. It isolates the r3-02 point: recovery needs a carrier RUNNING the
        // loop, and any Node CAN run it. C is that non-relay carrier.
        let (b1, b2) = colliding_recipients(0);
        let b2_route = route_key(&crypto::mailbox_tag(&b2.address(), 0));

        // A --- C(plain P2P carrier) --- B1(active colliding decoy). B2 offline/passive.
        let mut nodes = [
            Node::new(Identity::generate()),                   // 0 A sender
            Node::new(Identity::generate()),                   // 1 C carrier (NOT a relay service)
            Node::from_identity_secret(&b1.to_secret_bytes()), // 2 B1 active decoy
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        net.connect(&mut nodes, 1, 2, 2, 2);
        nodes[0].publish_prekey().unwrap();
        nodes[1].publish_prekey().unwrap();
        nodes[2].publish_prekey().unwrap();
        net.pump(&mut nodes);
        inject_prekey(&mut nodes[0], &b2);
        nodes[2].publish_recv_beacon().unwrap(); // only the active decoy beacons
        net.pump(&mut nodes);

        nodes[0]
            .send_message(b2.address(), "t".into(), b"p2p-passive".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);

        // The plain carrier C spooled B2's bundle despite B1's colliding live gradient.
        let spool = nodes[1].spoolable_private_bundles();
        let spooled: Vec<Bundle> = spool
            .iter()
            .filter(|(_, route, _, _)| *route == b2_route)
            .map(|(_, _, bytes, _)| Bundle::from_bytes(bytes).unwrap())
            .collect();
        assert!(
            !spooled.is_empty(),
            "the plain P2P carrier holds B2's bundle in its spool (no relay involved)"
        );

        // B2 comes online behind the SAME plain carrier C and beacons; C surfaces the wanted mailbox
        // and (running the reload loop itself) re-ingests the spool: no relay in the loop at any point.
        let mut nodes2 = [
            std::mem::replace(&mut nodes[1], Node::new(Identity::generate())),
            Node::from_identity_secret(&b2.to_secret_bytes()),
        ];
        let mut net2 = Wire2::new();
        net2.connect(&mut nodes2, 0, 5, 1, 5);
        nodes2[1].publish_prekey().unwrap();
        net2.pump(&mut nodes2);
        nodes2[1].publish_recv_beacon().unwrap();
        net2.pump(&mut nodes2);
        assert!(
            nodes2[0].take_wanted_mailboxes().contains(&b2_route),
            "the plain carrier surfaces B2's wanted mailbox (the P2P pull trigger)"
        );
        for b in spooled {
            nodes2[0].ingest(b);
        }
        net2.pump(&mut nodes2);
        let bodies: Vec<Vec<u8>> = nodes2[1]
            .take_inbox()
            .iter()
            .filter_map(|b| nodes2[1].read_message(b).ok().flatten().map(|m| m.body))
            .collect();
        assert_eq!(
            bodies,
            vec![b"p2p-passive".to_vec()],
            "a plain non-relay carrier recovers the passive colliding recipient off-relay"
        );
    }

    #[test]
    fn a_forged_private_ack_cannot_mark_a_send_delivered() {
        // core-protocol-r2-04: a §39 private ACK is unsigned and recognized only via the sender's
        // PUBLISHED SPK, and the acked bundle is sealed to the sender's PUBLIC address — so an attacker
        // who knows the sender's address and an in-flight bundle id can forge a Private{Ack{id}} the
        // sender recognizes. Without a recipient-only CDH proof this flipped the send to Delivered and
        // stopped retransmission though the real recipient never received it. Assert a forged ACK (no
        // valid proof) is REFUSED, and a genuine ACK (valid proof) is accepted.
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let sender_addr = sender.address();
        let sender_spk = sender.derive_prekey().public;
        // A second handle on the same identity so we can inject the sender's own prekey after `sender`
        // is moved into the node (Identity is not Clone — reconstruct from the secret bytes).
        let sender_twin = Identity::from_secret_bytes(&sender.to_secret_bytes());

        let mut node = Node::new(sender);
        // The sender must know the recipient's prekey to build the private bundle (recognition tag).
        inject_prekey(&mut node, &recipient);
        // It also needs its OWN prekey in-directory so `emit_private_ack` could seal an ACK to it (and so
        // our forged/genuine ACKs address a resolvable prekey). The node published its own on construction.
        inject_prekey(&mut node, &sender_twin);

        let mid = node
            .send_message(recipient.address(), "t".into(), b"hi".to_vec(), true)
            .unwrap();
        assert!(
            node.store.contains(&mid),
            "sender holds its own private bundle"
        );
        let delivered = |n: &Node, id: BundleId| n.tx.get(&id).is_some_and(|i| i.delivered);
        assert!(!delivered(&node, mid), "not yet delivered");

        // Grab the original bundle's recognition ephemeral so we can build BOTH a forged and a genuine ACK.
        let orig_eph = node
            .store
            .get(&mid)
            .unwrap()
            .inner
            .private
            .as_ref()
            .unwrap()
            .ephemeral;

        // (1) FORGED ACK: the attacker does NOT hold the recipient's SPK secret, so it cannot compute the
        // proof token. It sends a proof-less private ACK sealed to the sender's public address, stamped
        // with the recognition tag it derives from the sender's PUBLISHED SPK (that is the whole forgery).
        let forged = make_private_ack(&sender_addr, &sender_spk, mid, None);
        node.on_bundle(77, forged);
        assert!(
            !delivered(&node, mid),
            "a proof-less forged private ACK must NOT mark the send delivered"
        );
        assert!(
            node.store.contains(&mid),
            "and must NOT drop the original from the store (retransmission continues)"
        );

        // A forged ACK carrying a WRONG token is also refused.
        let forged2 = make_private_ack(&sender_addr, &sender_spk, mid, Some([0x42; 32]));
        node.on_bundle(78, forged2);
        assert!(
            !delivered(&node, mid),
            "a wrong-token forged private ACK must NOT mark the send delivered"
        );
        assert!(
            node.store.contains(&mid),
            "still held after the wrong-token forgery"
        );

        // (2) GENUINE ACK: the real recipient computes the CDH proof = recognition_shared(spk_secret, eph)
        // — exactly the vaccine token, computable ONLY with the recipient's SPK secret.
        let proof =
            crypto::recognition_shared(&recipient.derive_prekey().secret_bytes(), &orig_eph);
        let genuine = make_private_ack(&sender_addr, &sender_spk, mid, Some(proof));
        node.on_bundle(79, genuine);
        assert!(
            delivered(&node, mid),
            "a genuine private ACK with the recipient-only proof marks the send delivered"
        );
        assert!(
            !node.store.contains(&mid),
            "and the proven ACK clears the original from the store"
        );
    }

    /// Build a genuine, correctly-ratcheted §39 private message from a fresh Alice to `bob`, returning
    /// (alice_node, id, genuine_bundle). Alice holds her own private copy in the store.
    fn genuine_private_to(bob: &Identity) -> (Node, BundleId, Bundle) {
        let alice = Identity::generate();
        let mut alice_node = Node::new(alice);
        inject_prekey(&mut alice_node, bob);
        let mid = alice_node
            .send_message(
                bob.address(),
                "text/plain".into(),
                b"meet at dawn".to_vec(),
                true,
            )
            .unwrap();
        let genuine = alice_node
            .store
            .get(&mid)
            .expect("Alice holds her own private bundle");
        assert!(genuine.is_private());
        (alice_node, mid, genuine)
    }

    #[test]
    fn a_recognition_header_chimera_is_rejected_at_verify_so_it_cannot_occupy_a_genuine_private_id()
    {
        // core-protocol-r13-01 (§39 recognition-header chimera, 7th vector — the ROOT fix). Before r13
        // the private id bound ONLY the sealed payload, so an attacker who saw a genuine private bundle
        // could reuse its sealed bytes and rewrite the recognition header (tag/ephemeral/mailbox) to
        // garbage while keeping the SAME id — it self-verified. At a keep-first relay that chimera won the
        // store race, occupied the id, re-flooded its unrecognizable header, and DROPPED the genuine
        // same-id copy (store.put -> false), starving any recipient reachable only through that relay.
        // r13 binds the header into the wire id (id = H(content_id ‖ ephemeral ‖ mailbox ‖ tag)), so a
        // header rewrite yields a DIFFERENT id — a relay recomputes it with no secret and verify() rejects
        // a bundle whose id doesn't match its own header. The chimera can never occupy the genuine id.
        let bob = Identity::generate();
        let (_alice, mid, genuine) = genuine_private_to(&bob);

        // Attacker reuses the sealed bytes (same content_id) but flips the recognition tag, KEEPING the
        // genuine id field — exactly the pre-r13 occupation attack.
        let mut chimera = genuine.clone();
        chimera.inner.private.as_mut().unwrap().tag[0] ^= 0xFF;
        assert_eq!(
            chimera.id(),
            genuine.id(),
            "the attacker keeps the genuine id field (the occupation attempt)"
        );
        assert!(genuine.verify().is_ok(), "the genuine bundle verifies");
        assert!(
            chimera.verify().is_err(),
            "r13: a header-rewrite chimera no longer self-verifies — the id binds the header"
        );

        // A RELAY (not the recipient) sees the chimera FIRST. on_bundle rejects it at verify() before the
        // store, so it can neither mark the id seen nor occupy the keep-first slot.
        let mut relay = Node::new(Identity::generate());
        relay.on_bundle(1, chimera);
        assert!(
            !relay.store.seen(&mid),
            "the rejected chimera never marked the id seen at the relay"
        );
        assert!(
            !relay.store.contains(&mid),
            "and never occupied the keep-first store slot"
        );

        // The genuine copy then arrives and IS held + floodable with its GENUINE tag, so a recipient
        // behind this relay still receives a recognizable copy. (Revert r13 so the chimera self-verifies
        // and it occupies the slot first, genuine put() returns false, and the recipient is starved.)
        relay.on_bundle(2, genuine.clone());
        assert!(
            relay.store.contains(&mid),
            "the relay holds the genuine copy for onward flood"
        );
        assert_eq!(
            relay.store.get(&mid).unwrap().inner.private.as_ref().unwrap().tag,
            genuine.inner.private.as_ref().unwrap().tag,
            "the held copy carries the GENUINE recognition tag — a recipient behind the relay can recognize it"
        );
    }

    #[test]
    fn a_flipped_scalar_twin_cannot_reuse_a_genuine_private_id() {
        // core-protocol-r14-01: r13 bound the recognition HEADER into the wire id, but left the SignedInner
        // SCALAR fields unbound. flags.request_ack is not carried inside the seal, so an attacker who
        // captured a genuine ack-requested private bundle could clone it, flip request_ack -> false, keep
        // the same id, and it still self-verified + was still recognized. Winning the keep-first slot at a
        // recipient's chokepoint relay, that no-ack twin delivered the content but STRIPPED the recipient's
        // ACK (sender stranded on "Sent") and suppressed the delivery vaccine (relay copies linger to TTL).
        // r14 folds the WHOLE inner (every scalar) into the wire id, so any flipped field yields a
        // different id and verify() rejects a twin that keeps the genuine id.
        let bob = Identity::generate();
        let (_alice, mid, genuine) = genuine_private_to(&bob);
        assert!(
            genuine.inner.flags.request_ack,
            "the genuine send requested an ACK"
        );

        // Flip request_ack while KEEPING the genuine id field — the pre-r14 occupation attempt.
        let mut twin = genuine.clone();
        twin.inner.flags.request_ack = false;
        assert_eq!(
            twin.id(),
            genuine.id(),
            "the attacker keeps the genuine id field"
        );
        assert!(genuine.verify().is_ok(), "the genuine bundle verifies");
        assert!(
            twin.verify().is_err(),
            "r14: a flipped-scalar twin no longer self-verifies — the id binds flags (and every scalar)"
        );

        // A relay rejects the twin at verify() before the store, so it can't occupy the id or strip the ACK.
        let mut relay = Node::new(Identity::generate());
        relay.on_bundle(1, twin);
        assert!(
            !relay.store.seen(&mid) && !relay.store.contains(&mid),
            "the rejected twin never occupied the keep-first slot"
        );
        // The genuine ack-requesting copy is held + floodable, so the recipient still ACKs.
        relay.on_bundle(2, genuine.clone());
        assert!(
            relay.store.get(&mid).unwrap().inner.flags.request_ack,
            "the relay holds the genuine ack-requesting copy"
        );
    }

    #[test]
    fn a_genuine_private_copy_delivers_exactly_once_and_a_header_chimera_never_reaches_the_inbox() {
        // r12-01 delivery-once is decoupled from `store.seen` via `delivered_private` (populated only by
        // recognized copies). With r13 a header chimera fails verify() at the recipient's gate too, so it
        // never marks `seen` nor reaches the inbox; the genuine copy delivers, and a re-flooded GENUINE
        // duplicate is deduped (delivered exactly once).
        let bob = Identity::generate();
        let (_alice, mid, genuine) = genuine_private_to(&bob);
        let mut bob_node = Node::new(bob);

        // A header chimera is rejected at Bob's verify() gate — nothing delivered, nothing marked seen.
        let mut chimera = genuine.clone();
        chimera.inner.private.as_mut().unwrap().tag[0] ^= 0xFF;
        bob_node.on_bundle(1, chimera);
        assert!(
            bob_node.take_inbox().is_empty(),
            "the header chimera is rejected at verify — nothing delivered"
        );
        assert!(
            !bob_node.store.seen(&mid),
            "and it never marked the id seen"
        );

        // The genuine copy delivers once...
        bob_node.on_bundle(2, genuine.clone());
        let inbox = bob_node.take_inbox();
        assert_eq!(inbox.len(), 1, "the genuine private copy delivers");
        assert!(inbox[0].is_private());

        // ...and a re-flooded genuine duplicate does NOT double-deliver (delivered_private dedup).
        bob_node.on_bundle(3, genuine.clone());
        assert!(
            bob_node.take_inbox().is_empty(),
            "a genuine duplicate is deduped — delivered exactly once"
        );
    }

    #[test]
    fn a_forged_traced_ack_cannot_mark_a_send_delivered_or_drop_the_bundle() {
        // core-protocol-r7-01: a traced (Device-dst, cleartext-id) ACK is identity-signed, which
        // authenticates WHO signed it but not that they are the bundle's destination. An observer of
        // the bundle's cleartext id could otherwise forge an AckTo(sender, id) and flip the send to
        // Delivered + drop the sender's copy so it stops retransmitting, though the real recipient never
        // got it. The receiver now AUTHORIZES the acker against the acked bundle's plaintext Device(dst).
        // Assert a forged ACK (signed by a non-destination) is refused, and a genuine ACK (signed by the
        // destination) is honored.
        let recipient = Identity::generate();
        let attacker = Identity::generate();
        let recipient_addr = recipient.address();

        let mut node = Node::new(Identity::generate());
        // A traced direct bundle to the recipient, requesting an ACK. Sender holds it (pending + store).
        let bundle = Bundle::create(
            &node.identity,
            Destination::Device(recipient_addr),
            &recipient_addr,
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"hi".to_vec(),
            },
            BundleOpts {
                flags: BundleFlags {
                    request_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        let mid = bundle.id();
        node.submit(bundle);
        assert!(
            node.store.contains(&mid),
            "sender holds its own traced bundle"
        );
        // store.contains is the direct signal of whether an ACK was HONORED: honoring an ACK removes
        // the acked bundle from the store, so its staying present means the ACK was refused.

        // A helper to build an AckTo(sender, mid) signed by a chosen identity (the forgery lever).
        let make_ack = |signer: &Identity, to: PubKeyBytes| {
            Bundle::create(
                signer,
                Destination::AckTo(to, mid),
                &to,
                &Payload::Ack {
                    for_bundle_id: mid,
                    status: 0,
                    delivery_hops: 1,
                    delivery_ms: 1,
                    proof: None,
                },
                BundleOpts {
                    flags: BundleFlags {
                        is_ack: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap()
        };

        // (1) FORGED ACK: signed by the ATTACKER (not the recipient). Must NOT be honored, so the
        // sender's bundle stays in the store and retransmission keeps going. Before the fix, this
        // dropped the bundle (store.remove) on a merely-authenticated ack.
        node.on_bundle(77, make_ack(&attacker, node.address()));
        assert!(
            node.store.contains(&mid),
            "a forged traced ACK from a non-destination must NOT drop the sender's bundle"
        );

        // (2) GENUINE ACK: signed by the real RECIPIENT. IS honored (unchanged behavior): the acked
        // bundle is cleared from the store.
        node.on_bundle(78, make_ack(&recipient, node.address()));
        assert!(
            !node.store.contains(&mid),
            "a genuine traced ACK from the destination DOES clear the acked bundle"
        );
    }

    #[test]
    fn a_private_chimera_ack_cannot_forge_a_traced_delivery() {
        // core-protocol-r8-01: verify()'s PRIVATE branch binds only the sealed payload to the id, NOT
        // src/dst, so a private bundle's src is attacker-chosen. The r7-01 dst-match check trusted
        // bundle.inner.src, so an attacker could take a private ack (src unauthenticated), rewrite
        // src=recipient (to satisfy the dst check) + dst=AckTo(sender,mid) + is_ack, and slip it into
        // the traced-ack honor path to forge a delivery. The fix additionally requires the ack be
        // identity-signed (!is_private). Assert this chimera is refused.
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let recipient_addr = recipient.address();
        let recipient_spk = recipient.derive_prekey().public;

        let mut node = Node::new(sender);
        let sender_addr = node.address();
        // Sender holds a traced bundle to the recipient.
        let bundle = Bundle::create(
            &node.identity,
            Destination::Device(recipient_addr),
            &recipient_addr,
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"hi".to_vec(),
            },
            BundleOpts {
                flags: BundleFlags {
                    request_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        let mid = bundle.id();
        node.submit(bundle);
        assert!(node.store.contains(&mid), "sender holds its traced bundle");

        // Build the chimera: a PRIVATE ack sealed to the SENDER, then rewrite src=recipient and
        // dst=AckTo(sender,mid). The id is over the sealed payload only, so these rewrites do NOT break
        // verify()'s private-branch id check (that is the whole exploit).
        let ack_payload = Payload::Ack {
            for_bundle_id: mid,
            status: 0,
            delivery_hops: 1,
            delivery_ms: 1,
            proof: None,
        };
        let mut chimera = Bundle::create_private(
            &sender_addr,
            &recipient_spk,
            &ack_payload,
            Some(crypto::mailbox_route(&crypto::mailbox_tag(&sender_addr, 0))),
            BundleOpts {
                flags: BundleFlags {
                    is_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        chimera.inner.src = recipient_addr; // claimed, but UNauthenticated in a private bundle
        chimera.inner.dst = Destination::AckTo(sender_addr, mid); // target the traced-ack honor path
        assert!(
            chimera.is_private(),
            "chimera is private-flagged (src is not authenticated)"
        );
        // r10-01: the §39 invariant (private => Broadcast-dst) is now enforced at the gate, so a
        // private bundle with a rewritten AckTo/Device dst is rejected by verify() itself, before it
        // can ever reach the honor path. (The honor-path !is_private + Device-match guards remain as
        // defense in depth.)
        assert!(
            chimera.verify().is_err(),
            "verify() rejects a private bundle whose dst is not Broadcast (r10-01)"
        );

        node.on_bundle(77, chimera);
        assert!(
            node.store.contains(&mid),
            "a private-flagged chimera ack must NOT forge a traced delivery or drop the bundle"
        );
    }

    #[test]
    fn a_private_bundle_replayed_with_a_device_dst_is_rejected_at_the_gate() {
        // core-protocol-r10-01: the private id binds ONLY the sealed payload (not src/dst) and private
        // bundles are unsigned, so an attacker can replay a real §39 message's exact sealed bytes with
        // dst rewritten to Device(attacker) - SAME id. If accepted + stored (keep-first dedup), that
        // chimera would occupy the real message's id at a relay and could then be traced-ACK-purged +
        // immune-poisoned, a network-wide DoS of the real private message. verify() now enforces the
        // §39 invariant (private => Broadcast-dst) so the replay is rejected at ingest and can never be
        // stored to pre-seed a relay.
        let recipient = Identity::generate();
        let attacker = Identity::generate();
        let real = Bundle::create_private(
            &recipient.address(),
            &recipient.derive_prekey().public,
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"secret".to_vec(),
            },
            Some(crypto::mailbox_route(&crypto::mailbox_tag(
                &recipient.address(),
                0,
            ))),
            BundleOpts::default(),
        )
        .unwrap();
        assert!(
            real.verify().is_ok(),
            "the genuine Broadcast private bundle verifies"
        );

        // Replay its sealed bytes with dst rewritten to Device(attacker): same id, no signature.
        let mut replay = real.clone();
        replay.inner.dst = Destination::AckTo([0u8; 32], real.id()); // any non-Broadcast dst
        assert_eq!(
            replay.id(),
            real.id(),
            "the private id is unchanged by the dst rewrite"
        );
        assert!(
            replay.verify().is_err(),
            "a private bundle whose dst is not Broadcast is rejected at the gate (cannot pre-seed)"
        );
        let mut replay2 = real.clone();
        replay2.inner.dst = Destination::Device(attacker.address());
        assert!(
            replay2.verify().is_err(),
            "including a Device-dst replay (the r10 pre-seed shape)"
        );
    }

    #[test]
    fn a_forged_response_cannot_purge_a_private_bundle_a_relay_is_carrying() {
        // core-protocol-r11-01: the HttpResponse/ServiceResponse cleanup handlers purge +
        // immune-poison the id they name. That id is an attacker-chosen field in a bundle sealed to us,
        // so without authorization a forged response naming a real §39 private message's cleartext id
        // would purge + immune-poison that message at a relay carrying it - a network-wide DoS reached
        // outside the (now-closed) traced-ACK path. The handlers now purge ONLY for a request WE sent.
        let sender = Identity::generate();
        let bob = Identity::generate();
        let attacker = Identity::generate();

        // A relay R is carrying a real private message P (sender -> bob), which floods and is stored.
        let mut relay = Node::new(Identity::generate());
        let p = Bundle::create_private(
            &bob.address(),
            &bob.derive_prekey().public,
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"secret".to_vec(),
            },
            Some(crypto::mailbox_route(&crypto::mailbox_tag(
                &bob.address(),
                0,
            ))),
            BundleOpts::default(),
        )
        .unwrap();
        // Give P a real signed src so it is a well-formed flooded bundle from the sender's view; the
        // relay ingests it and holds it for onward flooding.
        let pid = p.id();
        relay.on_bundle(1, p);
        assert!(
            relay.store.contains(&pid),
            "relay is carrying the private message"
        );
        let _ = sender; // (sender identity only needed to frame the scenario)

        // Attacker seals a forged HttpResponse to the relay naming P's observed cleartext id.
        let forged = Bundle::create(
            &attacker,
            Destination::Device(relay.address()),
            &relay.address(),
            &Payload::HttpResponse {
                status: 200,
                headers: vec![],
                body: b"x".to_vec(),
                for_bundle_id: pid,
            },
            BundleOpts::default(),
        )
        .unwrap();
        relay.on_bundle(2, forged);
        assert!(
            relay.store.contains(&pid),
            "a forged response naming a private message's id must NOT purge it (r11-01)"
        );
    }

    #[test]
    fn a_signed_traced_ack_cannot_forge_delivery_of_a_default_private_send() {
        // core-protocol-r9-01: the DEFAULT send is §39 private, held by the sender as dst=Broadcast with
        // a CLEARTEXT id on the wire. The earlier fix only bound signer==dst for Device-dst bundles, so
        // for a Broadcast-held private send the check degraded to "any identity-signed ack is honored".
        // An attacker who merely OBSERVES the flooded private id could then sign a genuine traced
        // AckTo(sender, id) (their OWN identity, so it is identity-signed and passes the !is_private
        // gate) and forge Delivered + stop retransmit at the sender. The fix requires a POSITIVE
        // Device(dst)==signer match, so a Broadcast-held private send is never honored via the traced
        // path (it is acked only by the recipient-only CDH proof on the private path).
        let recipient = Identity::generate();
        let attacker = Identity::generate();

        let mut node = Node::new(Identity::generate());
        let sender_addr = node.address();
        // A default PRIVATE (§39) send: needs the recipient's prekey so it seals now (not deferred).
        inject_prekey(&mut node, &recipient);
        let mid = node
            .send_message(recipient.address(), "t".into(), b"hi".to_vec(), true)
            .unwrap();
        assert!(
            node.store.contains(&mid),
            "sender holds its own private send"
        );
        assert!(
            node.store.get(&mid).unwrap().is_private(),
            "and it is a §39 private (Broadcast-dst) bundle with a cleartext id"
        );

        // Attacker signs a GENUINE traced ACK (identity-signed, passes !is_private) naming that
        // observed cleartext id. Must NOT be honored: the held send is Broadcast, not Device(attacker).
        let forged = Bundle::create(
            &attacker,
            Destination::AckTo(sender_addr, mid),
            &sender_addr,
            &Payload::Ack {
                for_bundle_id: mid,
                status: 0,
                delivery_hops: 1,
                delivery_ms: 1,
                proof: None,
            },
            BundleOpts {
                flags: BundleFlags {
                    is_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        node.on_bundle(77, forged);
        assert!(
            node.store.contains(&mid),
            "a signed traced ACK naming a private send's cleartext id must NOT drop the private bundle"
        );
    }

    #[test]
    fn a_duplicate_vaccine_does_not_re_scan_and_is_rate_limited() {
        // core-protocol-r2-03 / security-privacy-r2-01: a token-only vaccine is unsigned + freely
        // mintable and, being is_ack, was EXEMPT from the private-ingest rate limit. Each arrival forced
        // an O(held-bundles) store scan with NO dedup in front. Assert (a) a duplicate copy of the SAME
        // vaccine short-circuits before the scan (seen-gated), and (b) Vaccine bundles are now subject to
        // the per-link rate limit so a single link cannot mint them without bound.
        let mut relay = Node::new(Identity::generate());

        // A forged vaccine with a random token: it matches nothing, so it is stored + would re-flood.
        let vax = Bundle::create_vaccine(
            [0x33; 32],
            BundleOpts {
                created_at: 0,
                ..Default::default()
            },
        );
        let vid = vax.id();
        relay.on_bundle(11, vax.clone());
        assert!(
            relay.store.seen(&vid),
            "first vaccine copy is recorded as seen"
        );
        // A duplicate copy (same id) must be short-circuited by the seen gate before the scan — we assert
        // the observable proxy: it is not re-stored/re-flooded and the seen set is unchanged.
        relay.on_bundle(11, vax.clone());
        assert!(
            relay.store.seen(&vid),
            "the duplicate vaccine is deduped (no re-processing)"
        );

        // Rate limit: flood cap+5 DISTINCT-token vaccines from one link within one window. The ingest
        // gate must drop the ones past the window cap (they never reach the store).
        let cap = MAX_PRIV_BUNDLES_PER_WINDOW as usize;
        let link = 22;
        let mut accepted = 0usize;
        for i in 0u32..(cap as u32 + 5) {
            let mut tok = [0u8; 32];
            tok[..4].copy_from_slice(&i.to_le_bytes()); // distinct token per i (distinct vaccine id)
            tok[4] = 0xAB;
            let v = Bundle::create_vaccine(
                tok,
                BundleOpts {
                    created_at: 0,
                    ..Default::default()
                },
            );
            let vid = v.id();
            relay.on_bundle(link, v);
            if relay.store.seen(&vid) {
                accepted += 1;
            }
        }
        assert!(
            accepted <= cap,
            "vaccines from one link are rate-limited like private bundles (accepted {accepted} <= cap {cap})"
        );
        assert!(
            accepted > 0,
            "the rate limit admits up to the cap, not zero"
        );
    }

    #[test]
    fn mailbox_reingest_over_the_flood_cap_is_never_dropped() {
        // relay-F (pass-5 audit): the relay's process_mailbox DELETES each spool copy, then re-ingests
        // via Node::ingest. Before the fix, ingest re-injected via LinkId::MAX, which is subject to the
        // F-07 256/window private-ingest cap, so a beacon pulling > cap bundles (a real backlog, or an
        // attacker co-locating spam under a shared mailbox prefix) dropped the overflow AFTER the durable
        // copy was gone: permanent loss. ingest now re-injects via LOCAL_LINK (our own trusted storage
        // re-injection), which is exempt, so EVERY pulled bundle is accepted. All ingests land in one
        // rate window (now_ms fixed at 0), so this would drop ~50 without the exemption.
        let mut relay = Node::new(Identity::generate());
        let recipient = Identity::generate();
        let mailbox = crypto::mailbox_tag(&recipient.address(), 0);
        let prefix = crypto::mailbox_route(&mailbox);
        let n = MAX_PRIV_BUNDLES_PER_WINDOW as usize + 50; // well over one window's cap
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let pb = Bundle::create_private(
                &recipient.address(),
                &recipient.derive_prekey().public,
                &Payload::PeerMessage {
                    content_type: "t".into(),
                    body: format!("m{i}").into_bytes(), // distinct body -> distinct bundle id
                },
                Some(prefix),
                BundleOpts::default(), // created_at = 0 (all in the same rate window)
            )
            .unwrap();
            assert!(pb.is_private());
            ids.push(pb.id());
            relay.ingest(pb); // the durable-storage re-ingest path
        }
        let accepted = ids.iter().filter(|id| relay.store.seen(id)).count();
        assert_eq!(
            accepted, n,
            "every re-ingested mailbox bundle is accepted (LOCAL_LINK exempt from F-07); none dropped-after-delete"
        );
    }

    #[test]
    fn an_evicted_then_repulled_mailbox_bundle_is_rehydrated_not_dropped() {
        // relay-A audit (2nd data-loss vector): the rate-cap fix closed the >cap-burst drop; this closes
        // the dedup-after-eviction drop. A private bundle spooled + held, then EVICTED from held under
        // relay pressure (store.remove keeps its `seen` dedup row), is re-pulled from its durable mailbox
        // on the SAME relay and re-ingested. A plain put is refused by the surviving seen row -> the
        // message is lost after process_mailbox's delete. The trusted re-ingest must RE-HOLD it.
        let mut relay = Node::new(Identity::generate());
        let recipient = Identity::generate();
        let mailbox = crypto::mailbox_tag(&recipient.address(), 0);
        let prefix = crypto::mailbox_route(&mailbox);
        let pb = Bundle::create_private(
            &recipient.address(),
            &recipient.derive_prekey().public,
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"held-then-evicted".to_vec(),
            },
            Some(prefix),
            BundleOpts::default(),
        )
        .unwrap();
        let id = pb.id();
        let repull = pb.clone(); // the durable mailbox copy, re-pulled later (same bytes -> same id)
        relay.ingest(pb);
        assert!(relay.store.contains(&id), "held after the first ingest");
        // Evict from held under relay pressure; the dedup row survives (exactly what store.remove does).
        relay.store.remove(&id);
        assert!(
            relay.store.seen(&id) && !relay.store.contains(&id),
            "precondition: evicted-but-seen"
        );
        // process_mailbox deletes the durable copy then re-ingests it: it must re-hold, not drop on the
        // surviving seen row.
        relay.ingest(repull);
        assert!(
            relay.store.contains(&id),
            "the re-pulled evicted bundle is re-held (rehydrate), not dropped on the surviving seen row"
        );
    }

    #[test]
    fn vaccine_carries_no_plaintext_delivered_id_but_a_holder_still_drops() {
        // sec-priv-07: the delivery vaccine floods ONLY the recognition token — no plaintext delivered
        // id. Prove (1) a party that did NOT capture the flood cannot read any bundle id off the wire
        // (the anti-packet's bytes contain neither the delivered id nor anything an outsider can bind to
        // one), and (2) a real HOLDER of the delivered bundle still recovers the match by the token and
        // drops its copy.
        let (mut nodes, mut net) = gradient_topology();

        // No-ack send ⇒ B delivers but emits NO vaccine, so R keeps its relayed copy for us to test.
        let bob = nodes[2].address();
        let id = nodes[0]
            .send_message(bob, "t".into(), b"vaxpriv".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        assert_eq!(nodes[2].take_inbox().len(), 1, "B received it");
        assert!(nodes[1].store.contains(&id), "relay R holds a copy");

        // Craft the real vaccine the recipient would emit.
        let eph = nodes[1]
            .store
            .get(&id)
            .unwrap()
            .inner
            .private
            .unwrap()
            .ephemeral;
        let token = crypto::recognition_shared(&nodes[2].prekey.secret_bytes(), &eph);
        let vax = Bundle::create_vaccine(
            token,
            BundleOpts {
                created_at: 0,
                ..Default::default()
            },
        );

        // (1) A non-capturing observer sees only the serialized anti-packet. The delivered id must NOT
        // appear anywhere in those bytes — that is the concrete metadata the old wire leaked.
        let wire = vax.to_bytes().unwrap();
        assert!(
            !wire.windows(32).any(|w| w == id),
            "the delivered bundle id must NOT appear on the vaccine wire (sec-priv-07)"
        );

        // (2) A real holder still drops the delivered bundle: it recovers the target from the token.
        assert_eq!(
            nodes[1].resolve_vaccine_target(&token),
            Some(id),
            "a holder recovers the delivered id from the token alone"
        );
        nodes[1].on_bundle(9, vax);
        assert!(
            !nodes[1].store.contains(&id),
            "the real vaccine still purges the holder's copy"
        );
        assert!(
            nodes[1].immune.contains_key(&id),
            "and marks it immune against re-flood"
        );

        // A token for a bundle we don't hold resolves to nothing (no false purge, no correlation gain).
        assert_eq!(
            nodes[1].resolve_vaccine_target(&[0x11; 32]),
            None,
            "a token we hold no bundle for matches nothing"
        );
    }

    #[test]
    fn large_message_auto_streams_and_arrives_whole() {
        // A big message (e.g. an image body) exceeds one bundle, so it's transparently
        // carried as a stream of chunks and reassembled — arriving as a normal inbox
        // message with the right content type and exact bytes (DESIGN.md §20).
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        exchange_prekeys(&mut net, &mut nodes); // content is ratcheted — need prekeys (§25)

        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect(); // ~200KB → multi-chunk
        nodes[0]
            .send_message_traced(nodes[1].address(), "image/jpeg".into(), body.clone(), true)
            .unwrap();
        net.pump(&mut nodes);

        let inbox = nodes[1].take_inbox();
        assert_eq!(inbox.len(), 1, "reassembled into exactly one message");
        let m = nodes[1]
            .read_message(&inbox[0])
            .unwrap()
            .expect("a user message");
        assert_eq!(m.content_type, "image/jpeg");
        assert_eq!(m.body, body, "bytes reassembled exactly, in order");
    }

    #[test]
    fn hops_request_response_round_trips() {
        // A hops:// request sealed to an endpoint surfaces there as an HTTP request; the
        // endpoint replies and the client gets the response, correlated by request id (§30).
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        let endpoint = nodes[1].address();
        nodes[0].set_time(1);

        let req = nodes[0]
            .send_hops_request(
                endpoint,
                "example.hopme.sh".into(),
                "GET".into(),
                "/hello".into(),
                vec![],
                vec![],
                64_000,
            )
            .unwrap();
        net.pump(&mut nodes);

        // Endpoint side: the request is surfaced for the operator's translator.
        let reqs = nodes[1].take_http_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].host, "example.hopme.sh");
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].url, "/hello");
        let (from, rid) = (reqs[0].from, reqs[0].id);
        nodes[1]
            .send_http_response(from, rid, 200, vec![], b"world".to_vec())
            .unwrap();
        net.pump(&mut nodes);

        // Client side: the response arrives, correlated to the request.
        let resps = nodes[0].take_http_responses();
        assert_eq!(resps.len(), 1);
        assert_eq!(resps[0].for_id, req);
        assert_eq!(resps[0].status, 200);
        assert_eq!(resps[0].body, b"world");
        assert!(
            !nodes[0].store.contains(&req),
            "request purged once answered"
        );
    }

    #[test]
    fn internet_peer_resolves_hns_locally_no_relay() {
        // An internet-connected node resolves HNS itself: resolve_hns surfaces a real-DNS
        // lookup for the host to perform; provide_dns_answer caches it and yields the result.
        // No bundle, no relay round-trip (DESIGN.md §30).
        let mut node = Node::new(Identity::generate());
        node.set_internet(true);

        assert_eq!(node.resolve_hns("Example.HopMe.sh."), HnsLookup::Pending);
        let lookups = node.take_dns_lookups();
        assert_eq!(
            lookups,
            vec!["example.hopme.sh".to_string()],
            "normalized + queued for host"
        );

        let endpoint = Identity::generate().address();
        node.provide_dns_answer("example.hopme.sh", Some(endpoint), 300);

        let results = node.take_hns_results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "example.hopme.sh");
        assert_eq!(results[0].address, Some(endpoint));

        // Now cached: a second resolve serves from cache with no new lookup.
        assert_eq!(
            node.resolve_hns("example.hopme.sh"),
            HnsLookup::Cached(Some(endpoint))
        );
        assert!(node.take_dns_lookups().is_empty());
    }

    #[test]
    fn hns_missing_record_is_a_negative_result() {
        // hops://thisdoesnotexist.com — no reachable well-known. The host reports None; we cache
        // the negative and surface a resolution error (address None), so we don't refetch on repeat.
        let mut node = Node::new(Identity::generate());
        node.set_internet(true);
        assert_eq!(node.resolve_hns("thisdoesnotexist.com"), HnsLookup::Pending);
        node.provide_dns_answer("thisdoesnotexist.com", None, 60);

        let results = node.take_hns_results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, None, "no endpoint → resolution error");
        assert_eq!(
            node.resolve_hns("thisdoesnotexist.com"),
            HnsLookup::Cached(None)
        );
    }

    #[test]
    fn hns_cache_honors_the_record_absolute_expiry_not_fetch_plus_ttl() {
        // reach-A audit: a record fetched near its expiry must be cached only until its OWN
        // issued_at+ttl, not now+ttl (which would trust it for up to ~2x its ttl and let a
        // publisher's revocation-by-expiry linger). Fetch a record with 10s of life left.
        let id = Identity::generate();
        let ttl = 3600u32;
        let issued = 1_000u64; // seconds
        let rec = crate::reach::ReachRecord::sign(&id, "wss://x/_hop", ttl, issued);
        let mut node = Node::new(Identity::generate());
        let now_secs = issued + ttl as u64 - 10; // still valid, but only 10s remain
        node.set_time(now_secs * 1000);
        node.provide_reach_record("x.com", rec.to_bytes());
        let entry = node.hns_cache.get("x.com").expect("record cached");
        assert_eq!(
            entry.expires_at_ms,
            (issued + ttl as u64) * 1000,
            "cache ends at the record's absolute expiry (issued+ttl), ~10s out"
        );
        assert_ne!(
            entry.expires_at_ms,
            node.now_ms + ttl as u64 * 1000,
            "NOT the buggy now+ttl (~1h out)"
        );
        assert_eq!(entry.address, Some(id.address()));
    }

    #[test]
    fn a_dropped_host_reach_callback_does_not_wedge_a_name_forever() {
        // reach-A audit: if the host drains a lookup but never calls provide_reach_record back (a
        // dropped fetch, contract violation), the periodic retry must re-emit it instead of leaving the
        // name stuck forever behind the dns_inflight guard.
        let mut node = Node::new(Identity::generate());
        node.set_internet(true);
        node.set_time(0);
        assert_eq!(node.resolve_hns("acme.com"), HnsLookup::Pending);
        assert_eq!(
            node.take_dns_lookups(),
            vec!["acme.com".to_string()],
            "the host is asked to resolve it once"
        );
        // The host never answers. Advance past the retry interval and tick.
        node.tick(HNS_RETRY_INTERVAL_MS + 1);
        assert_eq!(
            node.take_dns_lookups(),
            vec!["acme.com".to_string()],
            "the dropped lookup is re-emitted on retry (self-heals), not wedged"
        );
    }

    #[test]
    fn isolated_node_keeps_resolution_pending_then_resolves_on_internet() {
        // Resolution is delay-tolerant, but reach records are fetched over the domain's own TLS
        // well-known, which only THIS device can do (no mesh-assisted resolution): with no internet
        // the request returns NeedsResolver and stays pending, then completes once we gain internet.
        let mut node = Node::new(Identity::generate());
        assert_eq!(
            node.resolve_hns("example.hopme.sh"),
            HnsLookup::NeedsResolver
        );
        assert!(
            node.take_dns_lookups().is_empty(),
            "nothing to look up while offline"
        );

        // Gain internet → the pending domain is queued for our own DNS lookup.
        node.set_internet(true);
        assert_eq!(
            node.take_dns_lookups(),
            vec!["example.hopme.sh".to_string()]
        );
        let endpoint = Identity::generate().address();
        node.provide_dns_answer("example.hopme.sh", Some(endpoint), 300);
        assert_eq!(node.cached_hns("example.hopme.sh"), Some(Some(endpoint)));
    }

    #[test]
    fn duplicate_to_destination_re_acks_then_throttles() {
        // If our delivery-ACK is lost, the sender retransmits; a duplicate reaching the
        // destination must re-emit the ACK (so the sender can stop) — but throttled, so a
        // burst of duplicates can't cause an ACK storm (DESIGN.md §7).
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);

        exchange_prekeys(&mut net, &mut nodes); // content is ratcheted — need prekeys (§25)
        let id = nodes[0]
            .send_to(&nodes[1].address(), "t".into(), b"hi".to_vec(), true)
            .unwrap()
            .unwrap();
        let msg = nodes[0]
            .store
            .get(&id)
            .expect("our message is in the store");
        net.pump(&mut nodes);
        assert!(nodes[1].take_inbox().len() == 1, "delivered once");
        accept_all(&mut nodes[1]);

        // A duplicate arrives after the throttle window → re-ACK (something to send).
        nodes[1].set_time(REACK_MIN_INTERVAL_MS + 1);
        let _ = nodes[1].drain_outgoing();
        nodes[1].ingest(msg.clone());
        assert!(
            !nodes[1].drain_outgoing().is_empty(),
            "re-acked the duplicate"
        );
        assert!(
            nodes[1].take_inbox().is_empty(),
            "but did NOT re-deliver to the inbox"
        );

        // Another duplicate immediately → within throttle → no new ACK.
        nodes[1].ingest(msg);
        assert!(
            nodes[1].drain_outgoing().is_empty(),
            "throttled: no ACK storm"
        );
    }

    #[test]
    fn zero_relay_capacity_dedups_without_foreign_custody_and_keeps_local_traffic() {
        let mut relay = Node::new(Identity::generate());
        let foreign = Identity::generate();
        let destination = Identity::generate();
        let carried = Bundle::create(
            &foreign,
            Destination::Device(destination.address()),
            &destination.address(),
            &Payload::ServiceRequest {
                service: "foreign".into(),
                method: "hold".into(),
                args: vec![],
            },
            BundleOpts::default(),
        )
        .unwrap();
        let carried_id = carried.id();

        relay.ingest(carried.clone());
        assert!(relay.store.contains(&carried_id));
        assert!(!relay.relay_order.is_empty());
        assert!(relay.forwarded.contains_key(&carried_id));

        relay.set_max_relayed(0);
        assert_eq!(relay.max_relayed, 0);
        assert!(!relay.store.contains(&carried_id));
        assert!(relay.store.seen(&carried_id));
        assert!(relay.relay_order.is_empty());
        assert!(relay.relay_fwd.is_empty());
        assert!(!relay.forwarded.contains_key(&carried_id));

        // Trusted durable re-ingest can bypass held-copy dedup, but zero capacity immediately
        // releases it again and never offers a foreign copy onward.
        relay.ingest(carried);
        assert!(!relay.store.contains(&carried_id));
        assert!(relay.relay_order.is_empty());
        assert!(relay.drain_outgoing().is_empty());

        let local = Bundle::create(
            &relay.identity,
            Destination::Device(destination.address()),
            &destination.address(),
            &Payload::ServiceRequest {
                service: "local".into(),
                method: "send".into(),
                args: vec![],
            },
            BundleOpts::default(),
        )
        .unwrap();
        let local_id = local.id();
        relay.submit(local);
        assert!(
            relay.store.contains(&local_id),
            "local origin is not relay custody"
        );

        let addressed = Bundle::create(
            &foreign,
            Destination::Device(relay.address()),
            &relay.address(),
            &Payload::ServiceRequest {
                service: "app.local".into(),
                method: "receive".into(),
                args: b"ok".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap();
        relay.on_bundle(7, addressed);
        let requests = relay.take_service_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].args, b"ok");
    }

    #[test]
    fn zero_relay_capacity_never_calls_store_put_even_when_delete_would_fail() {
        let foreign = Identity::generate();
        let destination = Identity::generate();
        let bundle = Bundle::create(
            &foreign,
            Destination::Device(destination.address()),
            &destination.address(),
            &Payload::ServiceRequest {
                service: "foreign".into(),
                method: "relay".into(),
                args: Vec::new(),
            },
            BundleOpts::default(),
        )
        .unwrap();
        let id = bundle.id();
        let mut leaf = Node::with_store(
            Identity::generate(),
            FaultStore {
                fail_bundle_removes: usize::MAX,
                ..Default::default()
            },
        );
        leaf.set_max_relayed(0);
        leaf.ingest(bundle);
        assert_eq!(leaf.store.bundle_put_calls, 0);
        assert_eq!(leaf.store.bundle_remove_calls, 0);
        assert!(!leaf.store.contains(&id));
        assert!(!leaf.store.seen(&id));
        assert!(leaf.relay_order.is_empty());
        assert!(leaf.drain_outgoing().is_empty());
    }

    #[test]
    fn zero_capacity_leaf_cannot_bridge_two_peers_but_still_receives_local_traffic() {
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        nodes[1].set_max_relayed(0);
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        net.connect(&mut nodes, 1, 2, 2, 2);
        exchange_prekeys(&mut net, &mut nodes);

        let bridged = nodes[0]
            .send_message_traced(
                nodes[2].address(),
                "text/plain".into(),
                b"must not bridge".to_vec(),
                true,
            )
            .unwrap();
        net.pump(&mut nodes);
        assert!(nodes[2].inbox_items().is_empty());
        assert!(!nodes[1].store.contains(&bridged));
        assert!(!nodes[1].store.seen(&bridged));

        nodes[0]
            .send_message_traced(
                nodes[1].address(),
                "text/plain".into(),
                b"for the leaf".to_vec(),
                true,
            )
            .unwrap();
        net.pump(&mut nodes);
        let local = nodes[1].inbox_items();
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].body, b"for the leaf");
        assert!(nodes[1].accept_inbox(&local[0].id).unwrap());
    }

    #[test]
    fn eviction_prefers_already_relayed_over_not_yet_relayed() {
        // Custody policy (§6): under cap pressure, a bundle we've already relayed (and held
        // past the grace window) is evicted before one we haven't relayed yet — so a flood
        // of big transfers can't push out legitimate, not-yet-forwarded messages.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        nodes[0].set_time(0);
        nodes[0].set_max_relayed(1);

        let third = Identity::generate().address();
        let mk = |b: &[u8]| {
            Bundle::create(
                &Identity::generate(),
                Destination::Device(third),
                &third,
                &Payload::PeerMessage {
                    content_type: "t".into(),
                    body: b.to_vec(),
                },
                BundleOpts::default(),
            )
            .unwrap()
        };

        // A: relayed onward to node1, so it's "already relayed".
        let a = mk(b"a");
        let a_id = a.id();
        nodes[0].ingest(a);
        net.pump(&mut nodes);
        // Lose the peer so the next bundle has nowhere to go (stays not-yet-relayed), and
        // age A past the grace window.
        nodes[0].handle(BearerEvent::Disconnected(1));
        nodes[0].set_time(EVICT_GRACE_MS);

        // B: cannot be forwarded (no peer) → not-yet-relayed. Ingesting it trips the cap.
        let b = mk(b"b");
        let b_id = b.id();
        nodes[0].ingest(b);

        assert!(
            !nodes[0].store.contains(&a_id),
            "already-relayed, past-grace bundle is evicted"
        );
        assert!(
            nodes[0].store.contains(&b_id),
            "not-yet-relayed bundle is kept"
        );
    }

    #[test]
    fn handshake_then_direct_delivery() {
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);

        let b = msg(&nodes[0], &nodes[1], b"hello neighbor");
        nodes[0].submit(b);
        net.pump(&mut nodes);

        let inbox = nodes[1].take_inbox();
        assert_eq!(inbox.len(), 1);
        match inbox[0].open(&nodes[1].identity).unwrap() {
            Payload::PeerMessage { body, .. } => assert_eq!(body, b"hello neighbor"),
            _ => panic!("wrong payload"),
        }
    }

    #[test]
    fn duplicate_links_to_same_peer_dont_loop() {
        // Field bug (resource exhaustion): an iOS rotating-MAC dialer can open MORE THAN ONE
        // L2CAP channel to the same Android peer, so the node ends up with two Up links to the
        // SAME peer. If it doesn't dedup them, traffic can loop between the two links and exhaust
        // the (few-KB/s) BLE pipe — which is exactly the megabyte flood seen on-device. This test
        // reproduces it deterministically: connect two nodes with TWO link pairs, then verify the
        // network reaches quiescence with BOUNDED traffic (no loop) and the peer is identified once.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1); // link pair #1: node0 link1 <-> node1 link1
        net.connect(&mut nodes, 0, 2, 1, 2); // link pair #2: node0 link2 <-> node1 link2 (SAME peer)

        // Drive a message and pump with a byte/round budget. A loop manifests as either hitting
        // the round cap (never quiescent) or an explosive byte count.
        let b = msg(&nodes[0], &nodes[1], b"hi");
        nodes[0].submit(b);

        let mut total_bytes = 0usize;
        let mut rounds = 0usize;
        let quiesced = loop {
            if rounds >= 5000 {
                break false;
            }
            rounds += 1;
            let mut any = false;
            for i in 0..nodes.len() {
                let other = 1 - i;
                for (link, bytes) in nodes[i].drain_outgoing() {
                    any = true;
                    total_bytes += bytes.len();
                    // links are symmetric here (1<->1, 2<->2)
                    nodes[other].handle(BearerEvent::Data(link, bytes));
                }
            }
            if !any {
                break true;
            }
        };

        assert!(
            quiesced,
            "node never reached quiescence — TRAFFIC LOOP (rounds={rounds}, bytes={total_bytes})"
        );
        assert!(
            total_bytes < 50_000,
            "two-link handshake + one tiny message moved {total_bytes} bytes — amplification loop"
        );
        // The message must actually be delivered exactly once (not lost in the loop, not duplicated).
        assert_eq!(
            nodes[1].take_inbox().len(),
            1,
            "message should deliver exactly once over duplicate links"
        );
    }

    #[test]
    fn idle_established_link_does_not_flood() {
        // Field bug (resource exhaustion): on-device an idle, established BLE link sends ~10+ KB/s
        // continuously on near-empty stores (tx ~3-4x rx), saturating the few-KB/s pipe so real
        // messages crawl through over minutes/hours. This reproduces steady-state operation: two
        // connected nodes, prekeys exchanged, then many "ticks" with the periodic presence/prekey
        // re-publish the bearer does — and asserts an idle link moves only a TRICKLE, not a flood.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        exchange_prekeys(&mut net, &mut nodes);

        let mut now = 10_000u64;
        let tick_pump = |nodes: &mut [Node], now: u64, bytes: &mut usize| {
            for n in nodes.iter_mut() {
                n.tick(now);
            }
            for _ in 0..2000 {
                let mut any = false;
                for i in 0..nodes.len() {
                    let other = 1 - i;
                    for (link, b) in nodes[i].drain_outgoing() {
                        any = true;
                        *bytes += b.len();
                        nodes[other].handle(BearerEvent::Data(link, b));
                    }
                }
                if !any {
                    break;
                }
            }
        };

        // Warm up 60 "seconds" (let any initial gossip settle), re-publishing presence every 20s
        // and prekeys every 120s exactly like the Android/iOS bearer tick.
        let mut scratch = 0usize;
        for s in 0..60u64 {
            now += 1000;
            if s % 20 == 0 {
                for n in nodes.iter_mut() {
                    let _ = n.publish_service(
                        "presence".into(),
                        "x".into(),
                        String::new(),
                        vec![],
                        120_000,
                    );
                }
            }
            if s % 120 == 0 {
                for n in nodes.iter_mut() {
                    let _ = n.publish_prekey();
                }
            }
            tick_pump(&mut nodes, now, &mut scratch);
        }

        // Now MEASURE steady-state for 30 idle seconds.
        let mut bytes = 0usize;
        for s in 0..30u64 {
            now += 1000;
            if s % 20 == 0 {
                for n in nodes.iter_mut() {
                    let _ = n.publish_service(
                        "presence".into(),
                        "x".into(),
                        String::new(),
                        vec![],
                        120_000,
                    );
                }
            }
            tick_pump(&mut nodes, now, &mut bytes);
        }

        // 30 idle seconds on an established link should move only a handful of presence adverts —
        // KB, not the tens-to-hundreds of KB the device shows. A flood means a gossip re-send loop.
        assert!(
            bytes < 20_000,
            "idle link flooded {bytes} bytes in 30s — steady-state gossip loop"
        );
    }

    #[test]
    fn regossip_does_not_reflood_the_directory() {
        // Field bug (resource exhaustion at scale): the 12s re-gossip cleared sent_adverts on every
        // link and re-sent the WHOLE directory — O(directory x links) every cycle. In a busy multi-
        // peer mesh that floods the few-KB/s BLE pipe (tx >> rx, since the peer just dedups) and
        // starves real messages — minutes-to-hours delivery. New adverts already propagate on their
        // own (not in sent_adverts), and prekeys/presence are periodically RE-published, so the full
        // re-flood is redundant. Assert the re-gossip moves only a trickle when nothing changed.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);

        // Populate node 0 with many adverts from distinct publishers (a busy mesh's directory).
        for i in 0..40u32 {
            let pubid = Identity::generate();
            let a = Advert::publish(
                &pubid,
                AdvertKind::Service {
                    service: "presence".into(),
                    title: format!("n{i}"),
                    summary: String::new(),
                    tags: vec![],
                },
                1_000,
                120_000,
                1,
            )
            .unwrap();
            nodes[0].publish(a);
        }
        net.pump(&mut nodes); // node 1 receives the 40 adverts once (initial sync)

        // Run 5 re-gossip cycles with NO new adverts; measure bytes moved. An unchanged directory
        // should move almost nothing — the bug re-floods all 40 adverts every 12s cycle.
        let mut bytes = 0usize;
        let mut now = 1_000u64;
        for _ in 0..5 {
            now += REGOSSIP_INTERVAL_MS + 1_000;
            for n in nodes.iter_mut() {
                n.tick(now);
            }
            for _ in 0..2000 {
                let mut any = false;
                for i in 0..nodes.len() {
                    let other = 1 - i;
                    for (link, b) in nodes[i].drain_outgoing() {
                        any = true;
                        bytes += b.len();
                        nodes[other].handle(BearerEvent::Data(link, b));
                    }
                }
                if !any {
                    break;
                }
            }
        }
        assert!(
            bytes < 5_000,
            "re-gossip re-flooded the directory: {bytes} bytes over 5 idle cycles"
        );
    }

    #[test]
    fn reconnect_does_not_reflood_the_directory_3node() {
        // Field bug (resource exhaustion): the per-link gossip dedup (sent_adverts/sent_bundles) lived
        // on the `Established` instance and was wiped on every (re)establishment. BLE links flap, so
        // each reconnect re-offered the WHOLE directory to the peer — the ~116 rec/s, byte-identical-
        // across-links flood that saturated the pipe and starved real messages. The fix keys the dedup
        // on the PEER (snapshot on Disconnect, restore on Up), so after the one-time initial sync a
        // flapping link moves ~nothing.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        // Full triangle, distinct link ids per neighbour.
        net.connect(&mut nodes, 0, 1, 1, 10);
        net.connect(&mut nodes, 0, 2, 2, 20);
        net.connect(&mut nodes, 1, 12, 2, 21);

        // Each node's OWN securing adverts (prekey + presence) — these SHOULD re-offer on every flap.
        for n in nodes.iter_mut() {
            n.publish_prekey().unwrap();
            let _ = n.publish_service(
                "presence".into(),
                "x".into(),
                String::new(),
                vec![],
                120_000,
            );
        }
        // A LARGE FOREIGN directory (40 other devices' service adverts) — the bulk that must NOT be
        // re-flooded on a flap. This is what made the field flood catastrophic.
        for i in 0..40u32 {
            let pubid = Identity::generate();
            let a = Advert::publish(
                &pubid,
                AdvertKind::Service {
                    service: "market".into(),
                    title: format!("item{i}"),
                    summary: String::new(),
                    tags: vec![],
                },
                1_000,
                120_000,
                1,
            )
            .unwrap();
            nodes[0].publish(a);
        }
        net.pump(&mut nodes);

        let pairs: [((usize, LinkId), (usize, LinkId)); 3] =
            [((0, 1), (1, 10)), ((0, 2), (2, 20)), ((1, 12), (2, 21))];

        // Flap every link 10x (BLE drop/reconnect) with NO new adverts. Count only encrypted records
        // (the flood); handshake packets legitimately re-cross on reconnect and are not the bug.
        let mut data_bytes = 0usize;
        for _ in 0..10 {
            for &((a, la), (b, lb)) in pairs.iter() {
                nodes[a].handle(BearerEvent::Disconnected(la));
                nodes[b].handle(BearerEvent::Disconnected(lb));
                nodes[a].handle(BearerEvent::Connected(la, Role::Initiator));
                nodes[b].handle(BearerEvent::Connected(lb, Role::Responder));
            }
            for _ in 0..2000 {
                let mut any = false;
                for i in 0..nodes.len() {
                    for (link, bts) in nodes[i].drain_outgoing() {
                        any = true;
                        if matches!(
                            postcard::from_bytes::<LinkPacket>(&bts),
                            Ok(LinkPacket::Data(_)) | Ok(LinkPacket::DataFrag { .. })
                        ) {
                            data_bytes += bts.len();
                        }
                        if let Some(&(j, jl)) = net.routes.get(&(i, link)) {
                            nodes[j].handle(BearerEvent::Data(jl, bts));
                        }
                    }
                }
                if !any {
                    break;
                }
            }
        }
        // Post-fix: each flap re-offers each node's ~2 OWN securing adverts (intended, so a state-lost
        // peer re-secures) but NOT the 40-advert FOREIGN bulk. Pre-fix wiped the per-link dedup on every
        // (re)establishment → re-flooded the whole directory (40 foreign × every flap → hundreds of KB).
        assert!(
            data_bytes < 100_000,
            "reconnect re-flooded the foreign directory: {data_bytes} bytes over 10 flap cycles"
        );
    }

    #[test]
    fn hostile_fragment_count_is_rejected_before_reassembly() {
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 10);
        let ct = match nodes[0].links.get_mut(&1) {
            Some(LinkState::Up(est)) => est.session.encrypt(b"x").unwrap(),
            _ => panic!("link established"),
        };
        let hostile = LinkPacket::DataFrag {
            idx: 0,
            cnt: (MAX_RECORD_FRAGMENTS as u16) + 1,
            ct,
        };
        nodes[1].handle(BearerEvent::Data(
            10,
            postcard::to_allocvec(&hostile).unwrap(),
        ));
        match nodes[1].links.get(&10) {
            Some(LinkState::Up(est)) => {
                assert!(est.frag_buf.is_empty());
                assert_eq!(est.frag_next, 0);
            }
            _ => panic!("link remains established"),
        }
    }

    #[test]
    fn fragmented_advert_cannot_hide_behind_an_empty_first_fragment() {
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 10);
        let mut advert_piece = vec![0u8; MAX_RECORD_PLAINTEXT - 1];
        advert_piece[0] = 1;
        let (empty, advert) = match nodes[0].links.get_mut(&1) {
            Some(LinkState::Up(est)) => (
                est.session.encrypt(&[]).unwrap(),
                est.session.encrypt(&advert_piece).unwrap(),
            ),
            _ => panic!("link established"),
        };

        nodes[1].on_record_frag(10, 0, 3, &empty);
        nodes[1].on_record_frag(10, 1, 3, &advert);

        match nodes[1].links.get(&10) {
            Some(LinkState::Up(est)) => {
                assert!(est.frag_buf.is_empty());
                assert_eq!(est.frag_next, 0);
            }
            _ => panic!("link remains established"),
        }
    }

    #[test]
    fn advert_wire_size_is_rejected_from_the_discriminant_before_decode() {
        let mut oversized = vec![0u8; MAX_ADVERT_LINK_BYTES + 1];
        oversized[0] = 1;
        assert!(advert_record_exceeds_limit(&oversized));
        oversized[0] = 0;
        assert!(!advert_record_exceeds_limit(&oversized));
        assert!(!advert_record_exceeds_limit(&vec![
            1;
            MAX_ADVERT_LINK_BYTES
        ]));
    }

    #[test]
    fn invalid_reserved_advert_flood_is_bounded_per_link_and_globally() {
        let publisher = Identity::generate();
        let valid = Advert::publish(
            &publisher,
            AdvertKind::HpsTopic {
                nonce: [0u8; 12],
                ct: vec![],
            },
            0,
            60_000,
            1,
        )
        .unwrap();
        let mut invalid = valid.clone();
        invalid.sig[0] ^= 1;
        let mut node = Node::new(Identity::generate());

        for link in 1..=8 {
            for _ in 0..MAX_ADVERTS_PER_LINK_WINDOW {
                node.on_advert(link, publisher.address(), invalid.clone());
            }
        }
        assert_eq!(node.advert_ingest_global.1, MAX_ADVERTS_GLOBAL_WINDOW);
        assert!(node
            .advert_ingest
            .values()
            .all(|(_, count)| *count <= MAX_ADVERTS_PER_LINK_WINDOW));

        node.on_advert(9, publisher.address(), valid.clone());
        assert!(!node.directory.contains(&valid.id));
        node.set_time(ADVERT_VERIFY_WINDOW_MS);
        node.on_advert(9, publisher.address(), valid.clone());
        assert!(node.directory.contains(&valid.id));
    }

    #[test]
    fn advert_eviction_clears_live_and_reconnect_dedup_metadata() {
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 10);
        nodes[0].directory = Directory::with_relay_cap(1);
        let publisher = Identity::generate();
        let make = |title: &str, seq| {
            Advert::publish(
                &publisher,
                AdvertKind::Service {
                    service: "market".into(),
                    title: title.into(),
                    summary: String::new(),
                    tags: vec![],
                },
                0,
                60_000,
                seq,
            )
            .unwrap()
        };
        let first = make("first", 1);
        let second = make("second", 2);
        nodes[0].on_advert(1, publisher.address(), first.clone());
        nodes[0].peer_sent.insert(
            [9u8; 32],
            PeerSent {
                adverts: HashSet::from([first.id]),
                bundles: HashSet::new(),
                last_seen_ms: 0,
            },
        );

        nodes[0].on_advert(1, publisher.address(), second.clone());

        match nodes[0].links.get(&1) {
            Some(LinkState::Up(est)) => {
                assert!(!est.sent_adverts.contains(&first.id));
                assert!(est.sent_adverts.contains(&second.id));
            }
            _ => panic!("link remains established"),
        }
        assert!(!nodes[0].peer_sent[&[9u8; 32]].adverts.contains(&first.id));
    }

    #[test]
    fn reconnect_dedup_table_is_capped_and_ttl_pruned() {
        let mut node = Node::new(Identity::generate());
        for index in 0..=MAX_PEER_SENT {
            let mut peer = [0u8; 32];
            peer[..8].copy_from_slice(&(index as u64).to_be_bytes());
            node.peer_sent.insert(
                peer,
                PeerSent {
                    last_seen_ms: index as u64,
                    ..Default::default()
                },
            );
        }
        node.prune_peer_sent();
        assert_eq!(node.peer_sent.len(), MAX_PEER_SENT);

        node.set_time(PEER_SENT_TTL_MS + MAX_PEER_SENT as u64);
        node.prune_peer_sent();
        assert!(node.peer_sent.is_empty());
    }

    #[test]
    fn prekey_published_after_connect_propagates_over_stable_link() {
        // Removing the re-gossip re-flood must NOT regress prekey propagation: a prekey published
        // AFTER the link is up must still reach the peer over the STABLE link (no reconnect), so a
        // deferred forward-secret message flushes. This was the "move out of range and back to send"
        // case — now served by immediate new-advert propagation, not a directory re-flood.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1); // connect with NO prekeys exchanged

        // node 0 sends to node 1 but has no prekey yet → deferred ("Securing"), nothing delivered.
        let _ = nodes[0]
            .send_message_traced(nodes[1].address(), "t".into(), b"hi".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);
        assert_eq!(
            nodes[1].take_inbox().len(),
            0,
            "no prekey yet → nothing delivered"
        );

        // node 1 publishes its prekey AFTER connect — over the stable link it must reach node 0.
        nodes[1].publish_prekey().unwrap();
        net.pump(&mut nodes);

        assert_eq!(
            nodes[1].take_inbox().len(),
            1,
            "deferred message must flush once node 1's prekey propagates over the stable link"
        );
    }

    #[test]
    fn send_to_connected_peer_is_forward_secret() {
        // Messaging a connected peer is always forward-secret (DESIGN.md §25): once prekeys
        // are exchanged, send_to opens a ratchet session and the message decrypts via
        // read_message — content is never static-sealed.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        exchange_prekeys(&mut net, &mut nodes);

        let peers = nodes[0].peers();
        assert_eq!(peers, vec![nodes[1].address()]);

        let sent = nodes[0]
            .send_to(
                &nodes[1].address(),
                "text/plain".into(),
                b"hello peer".to_vec(),
                false,
            )
            .unwrap();
        assert!(sent.is_some());
        net.pump(&mut nodes);

        let inbox = nodes[1].take_inbox();
        assert_eq!(inbox.len(), 1);
        let m = nodes[1]
            .read_message(&inbox[0])
            .unwrap()
            .expect("a user message");
        assert_eq!(m.body, b"hello peer");
        assert!(
            nodes[1].has_session(&nodes[0].address()),
            "forward-secret session established"
        );

        // Sending to an unconnected address yields None, not an error.
        assert!(nodes[0]
            .send_to(&[9u8; 32], "t".into(), vec![], false)
            .unwrap()
            .is_none());
    }

    #[test]
    fn message_status_progresses_to_delivered() {
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        exchange_prekeys(&mut net, &mut nodes); // content is ratcheted — need prekeys (§25)

        let id = nodes[0]
            .send_to(
                &nodes[1].address(),
                "text/plain".into(),
                b"yo".to_vec(),
                true,
            )
            .unwrap()
            .unwrap();
        // Direct delivery to the destination isn't a relay handoff, so the relay
        // count stays 0 (it shows as Delivered once the ACK returns, not "Sent N").
        assert_eq!(nodes[0].message_status(&id), Some((0, false, 0, 0)));

        net.pump(&mut nodes);
        accept_all(&mut nodes[1]);
        net.pump(&mut nodes);

        let (relayed, delivered, hops, _) = nodes[0].message_status(&id).unwrap();
        assert_eq!(relayed, 0, "direct delivery is not counted as a relay peer");
        assert!(delivered, "ACK came back across the network → Delivered");
        assert_eq!(hops, 1, "direct delivery → 1 forward hop");
    }

    #[test]
    fn direct_destination_is_not_sprayed_to_a_present_relay() {
        // 0 is directly linked to BOTH the destination (1) and a relay (2). Sending
        // 0→1 must deliver directly and NOT strand a sprayed copy in 2's relay queue.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 2); // 0 <-> 1 (destination)
        net.connect(&mut nodes, 0, 3, 2, 4); // 0 <-> 2 (relay)
        exchange_prekeys(&mut net, &mut nodes); // content is ratcheted — need prekeys (§25)

        let id = nodes[0]
            .send_message_traced(
                nodes[1].address(),
                "text/plain".into(),
                b"hi".to_vec(),
                true,
            )
            .unwrap();
        net.pump(&mut nodes);

        // Destination got it; the relay holds nothing for it.
        assert_eq!(
            nodes[1].take_inbox().len(),
            1,
            "destination received directly"
        );
        accept_all(&mut nodes[1]);
        net.pump(&mut nodes);
        assert!(
            nodes[2].queue().is_empty(),
            "relay should not be holding a needless sprayed copy"
        );
        let (relayed, delivered, hops, _) = nodes[0].message_status(&id).unwrap();
        assert_eq!(relayed, 0, "no relay handoffs — delivered directly");
        assert!(delivered);
        assert_eq!(hops, 1);
    }

    #[test]
    fn content_never_static_seals_defers_until_prekey() {
        // The lock bug, fixed: device-to-device content is never static-sealed (DESIGN.md §25).
        // Sending before we know the peer's prekey queues the content (no insecure send); once
        // the prekey gossips in, it flushes forward-secret and a session forms (the 🔒).
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);

        // No prekeys yet → the send is deferred: a handle comes back, but nothing is delivered
        // and no static-sealed PeerMessage goes on the wire.
        let id = nodes[0]
            .send_message_traced(nodes[1].address(), "t".into(), b"secret".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        assert!(
            nodes[1].take_inbox().is_empty(),
            "no static-sealed content while deferred"
        );
        assert!(!nodes[1].has_session(&nodes[0].address()), "no session yet");

        // Prekeys gossip in → the queued content flushes forward-secret and decrypts.
        nodes[1].publish_prekey().unwrap();
        nodes[0].publish_prekey().unwrap();
        net.pump(&mut nodes);

        let inbox = nodes[1].take_inbox();
        assert_eq!(
            inbox.len(),
            1,
            "deferred content sends once a session can form"
        );
        assert!(
            matches!(
                nodes[1].open(&inbox[0]).unwrap(),
                Payload::SessionInit { .. }
            ),
            "ratcheted, never a static PeerMessage"
        );
        let m = nodes[1]
            .read_message(&inbox[0])
            .unwrap()
            .expect("a user message");
        nodes[1].accept_inbox(&inbox[0].id()).unwrap();
        net.pump(&mut nodes);
        assert_eq!(m.body, b"secret");
        assert!(
            nodes[1].has_session(&nodes[0].address()),
            "🔒 session established"
        );
        // Delivery status follows the original handle through the deferral.
        let (_, delivered, _, _) = nodes[0].message_status(&id).unwrap();
        assert!(delivered, "the ACK lands on the original handle");
    }

    #[test]
    fn forward_secret_session_end_to_end() {
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        net.pump(&mut nodes);

        // Both advertise prekeys; gossip distributes them to each other.
        nodes[0].publish_prekey().unwrap();
        nodes[1].publish_prekey().unwrap();
        net.pump(&mut nodes);

        // 0 → 1 should open a forward-secret session (prekey known), not a static seal.
        let id = nodes[0]
            .send_message_traced(
                nodes[1].address(),
                "text/plain".into(),
                b"secret hi".to_vec(),
                true,
            )
            .unwrap();
        net.pump(&mut nodes);

        let inbox = nodes[1].take_inbox();
        assert_eq!(inbox.len(), 1);
        assert!(
            matches!(
                nodes[1].open(&inbox[0]).unwrap(),
                Payload::SessionInit { .. }
            ),
            "should ride a session, not a static PeerMessage"
        );
        let msg = nodes[1].read_message(&inbox[0]).unwrap().unwrap();
        assert_eq!(msg.body, b"secret hi");
        assert_eq!(msg.from, nodes[0].address());
        nodes[1].accept_inbox(&inbox[0].id()).unwrap();
        net.pump(&mut nodes);

        // The ACK returned across the network → Delivered.
        let (_, delivered, _, _) = nodes[0].message_status(&id).unwrap();
        assert!(delivered, "session message should still ACK back");

        // 1 → 0 reply rides the same session (responder now has a sending chain).
        nodes[1]
            .send_message_traced(
                nodes[0].address(),
                "text/plain".into(),
                b"reply".to_vec(),
                false,
            )
            .unwrap();
        net.pump(&mut nodes);
        let inbox0 = nodes[0].take_inbox();
        assert_eq!(inbox0.len(), 1);
        let reply = nodes[0].read_message(&inbox0[0]).unwrap().unwrap();
        assert_eq!(reply.body, b"reply");
    }

    #[test]
    fn relays_across_an_intermediate_node() {
        // 0 <-> 1 <-> 2; 0 and 2 never connect directly. Message 0 -> 2.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 10, 1, 11);
        net.connect(&mut nodes, 1, 12, 2, 13);

        let b = msg(&nodes[0], &nodes[2], b"relay me");
        nodes[0].submit(b);
        net.pump(&mut nodes);

        assert!(
            nodes[1].take_inbox().is_empty(),
            "relay must not absorb the bundle"
        );
        let inbox = nodes[2].take_inbox();
        assert_eq!(inbox.len(), 1);
        match inbox[0].open(&nodes[2].identity).unwrap() {
            Payload::PeerMessage { body, .. } => assert_eq!(body, b"relay me"),
            _ => panic!("wrong payload"),
        }
    }

    #[test]
    fn delivery_ack_vaccinates_relays() {
        // 0 <-> 1 <-> 2. 0 → 2 (request ack). After delivery, the ACK floods back and
        // purges the relay's (1) copy and releases the source's (0) copy.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 10, 1, 11);
        net.connect(&mut nodes, 1, 12, 2, 13);
        exchange_prekeys(&mut net, &mut nodes); // content is ratcheted — need prekeys (§25)

        let id = nodes[0]
            .send_message_traced(
                nodes[2].address(),
                "text/plain".into(),
                b"relay me".to_vec(),
                true,
            )
            .unwrap();
        net.pump(&mut nodes);
        accept_all(&mut nodes[2]);
        net.pump(&mut nodes);

        let (_, delivered, _, _) = nodes[0].message_status(&id).unwrap();
        assert!(delivered, "should be delivered across the relay");
        assert!(
            nodes[1].queue().is_empty(),
            "relay copy purged by the delivery-ACK vaccine"
        );
        assert!(
            nodes[0].queue().is_empty(),
            "source releases its copy on ACK"
        );
    }

    #[test]
    fn custody_beacon_tells_a_peer_what_we_hold_so_it_suppresses_reoffers() {
        // §35 mode-1 custody beacon: node 1 holds a bundle and, with emit_have on, advertises it
        // on connect. Node 0 records it in peer_has for that link and will not re-offer it.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        nodes[1].set_emit_have(true);

        // Node 1 holds a foreign bundle X (admit it from nowhere so it is in the store).
        let from = Identity::generate();
        let to = Identity::generate();
        let x = Bundle::create(
            &from,
            Destination::Device(to.address()),
            &to.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"held".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap();
        let xid = x.id();
        nodes[1].on_bundle(7, x);
        assert!(nodes[1].store.contains(&xid));

        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 10, 1, 11); // node 0's link to node 1 is link 10
        net.pump(&mut nodes);

        // Node 0 learned, over the authenticated link, that node 1 already holds X.
        assert!(
            nodes[0].link_peer_has(10).contains(&xid),
            "the custody beacon populated peer_has, so X will not be re-offered to node 1"
        );
    }

    #[test]
    fn trace_records_each_relay_hop() {
        // 0 <-> 1 <-> 2; a message 0 → 2 should arrive carrying the short address of
        // each node that forwarded it (DESIGN.md §27).
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 10, 1, 11);
        net.connect(&mut nodes, 1, 12, 2, 13);
        let s0 = short_addr(&nodes[0].address());
        let s1 = short_addr(&nodes[1].address());

        let b = msg(&nodes[0], &nodes[2], b"trace me");
        nodes[0].submit(b);
        net.pump(&mut nodes);

        let inbox = nodes[2].take_inbox();
        assert_eq!(inbox.len(), 1);
        let trace = inbox[0].trace();
        assert_eq!(trace.len(), 2, "exactly the two forwarders, in order");
        // Provenance privacy (§27): device hops carry the count + app label but NOT the address —
        // they're anonymized to a zeroed short-addr, so the recipient can't see WHICH devices relayed.
        let _ = (s0, s1);
        assert!(
            trace.iter().all(|h| h.node == ShortAddr::default()),
            "device hops anonymized (no address)"
        );
        // App defaults to the shared fabric here (no set_app), stamped on each hop.
        assert!(
            trace.iter().all(|h| h.app == short_app(&crate::FABRIC_APP)),
            "carrier app stamped"
        );
    }

    #[test]
    fn relay_and_source_learn_route_from_returning_ack() {
        // 0 <-> 1 <-> 2. After 0 → 2 is delivered and the ACK floods back, the relay (1)
        // has learned it sits on the 0↔2 route — in both directions — and the source (0)
        // has learned it can reach 2 (DESIGN.md §27).
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 10, 1, 11);
        net.connect(&mut nodes, 1, 12, 2, 13);
        exchange_prekeys(&mut net, &mut nodes); // content is ratcheted — need prekeys (§25)
        let a0 = nodes[0].address();
        let a2 = nodes[2].address();

        assert!(
            !nodes[1].knows_route(&a2),
            "relay starts with no learned route"
        );
        nodes[0]
            .send_message_traced(a2, "text/plain".into(), b"learn me".to_vec(), true)
            .unwrap();
        net.pump(&mut nodes);
        accept_all(&mut nodes[2]);
        net.pump(&mut nodes);

        assert!(
            nodes[1].knows_route(&a0),
            "relay learned the route toward the source"
        );
        assert!(
            nodes[1].knows_route(&a2),
            "relay learned the route toward the destination"
        );
        assert!(
            nodes[0].knows_route(&a2),
            "source learned it can reach the destination"
        );
    }

    #[test]
    fn link_is_encrypted_on_the_wire() {
        // The plaintext must never appear in the bytes crossing the bearer.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let a = 0;
        nodes[a].handle(BearerEvent::Connected(1, Role::Initiator));
        nodes[1].handle(BearerEvent::Connected(1, Role::Responder));

        // Shuttle handshake by hand and capture all bytes.
        let mut captured: Vec<u8> = Vec::new();
        for _ in 0..8 {
            let out0 = nodes[0].drain_outgoing();
            let out1 = nodes[1].drain_outgoing();
            for (_, b) in &out0 {
                captured.extend_from_slice(b);
            }
            for (_, b) in &out1 {
                captured.extend_from_slice(b);
            }
            for (_, b) in out0 {
                nodes[1].handle(BearerEvent::Data(1, b));
            }
            for (_, b) in out1 {
                nodes[0].handle(BearerEvent::Data(1, b));
            }
        }

        let secret = b"top secret payload bytes";
        let bundle = msg(&nodes[0], &nodes[1], secret);
        nodes[0].submit(bundle);
        for (_, b) in nodes[0].drain_outgoing() {
            captured.extend_from_slice(&b);
            nodes[1].handle(BearerEvent::Data(1, b));
        }

        assert_eq!(nodes[1].take_inbox().len(), 1);
        assert!(
            !captured.windows(secret.len()).any(|w| w == secret),
            "plaintext leaked onto the wire"
        );
    }

    fn msg_ack(from: &Node, to: &Node, body: &[u8]) -> Bundle {
        Bundle::create(
            &from.identity,
            Destination::Device(to.address()),
            &to.identity.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: body.to_vec(),
            },
            BundleOpts {
                flags: BundleFlags {
                    request_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn ack_returns_and_clears_sender_pending() {
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);

        let b = msg_ack(&nodes[0], &nodes[1], b"please confirm");
        nodes[0].submit(b);
        assert_eq!(
            nodes[0].pending_count(),
            1,
            "sender tracks the unacked bundle"
        );
        net.pump(&mut nodes);

        assert_eq!(nodes[1].take_inbox().len(), 1, "recipient got the message");
        accept_all(&mut nodes[1]);
        net.pump(&mut nodes);
        assert!(
            nodes[0].take_inbox().is_empty(),
            "the ACK is consumed, not inboxed"
        );
        assert_eq!(
            nodes[0].pending_count(),
            0,
            "ACK cleared the sender's pending entry"
        );
        assert_eq!(
            nodes[1].pending_count(),
            0,
            "ACKs are not themselves tracked"
        );
    }

    #[test]
    fn unacked_bundle_expires_after_its_lifetime() {
        let mut node = Node::new(Identity::generate());
        let other = Node::new(Identity::generate());
        // No links: nothing can deliver, so the bundle stays pending until expiry.
        let b = Bundle::create(
            &node.identity,
            Destination::Device(other.address()),
            &other.identity.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"x".to_vec(),
            },
            BundleOpts {
                created_at: 0,
                lifetime_ms: 1_000,
                flags: BundleFlags {
                    request_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        node.submit(b);
        assert_eq!(node.pending_count(), 1);
        node.tick(500); // before lifetime — still pending
        assert_eq!(node.pending_count(), 1);
        node.tick(2_000); // past lifetime — given up
        assert_eq!(node.pending_count(), 0);
    }

    #[test]
    fn discover_presence_two_hops_away_and_message_it() {
        // 0 <-> 1 <-> 2. 0 and 2 never connect directly. 0 publishes an app-level
        // "presence" service carrying its display name; 2 discovers it via 1's gossip,
        // then messages 0's address — routed through 1. (The name↔address tie is an
        // app concern; the protocol only knows the service advert — DESIGN.md §4.)
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 10, 1, 11);
        net.connect(&mut nodes, 1, 12, 2, 13);
        exchange_prekeys(&mut net, &mut nodes); // content is ratcheted — need prekeys (§25)

        nodes[0]
            .publish_service(
                "presence".into(),
                "Alice".into(),
                String::new(),
                vec![],
                600_000,
            )
            .unwrap();
        net.pump(&mut nodes);

        let found = nodes[2].browse("presence", None);
        let alice = found
            .iter()
            .find(|a| a.body.publisher == nodes[0].address());
        let alice = alice.expect("2 should discover Alice's presence via 1");
        assert!(matches!(&alice.body.kind, AdvertKind::Service { title, .. } if title == "Alice"));
        assert_eq!(alice.hops, 2, "Alice is two hops away via node 1");
        let addr = alice.body.publisher;

        nodes[2]
            .send_message_traced(addr, "text/plain".into(), b"hi Alice".to_vec(), false)
            .unwrap();
        net.pump(&mut nodes);

        let inbox = nodes[0].take_inbox();
        assert_eq!(inbox.len(), 1);
        let m = nodes[0]
            .read_message(&inbox[0])
            .unwrap()
            .expect("a user message");
        assert_eq!(m.body, b"hi Alice");
    }

    #[test]
    fn discovery_gossips_over_links() {
        // 0 publishes a market advert; 2 discovers it transitively through 1.
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 10, 1, 11);
        net.connect(&mut nodes, 1, 12, 2, 13);

        let advert = Advert::publish(
            &nodes[0].identity,
            AdvertKind::Service {
                service: "market".into(),
                title: "Bike for sale".into(),
                summary: "blue".into(),
                tags: vec!["bicycle".into()],
            },
            0,
            600_000,
            1,
        )
        .unwrap();
        nodes[0].publish(advert);
        net.pump(&mut nodes);

        let hits = nodes[2].directory.browse("market", Some("bicycle"));
        assert_eq!(hits.len(), 1, "advert should reach node 2 via node 1");
        assert_eq!(hits[0].body.publisher, nodes[0].address());
    }

    #[test]
    fn hps_service_subscribe_publish_round_trips() {
        // A node hosts an hps:// service; a subscriber requests its keys (open access) and
        // then receives the owner's signed broadcasts, verified against the service key. A
        // subscriber can read but never forge a broadcast (§32).
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);

        // Node 0 hosts a service at "news"; node 1 subscribes and is handed the keys.
        let svc_pubkey = nodes[0].register_service(
            "news",
            crate::hps::ServiceKind::Service,
            crate::hps::AccessMode::Open,
            crate::hps::Visibility::Private,
        );
        assert!(svc_pubkey.is_some(), "a service mints a signing key");
        nodes[1].hps_subscribe(nodes[0].address(), "news").unwrap();
        net.pump(&mut nodes);

        // A subscriber can't publish to a service it doesn't host — only the owner broadcasts.
        assert!(nodes[1].hps_publish("news", b"forged").is_err());

        // The owner broadcasts; the subscriber decrypts + verifies against the service key.
        nodes[0].hps_publish("news", b"breaking").unwrap();
        net.pump(&mut nodes);

        let msgs = take_hps_and_accept(&mut nodes[1]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].path, "news");
        assert_eq!(msgs[0].body, b"breaking");
        assert_eq!(msgs[0].sender, nodes[0].address());
    }

    #[test]
    fn hps_channel_members_read_each_others_posts() {
        // A channel: anyone holding the content key reads and writes, and every post is
        // verified against its writer's own address. Node 0 hosts; members 1 and 2 join,
        // then member 1's post reaches member 2, attributed to member 1 (§32).
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1); // 0 <-> 1
        net.connect(&mut nodes, 0, 2, 2, 2); // 0 <-> 2
        net.connect(&mut nodes, 1, 3, 2, 3); // 1 <-> 2

        assert!(
            nodes[0]
                .register_service(
                    "lobby",
                    crate::hps::ServiceKind::Channel,
                    crate::hps::AccessMode::Open,
                    crate::hps::Visibility::Private
                )
                .is_none(),
            "a channel has no service signing key"
        );
        nodes[1].hps_subscribe(nodes[0].address(), "lobby").unwrap();
        nodes[2].hps_subscribe(nodes[0].address(), "lobby").unwrap();
        net.pump(&mut nodes);

        nodes[1].hps_publish("lobby", b"hi all").unwrap();
        net.pump(&mut nodes);

        let msgs = take_hps_and_accept(&mut nodes[2]);
        assert_eq!(msgs.len(), 1, "the post floods to the other member");
        assert_eq!(msgs[0].body, b"hi all");
        assert_eq!(
            msgs[0].sender,
            nodes[1].address(),
            "verified as member 1's post"
        );
    }

    #[test]
    fn large_broadcast_fragments_across_the_link() {
        // hps:// broadcasts aren't carrier-chunked (no single dst), so a big channel post
        // exceeds one Noise message (max 65535B) and must fragment at the link layer, or it
        // is silently dropped at encrypt (DESIGN.md §20).
        let mut nodes = [
            Node::new(Identity::generate()),
            Node::new(Identity::generate()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);

        nodes[0].register_service(
            "lobby",
            crate::hps::ServiceKind::Channel,
            crate::hps::AccessMode::Open,
            crate::hps::Visibility::Private,
        );
        nodes[1].hps_subscribe(nodes[0].address(), "lobby").unwrap();
        net.pump(&mut nodes);

        // ~200KB body → the sealed broadcast bundle far exceeds one Noise message.
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        nodes[0].hps_publish("lobby", &big).unwrap();
        net.pump(&mut nodes);

        let msgs = take_hps_and_accept(&mut nodes[1]);
        assert_eq!(
            msgs.len(),
            1,
            "the large broadcast reassembled and decrypted"
        );
        assert_eq!(msgs[0].body, big, "bytes intact across link fragmentation");
    }

    #[test]
    fn hps_publish_to_unregistered_path_errors() {
        // Publishing to a path we neither host nor subscribe to is an error (§32).
        let mut node = Node::new(Identity::generate());
        assert!(node.hps_publish("nope", b"x").is_err());
    }

    /// Helper: a node on a real app secret (so hps isolation is active, not the open fabric).
    fn app_node(secret: u8) -> Node<MemoryStore> {
        Node::with_store_app(
            Identity::generate(),
            MemoryStore::new(),
            crate::app::AppKeys::from_secret([secret; 32]),
        )
    }

    #[test]
    fn hps_channel_host_receives_member_posts() {
        // A channel is group chat: the HOST must also receive members' posts, even though it
        // keeps the topic in `services` (not `subscriptions`). Regression for "host can send but
        // doesn't get messages from other members."
        let mut nodes = [app_node(4), app_node(4)];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        nodes[0].register_service(
            "lobby",
            crate::hps::ServiceKind::Channel,
            crate::hps::AccessMode::Open,
            crate::hps::Visibility::Private,
        );
        nodes[1].hps_subscribe(nodes[0].address(), "lobby").unwrap();
        net.pump(&mut nodes);

        // Member 1 posts; the host (node 0) must receive it.
        nodes[1].hps_publish("lobby", b"hi host").unwrap();
        net.pump(&mut nodes);
        let host_msgs = take_hps_and_accept(&mut nodes[0]);
        assert_eq!(host_msgs.len(), 1, "host receives the member's post");
        assert_eq!(host_msgs[0].body, b"hi host");
        assert_eq!(host_msgs[0].sender, nodes[1].address());
    }

    #[test]
    fn hps_request_to_join_needs_approval() {
        // RequestToJoin: a subscribe request is queued, not auto-keyed. The requester can't read
        // until the host approves (§32).
        let mut nodes = [app_node(5), app_node(5)];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        nodes[0].register_service(
            "lobby",
            crate::hps::ServiceKind::Channel,
            crate::hps::AccessMode::RequestToJoin,
            crate::hps::Visibility::Private,
        );
        let requester = nodes[1].address();
        nodes[1].hps_subscribe(nodes[0].address(), "lobby").unwrap();
        net.pump(&mut nodes);
        assert_eq!(
            nodes[0].hps_pending("lobby"),
            vec![requester],
            "queued, not keyed"
        );

        nodes[0].hps_publish("lobby", b"members only").unwrap();
        net.pump(&mut nodes);
        assert!(
            nodes[1].take_hps_messages().is_empty(),
            "no keys yet → can't read"
        );

        nodes[0].hps_approve("lobby", requester).unwrap();
        net.pump(&mut nodes);
        nodes[0].hps_publish("lobby", b"welcome").unwrap();
        net.pump(&mut nodes);
        let msgs = take_hps_and_accept(&mut nodes[1]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, b"welcome");
    }

    #[test]
    fn hps_invite_then_accept() {
        // Invite: a topic can't be self-joined; only a host-initiated invite, once accepted,
        // yields keys (§32, consent-based).
        let mut nodes = [app_node(6), app_node(6)];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        nodes[0].register_service(
            "vip",
            crate::hps::ServiceKind::Channel,
            crate::hps::AccessMode::Invite,
            crate::hps::Visibility::Private,
        );
        let dest = nodes[1].address();

        // Self-join is ignored for an Invite topic.
        nodes[1].hps_subscribe(nodes[0].address(), "vip").unwrap();
        net.pump(&mut nodes);
        nodes[0].hps_publish("vip", b"x").unwrap();
        net.pump(&mut nodes);
        assert!(
            nodes[1].take_hps_messages().is_empty(),
            "can't self-join an invite topic"
        );

        // Host invites; destination sees it and accepts.
        nodes[0].hps_invite("vip", dest).unwrap();
        net.pump(&mut nodes);
        let invites = nodes[1].take_hps_invites();
        assert_eq!(invites.len(), 1);
        assert_eq!(invites[0].path, "vip");
        nodes[1]
            .hps_accept_invite(nodes[0].address(), "vip")
            .unwrap();
        net.pump(&mut nodes);

        nodes[0].hps_publish("vip", b"hi vip").unwrap();
        net.pump(&mut nodes);
        let msgs = take_hps_and_accept(&mut nodes[1]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, b"hi vip");
    }

    #[test]
    fn hps_app_secret_isolates_join() {
        // A node with a DIFFERENT app secret can't join an Open topic — the host rejects the
        // foreign app id + proof, so no keys are handed off (§32 app isolation).
        let mut nodes = [app_node(1), app_node(2)];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        nodes[0].register_service(
            "lobby",
            crate::hps::ServiceKind::Channel,
            crate::hps::AccessMode::Open,
            crate::hps::Visibility::Private,
        );
        nodes[1].hps_subscribe(nodes[0].address(), "lobby").unwrap();
        net.pump(&mut nodes);
        nodes[0].hps_publish("lobby", b"members only").unwrap();
        net.pump(&mut nodes);
        assert!(
            nodes[1].take_hps_messages().is_empty(),
            "foreign-app node can't join"
        );
        assert!(
            nodes[0].hps_members("lobby").is_empty(),
            "host recorded no foreign member"
        );
    }

    #[test]
    fn hps_rekey_revokes_removed_member() {
        // Selective forward rotation: after rekey-with-remove, the removed member can no longer
        // read new posts while the retained member can (§32 revocation).
        let mut nodes = [app_node(7), app_node(7), app_node(7)];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        net.connect(&mut nodes, 0, 2, 2, 2);
        net.connect(&mut nodes, 1, 3, 2, 3);
        nodes[0].register_service(
            "room",
            crate::hps::ServiceKind::Channel,
            crate::hps::AccessMode::Open,
            crate::hps::Visibility::Private,
        );
        let m2 = nodes[2].address();
        nodes[1].hps_subscribe(nodes[0].address(), "room").unwrap();
        nodes[2].hps_subscribe(nodes[0].address(), "room").unwrap();
        net.pump(&mut nodes);

        nodes[0].hps_publish("room", b"v1").unwrap();
        net.pump(&mut nodes);
        assert_eq!(take_hps_and_accept(&mut nodes[1]).len(), 1, "m1 reads v1");
        assert_eq!(take_hps_and_accept(&mut nodes[2]).len(), 1, "m2 reads v1");

        // Rotate, removing member 2.
        nodes[0].hps_rekey("room", None, &[m2]).unwrap();
        net.pump(&mut nodes);
        nodes[0].hps_publish("room", b"v2").unwrap();
        net.pump(&mut nodes);
        assert_eq!(
            take_hps_and_accept(&mut nodes[1]).len(),
            1,
            "retained m1 reads v2"
        );
        assert!(
            nodes[2].take_hps_messages().is_empty(),
            "removed m2 can't read v2"
        );
    }

    #[test]
    fn hps_subscription_expectations_are_bounded_expired_and_restart_safe() {
        let secret = Identity::generate().to_secret_bytes();
        let host = Identity::generate().address();
        let mut node = Node::from_identity_secret(&secret);
        node.set_time(1_000);
        for index in 0..=MAX_HPS_SUBSCRIBE_PENDING {
            node.expect_hps_keys(host, &format!("room-{index}"))
                .unwrap();
        }
        assert_eq!(node.hps_subscribe_pending.len(), MAX_HPS_SUBSCRIBE_PENDING);
        assert_eq!(
            node.store.list_kv("hps/sub-pending/").len(),
            MAX_HPS_SUBSCRIBE_PENDING
        );
        assert!(node
            .expect_hps_keys(host, &"x".repeat(MAX_HPS_PATH_BYTES + 1))
            .is_err());

        let store = node.clone_store();
        let mut restored = Node::with_store(Identity::from_secret_bytes(&secret), store);
        assert_eq!(
            restored.hps_subscribe_pending.len(),
            MAX_HPS_SUBSCRIBE_PENDING
        );
        restored.tick(1_000 + HPS_SUBSCRIBE_PENDING_TTL_MS);
        assert!(restored.hps_subscribe_pending.is_empty());
        assert!(restored.store.list_kv("hps/sub-pending/").is_empty());

        let other_host = Identity::generate().address();
        restored.expect_hps_keys(other_host, "room-0").unwrap();
        assert_eq!(restored.hps_subscribe_pending["room-0"].host, other_host);
    }

    #[test]
    fn hps_expectation_create_replace_and_expiry_are_critical() {
        let host = Identity::generate();
        let mut subscriber = Node::with_store(Identity::generate(), FaultStore::default());
        subscriber.set_time(100);
        subscriber.store.fail_critical_put_prefix = Some("hps/sub-pending/".into());
        assert!(subscriber.hps_subscribe(host.address(), "room").is_err());
        assert!(subscriber.hps_subscribe_pending.is_empty());
        assert!(subscriber.store.list_kv("hps/sub-pending/").is_empty());
        assert!(subscriber.store.have().ids.is_empty());
        assert!(subscriber.drain_outgoing().is_empty());

        subscriber.store.fail_critical_put_prefix = None;
        subscriber.expect_hps_keys(host.address(), "room").unwrap();
        let original = subscriber.hps_subscribe_pending["room"];
        subscriber.set_time(200);
        subscriber.store.fail_critical_put_prefix = Some("hps/sub-pending/".into());
        assert!(subscriber.expect_hps_keys(host.address(), "room").is_err());
        assert_eq!(
            subscriber.hps_subscribe_pending["room"].expires_at_ms,
            original.expires_at_ms
        );

        subscriber.store.fail_critical_put_prefix = None;
        subscriber.expect_hps_keys(host.address(), "room").unwrap();
        let replacement = subscriber.hps_subscribe_pending["room"];
        assert!(replacement.expires_at_ms > original.expires_at_ms);

        subscriber.set_time(replacement.expires_at_ms);
        subscriber.store.fail_critical_remove_prefix = Some("hps/sub-pending/".into());
        assert!(subscriber.expire_hps_subscribe_pending().is_err());
        assert!(subscriber.hps_subscribe_pending.contains_key("room"));
        assert!(subscriber
            .store
            .get_kv(&Node::<FaultStore>::hps_subscribe_pending_key("room"))
            .is_some());
    }

    #[test]
    fn restored_hps_expectation_holds_keys_until_anchor_then_retries_or_expires() {
        let app = crate::app::AppKeys::from_secret([42u8; 32]);
        let host = Identity::generate();
        let subscriber_secret = Identity::generate().to_secret_bytes();
        let mut subscriber = Node::with_store_app(
            Identity::from_secret_bytes(&subscriber_secret),
            MemoryStore::new(),
            app.clone(),
        );
        subscriber.set_time(1_000);
        subscriber.expect_hps_keys(host.address(), "fresh").unwrap();
        let expiry = subscriber.hps_subscribe_pending["fresh"].expires_at_ms;
        let keys = Bundle::create(
            &host,
            Destination::Device(subscriber.address()),
            &subscriber.address(),
            &Payload::HpsKeys {
                path: "fresh".into(),
                content_key: [7u8; 32],
                service_pubkey: None,
                epoch: 1,
            },
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();
        let keys_id = keys.id();
        let store = subscriber.clone_store();
        let mut subscriber = Node::with_store_app(
            Identity::from_secret_bytes(&subscriber_secret),
            store,
            app.clone(),
        );
        subscriber.set_time(1_001);
        subscriber.on_bundle(1, keys.clone());
        assert!(!subscriber.subscriptions.contains_key("fresh"));
        assert!(!subscriber.store.seen(&keys_id));

        subscriber.tick(1_001);
        subscriber.on_bundle(1, keys);
        assert_eq!(subscriber.subscriptions["fresh"].content_key, [7u8; 32]);

        let mut stale = Node::with_store_app(
            Identity::from_secret_bytes(&subscriber_secret),
            MemoryStore::new(),
            app,
        );
        stale.set_time(1_000);
        stale.expect_hps_keys(host.address(), "stale").unwrap();
        let stale_store = stale.clone_store();
        let mut stale =
            Node::with_store(Identity::from_secret_bytes(&subscriber_secret), stale_store);
        stale.tick(expiry);
        assert!(!stale.hps_subscribe_pending.contains_key("stale"));
        assert!(stale.store.list_kv("hps/sub-pending/").is_empty());
    }

    #[test]
    fn hps_keys_require_the_persisted_expected_host_and_never_overwrite() {
        let app = crate::app::AppKeys::from_secret([10u8; 32]);
        let mut host = Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone());
        host.register_service(
            "room",
            crate::hps::ServiceKind::Channel,
            crate::hps::AccessMode::Open,
            crate::hps::Visibility::Private,
        );
        let cfg = host.services["room"].clone();
        let host_addr = host.address();
        let sub_secret = Identity::generate().to_secret_bytes();
        let mut sub = Node::with_store_app(
            Identity::from_secret_bytes(&sub_secret),
            MemoryStore::new(),
            app.clone(),
        );
        sub.hps_subscribe(host_addr, "room").unwrap();
        assert_eq!(sub.hps_subscribe_pending["room"].host, host_addr);

        let store = sub.clone_store();
        let mut sub =
            Node::with_store_app(Identity::from_secret_bytes(&sub_secret), store, app.clone());
        assert_eq!(
            sub.hps_subscribe_pending["room"].host, host_addr,
            "the expected host/path handshake survives restart"
        );

        let attacker = Identity::generate();
        let forged = Bundle::create(
            &attacker,
            Destination::Device(sub.address()),
            &sub.address(),
            &Payload::HpsKeys {
                path: "room".into(),
                content_key: [0x44; 32],
                service_pubkey: None,
                epoch: cfg.epoch,
            },
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();
        sub.on_bundle(1, forged);
        assert!(!sub.subscriptions.contains_key("room"));
        assert_eq!(sub.hps_subscribe_pending["room"].host, host_addr);
        sub.tick(1);

        let genuine = Bundle::create(
            &host.identity,
            Destination::Device(sub.address()),
            &sub.address(),
            &Payload::HpsKeys {
                path: "room".into(),
                content_key: cfg.content_key,
                service_pubkey: cfg.service_pubkey(),
                epoch: cfg.epoch,
            },
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();
        sub.on_bundle(2, genuine);
        assert_eq!(sub.subscriptions["room"].content_key, cfg.content_key);
        assert!(!sub.hps_subscribe_pending.contains_key("room"));
        assert!(sub
            .store
            .get_kv(&Node::<MemoryStore>::hps_subscribe_pending_key("room"))
            .is_none());

        // Even the expected host cannot replace installed keys with an unsolicited second HpsKeys.
        let overwrite = Bundle::create(
            &host.identity,
            Destination::Device(sub.address()),
            &sub.address(),
            &Payload::HpsKeys {
                path: "room".into(),
                content_key: [0x55; 32],
                service_pubkey: None,
                epoch: cfg.epoch + 1,
            },
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();
        sub.on_bundle(3, overwrite);
        assert_eq!(sub.subscriptions["room"].content_key, cfg.content_key);
    }

    #[test]
    fn hps_rekey_requires_stored_host_and_rejects_path_collision_after_restart() {
        let app = crate::app::AppKeys::from_secret([11u8; 32]);
        let host_a = Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone());
        let host_b = Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone());
        let sub_secret = Identity::generate().to_secret_bytes();
        let mut sub = Node::with_store_app(
            Identity::from_secret_bytes(&sub_secret),
            MemoryStore::new(),
            app.clone(),
        );
        sub.install_subscription("old", host_a.address(), [1u8; 32], None, 1);
        sub.install_subscription("occupied", host_b.address(), [9u8; 32], None, 7);

        let store = sub.clone_store();
        let mut sub =
            Node::with_store_app(Identity::from_secret_bytes(&sub_secret), store, app.clone());

        let wrong_host = Bundle::create(
            &host_b.identity,
            Destination::Device(sub.address()),
            &sub.address(),
            &Payload::HpsRekey {
                old_path: "old".into(),
                new_path: "fresh".into(),
                epoch: 2,
                content_key: [2u8; 32],
                service_pubkey: None,
                proof: host_b.hps_proof("old", &host_b.address()),
            },
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();
        sub.on_bundle(1, wrong_host);
        assert_eq!(sub.subscriptions["old"].content_key, [1u8; 32]);
        assert!(!sub.subscriptions.contains_key("fresh"));

        let collision = Bundle::create(
            &host_a.identity,
            Destination::Device(sub.address()),
            &sub.address(),
            &Payload::HpsRekey {
                old_path: "old".into(),
                new_path: "occupied".into(),
                epoch: 2,
                content_key: [2u8; 32],
                service_pubkey: None,
                proof: host_a.hps_proof("old", &host_a.address()),
            },
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();
        sub.on_bundle(2, collision);
        assert_eq!(sub.subscriptions["old"].content_key, [1u8; 32]);
        assert_eq!(sub.subscriptions["occupied"].content_key, [9u8; 32]);
    }

    #[test]
    fn hps_reach_ack_requires_current_key_mac_and_exact_epoch() {
        let app = crate::app::AppKeys::from_secret([12u8; 32]);
        let mut host = Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone());
        host.register_service(
            "room",
            crate::hps::ServiceKind::Channel,
            crate::hps::AccessMode::Open,
            crate::hps::Visibility::Private,
        );
        let cfg = host.services["room"].clone();
        let tag = host.app.topic_tag("room");
        let member = Identity::generate();
        let member_addr = member.address();

        let future_epoch = cfg.epoch + 1;
        let future_mac =
            hps::reach_ack_mac(&cfg.content_key, &app.id, &member_addr, &tag, future_epoch);
        let future = Bundle::create(
            &member,
            Destination::Device(host.address()),
            &host.address(),
            &Payload::HpsReachAck {
                topic_tag: tag,
                epoch: future_epoch,
                mac: future_mac,
            },
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();
        host.on_bundle(1, future);
        assert_eq!(host.hps_reach("room"), 0);
        assert!(host.hps_members("room").is_empty());

        let bad_mac = Bundle::create(
            &member,
            Destination::Device(host.address()),
            &host.address(),
            &Payload::HpsReachAck {
                topic_tag: tag,
                epoch: cfg.epoch,
                mac: [0x77; 32],
            },
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();
        host.on_bundle(2, bad_mac);
        assert_eq!(host.hps_reach("room"), 0);

        let mac = hps::reach_ack_mac(&cfg.content_key, &app.id, &member_addr, &tag, cfg.epoch);
        let valid = Bundle::create(
            &member,
            Destination::Device(host.address()),
            &host.address(),
            &Payload::HpsReachAck {
                topic_tag: tag,
                epoch: cfg.epoch,
                mac,
            },
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();
        host.on_bundle(3, valid);
        assert_eq!(host.hps_reach("room"), 1);
        assert_eq!(host.hps_members("room"), vec![member_addr]);
    }

    #[test]
    fn hps_rekey_move_persists_reduced_members_and_removes_old_rows() {
        let app = crate::app::AppKeys::from_secret([13u8; 32]);
        let host_secret = Identity::generate().to_secret_bytes();
        let mut host = Node::with_store_app(
            Identity::from_secret_bytes(&host_secret),
            MemoryStore::new(),
            app.clone(),
        );
        host.register_service(
            "room",
            crate::hps::ServiceKind::Channel,
            crate::hps::AccessMode::RequestToJoin,
            crate::hps::Visibility::Private,
        );
        let retained = Identity::generate().address();
        let removed = Identity::generate().address();
        host.record_member("room", retained);
        host.record_member("room", removed);
        host.hps_pending.insert("room".into(), vec![removed]);
        host.persist_pending("room");

        host.hps_rekey("room", Some("room-v2"), &[removed]).unwrap();
        assert!(host.store.get_kv("hps/svc/room").is_none());
        assert!(host.store.get_kv("hps/members/room").is_none());
        assert!(host.store.get_kv("hps/pending/room").is_none());

        let store = host.clone_store();
        let host = Node::with_store_app(Identity::from_secret_bytes(&host_secret), store, app);
        assert!(!host.services.contains_key("room"));
        assert!(host.services.contains_key("room-v2"));
        assert_eq!(
            host.hps_members("room-v2")
                .into_iter()
                .collect::<HashSet<_>>(),
            HashSet::from([retained])
        );
        assert!(host.hps_members("room").is_empty());
        assert!(host.hps_pending("room").is_empty());
    }

    #[test]
    fn hps_rekey_failure_at_every_batch_boundary_keeps_the_old_generation() {
        let app = crate::app::AppKeys::from_secret([17u8; 32]);
        let host_secret = Identity::generate().to_secret_bytes();
        let retained = Identity::generate().address();
        let removed = Identity::generate().address();
        let mut baseline = Node::with_store_app(
            Identity::from_secret_bytes(&host_secret),
            FaultStore::default(),
            app.clone(),
        );
        baseline.register_service(
            "room",
            crate::hps::ServiceKind::Channel,
            crate::hps::AccessMode::RequestToJoin,
            crate::hps::Visibility::Private,
        );
        baseline.record_member("room", retained);
        baseline.record_member("room", removed);
        baseline.hps_pending.insert("room".into(), vec![removed]);
        baseline.persist_pending("room");
        let old_cfg = baseline.services["room"].clone();
        let durable = baseline.store.inner.clone();

        for (new_path, mutation_count) in [(None, 2usize), (Some("room-v2"), 5usize)] {
            for boundary in 0..mutation_count {
                let mut host = Node::with_store_app(
                    Identity::from_secret_bytes(&host_secret),
                    FaultStore {
                        inner: durable.clone(),
                        fail_batch_after: Some(boundary),
                        ..Default::default()
                    },
                    app.clone(),
                );

                assert!(host.hps_rekey("room", new_path, &[removed]).is_err());
                assert_eq!(host.services["room"].epoch, old_cfg.epoch);
                assert_eq!(host.services["room"].content_key, old_cfg.content_key);
                assert_eq!(
                    host.hps_members("room").into_iter().collect::<HashSet<_>>(),
                    HashSet::from([retained, removed])
                );
                assert!(!host.services.contains_key("room-v2"));
                assert!(host.drain_outgoing().is_empty());

                let restored = Node::with_store_app(
                    Identity::from_secret_bytes(&host_secret),
                    FaultStore {
                        inner: host.store.inner.clone(),
                        ..Default::default()
                    },
                    app.clone(),
                );
                assert_eq!(restored.services["room"].epoch, old_cfg.epoch);
                assert_eq!(
                    restored
                        .hps_members("room")
                        .into_iter()
                        .collect::<HashSet<_>>(),
                    HashSet::from([retained, removed])
                );
                assert!(!restored.services.contains_key("room-v2"));
            }
        }
    }

    #[test]
    fn incoming_hps_rekey_batch_failure_preserves_the_old_subscription_after_restart() {
        let app = crate::app::AppKeys::from_secret([18u8; 32]);
        let host = Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone());
        let subscriber_secret = Identity::generate().to_secret_bytes();
        let mut baseline = Node::with_store_app(
            Identity::from_secret_bytes(&subscriber_secret),
            FaultStore::default(),
            app.clone(),
        );
        baseline.install_subscription("room", host.address(), [1u8; 32], None, 1);
        let durable = baseline.store.inner.clone();

        for boundary in 0..2 {
            let mut subscriber = Node::with_store_app(
                Identity::from_secret_bytes(&subscriber_secret),
                FaultStore {
                    inner: durable.clone(),
                    fail_batch_after: Some(boundary),
                    ..Default::default()
                },
                app.clone(),
            );
            let rekey = Bundle::create(
                &host.identity,
                Destination::Device(subscriber.address()),
                &subscriber.address(),
                &Payload::HpsRekey {
                    old_path: "room".into(),
                    new_path: "room-v2".into(),
                    epoch: 2,
                    content_key: [2u8; 32],
                    service_pubkey: None,
                    proof: host.hps_proof("room", &host.address()),
                },
                BundleOpts {
                    app: app.id,
                    ..Default::default()
                },
            )
            .unwrap();
            subscriber.on_bundle(1, rekey);

            assert_eq!(subscriber.subscriptions["room"].content_key, [1u8; 32]);
            assert!(!subscriber.subscriptions.contains_key("room-v2"));
            let restored = Node::with_store_app(
                Identity::from_secret_bytes(&subscriber_secret),
                FaultStore {
                    inner: subscriber.store.inner.clone(),
                    ..Default::default()
                },
                app.clone(),
            );
            assert_eq!(restored.subscriptions["room"].content_key, [1u8; 32]);
            assert!(!restored.subscriptions.contains_key("room-v2"));
        }
    }

    #[test]
    fn hps_leave_reduced_member_set_survives_host_restart() {
        let app = crate::app::AppKeys::from_secret([14u8; 32]);
        let host_secret = Identity::generate().to_secret_bytes();
        let mut nodes = [
            Node::with_store_app(
                Identity::from_secret_bytes(&host_secret),
                MemoryStore::new(),
                app.clone(),
            ),
            Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone()),
        ];
        let mut net = Wire2::new();
        net.connect(&mut nodes, 0, 1, 1, 1);
        nodes[0].register_service(
            "room",
            crate::hps::ServiceKind::Channel,
            crate::hps::AccessMode::Open,
            crate::hps::Visibility::Private,
        );
        let member = nodes[1].address();
        let old_epoch = nodes[0].services["room"].epoch;
        nodes[1].hps_subscribe(nodes[0].address(), "room").unwrap();
        net.pump(&mut nodes);
        assert_eq!(nodes[0].hps_members("room"), vec![member]);

        nodes[1].hps_leave("room").unwrap().unwrap();
        net.pump(&mut nodes);
        assert!(nodes[0].hps_members("room").is_empty());
        assert_eq!(nodes[0].services["room"].epoch, old_epoch + 1);
        assert!(!nodes[1].subscriptions.contains_key("room"));

        let store = nodes[0].clone_store();
        let host = Node::with_store_app(Identity::from_secret_bytes(&host_secret), store, app);
        assert!(
            host.hps_members("room").is_empty(),
            "restart must not resurrect a member who left"
        );
        assert_eq!(host.services["room"].epoch, old_epoch + 1);
    }

    #[test]
    fn hps_leave_persistence_failure_keeps_the_live_subscription() {
        let app = crate::app::AppKeys::from_secret([19u8; 32]);
        let host = Identity::generate().address();
        let mut member = Node::with_store_app(Identity::generate(), FaultStore::default(), app);
        member.install_subscription("room", host, [3u8; 32], None, 1);
        member.store.fail_critical_remove_prefix = Some("hps/sub/".into());

        assert!(member.hps_leave("room").is_err());
        assert!(member.subscriptions.contains_key("room"));
        assert!(member.store.get_kv("hps/sub/room").is_some());
        assert!(member.drain_outgoing().is_empty());
    }

    #[test]
    fn hps_leave_atomically_removes_topic_state_and_persists_outbound_custody() {
        let app = crate::app::AppKeys::from_secret([29u8; 32]);
        let member_secret = Identity::generate().to_secret_bytes();
        let host = Identity::generate();
        let mut member = Node::with_store_app(
            Identity::from_secret_bytes(&member_secret),
            FaultStore::default(),
            app.clone(),
        );
        member.install_subscription("room", host.address(), [3u8; 32], None, 1);
        let topic_tag = member.app.topic_tag("room");
        let message = HpsMessage {
            id: [7u8; 32],
            path: "room".into(),
            sender: host.address(),
            body: b"pending".to_vec(),
        };
        let charge = member
            .reserve_app_queue(
                AppQueueKind::HpsMessage,
                Some(message.sender),
                Node::<FaultStore>::hps_message_bytes(&message),
            )
            .unwrap();
        assert!(member
            .accept_hps_publication(topic_tag, 1, message, 10_000, charge)
            .unwrap());
        let durable = member.store.inner.clone();

        // Subscription, replay, inbox, and outbound custody are the four mutations in this small
        // leave. Every failure boundary must expose the complete old state, including after restart.
        for boundary in 0..4 {
            let mut attempt = Node::with_store_app(
                Identity::from_secret_bytes(&member_secret),
                FaultStore {
                    inner: durable.clone(),
                    fail_batch_after: Some(boundary),
                    ..Default::default()
                },
                app.clone(),
            );
            assert!(attempt.hps_leave("room").is_err(), "boundary {boundary}");
            assert!(attempt.subscriptions.contains_key("room"));
            assert!(attempt.hps_replays.contains_key(&(topic_tag, 1)));
            assert_eq!(attempt.hps_inbox.len(), 1);
            assert!(attempt.store.have().ids.is_empty());
            assert!(attempt.drain_outgoing().is_empty());

            let restored = Node::with_store_app(
                Identity::from_secret_bytes(&member_secret),
                FaultStore {
                    inner: attempt.store.inner.clone(),
                    ..Default::default()
                },
                app.clone(),
            );
            assert!(restored.subscriptions.contains_key("room"));
            assert!(restored.hps_replays.contains_key(&(topic_tag, 1)));
            assert_eq!(restored.hps_inbox.len(), 1);
            assert!(restored.store.have().ids.is_empty());
        }

        let mut committed = Node::with_store_app(
            Identity::from_secret_bytes(&member_secret),
            FaultStore {
                inner: durable,
                ..Default::default()
            },
            app.clone(),
        );
        let leave_id = committed.hps_leave("room").unwrap().unwrap();
        assert!(!committed.subscriptions.contains_key("room"));
        assert!(!committed.hps_replays.contains_key(&(topic_tag, 1)));
        assert!(committed.hps_inbox.is_empty());
        assert!(committed.store.contains(&leave_id));

        let restarted = Node::with_store_app(
            Identity::from_secret_bytes(&member_secret),
            FaultStore {
                inner: committed.store.inner.clone(),
                ..Default::default()
            },
            app,
        );
        assert!(!restarted.subscriptions.contains_key("room"));
        assert!(!restarted.hps_replays.contains_key(&(topic_tag, 1)));
        assert!(restarted.hps_inbox.is_empty());
        assert!(restarted.store.contains(&leave_id));
        assert!(matches!(
            restarted.store.get(&leave_id).and_then(|bundle| bundle.open(&host).ok()),
            Some(Payload::HpsLeave { path, .. }) if path == "room"
        ));
    }

    #[test]
    fn hps_publish_signature_rejects_outer_sender_rewrap() {
        let app = crate::app::AppKeys::from_secret([15u8; 32]);
        let mut host = Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone());
        let mut sub = Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone());
        host.register_service(
            "news",
            crate::hps::ServiceKind::Service,
            crate::hps::AccessMode::Open,
            crate::hps::Visibility::Private,
        );
        let cfg = host.services["news"].clone();
        sub.install_subscription(
            "news",
            host.address(),
            cfg.content_key,
            cfg.service_pubkey(),
            cfg.epoch,
        );
        let publish_id = host.hps_publish("news", b"genuine").unwrap();
        let original = host.store.get(&publish_id).unwrap();
        let payload = original.open(&hps::broadcast_identity()).unwrap();

        let attacker = Identity::generate();
        let rewrapped = Bundle::create(
            &attacker,
            Destination::Broadcast,
            &hps::broadcast_identity().address(),
            &payload,
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();
        sub.on_bundle(1, rewrapped);
        assert!(sub.take_hps_messages().is_empty());

        sub.on_bundle(2, original);
        let messages = take_hps_and_accept(&mut sub);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].body, b"genuine");
    }

    #[test]
    fn hps_service_rejects_a_valid_service_signature_from_any_sender_but_its_host() {
        let app = crate::app::AppKeys::from_secret([20u8; 32]);
        let mut host = Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone());
        let mut subscriber =
            Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone());
        host.register_service(
            "news",
            crate::hps::ServiceKind::Service,
            crate::hps::AccessMode::Open,
            crate::hps::Visibility::Private,
        );
        let cfg = host.services["news"].clone();
        subscriber.install_subscription(
            "news",
            host.address(),
            cfg.content_key,
            cfg.service_pubkey(),
            cfg.epoch,
        );

        let attacker = Identity::generate();
        let topic_tag = subscriber.app.topic_tag("news");
        let (nonce, ciphertext) = hps::seal_content(&cfg.content_key, b"wrong host");
        let sig = hps::sign_publish(
            &cfg.signing_seed.unwrap(),
            &app.id,
            &attacker.address(),
            &topic_tag,
            cfg.epoch,
            &nonce,
            &ciphertext,
        );
        let publication = Bundle::create(
            &attacker,
            Destination::Broadcast,
            &hps::broadcast_identity().address(),
            &Payload::HpsPublish {
                topic_tag,
                epoch: cfg.epoch,
                nonce: nonce.to_vec(),
                ciphertext,
                sig: sig.to_vec(),
            },
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();

        subscriber.on_bundle(1, publication);
        assert!(subscriber.take_hps_messages().is_empty());
    }

    #[test]
    fn hps_publication_commit_is_atomic_and_restart_redelivers_until_acceptance() {
        let app = crate::app::AppKeys::from_secret([55u8; 32]);
        let mut host = Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone());
        let subscriber_secret = Identity::generate().to_secret_bytes();
        let mut subscriber = Node::with_store_app(
            Identity::from_secret_bytes(&subscriber_secret),
            FaultStore::default(),
            app.clone(),
        );
        host.register_service(
            "room",
            crate::hps::ServiceKind::Channel,
            crate::hps::AccessMode::Open,
            crate::hps::Visibility::Private,
        );
        let cfg = host.services["room"].clone();
        subscriber.install_subscription("room", host.address(), cfg.content_key, None, cfg.epoch);
        let outer_id = host.hps_publish("room", b"persist me").unwrap();
        let publication = host.store.get(&outer_id).unwrap();

        subscriber.store.fail_critical_put_prefix = Some("hps/inbox/".into());
        subscriber.on_bundle(1, publication.clone());
        assert!(subscriber.take_hps_messages().is_empty());
        assert!(subscriber.hps_replays.is_empty());
        assert!(subscriber.store.list_kv("hps/inbox/").is_empty());
        assert!(!subscriber.store.seen(&outer_id));

        subscriber.store.fail_critical_put_prefix = None;
        subscriber.on_bundle(1, publication);
        let first = subscriber.take_hps_messages();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].body, b"persist me");
        assert_eq!(subscriber.take_hps_messages()[0].id, first[0].id);

        let mut restarted = Node::with_store_app(
            Identity::from_secret_bytes(&subscriber_secret),
            FaultStore {
                inner: subscriber.store.inner.clone(),
                ..Default::default()
            },
            app,
        );
        assert_eq!(restarted.take_hps_messages()[0].id, first[0].id);
        restarted.store.fail_critical_remove_prefix = Some("hps/inbox/".into());
        assert!(restarted.accept_hps_message(&first[0].id).is_err());
        assert_eq!(restarted.take_hps_messages().len(), 1);

        let mut redelivered = Node::with_store(
            Identity::from_secret_bytes(&subscriber_secret),
            FaultStore {
                inner: restarted.store.inner.clone(),
                ..Default::default()
            },
        );
        assert_eq!(redelivered.take_hps_messages()[0].id, first[0].id);
        assert!(redelivered.accept_hps_message(&first[0].id).unwrap());
        assert!(redelivered.take_hps_messages().is_empty());
    }

    #[test]
    fn durable_hps_inbox_is_bounded_and_expired_without_weakening_replay() {
        let topic_tag = [8u8; 16];
        let mut node = Node::new(Identity::generate());
        node.set_time(100);
        for index in 0..MAX_DURABLE_HPS_MESSAGES {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let message = HpsMessage {
                id,
                path: "room".into(),
                sender: [index as u8; 32],
                body: vec![index as u8],
            };
            let charge = node
                .reserve_app_queue(
                    AppQueueKind::HpsMessage,
                    Some(message.sender),
                    Node::<MemoryStore>::hps_message_bytes(&message),
                )
                .unwrap();
            node.accept_hps_publication(
                topic_tag,
                1,
                message,
                100 + DURABLE_HOST_DELIVERY_TTL_MS,
                charge,
            )
            .unwrap();
        }
        assert_eq!(node.hps_inbox.len(), MAX_DURABLE_HPS_MESSAGES);
        let overflow_id = [0xff; 32];
        let overflow = HpsMessage {
            id: overflow_id,
            path: "room".into(),
            sender: [4u8; 32],
            body: Vec::new(),
        };
        let charge = AppQueueCharge {
            kind: AppQueueKind::HpsMessage,
            source: Some(overflow.sender),
            bytes: 0,
        };
        assert!(node
            .accept_hps_publication(
                topic_tag,
                1,
                overflow,
                100 + DURABLE_HOST_DELIVERY_TTL_MS,
                charge,
            )
            .is_err());
        assert!(!node.hps_replays[&(topic_tag, 1)]
            .iter()
            .any(|(id, _)| *id == overflow_id));

        node.tick(100 + DURABLE_HOST_DELIVERY_TTL_MS);
        assert!(node.hps_inbox.is_empty());
        assert!(node.store.list_kv("hps/inbox/").is_empty());
        assert!(!node.hps_replays.contains_key(&(topic_tag, 1)));
    }

    #[test]
    fn unaccepted_hps_publication_blocks_replay_until_expiry_cleanup() {
        let topic_tag = [9u8; 16];
        let publication_id = [7u8; 32];
        let mut node = Node::new(Identity::generate());
        let message = HpsMessage {
            id: publication_id,
            path: "room".into(),
            sender: [5u8; 32],
            body: b"once".to_vec(),
        };
        let charge = node
            .reserve_app_queue(
                AppQueueKind::HpsMessage,
                Some(message.sender),
                Node::<MemoryStore>::hps_message_bytes(&message),
            )
            .unwrap();
        assert!(node
            .accept_hps_publication(topic_tag, 1, message.clone(), 100, charge)
            .unwrap());

        node.set_time(101);
        let duplicate_charge = node
            .reserve_app_queue(
                AppQueueKind::HpsMessage,
                Some(message.sender),
                Node::<MemoryStore>::hps_message_bytes(&message),
            )
            .unwrap();
        assert!(!node
            .accept_hps_publication(topic_tag, 1, message, 200, duplicate_charge)
            .unwrap());
        node.release_app_queue(duplicate_charge);
        assert_eq!(node.hps_inbox.len(), 1);

        node.tick(101);
        assert!(node.hps_inbox.is_empty());
        assert!(!node.hps_publication_recorded(&topic_tag, 1, &publication_id));
    }

    #[test]
    fn hps_publication_replay_is_rejected_across_rewrap_and_restart_then_expires() {
        let app = crate::app::AppKeys::from_secret([21u8; 32]);
        let mut host = Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone());
        let subscriber_secret = Identity::generate().to_secret_bytes();
        let mut subscriber = Node::with_store_app(
            Identity::from_secret_bytes(&subscriber_secret),
            MemoryStore::new(),
            app.clone(),
        );
        host.register_service(
            "room",
            crate::hps::ServiceKind::Channel,
            crate::hps::AccessMode::Open,
            crate::hps::Visibility::Private,
        );
        let cfg = host.services["room"].clone();
        subscriber.install_subscription("room", host.address(), cfg.content_key, None, cfg.epoch);
        let original_id = host.hps_publish("room", b"once").unwrap();
        let payload = host
            .store
            .get(&original_id)
            .unwrap()
            .open(&hps::broadcast_identity())
            .unwrap();
        let rewrap = |created_at| {
            Bundle::create(
                &host.identity,
                Destination::Broadcast,
                &hps::broadcast_identity().address(),
                &payload,
                BundleOpts {
                    app: app.id,
                    created_at,
                    lifetime_ms: 1_000,
                    ..Default::default()
                },
            )
            .unwrap()
        };

        subscriber.set_time(100);
        subscriber.on_bundle(1, rewrap(10));
        assert_eq!(take_hps_and_accept(&mut subscriber).len(), 1);
        let store = subscriber.clone_store();
        let mut subscriber = Node::with_store_app(
            Identity::from_secret_bytes(&subscriber_secret),
            store,
            app.clone(),
        );
        subscriber.set_time(100);
        subscriber.on_bundle(2, rewrap(11));
        assert!(subscriber.take_hps_messages().is_empty());

        subscriber.tick(1_100);
        subscriber.on_bundle(3, rewrap(12));
        let messages = take_hps_and_accept(&mut subscriber);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].body, b"once");
    }

    #[test]
    fn hps_publication_replay_set_is_capped_and_rehydrates_at_the_cap() {
        let secret = Identity::generate().to_secret_bytes();
        let topic_tag = [7u8; 16];
        let mut node = Node::from_identity_secret(&secret);
        node.set_time(100);
        for index in 0..=MAX_HPS_REPLAYS_PER_TOPIC {
            let mut publication_id = [0u8; 32];
            publication_id[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let message = HpsMessage {
                id: publication_id,
                path: "room".into(),
                sender: [9u8; 32],
                body: vec![index as u8],
            };
            let charge = node
                .reserve_app_queue(
                    AppQueueKind::HpsMessage,
                    Some(message.sender),
                    Node::<MemoryStore>::hps_message_bytes(&message),
                )
                .unwrap();
            assert!(node
                .accept_hps_publication(topic_tag, 3, message, 10_000 + index as u64, charge,)
                .unwrap());
            assert!(node.accept_hps_message(&publication_id).unwrap());
        }
        let entries = &node.hps_replays[&(topic_tag, 3)];
        assert_eq!(entries.len(), MAX_HPS_REPLAYS_PER_TOPIC);
        assert!(!entries.iter().any(|(id, _)| *id == [0u8; 32]));

        let store = node.clone_store();
        let restored = Node::with_store(Identity::from_secret_bytes(&secret), store);
        assert_eq!(
            restored.hps_replays[&(topic_tag, 3)].len(),
            MAX_HPS_REPLAYS_PER_TOPIC
        );
    }

    #[test]
    fn hps_replay_generations_are_globally_capped_at_runtime_and_rehydrate() {
        let topic = |index: usize| {
            let mut tag = [0u8; 16];
            tag[..8].copy_from_slice(&(index as u64).to_be_bytes());
            (tag, index as u32)
        };
        let publication = |index: usize| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(index as u64).to_be_bytes());
            id
        };

        let mut node = Node::new(Identity::generate());
        node.set_time(1);
        for index in 0..MAX_HPS_REPLAYS_GLOBAL {
            node.hps_replays.insert(
                topic(index),
                vec![(publication(index), 1_000 + index as u64)],
            );
        }
        let new_index = MAX_HPS_REPLAYS_GLOBAL;
        let message = HpsMessage {
            id: publication(new_index),
            path: "room".into(),
            sender: [9u8; 32],
            body: Vec::new(),
        };
        let charge = node
            .reserve_app_queue(
                AppQueueKind::HpsMessage,
                Some(message.sender),
                Node::<MemoryStore>::hps_message_bytes(&message),
            )
            .unwrap();
        let (new_tag, new_epoch) = topic(new_index);
        assert!(node
            .accept_hps_publication(new_tag, new_epoch, message, 10_000, charge)
            .unwrap());
        assert_eq!(
            node.hps_replays.values().map(Vec::len).sum::<usize>(),
            MAX_HPS_REPLAYS_GLOBAL
        );
        assert!(!node.hps_replays.contains_key(&topic(0)));
        assert!(node.hps_replays.contains_key(&topic(new_index)));

        let secret = Identity::generate().to_secret_bytes();
        let mut store = MemoryStore::new();
        for index in 0..=MAX_HPS_REPLAYS_GLOBAL {
            let (topic_tag, epoch) = topic(index);
            store.put_kv(
                &Node::<MemoryStore>::hps_replay_key(&topic_tag, epoch),
                postcard::to_allocvec(&PersistedHpsReplay {
                    topic_tag,
                    epoch,
                    entries: vec![(publication(index), 10_000)],
                })
                .unwrap(),
            );
        }
        let restored = Node::with_store(Identity::from_secret_bytes(&secret), store);
        assert_eq!(
            restored.hps_replays.values().map(Vec::len).sum::<usize>(),
            MAX_HPS_REPLAYS_GLOBAL
        );
        assert_eq!(
            restored.store.list_kv("hps/replay/").len(),
            MAX_HPS_REPLAYS_GLOBAL,
            "rehydrate deletes generations beyond the global budget"
        );
    }

    #[test]
    fn hps_rehydrate_preserves_unaccepted_inbox_replay_markers_at_the_global_cap() {
        let mut store = MemoryStore::new();
        for index in 0..MAX_HPS_REPLAYS_GLOBAL {
            let mut topic_tag = [0u8; 16];
            topic_tag[8..].copy_from_slice(&(index as u64).to_be_bytes());
            let mut publication_id = [0u8; 32];
            publication_id[24..].copy_from_slice(&(index as u64).to_be_bytes());
            store.put_kv(
                &Node::<MemoryStore>::hps_replay_key(&topic_tag, index as u32),
                postcard::to_allocvec(&PersistedHpsReplay {
                    topic_tag,
                    epoch: index as u32,
                    entries: vec![(publication_id, 10_000)],
                })
                .unwrap(),
            );
        }

        // This key sorts after every attacker-controlled row above. Rehydrate must reserve room for
        // its replay marker before the earlier rows consume the global budget.
        let protected_topic = ([0xff; 16], u32::MAX);
        let protected_id = [0xee; 32];
        let protected_message = HpsMessage {
            id: protected_id,
            path: "durable".into(),
            sender: [7u8; 32],
            body: b"keep me".to_vec(),
        };
        store.put_kv(
            &Node::<MemoryStore>::hps_replay_key(&protected_topic.0, protected_topic.1),
            postcard::to_allocvec(&PersistedHpsReplay {
                topic_tag: protected_topic.0,
                epoch: protected_topic.1,
                entries: vec![(protected_id, 10_000)],
            })
            .unwrap(),
        );
        store.put_kv(
            &Node::<MemoryStore>::hps_inbox_key(&protected_id),
            postcard::to_allocvec(&PersistedHpsInbox {
                message: protected_message.clone(),
                topic_tag: protected_topic.0,
                epoch: protected_topic.1,
                received_at_ms: 1,
                expires_at_ms: 10_000,
            })
            .unwrap(),
        );

        let restored = Node::with_store(Identity::generate(), store);
        let messages = restored.take_hps_messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, protected_message.id);
        assert_eq!(messages[0].path, protected_message.path);
        assert_eq!(messages[0].body, protected_message.body);
        assert!(restored.hps_publication_recorded(
            &protected_topic.0,
            protected_topic.1,
            &protected_id
        ));
        assert_eq!(
            restored.hps_replays.values().map(Vec::len).sum::<usize>(),
            MAX_HPS_REPLAYS_GLOBAL
        );
        assert!(restored
            .store
            .get_kv(&Node::<MemoryStore>::hps_inbox_key(&protected_id))
            .is_some());
    }

    #[test]
    fn hps_reach_ack_suppression_is_bounded_and_expires() {
        let mut node = Node::new(Identity::generate());
        node.set_time(1);
        for index in 0..=MAX_HPS_ACKED {
            let mut tag = [0u8; 16];
            tag[..8].copy_from_slice(&(index as u64).to_be_bytes());
            assert!(node.record_hps_ack((tag, index as u32), 100 + index as u64));
        }
        assert_eq!(node.hps_acked.len(), MAX_HPS_ACKED);
        assert!(!node.hps_acked.contains_key(&([0u8; 16], 0)));
        node.tick(100 + MAX_HPS_ACKED as u64);
        assert!(node.hps_acked.is_empty());
    }

    #[test]
    fn hps_publish_rejects_validly_signed_future_epoch() {
        let app = crate::app::AppKeys::from_secret([16u8; 32]);
        let writer = Identity::generate();
        let mut reader =
            Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone());
        let path = "room";
        let content_key = [0x33; 32];
        let tag = reader.app.topic_tag(path);
        reader.install_subscription(path, writer.address(), content_key, None, 0);

        let (nonce, ciphertext) = hps::seal_content(&content_key, b"from the future");
        let future_epoch = 1;
        let signature = writer
            .sign(&hps::publish_signing_bytes(
                &app.id,
                &writer.address(),
                &tag,
                future_epoch,
                &nonce,
                &ciphertext,
            ))
            .to_vec();
        let future = Bundle::create(
            &writer,
            Destination::Broadcast,
            &hps::broadcast_identity().address(),
            &Payload::HpsPublish {
                topic_tag: tag,
                epoch: future_epoch,
                nonce: nonce.to_vec(),
                ciphertext,
                sig: signature,
            },
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();
        reader.on_bundle(1, future);
        assert!(reader.take_hps_messages().is_empty());

        let (nonce, ciphertext) = hps::seal_content(&content_key, b"current");
        let signature = writer
            .sign(&hps::publish_signing_bytes(
                &app.id,
                &writer.address(),
                &tag,
                0,
                &nonce,
                &ciphertext,
            ))
            .to_vec();
        let current = Bundle::create(
            &writer,
            Destination::Broadcast,
            &hps::broadcast_identity().address(),
            &Payload::HpsPublish {
                topic_tag: tag,
                epoch: 0,
                nonce: nonce.to_vec(),
                ciphertext,
                sig: signature,
            },
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();
        reader.on_bundle(2, current);
        let messages = take_hps_and_accept(&mut reader);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].body, b"current");
    }

    // --- F-18d: guard_core exception-safety pass -------------------------------------------
    //
    // `guard_core` (services/hop-relayd, hop-endpoint, hop-gateway) wraps a whole `node.handle`
    // / `node.ingest` call in `catch_unwind`, not the individual `self.*` mutations inside one
    // `on_bundle` match arm. A pass-18 adversarial audit (F-18d) asked: for every arm that
    // mutates MORE THAN ONE piece of paired bookkeeping (pending/tx/forwarded/store/relay_order/
    // subscriptions/...), could a panic landing BETWEEN those mutations, reachable from
    // attacker-controlled wire bytes, leave Node in an exploitable half-applied state?
    //
    // A full audit of `on_bundle` and every helper it calls (bundle::verify/open, reach-record
    // verify, hps's AEAD open/verify, store's put/remove/seen, stream reassembly, route learning)
    // found no reachable panic today: every attacker-shaped field is decoded via `Option`/`Result`
    // (`.get()`, `?`, `ok_or`, `checked_sub`, `saturating_*`), never an indexing/unwrap panic. That
    // matches the auditor's own conclusion. Two things still make this a real, enforced property
    // rather than an
    // accident:
    //
    // 1. The `HpsRekey` arm had a structurally risky ordering: remove the OLD subscription's
    //    bookkeeping, THEN install the new one. Nothing in today's call graph panics between
    //    those two steps, but a future change (e.g. `install_subscription` growing a fallible
    //    persistence step) could, and the old order would silently destroy a working
    //    subscription with nothing installed to replace it. Reordered to install-then-remove
    //    (see `on_bundle`'s `Payload::HpsRekey` arm) so the worst a mid-arm panic can do is
    //    leave a harmless stale duplicate, never a lost subscription.
    // 2. The tests below drive REAL panics (via a stubbed `Store`) through `catch_unwind`
    //    (mirroring `guard_core` exactly) at the exact point between paired mutations in two of
    //    the highest-value arms, and assert the surviving state is never exploitable. If a
    //    future edit reintroduces the risky ordering, or drops one half of a paired mutation,
    //    these tests fail.

    /// Test double: wraps a real store but panics on ONE specific `put_kv` key, standing in for
    /// a hypothetical future fallible write inside an `on_bundle` helper (persistence, a
    /// backend swap, etc.) so we can prove an arm's ordering is fail-safe under a genuine
    /// mid-arm panic, not just reason about it.
    struct PanicOnPutKv {
        inner: MemoryStore,
        panic_key: String,
    }

    impl Store for PanicOnPutKv {
        fn put(&mut self, bundle: Bundle, now_ms: u64) -> bool {
            self.inner.put(bundle, now_ms)
        }
        fn get(&self, id: &BundleId) -> Option<Bundle> {
            self.inner.get(id)
        }
        fn remove(&mut self, id: &BundleId) -> Option<Bundle> {
            self.inner.remove(id)
        }
        fn seen(&self, id: &BundleId) -> bool {
            self.inner.seen(id)
        }
        fn contains(&self, id: &BundleId) -> bool {
            self.inner.contains(id)
        }
        fn have(&self) -> crate::store::HaveSet {
            self.inner.have()
        }
        fn prune(&mut self, now_ms: u64) {
            self.inner.prune(now_ms)
        }
        fn split_copies(&mut self, id: &BundleId) -> u16 {
            self.inner.split_copies(id)
        }
        fn set_copies(&mut self, id: &BundleId, copies: u16) {
            self.inner.set_copies(id, copies)
        }
        fn seen_expiry(&self, id: &BundleId) -> Option<u64> {
            self.inner.seen_expiry(id)
        }
        fn put_kv(&mut self, key: &str, value: Vec<u8>) {
            if key == self.panic_key {
                panic!("PanicOnPutKv: simulated fallible-write panic on {key}");
            }
            self.inner.put_kv(key, value)
        }
        fn apply_kv_batch(&mut self, mutations: &[KvMutation]) -> std::result::Result<(), String> {
            if mutations.iter().any(|mutation| {
                matches!(mutation, KvMutation::Put { key, .. } if key == &self.panic_key)
            }) {
                panic!(
                    "PanicOnPutKv: simulated fallible-write panic on {}",
                    self.panic_key
                );
            }
            self.inner.apply_kv_batch(mutations)
        }
        fn put_kv_critical(
            &mut self,
            key: &str,
            value: Vec<u8>,
        ) -> std::result::Result<(), String> {
            self.inner.put_kv_critical(key, value)
        }
        fn get_kv(&self, key: &str) -> Option<Vec<u8>> {
            self.inner.get_kv(key)
        }
        fn remove_kv(&mut self, key: &str) {
            self.inner.remove_kv(key)
        }
        fn remove_kv_critical(&mut self, key: &str) -> std::result::Result<(), String> {
            self.inner.remove_kv_critical(key)
        }
        fn list_kv(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
            self.inner.list_kv(prefix)
        }
    }

    #[test]
    fn hps_rekey_install_before_remove_survives_a_mid_arm_panic() {
        // See the F-18d block comment above. This proves the FIXED ordering (install the new
        // subscription, then remove the old one) is fail-safe: a panic injected exactly where a
        // fallible step could someday land (persisting the NEW subscription) is caught
        // (`catch_unwind`, mirroring `guard_core`) and the OLD, still-working subscription is
        // untouched. With the old (remove-then-install) ordering this same panic would have
        // fired AFTER the old subscription was already torn down, losing it outright.
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let app = crate::app::AppKeys::from_secret([9u8; 32]);
        let host = Node::with_store_app(Identity::generate(), MemoryStore::new(), app.clone());

        let old_path = "room";
        let new_path = "room-v2";
        let host_addr = host.address();
        let content_key_v1 = [1u8; 32];

        // The subscriber's store panics ONLY on the new path's persistence write; the old
        // path's own (already-durable) entry is untouched by that key.
        let mut sub = Node::with_store_app(
            Identity::generate(),
            PanicOnPutKv {
                inner: MemoryStore::new(),
                panic_key: format!("hps/sub/{new_path}"),
            },
            app.clone(),
        );
        sub.install_subscription(old_path, host_addr, content_key_v1, None, 1);
        assert!(sub.subscriptions.contains_key(old_path));

        // A real, authorized HpsRekey bundle from host -> sub (mirrors `send_to_host`).
        let proof = host.hps_proof(old_path, &host_addr);
        let bundle = Bundle::create(
            &host.identity,
            Destination::Device(sub.address()),
            &sub.address(),
            &Payload::HpsRekey {
                old_path: old_path.to_string(),
                new_path: new_path.to_string(),
                epoch: 2, // > the held subscription's epoch (1)
                content_key: [2u8; 32],
                service_pubkey: None,
                proof,
            },
            BundleOpts {
                app: app.id,
                ..Default::default()
            },
        )
        .unwrap();

        let caught = catch_unwind(AssertUnwindSafe(|| sub.on_bundle(1, bundle)));
        assert!(
            caught.is_err(),
            "the stubbed store's panic must actually fire (test is broken if not)"
        );

        // The invariant that matters: a mid-arm panic never leaves the topic with NO
        // subscription at all, and never silently swaps in a half-applied new one.
        assert!(
            sub.subscriptions.contains_key(old_path),
            "a mid-arm panic during rekey must not destroy the old (working) subscription"
        );
        assert_eq!(
            sub.subscriptions[old_path].content_key, content_key_v1,
            "the surviving subscription is the OLD one, untouched, not a half-applied new one"
        );
    }

    #[test]
    fn traced_ack_purge_arm_is_never_left_half_applied_under_a_mid_arm_panic() {
        // The traced-ACK arm (`on_bundle`, `is_for(&bundle, &self.address())` +
        // `flags.is_ack` + authorized) mutates FOUR pieces of paired bookkeeping in sequence:
        // `pending`, `store`, `tx` (delivered flag), and `forwarded` (+ route learning). Every
        // one of those is an infallible HashMap/Vec primitive (none can panic on its own), so
        // this test injects a panic via a stubbed store's `remove` (standing in for a
        // hypothetical future change that makes bundle removal fallible) at the exact point
        // between the FIRST paired mutation (`pending.remove`) and the rest, and asserts the
        // surviving state is not exploitable: specifically, a message can never end up shown as
        // "Delivered" in the UI (`tx.delivered`) while `pending` still independently tracks it
        // as outstanding-and-retransmitting (which would be a confusing but harmless double
        // bookkeeping) NOR the reverse: `pending` cleared (retransmission stops) while `tx`
        // never learns delivery (the actually-observed failure mode: a stuck "Sending…" status,
        // cosmetic, never a security exposure since no other party's state is touched).
        use std::panic::{catch_unwind, AssertUnwindSafe};

        struct PanicOnRemove {
            inner: MemoryStore,
            panic_id: BundleId,
        }
        impl Store for PanicOnRemove {
            fn put(&mut self, bundle: Bundle, now_ms: u64) -> bool {
                self.inner.put(bundle, now_ms)
            }
            fn get(&self, id: &BundleId) -> Option<Bundle> {
                self.inner.get(id)
            }
            fn remove(&mut self, id: &BundleId) -> Option<Bundle> {
                if *id == self.panic_id {
                    panic!("PanicOnRemove: simulated panic removing the acked bundle");
                }
                self.inner.remove(id)
            }
            fn seen(&self, id: &BundleId) -> bool {
                self.inner.seen(id)
            }
            fn contains(&self, id: &BundleId) -> bool {
                self.inner.contains(id)
            }
            fn have(&self) -> crate::store::HaveSet {
                self.inner.have()
            }
            fn prune(&mut self, now_ms: u64) {
                self.inner.prune(now_ms)
            }
            fn split_copies(&mut self, id: &BundleId) -> u16 {
                self.inner.split_copies(id)
            }
            fn set_copies(&mut self, id: &BundleId, copies: u16) {
                self.inner.set_copies(id, copies)
            }
            fn apply_kv_batch(
                &mut self,
                mutations: &[KvMutation],
            ) -> std::result::Result<(), String> {
                self.inner.apply_kv_batch(mutations)
            }
            fn put_kv_critical(
                &mut self,
                key: &str,
                value: Vec<u8>,
            ) -> std::result::Result<(), String> {
                self.inner.put_kv_critical(key, value)
            }
            fn remove_kv_critical(&mut self, key: &str) -> std::result::Result<(), String> {
                self.inner.remove_kv_critical(key)
            }
        }

        // Alice holds a traced, ack-requesting bundle addressed to Bob (mirrors the existing
        // `a_forged_traced_ack_cannot_mark_a_send_delivered_or_drop_the_bundle`-style tests' `submit()` pattern rather than
        // the full session/prekey machinery, which isn't the point of this test).
        let bob = Identity::generate();
        let bob_addr = bob.address();
        let bundle = Bundle::create(
            &Identity::generate(),
            Destination::Device(bob_addr),
            &bob_addr,
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"hi".to_vec(),
            },
            BundleOpts {
                flags: BundleFlags {
                    request_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        let mid = bundle.id();

        // Build Alice directly on the panic-injecting store (Rust's generics don't allow
        // swapping a `Node<S>`'s store for a different concrete `S` after construction), so the
        // panic fires exactly where a REAL future change could introduce one: removing the acked
        // bundle, between `pending.remove(&for_bundle_id)` (already applied) and the rest of the
        // traced-ACK arm's paired mutations (`store.remove`/tx-flip/`forwarded.remove`).
        let alice_identity = Identity::generate();
        let alice_addr = alice_identity.address();
        let mut alice = Node::with_store(
            alice_identity,
            PanicOnRemove {
                inner: MemoryStore::new(),
                panic_id: mid,
            },
        );
        alice.submit(bundle);
        alice.tx.insert(mid, TxInfo::default());
        assert!(
            alice.pending.contains_key(&mid),
            "sender tracks the send as pending an ACK"
        );

        // Bob acks it back, identity-signed and naming Alice as destination (authorized).
        // `Destination::AckTo(alice_addr, mid)` is is_for()-matched at Alice, exactly like the
        // adjacent `a_forged_traced_ack_cannot_mark_a_send_delivered_or_drop_the_bundle`-style tests in this module.
        let ack = Bundle::create(
            &bob,
            Destination::AckTo(alice_addr, mid),
            &alice_addr,
            &Payload::Ack {
                for_bundle_id: mid,
                status: 0,
                delivery_hops: 1,
                delivery_ms: 5,
                proof: None,
            },
            BundleOpts {
                flags: BundleFlags {
                    is_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();

        let caught = catch_unwind(AssertUnwindSafe(|| alice.on_bundle(1, ack)));
        assert!(
            caught.is_err(),
            "the stubbed store's panic must actually fire (test is broken if not)"
        );

        // The exploitable-inconsistency check: `tx.delivered` and `pending` must never disagree
        // in the DANGEROUS direction (delivered=true while a retransmit loop is still live for
        // the same id, which could re-deliver / double-count at the sender). Cosmetic
        // disagreement in the SAFE direction (retransmission stopped, status not yet flipped)
        // is acceptable and self-corrects on the next duplicate ACK.
        let display = alice.display_id(&mid);
        let shown_delivered = alice.tx.get(&display).is_some_and(|i| i.delivered);
        let still_pending_retransmit = alice.pending.contains_key(&mid);
        assert!(
            !(shown_delivered && still_pending_retransmit),
            "must never show Delivered while still actively retransmitting the same send"
        );
    }

    #[test]
    fn reserved_link_zero_is_never_admitted_as_a_connection() {
        // core-05: LinkId 0 is the local re-injection sentinel and is exempt from the F-07
        // private-ingest rate limit. A bearer that (buggily or maliciously) hands us Connected(0)
        // must be refused, so its traffic can never inherit that exemption. A refused link emits no
        // handshake; a real link (id 1) does.
        let mut node = Node::new(Identity::generate());
        node.handle(BearerEvent::Connected(LOCAL_LINK, Role::Initiator));
        assert!(
            node.drain_outgoing().is_empty(),
            "link 0 must be refused (no handshake sent)"
        );
        node.handle(BearerEvent::Connected(1, Role::Initiator));
        assert!(
            !node.drain_outgoing().is_empty(),
            "a real link handshakes normally"
        );
    }

    #[test]
    fn prekey_rotates_on_epoch_and_retains_a_bounded_window() {
        // core-03: crossing a prekey epoch publishes a new SPK, keeps the prior epoch's secret (so a
        // late session init still resolves), and eventually wipes secrets older than the window.
        let mut node = Node::new(Identity::generate());
        let e0 = node.current_prekey_public();
        assert!(node.holds_prekey_secret(&e0));

        // Advance one epoch: a new prekey is published; both epochs' secrets are retained.
        node.tick(PREKEY_EPOCH_MS);
        let e1 = node.current_prekey_public();
        assert_ne!(e0, e1, "prekey rotated on the epoch boundary");
        assert!(node.holds_prekey_secret(&e1), "current epoch secret held");
        assert!(
            node.holds_prekey_secret(&e0),
            "prior epoch secret retained within the window"
        );

        // Advance far past the window: the original (base) epoch-0 secret is always kept, but an
        // out-of-window intermediate epoch's secret is wiped so compromise stays bounded.
        let intermediate = node.identity.derive_prekey_epoch(2).public;
        node.tick(PREKEY_EPOCH_MS * 5);
        let e5 = node.current_prekey_public();
        assert!(node.holds_prekey_secret(&e5), "newest epoch secret held");
        assert!(
            !node.holds_prekey_secret(&intermediate),
            "an out-of-window past epoch secret is wiped"
        );
    }
}

/// §35 carriage gate + meter tests (rotating key-hint stamps): a `Keyed` node only takes custody
/// of a foreign bundle whose stamp signer is in its keyserver, meters each accept once to its
/// tenant, and leaves `Open` nodes byte-for-byte at the pre-stamp behavior.
#[cfg(test)]
mod access_gate_tests {
    use super::*;
    use crate::access::{
        carriage_hint, epoch_of, AccessPolicy, CarriageStamp, KeyServer, KeyedAccess, Stamper,
        TenantId, CARRIAGE_EPOCH_MS,
    };

    const TENANT: TenantId = [7u8; 16];
    const NOW: u64 = 100 * CARRIAGE_EPOCH_MS + 5;

    /// A keyed relay knowing exactly `TENANT -> stamper.key`, clock seeded + tables refreshed.
    fn keyed_relay(stamper_key: &Identity) -> Node {
        let mut node = Node::new(Identity::generate());
        node.set_time(NOW);
        let mut server = KeyServer::new();
        server.insert(TENANT, stamper_key.address());
        node.set_access_policy(AccessPolicy::Keyed(KeyedAccess::new(
            server,
            HashSet::new(),
        )));
        node.refresh_access();
        node
    }

    fn tenant_stamper() -> (Stamper, Identity) {
        let key = Identity::generate();
        (
            Stamper::new(TENANT, Identity::from_secret_bytes(&key.to_secret_bytes())),
            key,
        )
    }

    /// A foreign traced bundle between two identities that are not the node under test.
    fn foreign(body: &[u8]) -> Bundle {
        let from = Identity::generate();
        let to = Identity::generate();
        Bundle::create(
            &from,
            Destination::Device(to.address()),
            &to.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: body.to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap()
    }

    #[test]
    fn a_keyed_node_refuses_unstamped_foreign_bundles() {
        let (_, key) = tenant_stamper();
        let mut relay = keyed_relay(&key);
        let b = foreign(b"no postage");
        let id = b.id();
        relay.on_bundle(9, b);
        assert!(!relay.store.contains(&id), "custody refused");
        assert!(!relay.store.seen(&id), "never entered the store");
        assert_eq!(relay.take_access_refused(), 1);
        assert!(relay.take_usage().is_empty(), "refusals are never metered");
    }

    #[test]
    fn a_keyed_node_admits_a_stamped_bundle_but_does_not_bill_at_custody() {
        // Custody records the VERIFIED attribution; billing is delivery-justified and does NOT
        // fire here (the wire-level `delivery_bills_the_recorded_tenant` proves the delivery bill).
        let (stamper, key) = tenant_stamper();
        let mut relay = keyed_relay(&key);
        let mut b = foreign(b"stamped");
        let id = b.id();
        b.env.access = Some(Box::new(stamper.stamp(&id, NOW)));

        relay.on_bundle(9, b.clone());
        assert!(relay.store.contains(&id), "admitted to custody");
        // Duplicate flood from another link: keep-first, still held once.
        relay.on_bundle(10, b);
        assert!(
            relay.take_usage().is_empty(),
            "custody records but does not bill"
        );
        assert_eq!(relay.take_access_refused(), 0);
    }

    #[test]
    fn a_denied_tenant_is_refused() {
        let (stamper, key) = tenant_stamper();
        let mut relay = Node::new(Identity::generate());
        relay.set_time(NOW);
        let mut server = KeyServer::new();
        server.insert(TENANT, key.address());
        let mut denied = HashSet::new();
        denied.insert(TENANT);
        relay.set_access_policy(AccessPolicy::Keyed(KeyedAccess::new(server, denied)));
        relay.refresh_access();
        let mut b = foreign(b"denied");
        let id = b.id();
        b.env.access = Some(Box::new(stamper.stamp(&id, NOW)));
        relay.on_bundle(9, b);
        assert!(!relay.store.contains(&id));
        assert_eq!(relay.take_access_refused(), 1);
    }

    #[test]
    fn a_forged_stamp_with_the_right_hint_but_wrong_key_is_refused() {
        // Attacker knows the tenant id (right bucket) but not the key: no valid signature.
        let (_, key) = tenant_stamper();
        let mut relay = keyed_relay(&key);
        let mut b = foreign(b"forged");
        let id = b.id();
        let e = epoch_of(NOW);
        b.env.access = Some(Box::new(CarriageStamp {
            hint: carriage_hint(&TENANT, e),
            sig: Identity::generate().sign(b"whatever").to_vec(),
            epoch: e,
        }));
        relay.on_bundle(9, b);
        assert!(!relay.store.contains(&id), "wrong signer never resolves");
    }

    #[test]
    fn a_stamp_from_a_tenant_not_in_the_keyserver_is_refused() {
        // Cryptographic partition: a stamper whose tenant is unknown to this fleet's keyserver.
        let (_, key) = tenant_stamper();
        let mut relay = keyed_relay(&key);
        let other = Stamper::new([9u8; 16], Identity::generate());
        let mut b = foreign(b"other fleet");
        let id = b.id();
        b.env.access = Some(Box::new(other.stamp(&id, NOW)));
        relay.on_bundle(9, b);
        assert!(!relay.store.contains(&id));
    }

    #[test]
    fn local_link_reingest_is_exempt_and_never_double_metered() {
        let (_, key) = tenant_stamper();
        let mut relay = keyed_relay(&key);
        let b = foreign(b"durable copy");
        let id = b.id();
        relay.on_bundle(LOCAL_LINK, b);
        assert!(
            relay.store.contains(&id),
            "re-ingest admitted without a stamp"
        );
        assert!(relay.take_usage().is_empty(), "re-ingest is never metered");
        assert_eq!(relay.take_access_refused(), 0);
    }

    #[test]
    fn an_open_node_behaves_exactly_as_before_stamps_existed() {
        let mut device = Node::new(Identity::generate());
        let b = foreign(b"open world");
        let id = b.id();
        device.on_bundle(9, b);
        assert!(device.store.contains(&id));
        assert!(device.take_usage().is_empty(), "Open never meters");
    }

    #[test]
    fn a_proven_delivery_bills_the_recorded_tenant_exactly_once() {
        // Custody records attribution; a returning delivery-ACK that purges the held copy is the
        // billable event. Build the sender + recipient explicitly so we can hand-craft the ACK.
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let (stamper, key) = tenant_stamper();
        let mut relay = keyed_relay(&key);

        // A stamped, device-addressed bundle the relay carries toward `recipient`.
        let mut b = Bundle::create(
            &sender,
            Destination::Device(recipient.address()),
            &recipient.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"carry me".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap();
        let bid = b.id();
        b.env.access = Some(Box::new(stamper.stamp(&bid, NOW)));
        relay.on_bundle(9, b);
        assert!(relay.store.contains(&bid), "held");
        assert!(relay.take_usage().is_empty(), "not billed at custody");

        // The recipient's delivery ACK: identity-signed, dst = AckTo(sender, bid), is_ack. Exactly
        // what emit_ack builds; the relay's authorize check honors it (it holds bid, bid.dst ==
        // Device(recipient) == ack.src, ack identity-signed) and purges + bills.
        let ack = Bundle::create(
            &recipient,
            Destination::AckTo(sender.address(), bid),
            &sender.address(),
            &Payload::Ack {
                for_bundle_id: bid,
                status: 0,
                delivery_hops: 1,
                delivery_ms: 0,
                proof: None,
            },
            BundleOpts {
                flags: BundleFlags {
                    is_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        relay.on_bundle(9, ack);

        assert!(!relay.store.contains(&bid), "purged by the delivery ACK");
        let usage = relay.take_usage();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].0, TENANT);
        assert_eq!(usage[0].1.bundles, 1, "billed once, on proven delivery");
        assert!(usage[0].1.payload_bytes > 0);
    }

    #[test]
    fn a_keyed_relay_admits_unstamped_vaccines_and_never_meters_them() {
        // Vaccines are §39 anti-packets: they must propagate through a keyed relay unstamped (so
        // delivery recovery works fleet-wide) and are never billed.
        let (_, key) = tenant_stamper();
        let mut relay = keyed_relay(&key);
        let vax = Bundle::create_vaccine([3u8; 32], BundleOpts::default());
        let vid = vax.id();
        relay.on_bundle(9, vax);
        assert!(
            relay.store.contains(&vid),
            "unstamped vaccine admitted (propagates)"
        );
        assert_eq!(
            relay.take_access_refused(),
            0,
            "vaccine not refused by the gate"
        );
        assert!(relay.take_usage().is_empty(), "vaccines are never metered");
    }

    #[test]
    fn a_spooled_delivery_bills_even_after_the_stamp_epoch_rolls() {
        // The offline path: a bundle stamped long ago, spooled, then pulled back via LOCAL_LINK
        // re-ingest and delivered. The relay attributes it (any-epoch) at re-ingest so the
        // delivery bills, even though the stamp is far too old for the fresh-admission window.
        use crate::access::CARRIAGE_EPOCH_MS;
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let (stamper, key) = tenant_stamper();
        let mut relay = keyed_relay(&key); // clock/tables at NOW (epoch 100)

        let mut b = Bundle::create(
            &sender,
            Destination::Device(recipient.address()),
            &recipient.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"spooled".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap();
        let bid = b.id();
        // Stamped 50 epochs ago: too old for `resolve` (current/prev only), fine for `attribute`.
        b.env.access = Some(Box::new(stamper.stamp(&bid, NOW - 50 * CARRIAGE_EPOCH_MS)));

        // Durable re-ingest (LOCAL_LINK): admitted + attributed, not yet billed.
        relay.on_bundle(LOCAL_LINK, b);
        assert!(relay.store.contains(&bid), "re-ingested to custody");
        assert!(relay.take_usage().is_empty(), "not billed at re-ingest");

        // Delivery proof bills the attributed tenant.
        let ack = Bundle::create(
            &recipient,
            Destination::AckTo(sender.address(), bid),
            &sender.address(),
            &Payload::Ack {
                for_bundle_id: bid,
                status: 0,
                delivery_hops: 1,
                delivery_ms: 0,
                proof: None,
            },
            BundleOpts {
                flags: BundleFlags {
                    is_ack: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        relay.on_bundle(9, ack);
        let usage = relay.take_usage();
        assert_eq!(usage.len(), 1, "the offline delivery billed once");
        assert_eq!(usage[0].0, TENANT);
    }

    #[test]
    fn an_undelivered_hold_is_pruned_without_billing() {
        // Admitted + held but never delivered: dropping it from the store (mimicking
        // eviction/expiry) leaves attribution that `tick` prunes, and it is never billed.
        let (stamper, key) = tenant_stamper();
        let mut relay = keyed_relay(&key);
        let mut b = foreign(b"never delivered");
        let id = b.id();
        b.env.access = Some(Box::new(stamper.stamp(&id, NOW)));
        relay.on_bundle(9, b);
        assert!(relay.store.contains(&id));
        relay.store.remove(&id); // eviction / expiry
        relay.tick(NOW + 1);
        assert!(
            relay.take_usage().is_empty(),
            "an undelivered hold is never billed"
        );
    }

    #[test]
    fn submit_stamps_every_originated_bundle_when_a_stamper_is_set() {
        let key = Identity::generate();
        let mut sender = Node::new(Identity::generate());
        sender.set_time(NOW);
        sender.set_stamper(Some(Stamper::new(
            TENANT,
            Identity::from_secret_bytes(&key.to_secret_bytes()),
        )));
        let to = Identity::generate();
        let b = Bundle::create(
            &sender.identity,
            Destination::Device(to.address()),
            &to.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"outbound".to_vec(),
            },
            BundleOpts::default(),
        )
        .unwrap();
        let id = b.id();
        assert!(b.env.access.is_none());
        sender.submit(b);
        let held = sender.store.get(&id).expect("submitted into the store");
        assert!(held.env.access.is_some(), "submit attached the stamp");
        // The stamp verifies at a keyed relay that knows this tenant: admitted to custody
        // (billing waits for delivery proof, tested at the wire level).
        let mut relay = keyed_relay(&key);
        relay.on_bundle(9, held);
        assert!(relay.store.contains(&id));
        assert!(
            relay.take_usage().is_empty(),
            "admitted, billed only on delivery"
        );
    }
}
