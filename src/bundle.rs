//! The bundle: the unit of store-and-forward. See DESIGN.md §5.
//!
//! A bundle splits into a signed inner header ([`SignedInner`], covered by the
//! source signature) and a mutable forwarding [`Envelope`] (`hop_limit`,
//! `custody`) that relays may update without invalidating the signature.

use serde::{Deserialize, Serialize};

use crate::crypto::{self, Identity, PubKeyBytes, Sealed, ShortAddr, Tag, XPubKeyBytes};
use crate::error::{Error, Result};
use crate::{AppId, ShortApp, FABRIC_APP};

/// One entry in a bundle's provenance trace (DESIGN.md §27): the forwarder's short
/// address plus the short id of the app that carried it (e.g. a relay stamps the Hop
/// relay app). Together they show *who* and *what* moved the bundle on each hop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceHop {
    pub node: ShortAddr,
    pub app: ShortApp,
}

/// Wire format version.
// v2: §39 mailbox-tag derivation changed to H(address ‖ epoch) (F-06), a semantic wire change on the
// private path. Bumped so a mixed old/new fleet fails loudly at the version gate rather than silently
// mis-addressing private bundles. (Struct layouts are unchanged; the break is in tag semantics.)
// v3: two coupled §39 semantic changes, both invisible in struct layout but breaking cross-version
// interop, so the version gate must reject a mixed fleet:
//   * sec-priv-04: routing/spool/want-beacon now key on the mailbox-tag's 2-byte PREFIX, not the full
//     tag. An old node keys the gradient on the full tag, so it would never match a new node's
//     prefix-bucketed spool/want — private delivery would silently degrade to flood-only across the
//     boundary. Bumping forces the mismatch to surface at `verify()` instead.
//   * sec-priv-07: the delivery Vaccine no longer carries the plaintext delivered id; it floods only a
//     blinded token. An old node can't act on the new anti-packet (different variant shape).
// v4: core-protocol-r2-04 added a recipient-only CDH `proof` field to `Payload::Ack` (the private-ACK
// forgery fix). `Ack` rides INSIDE the seal, so a reorder would be version-gated only if the version
// also bumped — and this IS a struct-layout change (a trailing `Option` field), so a v3 decoder would
// fail to parse a v4 Ack and vice-versa. The gate must reject a mixed v3/v4 fleet: a v3 sender's
// unproven private ACK would otherwise be silently trusted by a v4 recipient, and a v4 proof would be
// unparseable by a v3 sender. No v3-decode window is offered because the Ack layout genuinely differs
// (accepting v3 bytes and decoding as v4 would misread the trailing bytes) — mixed-fleet rollout is an
// infra/version-negotiation concern, not a safe in-core transcode.
// core-protocol-r13-01 bumped v4 -> v5: the §39 private WIRE id binds the recognition header.
// core-protocol-r14-01 bumped v5 -> v6: the private WIRE id now binds the ENTIRE inner (header + all
// scalar fields, incl. flags), so no unbound field — e.g. a flipped flags.request_ack twin — can share a
// genuine private id and shadow it at a keep-first relay. See compute_private_wire_id.
// v6 -> v7: HNS consolidated onto self-certifying reach records. The `Payload::HnsQuery`/`HnsAnswer`
// variants (mesh-assisted name resolution) were REMOVED, which shifts the postcard discriminant
// of every later variant, so a v6 decoder misreads a v7 Payload and vice-versa — the version gate must
// reject a mixed v6/v7 fleet. Name resolution is now a direct HTTPS /.well-known/hop fetch of the reach
// record (Node::provide_reach_record); the old validator + DoH machinery are gone.
pub const BUNDLE_VERSION: u8 = 7;

/// Globally-unique bundle id: `BLAKE3(src || nonce || payload_hash)`.
pub type BundleId = [u8; 32];

/// Where a bundle is headed. See DESIGN.md §5.
///
/// WIRE DISCIPLINE (append-only): postcard encodes an enum by its variant *index*, so
/// removing or reordering a variant renumbers the ones after it and breaks decode across
/// every peer and the deployed relay (this is what the `InternetEgress` removal did —
/// commit 5dd64d3). Only ever *append* new variants at the end, and bump [`BUNDLE_VERSION`]
/// when the wire layout changes. The discriminant order is locked by `destination_discriminants_are_stable`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Destination {
    /// Use Case B: a specific device address.
    Device(PubKeyBytes),
    /// An ACK routed back to `origin` for a given bundle id.
    AckTo(PubKeyBytes, BundleId),
    /// Flood to everyone: every node relays it onward AND processes it locally (deduped by id).
    /// Used by `hps://` publishes, which fan out to subscribers the publisher doesn't enumerate
    /// (DESIGN.md §32).
    Broadcast,
    /// §39 delivery **vaccine** (sec-priv-07): floods ONLY the recipient's revealed recognition
    /// **token** (the ephemeral·SPK DH `shared`) — deliberately NO plaintext delivered id. A node
    /// holding the delivered bundle recovers the match itself: for each held private bundle it checks
    /// `recognition_tag_from_shared(token, held_id) == held_tag` and drops the one that matches
    /// (epidemic recovery on delivery). Omitting the id is the privacy win: a passive observer that
    /// did NOT capture the specific flood can no longer read a bundle id off the anti-packet and learn
    /// a delivery event, and even a global log sees only an opaque 32-byte token with no id to bind it
    /// to. (The residual — an observer that DID capture the flood retains that bundle's own public
    /// `(id, tag)` and can still confirm delivery via the public recognition function — is intrinsic
    /// to any self-verifying epidemic anti-packet and is the documented §39 cost; see the module docs
    /// and `vaccine_hides_delivered_id_from_non_capturing_observer`.) The token is CDH-safe: it reveals
    /// nothing that identifies the recipient. Carries NO src/dst/recipient.
    Vaccine([u8; 32]),
}

/// Per-bundle flags. Plain bools to avoid a bitflags dependency.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleFlags {
    pub request_ack: bool,
    pub is_ack: bool,
    pub custody_requested: bool,
}

/// Identifies a long-lived stream session (SSE/WebSocket) the gateway holds on a
/// device's behalf. See DESIGN.md §20.
pub type StreamId = [u8; 16];

/// The kind of gateway-held streaming connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamKind {
    /// Server-Sent Events (one-way, server → device).
    Sse,
    /// WebSocket (bidirectional).
    WebSocket,
}

/// The application payload, *before* sealing. Lives encrypted inside [`Sealed`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload {
    HttpRequest {
        /// The target domain this request is for (e.g. `example.com`). Part of the signed
        /// bundle, so a `hop-endpoint` can validate it against the single domain it's
        /// authorized to serve and refuse anything else — the endpoint can never be steered
        /// to a different origin (DESIGN.md §30).
        host: String,
        method: String,
        /// Path + query only (no scheme/authority). The endpoint prepends its own origin.
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        max_resp_bytes: u32,
    },
    HttpResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        for_bundle_id: BundleId,
    },
    PeerMessage {
        content_type: String,
        body: Vec<u8>,
    },
    /// First message of a forward-secret session (DESIGN.md §25). Carries the X3DH
    /// ephemeral and the prekey it used (so the recipient derives the same root),
    /// plus the first ratchet message. Re-sent until the recipient replies, so any
    /// copy can bootstrap the session. The ratchet ciphertext is already end-to-end
    /// encrypted; the surrounding bundle seal is redundant for sessions (a later
    /// bundle-format change can carry it unsealed).
    SessionInit {
        ek_pub: XPubKeyBytes,
        spk_pub: XPubKeyBytes,
        msg: crate::session::RatchetMessage,
    },
    /// A ratchet message in an established forward-secret session.
    SessionMessage {
        msg: crate::session::RatchetMessage,
    },
    /// §39 untraceable wrapper. Carries the *real* sender's identity plus an already
    /// forward-secret inner payload (a `SessionInit`/`SessionMessage`), the whole of which
    /// is sealed to the recipient's address inside a [`PrivateHeader`] envelope whose
    /// cleartext src is zeroed and whose dst floods (`Broadcast`). The network learns
    /// nothing; only the holder of the matching prekey recognizes and opens it, then reads
    /// `sender` (authenticated by the inner ratchet — X3DH binds this identity) instead of
    /// the zeroed envelope src.
    Private {
        sender: PubKeyBytes,
        inner: Box<Payload>,
    },
    Ack {
        for_bundle_id: BundleId,
        status: u8,
        /// Hops the original message took to reach the destination (the forward path
        /// length the destination observed on arrival). Reported back for the UI.
        delivery_hops: u8,
        /// **Forward-path** latency the destination observed: its receive time minus the
        /// message's `created_at` (the sender's send time). Reported back so the sender can
        /// show "reached B in X" — the A→B leg — instead of the A→B→A round trip it would
        /// otherwise measure from the ACK's arrival. Relies on rough clock agreement between
        /// devices (NTP-synced phones are close); `delivery_hops` is the clock-free measure.
        delivery_ms: u32,
        /// **core-protocol-r2-04 recipient-only delivery proof.** On a §39 **private** ACK this is
        /// `Some(token)` where `token = recognition_shared(recipient_spk_secret, original.ephemeral)` —
        /// the SAME CDH value the delivery vaccine reveals, computable ONLY by the bundle's true
        /// recipient (it needs the SPK secret). The sender, still holding the original private bundle,
        /// verifies `recognition_tag_from_shared(token, for_bundle_id) == original.private.tag` before
        /// flipping the send to Delivered. Without this, a private ACK was accepted on recognition
        /// alone — but a private bundle is sealed to the sender's *public* address and its recognition
        /// tag keys on the sender's *published* SPK public, so anyone who learned the sender's address
        /// and guessed an in-flight `for_bundle_id` could forge a Delivered. `None` on the identity-
        /// signed **traced** ACK path (there the Ed25519 signature already authenticates the acker).
        proof: Option<[u8; 32]>,
    },
    /// Open a gateway-held streaming connection (SSE/WebSocket). See DESIGN.md §20.
    StreamOpen {
        stream_id: StreamId,
        kind: StreamKind,
        method: String,
        url: String,
        headers: Vec<(String, String)>,
    },
    /// One ordered chunk of a stream, in either direction. `fin` marks the last.
    StreamData {
        stream_id: StreamId,
        seq: u64,
        bytes: Vec<u8>,
        fin: bool,
    },
    /// Flow-control / catch-up: "I have everything contiguously through `ack`."
    /// Lets the holder release buffered chunks and resend any the peer missed.
    StreamAck {
        stream_id: StreamId,
        ack: u64,
    },
    /// Tear down a stream session.
    StreamClose {
        stream_id: StreamId,
        reason: u16,
    },
    /// Invoke a service/command on the destination node (DESIGN.md §29). `service` is a
    /// namespaced name — built-in ones start `hop.` (e.g. `hop.identify`) and are answered
    /// by the node itself; others are dispatched to the embedding app. `method` is a
    /// command within the service; `args` is an opaque, app-defined request body. The
    /// reply comes back as a [`Payload::ServiceResponse`] correlated by the request id.
    ServiceRequest {
        service: String,
        method: String,
        args: Vec<u8>,
    },
    /// A reply to a [`Payload::ServiceRequest`], sealed back to the caller. `status` is 0
    /// on success (else an app/service error code); `body` is the opaque result.
    ServiceResponse {
        for_bundle_id: BundleId,
        status: u16,
        body: Vec<u8>,
    },
    /// **Transport carrier** for an oversized bundle (DESIGN.md §20). A bundle too large
    /// to send in one shot is split into ordered `Carrier` chunks carrying its raw bytes;
    /// the receiver reassembles them and processes the original bundle as if it arrived
    /// whole. This is invisible plumbing — distinct from `StreamData`, which is an
    /// *application* stream delivered to the app progressively (SSE/WebSocket/live).
    Carrier {
        stream_id: StreamId,
        seq: u64,
        bytes: Vec<u8>,
        fin: bool,
    },
    // --- hps:// pub/sub (DESIGN.md §32). Appended at the end to keep earlier discriminants. ---
    /// Ask to join a topic at `path` on the recipient node (sealed to the host). `proof`
    /// demonstrates the requester holds the host's app secret (DESIGN.md §32 app isolation). The
    /// host replies with [`Payload::HpsKeys`] for an Open topic, or queues the request for a
    /// RequestToJoin topic; ignored for Invite topics.
    HpsJoinRequest {
        path: String,
        proof: [u8; 32],
    },
    /// The keys for a subscribed topic, sealed back to the subscriber. `service_pubkey` is
    /// `Some` for a service (verify broadcasts against it) and `None` for a channel (verify
    /// each post against its sender's address). `epoch` is the rekey generation.
    HpsKeys {
        path: String,
        content_key: [u8; 32],
        service_pubkey: Option<[u8; 32]>,
        epoch: u32,
    },
    /// Host → destination: an invite to a topic (DESIGN.md §32 Invite mode). The destination
    /// accepts with [`Payload::HpsInviteAccept`] to receive the keys. `proof` carries the host's
    /// app-secret proof so the invitee knows it's a same-app invite.
    HpsInvite {
        path: String,
        kind: crate::hps::ServiceKind,
        proof: [u8; 32],
    },
    /// Destination → host: accept a pending invite; the host then seals [`Payload::HpsKeys`].
    HpsInviteAccept {
        path: String,
        proof: [u8; 32],
    },
    /// Member → host: leave a topic, so the host drops them from the retained set / reach tally.
    HpsLeave {
        path: String,
        proof: [u8; 32],
    },
    /// Host → retained member: rotate to a new key generation (revocation, DESIGN.md §32).
    /// `new_path` equals `old_path` unless the topic was moved. Removed members never receive
    /// this and keep the dead key.
    HpsRekey {
        old_path: String,
        new_path: String,
        epoch: u32,
        content_key: [u8; 32],
        service_pubkey: Option<[u8; 32]>,
        proof: [u8; 32],
    },
    /// Member → host: confirms decrypting a broadcast, so the host can tally unique acking
    /// addresses as reach and build the retained-member set (DESIGN.md §32). `topic_tag` is the
    /// opaque per-topic tag; `epoch` is the generation the member is on.
    HpsReachAck {
        topic_tag: [u8; 16],
        epoch: u32,
    },
    /// A published message, flooded ([`Destination::Broadcast`]) to all subscribers. The body
    /// is content-key encrypted; `sig` is the sender's signature over `path‖nonce‖ciphertext`.
    /// `topic_tag` is the opaque per-topic tag (a foreign app that opens the public broadcast
    /// envelope can't tell which topic it is); `epoch` is the key generation.
    HpsPublish {
        topic_tag: [u8; 16],
        epoch: u32,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        sig: Vec<u8>,
    },
    /// "I can't decrypt your forward-secret messages — our ratchet desynced; please drop our
    /// session and re-establish" (DESIGN.md §25). A control message, statically sealed (it
    /// carries no content). The sender drops its session and re-initiates a fresh handshake,
    /// which re-syncs the ratchet so subsequent messages decrypt again.
    SessionReset,
}

/// §39 private-bundle header. Present iff this is an **untraceable** bundle (DESIGN.md
/// §39). Such a bundle carries no identity `src` (it is zeroed) and floods
/// (`dst = Destination::Broadcast`) like any flood, but the recipient is found by the
/// recognition `tag` rather than an address match, and it is not identity-signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateHeader {
    /// Recognition tag — `KDF(ephemeral·SPK, id)`. Only the recipient recomputes it.
    pub tag: Tag,
    /// The recognition ephemeral public (the recipient DHs it against its prekey).
    pub ephemeral: XPubKeyBytes,
    /// core-protocol-r2-02: the recipient's mailbox **routing prefix** (`crypto::MailboxRoute`, the
    /// leading [`crypto::MAILBOX_ROUTE_PREFIX_BYTES`] of `H(address ‖ epoch)`), so a relay can steer/
    /// spool this bundle toward the recipient's want-beacon bucket. We carry ONLY the prefix, never the
    /// full 16-byte tag. The full tag is a public deterministic function of a (broadly-known) address:
    /// carrying it verbatim let a bundle-capturing address-knower recompute the target's tag and
    /// uniquely re-link the recipient off the header — defeating the sec-priv-04 anonymity-set claim
    /// (which only routing DECISIONS honored). With just the prefix on the wire, a capturer learns only
    /// the same anonymity-set membership the routing layer already exposed: "some address colliding on
    /// this prefix", never a unique confirmation. Routing is unaffected (every decision already keyed on
    /// exactly this prefix); the final "is this mine?" is still the per-message-ephemeral `tag`.
    pub mailbox: Option<crate::crypto::MailboxRoute>,
}

/// The signed portion of a bundle. For a **traced** bundle the source signature covers
/// this exactly. A **private** bundle (§39) sets `src = [0; 32]`, `dst =
/// Destination::Broadcast`, carries a [`PrivateHeader`], and is not identity-signed (its
/// id alone binds the sealed bytes); recognition replaces address routing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedInner {
    pub version: u8,
    /// Application namespace on the shared fabric (DESIGN.md §17).
    pub app: AppId,
    pub id: BundleId,
    /// Sender address. Zeroed on a private bundle (§39) — its sender is anonymous.
    pub src: PubKeyBytes,
    /// Destination. `Broadcast` on a private bundle (§39), which floods + is recognized.
    pub dst: Destination,
    /// Present iff this is a §39 private (untraceable) bundle.
    pub private: Option<PrivateHeader>,
    /// Sender clock in ms — advisory only (see DESIGN.md §8).
    pub created_at: u64,
    pub lifetime_ms: u32,
    pub flags: BundleFlags,
    /// Service priority (0 = lowest). Relays evict low-priority relayed bundles
    /// first under storage pressure (§ relay queue). Default normal.
    pub priority: u8,
    pub payload: Sealed,
}

/// The mutable forwarding envelope. NOT covered by the signature; relays update it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub hop_limit: u8,
    pub custody: Option<PubKeyBytes>,
    /// Binary spray-and-wait copy budget held by the current custodian (§6). The
    /// count travels with the bundle so a receiver knows how many copies it now
    /// owns. Not signed — it's per-custodian forwarding state, not content.
    pub copies: u16,
    /// Hops travelled from the source so far — incremented on each forward. Lets
    /// the destination see the path length A→B. Not signed (advisory).
    pub hops: u8,
    /// Provenance: one [`TraceHop`] per forwarder, in order (DESIGN.md §27). Not
    /// signed — it's mutable forwarding metadata. Lets the destination see the path
    /// (who + which app) and nodes learn routes from ACK/trace correlation.
    pub trace: Vec<TraceHop>,
}

/// Delivery options for a new bundle. Use `..Default::default()` for the rest.
#[derive(Clone, Copy, Debug)]
pub struct BundleOpts {
    /// Application namespace on the shared fabric (DESIGN.md §17).
    pub app: AppId,
    /// Sender clock in ms — advisory only (see DESIGN.md §8).
    pub created_at: u64,
    pub lifetime_ms: u32,
    pub hop_limit: u8,
    /// Initial spray-and-wait copy budget L (§6). 1 = direct-delivery only.
    pub copies: u16,
    /// Service priority (0 = lowest, default 4 = normal).
    pub priority: u8,
    pub flags: BundleFlags,
}

impl Default for BundleOpts {
    fn default() -> Self {
        Self {
            app: FABRIC_APP,
            created_at: 0,
            lifetime_ms: 86_400_000, // 24h — a delay-tolerant default (hops can take a long time)
            hop_limit: 8,
            copies: 8,
            priority: 4,
            flags: BundleFlags::default(),
        }
    }
}

/// A complete bundle as it travels across links.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub inner: SignedInner,
    pub env: Envelope,
    pub sig: Vec<u8>,
}

impl Bundle {
    /// Build, seal, and sign a new bundle from `from` to `dst`.
    ///
    /// `seal_to` is the **address** the payload is sealed to (its X25519 key is
    /// derived from it) — usually the destination device (B), or a gateway address
    /// for egress (A). An address is all you need; no separate sealing key.
    pub fn create(
        from: &Identity,
        dst: Destination,
        seal_to: &PubKeyBytes,
        payload: &Payload,
        opts: BundleOpts,
    ) -> Result<Self> {
        let plaintext = postcard::to_allocvec(payload)?;
        let sealed = crypto::seal(seal_to, &plaintext)?;

        let src = from.address();
        let id = compute_id(&src, &sealed);

        let inner = SignedInner {
            version: BUNDLE_VERSION,
            app: opts.app,
            id,
            src,
            dst,
            private: None,
            created_at: opts.created_at,
            lifetime_ms: opts.lifetime_ms,
            flags: opts.flags,
            priority: opts.priority,
            payload: sealed,
        };

        let sig = from.sign(&postcard::to_allocvec(&inner)?).to_vec();
        let env = Envelope {
            hop_limit: opts.hop_limit,
            custody: opts.flags.custody_requested.then_some(src),
            copies: opts.copies.max(1),
            hops: 0,
            trace: Vec::new(),
        };

        Ok(Bundle { inner, env, sig })
    }

    /// Build a §39 **private** (untraceable) bundle: no identity `src` (zeroed), it floods
    /// (`Destination::Broadcast`), and it is not identity-signed (empty `sig`). `seal_to`
    /// seals the payload (for now to an address — session-based sealing is a later phase);
    /// `recipient_spk_pub` is the recipient's signed-prekey public, used to derive the
    /// recognition tag only the recipient can recompute.
    pub fn create_private(
        seal_to: &PubKeyBytes,
        recipient_spk_pub: &XPubKeyBytes,
        payload: &Payload,
        // core-protocol-r2-02: the recipient's mailbox ROUTING PREFIX only, never the full tag.
        mailbox: Option<crate::crypto::MailboxRoute>,
        opts: BundleOpts,
    ) -> Result<Self> {
        let plaintext = postcard::to_allocvec(payload)?;
        let sealed = crypto::seal(seal_to, &plaintext)?;
        // r13-01: the recognition tag keys on the CONTENT id (sealed payload), computed before the id so
        // there is no id⇄tag circularity. r14-01: the wire id then binds the WHOLE inner (header + every
        // scalar field), so assemble the inner with a zeroed id and stamp the real id over it.
        let content_id = compute_private_content_id(&sealed);
        let (ephemeral, tag) = crypto::recognition_tag_sender(recipient_spk_pub, &content_id);
        let header = PrivateHeader {
            tag,
            ephemeral,
            mailbox,
        };

        let mut inner = SignedInner {
            version: BUNDLE_VERSION,
            app: opts.app,
            id: [0u8; 32],
            src: [0u8; 32],
            dst: Destination::Broadcast,
            private: Some(header),
            created_at: opts.created_at,
            lifetime_ms: opts.lifetime_ms,
            flags: opts.flags,
            priority: opts.priority,
            payload: sealed,
        };
        inner.id = compute_private_wire_id(&inner);
        let env = Envelope {
            hop_limit: opts.hop_limit,
            custody: None,
            copies: opts.copies.max(1),
            hops: 0,
            trace: Vec::new(),
        };
        Ok(Bundle {
            inner,
            env,
            sig: Vec::new(),
        })
    }

    /// Is this a §39 private (untraceable) bundle?
    pub fn is_private(&self) -> bool {
        self.inner.private.is_some()
    }

    /// §39 delivery vaccine anti-packet (sec-priv-07): an anonymous, unsigned bundle that floods ONLY
    /// the recipient's revealed recognition token — no plaintext delivered id. No src, no recipient,
    /// empty seal. Self-verifying by id (`id = H(domain ‖ token)`), and since the token is effectively
    /// unique per delivered bundle (a fresh ephemeral per message), all copies of one delivery's
    /// vaccine still dedup to a single flood.
    pub fn create_vaccine(token: [u8; 32], opts: BundleOpts) -> Self {
        let id = compute_vaccine_id(&token);
        let inner = SignedInner {
            version: BUNDLE_VERSION,
            app: opts.app,
            id,
            src: [0u8; 32],
            dst: Destination::Vaccine(token),
            private: None,
            created_at: opts.created_at,
            lifetime_ms: opts.lifetime_ms,
            flags: BundleFlags {
                is_ack: true,
                ..opts.flags
            },
            priority: opts.priority,
            payload: Sealed {
                ephemeral_pub: [0u8; 32],
                nonce: [0u8; 12],
                ciphertext: Vec::new(),
            },
        };
        let env = Envelope {
            hop_limit: opts.hop_limit,
            custody: None,
            copies: opts.copies.max(1),
            hops: 0,
            trace: Vec::new(),
        };
        Bundle {
            inner,
            env,
            sig: Vec::new(),
        }
    }

    /// §39 "is this mine?": true iff this is a private bundle whose recognition tag the
    /// holder of `spk_secret` recomputes. One DH + one hash; no payload decryption.
    pub fn recognized_by(&self, spk_secret: &[u8; 32]) -> bool {
        match &self.inner.private {
            Some(ph) => {
                // r13-01: the tag keys on the content id (sealed payload), not the wire id.
                let content_id = compute_private_content_id(&self.inner.payload);
                crypto::recognition_tag_recipient(spk_secret, &ph.ephemeral, &content_id) == ph.tag
            }
            None => false,
        }
    }

    /// r13-01: the §39 content id — `BLAKE3(domain ‖ sealed payload)` — that the recognition tag, the
    /// delivery vaccine, and the private-ACK proof all key on. Distinct from the wire [`Bundle::id`],
    /// which also binds the recognition header so a header rewrite can't reuse a genuine id. `None` for
    /// a non-private bundle.
    pub fn private_content_id(&self) -> Option<BundleId> {
        self.inner
            .private
            .as_ref()
            .map(|_| compute_private_content_id(&self.inner.payload))
    }

    /// The bundle id.
    pub fn id(&self) -> BundleId {
        self.inner.id
    }

    /// Verify the source signature and that the id matches the sealed payload.
    /// Relays should call this before forwarding to avoid amplifying garbage.
    pub fn verify(&self) -> Result<()> {
        // Reject a bundle whose wire version this build doesn't speak. Relays call verify()
        // before storing/forwarding (node.rs `on_bundle`), so this is the network hot-path
        // guard that complements the decode-time check in [`Bundle::from_bytes`] — a peer on a
        // newer wire layout is rejected loudly instead of misinterpreted (F-02).
        if !is_supported_bundle_version(self.inner.version) {
            return Err(Error::UnsupportedVersion {
                got: self.inner.version,
                supported: BUNDLE_VERSION,
            });
        }
        // Private bundle (§39): not identity-signed. The id alone binds the sealed bytes;
        // the recipient is found by the recognition tag, not a signature or a dst.
        if self.inner.private.is_some() {
            // core-protocol-r10-01: enforce the §39 invariant that a private bundle is ALWAYS
            // Broadcast-dst (create_private sets exactly this; a private bundle floods and is routed by
            // its recognition tag / mailbox prefix, never a dst). dst is now also folded into the id
            // (r14), but keep this explicit gate so a malformed shape is rejected with a clear invariant.
            if !matches!(self.inner.dst, Destination::Broadcast) {
                return Err(Error::BadSignature);
            }
            // core-protocol-r13-01/r14-01: the wire id binds the ENTIRE inner — the sealed payload, the
            // recognition header (tag/ephemeral/mailbox), AND every scalar (app/created_at/lifetime_ms/
            // flags/priority/...). A chimera reusing the sealed bytes but rewriting the header (r13) OR a
            // twin flipping a scalar like flags.request_ack (r14) MUST carry a different id, so it can
            // never occupy the genuine bundle's id at a keep-first relay to shadow it. A relay recomputes
            // this with no recipient secret; there is no signature, so this id-recomputation IS the
            // integrity check for an unsigned private bundle.
            return if compute_private_wire_id(&self.inner) == self.inner.id {
                Ok(())
            } else {
                Err(Error::BadSignature)
            };
        }
        // §39 vaccine (sec-priv-07): anonymous + unsigned. Self-verifying — its id binds its own token,
        // so a tampered anti-packet is rejected. The token is matched against each held bundle's tag at
        // drop time; no plaintext delivered id rides in the clear.
        if let Destination::Vaccine(token) = &self.inner.dst {
            // core-protocol-r15-01: the vaccine id binds ONLY the token (by design — so every re-emitted
            // vaccine for one delivery dedups to a single flood), which leaves the rest of the bundle
            // unbound and, like any unsigned self-verifying id, forgeable in SHAPE. A same-id twin that
            // flips `is_ack` to false passes the id check yet skips the entire is_ack-gated resolve/drop
            // in on_bundle, so it marks the vaccine id `seen` WITHOUT purging — then the genuine
            // anti-packet is deduped out and the delivered §39 bundle lingers + re-floods to TTL
            // (epidemic recovery defeated). A payload-bearing twin would similarly amplify the flood.
            // Enforce the canonical vaccine shape at the gate: it IS an ack, it is anonymous (no src),
            // and it carries no payload — exactly what `create_vaccine` builds.
            let canonical = self.inner.flags.is_ack
                && self.inner.src == [0u8; 32]
                && self.inner.payload.ciphertext.is_empty();
            return if canonical && compute_vaccine_id(token) == self.inner.id {
                Ok(())
            } else {
                Err(Error::BadSignature)
            };
        }
        if compute_id(&self.inner.src, &self.inner.payload) != self.inner.id {
            return Err(Error::BadSignature);
        }
        let msg = postcard::to_allocvec(&self.inner)?;
        if crypto::verify(&self.inner.src, &msg, &self.sig) {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }

    /// Open the sealed payload with the recipient identity (destination or gateway).
    pub fn open(&self, recipient: &Identity) -> Result<Payload> {
        let plaintext = recipient.open(&self.inner.payload)?;
        Ok(postcard::from_bytes(&plaintext)?)
    }

    /// Binary spray-and-wait handoff (§6): split this custodian's copy budget,
    /// reducing our own count and returning the number to give the peer
    /// (`floor(n/2)`). At a single copy this returns 0 — the wait phase, where the
    /// bundle is only ever handed directly to its destination.
    pub fn split_copies(&mut self) -> u16 {
        let give = self.env.copies / 2;
        self.env.copies -= give;
        give
    }

    /// Are we down to the last copy (wait phase)?
    pub fn is_last_copy(&self) -> bool {
        self.env.copies <= 1
    }

    /// Mark this copy as forwarded one hop: increment travelled `hops` and
    /// decrement `hop_limit`. Returns false if the hop limit is exhausted.
    pub fn forwarded(&mut self) -> bool {
        self.env.hops = self.env.hops.saturating_add(1);
        self.decrement_hop()
    }

    /// Append a forwarder (node + carrying app) to the provenance trace (DESIGN.md
    /// §27). Capped so a long-lived bundle can't grow an unbounded header.
    pub fn add_hop(&mut self, node: ShortAddr, app: ShortApp) {
        const MAX_TRACE: usize = 16;
        if self.env.trace.len() < MAX_TRACE {
            self.env.trace.push(TraceHop { node, app });
        }
    }

    /// The provenance trace: who (and which app) forwarded this bundle, in order.
    pub fn trace(&self) -> &[TraceHop] {
        &self.env.trace
    }

    /// Decrement the hop limit for forwarding. Returns false if undeliverable.
    pub fn decrement_hop(&mut self) -> bool {
        match self.env.hop_limit.checked_sub(1) {
            Some(n) => {
                self.env.hop_limit = n;
                true
            }
            None => false,
        }
    }

    /// Encode to the wire format (postcard — see DESIGN.md §13.4).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_allocvec(self)?)
    }

    /// Decode from the wire format.
    ///
    /// The first byte is `SignedInner::version` (postcard encodes struct fields in order,
    /// and `version` leads `SignedInner`, which leads `Bundle`). We reject an unknown
    /// version *before* decoding so a discriminant shift in a newer build fails loudly with
    /// [`Error::UnsupportedVersion`] instead of silently misdecoding into the wrong variant.
    /// See DESIGN.md §13.4 and the append-only enum discipline on [`Destination`]/[`Payload`].
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        match data.first() {
            None => return Err(Error::Codec(postcard::Error::DeserializeUnexpectedEnd)),
            Some(&v) if !is_supported_bundle_version(v) => {
                return Err(Error::UnsupportedVersion {
                    got: v,
                    supported: BUNDLE_VERSION,
                });
            }
            _ => {}
        }
        Ok(postcard::from_bytes(data)?)
    }
}

/// Which bundle wire versions this build can decode. Add older versions here when a
/// migration path is needed; today only the current version is accepted.
fn is_supported_bundle_version(v: u8) -> bool {
    v == BUNDLE_VERSION
}

fn compute_id(src: &PubKeyBytes, sealed: &Sealed) -> BundleId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(src);
    hasher.update(&sealed.ephemeral_pub);
    hasher.update(&sealed.nonce);
    hasher.update(&sealed.ciphertext);
    *hasher.finalize().as_bytes()
}

/// §39 private CONTENT id: `BLAKE3(domain ‖ sealed)` — no `src`. The seal's own ephemeral + nonce make
/// it unique per message. The recognition tag is keyed on THIS (available before the wire id, so there
/// is no id⇄tag circularity), and a header rewrite leaves it unchanged. The WIRE id (below) then binds
/// content_id ‖ header, so the two together defeat the recognition-header chimera class.
fn compute_private_content_id(sealed: &Sealed) -> BundleId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hop private bundle id v1");
    hasher.update(&sealed.ephemeral_pub);
    hasher.update(&sealed.nonce);
    hasher.update(&sealed.ciphertext);
    *hasher.finalize().as_bytes()
}

/// §39 private WIRE id (core-protocol-r13-01 + r14-01): `BLAKE3(domain ‖ postcard(inner with id zeroed))`.
/// This is the bundle's on-wire `id`. A private bundle carries NO signature, so its id is its ONLY
/// integrity check — it must therefore commit to the ENTIRE [`SignedInner`]: the sealed payload, the
/// recognition header (`tag`/`ephemeral`/`mailbox`, inside `private`), AND every scalar field
/// (`version`/`app`/`src`/`dst`/`created_at`/`lifetime_ms`/`flags`/`priority`). Any tamper — a rewritten
/// recognition header (the r13 chimera class) OR a flipped scalar such as `flags.request_ack` (the r14
/// twin, which stripped the recipient's ACK + the delivery vaccine) — yields a DIFFERENT id, so the twin
/// floods as its own bundle and can never occupy the genuine id at a keep-first relay store. Any relay
/// recomputes this with NO secret, and `verify()` rejects a bundle whose id doesn't match its own bytes,
/// closing the whole tampering class at the gate. Hashing the postcard encoding (with `id` zeroed to
/// break the self-reference) auto-binds any field added to `SignedInner` later, so the id can never again
/// silently leave a mutable field unbound.
fn compute_private_wire_id(inner: &SignedInner) -> BundleId {
    let mut zeroed = inner.clone();
    zeroed.id = [0u8; 32];
    let bytes = postcard::to_allocvec(&zeroed)
        .expect("a SignedInner that decoded from the wire always re-serializes");
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hop private bundle wire-id v2");
    hasher.update(&bytes);
    *hasher.finalize().as_bytes()
}

/// §39 vaccine id (sec-priv-07): `BLAKE3(domain ‖ token)` — deterministic, so all vaccines for one
/// delivery dedup to a single flood (the token is unique per delivered bundle), and self-verifying
/// (the id binds its own token, no signature needed — a tampered token yields a different id and is
/// rejected by `verify()`). The `v2` domain shift also hard-forks the id off the old `(delivered,
/// token)` layout so a stale-wire anti-packet can't be mistaken for a valid one.
fn compute_vaccine_id(token: &[u8; 32]) -> BundleId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hop vaccine id v2");
    hasher.update(token);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(from: &Identity, to_addr: &PubKeyBytes) -> Bundle {
        Bundle::create(
            from,
            Destination::Broadcast,
            to_addr,
            &Payload::PeerMessage {
                content_type: "text/plain".into(),
                body: b"hello mesh".to_vec(),
            },
            BundleOpts {
                created_at: 1_000,
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
    fn create_verify_open_roundtrip() {
        let alice = Identity::generate();
        let gw = Identity::generate();
        let b = sample(&alice, &gw.address());

        b.verify().unwrap();
        match b.open(&gw).unwrap() {
            Payload::PeerMessage { body, .. } => assert_eq!(body, b"hello mesh"),
            _ => panic!("wrong payload"),
        }
    }

    #[test]
    fn wire_roundtrip_is_stable() {
        let alice = Identity::generate();
        let gw = Identity::generate();
        let b = sample(&alice, &gw.address());

        let bytes = b.to_bytes().unwrap();
        let decoded = Bundle::from_bytes(&bytes).unwrap();
        assert_eq!(b, decoded);
        decoded.verify().unwrap();
    }

    #[test]
    fn tampering_breaks_verification() {
        let alice = Identity::generate();
        let gw = Identity::generate();
        let mut b = sample(&alice, &gw.address());

        b.inner.lifetime_ms = 1; // mutate a signed field
        assert!(matches!(b.verify(), Err(Error::BadSignature)));
    }

    #[test]
    fn forwarding_envelope_is_not_signed() {
        let alice = Identity::generate();
        let gw = Identity::generate();
        let mut b = sample(&alice, &gw.address());

        assert!(b.decrement_hop()); // relays mutate the envelope
        b.verify().unwrap(); // signature still valid
    }

    // --- §39 private (untraceable) bundles -------------------------------------

    fn sample_private(to: &Identity, spk_pub: &XPubKeyBytes) -> Bundle {
        Bundle::create_private(
            &to.address(),
            spk_pub,
            &Payload::PeerMessage {
                content_type: "text/plain".into(),
                body: b"psst".to_vec(),
            },
            None,
            BundleOpts::default(),
        )
        .unwrap()
    }

    #[test]
    fn private_bundle_roundtrips_recognizes_and_verifies() {
        let bob = Identity::generate();
        let spk = bob.derive_prekey();
        let b = sample_private(&bob, &spk.public);

        // No identity src; floods; not identity-signed.
        assert!(b.is_private());
        assert_eq!(b.inner.src, [0u8; 32]);
        assert!(matches!(b.inner.dst, Destination::Broadcast));
        assert!(b.sig.is_empty());

        // Survives the wire and still verifies (id binds the sealed bytes, no signature).
        let decoded = Bundle::from_bytes(&b.to_bytes().unwrap()).unwrap();
        assert_eq!(b, decoded);
        decoded.verify().unwrap();

        // "Is this mine?" — the recipient's prekey recognizes it; a stranger's does not.
        assert!(decoded.recognized_by(&spk.secret_bytes()));
        assert!(!decoded.recognized_by(&Identity::generate().derive_prekey().secret_bytes()));

        // And the recipient can open the sealed payload.
        match decoded.open(&bob).unwrap() {
            Payload::PeerMessage { body, .. } => assert_eq!(body, b"psst"),
            _ => panic!("wrong payload"),
        }
    }

    #[test]
    fn private_bundle_id_tamper_breaks_verify_and_traced_is_not_private() {
        let bob = Identity::generate();
        let spk = bob.derive_prekey();
        let mut b = sample_private(&bob, &spk.public);
        b.inner.id[0] ^= 1; // tamper the id → no longer binds the sealed bytes
        assert!(matches!(b.verify(), Err(Error::BadSignature)));

        // A normal traced bundle is not private and isn't recognized by anyone's prekey.
        let traced = sample(&Identity::generate(), &bob.address());
        assert!(!traced.is_private());
        assert!(!traced.recognized_by(&spk.secret_bytes()));
    }

    // --- wire-format versioning (F-02) -----------------------------------------

    #[test]
    fn version_byte_leads_the_wire_and_current_decodes() {
        let alice = Identity::generate();
        let gw = Identity::generate();
        let b = sample(&alice, &gw.address());
        let bytes = b.to_bytes().unwrap();
        // SignedInner::version leads the struct, so it is the first wire byte.
        assert_eq!(bytes[0], BUNDLE_VERSION);
        assert!(Bundle::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn unknown_version_is_rejected_not_misdecoded() {
        let alice = Identity::generate();
        let gw = Identity::generate();
        let b = sample(&alice, &gw.address());
        let mut bytes = b.to_bytes().unwrap();
        bytes[0] = BUNDLE_VERSION + 7; // a future build's layout
        match Bundle::from_bytes(&bytes) {
            Err(Error::UnsupportedVersion { got, supported }) => {
                assert_eq!(got, BUNDLE_VERSION + 7);
                assert_eq!(supported, BUNDLE_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
        // Empty input is a clean codec error, not a panic.
        assert!(Bundle::from_bytes(&[]).is_err());
    }

    #[test]
    fn destination_discriminants_are_stable() {
        // Locks the append-only wire order: removing/reordering a variant renumbers the
        // rest and silently misroutes across peers (the InternetEgress-removal outage).
        // postcard writes an enum discriminant as a leading varint; assert each here.
        let dev = postcard::to_allocvec(&Destination::Device([9u8; 32])).unwrap();
        let ack = postcard::to_allocvec(&Destination::AckTo([9u8; 32], [1u8; 32])).unwrap();
        let bcast = postcard::to_allocvec(&Destination::Broadcast).unwrap();
        let vacc = postcard::to_allocvec(&Destination::Vaccine([1u8; 32])).unwrap();
        assert_eq!(dev[0], 0, "Device must stay discriminant 0");
        assert_eq!(ack[0], 1, "AckTo must stay discriminant 1");
        assert_eq!(
            bcast,
            vec![2],
            "Broadcast must stay discriminant 2 (and carry no data)"
        );
        // core-04: pin the appended Vaccine variant too, so a future reorder can't silently
        // shift its discriminant and break delivery-vaccine decode across the fleet.
        assert_eq!(vacc[0], 3, "Vaccine must stay discriminant 3");
        assert_eq!(
            vacc.len(),
            1 + 32,
            "Vaccine carries only the 32-byte token (sec-priv-07: no plaintext delivered id)"
        );
    }

    #[test]
    fn payload_and_streamkind_discriminants_are_stable() {
        // core-protocol-r2-05: `Payload` rides INSIDE the seal and postcard encodes it by variant
        // INDEX. A reorder within the same BUNDLE_VERSION would silently misdecode sealed content across
        // the fleet with no version-gate failure. Lock every variant's leading discriminant here (mirror
        // of `destination_discriminants_are_stable`) so an accidental reorder fails CI loudly. To ADD a
        // variant, append it at the END with the next index and extend this list — never reorder.
        use crate::session::{Header, RatchetMessage};
        let ratchet = RatchetMessage {
            header: Header {
                dh: [0u8; 32],
                pn: 0,
                n: 0,
            },
            ciphertext: Vec::new(),
        };
        // (expected discriminant, a constructed instance). Order MUST match the enum declaration.
        let variants: Vec<(usize, Payload)> = vec![
            (
                0,
                Payload::HttpRequest {
                    host: String::new(),
                    method: String::new(),
                    url: String::new(),
                    headers: Vec::new(),
                    body: Vec::new(),
                    max_resp_bytes: 0,
                },
            ),
            (
                1,
                Payload::HttpResponse {
                    status: 0,
                    headers: Vec::new(),
                    body: Vec::new(),
                    for_bundle_id: [0u8; 32],
                },
            ),
            (
                2,
                Payload::PeerMessage {
                    content_type: String::new(),
                    body: Vec::new(),
                },
            ),
            (
                3,
                Payload::SessionInit {
                    ek_pub: [0u8; 32],
                    spk_pub: [0u8; 32],
                    msg: ratchet.clone(),
                },
            ),
            (
                4,
                Payload::SessionMessage {
                    msg: ratchet.clone(),
                },
            ),
            (
                5,
                Payload::Private {
                    sender: [0u8; 32],
                    inner: Box::new(Payload::PeerMessage {
                        content_type: String::new(),
                        body: Vec::new(),
                    }),
                },
            ),
            (
                6,
                Payload::Ack {
                    for_bundle_id: [0u8; 32],
                    status: 0,
                    delivery_hops: 0,
                    delivery_ms: 0,
                    proof: None,
                },
            ),
            (
                7,
                Payload::StreamOpen {
                    stream_id: [0u8; 16],
                    kind: StreamKind::Sse,
                    method: String::new(),
                    url: String::new(),
                    headers: Vec::new(),
                },
            ),
            (
                8,
                Payload::StreamData {
                    stream_id: [0u8; 16],
                    seq: 0,
                    bytes: Vec::new(),
                    fin: false,
                },
            ),
            (
                9,
                Payload::StreamAck {
                    stream_id: [0u8; 16],
                    ack: 0,
                },
            ),
            (
                10,
                Payload::StreamClose {
                    stream_id: [0u8; 16],
                    reason: 0,
                },
            ),
            (
                11,
                Payload::ServiceRequest {
                    service: String::new(),
                    method: String::new(),
                    args: Vec::new(),
                },
            ),
            (
                12,
                Payload::ServiceResponse {
                    for_bundle_id: [0u8; 32],
                    status: 0,
                    body: Vec::new(),
                },
            ),
            (
                13,
                Payload::Carrier {
                    stream_id: [0u8; 16],
                    seq: 0,
                    bytes: Vec::new(),
                    fin: false,
                },
            ),
            (
                14,
                Payload::HpsJoinRequest {
                    path: String::new(),
                    proof: [0u8; 32],
                },
            ),
            (
                15,
                Payload::HpsKeys {
                    path: String::new(),
                    content_key: [0u8; 32],
                    service_pubkey: None,
                    epoch: 0,
                },
            ),
            (
                16,
                Payload::HpsInvite {
                    path: String::new(),
                    kind: crate::hps::ServiceKind::Channel,
                    proof: [0u8; 32],
                },
            ),
            (
                17,
                Payload::HpsInviteAccept {
                    path: String::new(),
                    proof: [0u8; 32],
                },
            ),
            (
                18,
                Payload::HpsLeave {
                    path: String::new(),
                    proof: [0u8; 32],
                },
            ),
            (
                19,
                Payload::HpsRekey {
                    old_path: String::new(),
                    new_path: String::new(),
                    epoch: 0,
                    content_key: [0u8; 32],
                    service_pubkey: None,
                    proof: [0u8; 32],
                },
            ),
            (
                20,
                Payload::HpsReachAck {
                    topic_tag: [0u8; 16],
                    epoch: 0,
                },
            ),
            (
                21,
                Payload::HpsPublish {
                    topic_tag: [0u8; 16],
                    epoch: 0,
                    nonce: Vec::new(),
                    ciphertext: Vec::new(),
                    sig: Vec::new(),
                },
            ),
            (22, Payload::SessionReset),
        ];
        for (want, p) in &variants {
            let enc = postcard::to_allocvec(p).unwrap();
            assert_eq!(
                enc[0] as usize, *want,
                "Payload::{p:?} must keep discriminant {want} (append-only wire discipline)"
            );
        }
        assert_eq!(variants.len(), 23, "all 23 Payload variants are pinned");

        // StreamKind also rides inside sealed StreamOpen; pin it too.
        assert_eq!(postcard::to_allocvec(&StreamKind::Sse).unwrap(), vec![0]);
        assert_eq!(
            postcard::to_allocvec(&StreamKind::WebSocket).unwrap(),
            vec![1]
        );
    }

    #[test]
    fn a_non_canonical_vaccine_twin_is_rejected_at_verify() {
        // core-protocol-r15-01: the vaccine id = BLAKE3(domain ‖ token) binds ONLY the token, so every
        // field but the token is unbound on this unsigned, self-verifying bundle. Pre-r15 an attacker who
        // captured a genuine vaccine's (cleartext) token could mint a same-id twin with is_ack flipped
        // OFF: it passed verify(), skipped the is_ack-gated resolve/drop, and marked the vaccine id `seen`
        // — so the genuine anti-packet was later deduped out and the delivered §39 bundle was never purged
        // (epidemic recovery defeated). r15 enforces the canonical vaccine shape at verify().
        let token = [7u8; 32];
        let genuine = Bundle::create_vaccine(token, BundleOpts::default());
        assert!(genuine.verify().is_ok(), "a genuine vaccine verifies");
        assert!(genuine.inner.flags.is_ack, "a genuine vaccine is an ack");

        // Same token => same id, but is_ack flipped off — the resolve-suppression twin.
        let mut no_ack = genuine.clone();
        no_ack.inner.flags.is_ack = false;
        assert_eq!(
            no_ack.id(),
            genuine.id(),
            "the twin keeps the genuine vaccine id (the occupation attempt)"
        );
        assert!(
            no_ack.verify().is_err(),
            "r15: a non-ack vaccine twin is rejected — it can no longer occupy the vaccine id's seen slot"
        );

        // A payload-bearing twin (flood amplification) is rejected too.
        let mut bloated = genuine.clone();
        bloated.inner.payload.ciphertext = vec![0u8; 4096];
        assert!(
            bloated.verify().is_err(),
            "r15: a vaccine carrying a payload is rejected (no flood amplification)"
        );

        // A non-anonymous twin (src set) is rejected.
        let mut with_src = genuine.clone();
        with_src.inner.src = [9u8; 32];
        assert!(
            with_src.verify().is_err(),
            "r15: a vaccine must be anonymous (no src)"
        );
    }
}
