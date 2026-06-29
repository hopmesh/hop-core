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
pub const BUNDLE_VERSION: u8 = 1;

/// Globally-unique bundle id: `BLAKE3(src || nonce || payload_hash)`.
pub type BundleId = [u8; 32];

/// Where a bundle is headed. See DESIGN.md §5.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Destination {
    /// Use Case B: a specific device address.
    Device(PubKeyBytes),
    /// Use Case A: any gateway with the egress capability.
    InternetEgress,
    /// An ACK routed back to `origin` for a given bundle id.
    AckTo(PubKeyBytes, BundleId),
    /// Flood to everyone: every node relays it onward AND processes it locally (deduped by id).
    /// Used by `hps://` publishes, which fan out to subscribers the publisher doesn't enumerate
    /// (DESIGN.md §32).
    Broadcast,
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
    /// HNS resolution query (DESIGN.md §30): "what is the hops endpoint address for this
    /// domain?" Sealed and addressed to an internet-connected peer (e.g. a relay) that can
    /// reach the public DNS. Any such peer may answer; a relay *may* serve this but need not.
    HnsQuery {
        /// The fully-qualified domain to resolve (the resolver looks up `_hopaddress.<domain>`).
        domain: String,
    },
    /// HNS resolution answer (DESIGN.md §30): the **raw DoH response bodies** making up the
    /// domain's full DNSSEC chain. The asker re-validates this proof itself against the root
    /// anchors — so it never trusts the answering node, only the cryptography. (Carrying the
    /// proof, not a bare address, is what makes multi-hop resolution trustless.)
    HnsAnswer {
        domain: String,
        proof: Vec<String>,
        for_query: BundleId,
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
    HpsJoinRequest { path: String, proof: [u8; 32] },
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
    HpsInvite { path: String, kind: crate::hps::ServiceKind, proof: [u8; 32] },
    /// Destination → host: accept a pending invite; the host then seals [`Payload::HpsKeys`].
    HpsInviteAccept { path: String, proof: [u8; 32] },
    /// Member → host: leave a topic, so the host drops them from the retained set / reach tally.
    HpsLeave { path: String, proof: [u8; 32] },
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
    HpsReachAck { topic_tag: [u8; 16], epoch: u32 },
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
    /// Optional rotatable mailbox pseudonym, so a relay can spool by it for pull (§39).
    pub mailbox: Option<Tag>,
    /// Optional `k`-bit gradient prefix hint (blinded). Routing detail; opaque here.
    pub hint: Option<Vec<u8>>,
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
        mailbox: Option<Tag>,
        hint: Option<Vec<u8>>,
        opts: BundleOpts,
    ) -> Result<Self> {
        let plaintext = postcard::to_allocvec(payload)?;
        let sealed = crypto::seal(seal_to, &plaintext)?;
        let id = compute_private_id(&sealed);
        let (ephemeral, tag) = crypto::recognition_tag_sender(recipient_spk_pub, &id);

        let inner = SignedInner {
            version: BUNDLE_VERSION,
            app: opts.app,
            id,
            src: [0u8; 32],
            dst: Destination::Broadcast,
            private: Some(PrivateHeader { tag, ephemeral, mailbox, hint }),
            created_at: opts.created_at,
            lifetime_ms: opts.lifetime_ms,
            flags: opts.flags,
            priority: opts.priority,
            payload: sealed,
        };
        let env = Envelope {
            hop_limit: opts.hop_limit,
            custody: None,
            copies: opts.copies.max(1),
            hops: 0,
            trace: Vec::new(),
        };
        Ok(Bundle { inner, env, sig: Vec::new() })
    }

    /// Is this a §39 private (untraceable) bundle?
    pub fn is_private(&self) -> bool {
        self.inner.private.is_some()
    }

    /// §39 "is this mine?": true iff this is a private bundle whose recognition tag the
    /// holder of `spk_secret` recomputes. One DH + one hash; no payload decryption.
    pub fn recognized_by(&self, spk_secret: &[u8; 32]) -> bool {
        match &self.inner.private {
            Some(ph) => {
                crypto::recognition_tag_recipient(spk_secret, &ph.ephemeral, &self.inner.id) == ph.tag
            }
            None => false,
        }
    }

    /// The bundle id.
    pub fn id(&self) -> BundleId {
        self.inner.id
    }

    /// Verify the source signature and that the id matches the sealed payload.
    /// Relays should call this before forwarding to avoid amplifying garbage.
    pub fn verify(&self) -> Result<()> {
        // Private bundle (§39): not identity-signed. The id alone binds the sealed bytes;
        // the recipient is found by the recognition tag, not a signature or a dst.
        if self.inner.private.is_some() {
            return if compute_private_id(&self.inner.payload) == self.inner.id {
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
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Ok(postcard::from_bytes(data)?)
    }
}

fn compute_id(src: &PubKeyBytes, sealed: &Sealed) -> BundleId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(src);
    hasher.update(&sealed.ephemeral_pub);
    hasher.update(&sealed.nonce);
    hasher.update(&sealed.ciphertext);
    *hasher.finalize().as_bytes()
}

/// §39 private bundle id: `BLAKE3(domain ‖ sealed)` — no `src`. The seal's own ephemeral
/// + nonce make it unique per message, and the recognition tag binds to it.
fn compute_private_id(sealed: &Sealed) -> BundleId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hop private bundle id v1");
    hasher.update(&sealed.ephemeral_pub);
    hasher.update(&sealed.nonce);
    hasher.update(&sealed.ciphertext);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(from: &Identity, to_addr: &PubKeyBytes) -> Bundle {
        Bundle::create(
            from,
            Destination::InternetEgress,
            to_addr,
            &Payload::PeerMessage {
                content_type: "text/plain".into(),
                body: b"hello mesh".to_vec(),
            },
            BundleOpts {
                created_at: 1_000,
                flags: BundleFlags { request_ack: true, ..Default::default() },
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
            &Payload::PeerMessage { content_type: "text/plain".into(), body: b"psst".to_vec() },
            None,
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
}
