//! Wire-byte determination that the node layer owns.
//!
//! Everything in this module decides bytes that leave the machine, or the exact envelope of
//! bytes we are willing to accept. It is deliberately separated from [`crate::node`], whose
//! remaining ~9k production lines are protocol state machine, scheduling, and bookkeeping that
//! cannot move a byte on the wire.
//!
//! `core/hop-core/vectors/wire-source-manifest.txt` names this file, not `node.rs`. The split is
//! the whole point: a read-only getter or a replay bound in the state machine is not a wire
//! change and must not demand a `BUNDLE_VERSION` bump, while anything below is.
//!
//! WIRE DISCIPLINE for this file:
//! - The enums are APPEND-ONLY. Postcard encodes variants by index, so reordering or removing a
//!   variant silently renumbers the rest. Append, never insert.
//! - Changing any constant below changes the accepted or emitted framing envelope.
//! - Any edit here is a wire change. Bump `BUNDLE_VERSION` (`crate::bundle`) and regenerate the
//!   deterministic corpus.
//!
//! The layout of a *bundle* is not here: that belongs to [`crate::bundle`] (fields, id
//! derivation, sealing), with [`crate::crypto`], [`crate::discover`], [`crate::hps`],
//! [`crate::access`], and [`crate::reach`] owning their own sealed layouts. The node layer only
//! chooses field VALUES for those, which the deterministic corpus pins independently.

use serde::{Deserialize, Serialize};

use crate::bundle::{Payload, StreamId};
use crate::crypto::{short_addr, PubKeyBytes, ShortAddr};

// --- link framing (DESIGN.md §20) -------------------------------------------

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
pub(crate) const MAX_RECORD_PLAINTEXT: usize = 60_000;
/// Hard aggregate cap for one link record. User payloads larger than this are not rejected: the
/// carrier-stream layer splits them into 48 KiB bundles before they reach link framing.
pub(crate) const MAX_REASSEMBLED_RECORD: usize = 1 << 20;
pub(crate) const MAX_RECORD_FRAGMENTS: usize =
    MAX_REASSEMBLED_RECORD.div_ceil(MAX_RECORD_PLAINTEXT);
/// Aggregate cap applied before decoding an attacker-controlled postcard link packet.
pub const MAX_LINK_PACKET_BYTES: usize = 64 * 1024;
pub(crate) const MAX_HANDSHAKE_MESSAGE_BYTES: usize = 1024;
pub(crate) const MAX_ADVERT_LINK_BYTES: usize = crate::discover::MAX_ADVERT_WIRE_BYTES + 8;

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
    Bundle(crate::bundle::Bundle),
    Advert(crate::discover::Advert),
    /// §35 custody beacon: "I already hold these ids, do not offer them to me." Mode-1 only:
    /// exchanged over the authenticated Noise link with the peer it constrains, so it is the
    /// peer's own truthful claim about its own store (no forgery/censorship surface, unlike a
    /// flooded beacon). Cuts duplicate-ingress COGS.
    Have(crate::store::HaveSet),
}

/// Postcard encodes this two-variant enum with a one-byte discriminant (`Bundle = 0`, `Advert = 1`).
/// Pinning that below lets us reject an oversized advert before deserializing attacker-sized strings
/// and vectors. A unit test asserts the discriminant assumption against the actual serializer.
pub(crate) fn advert_record_exceeds_limit(plaintext: &[u8]) -> bool {
    plaintext.first() == Some(&1) && plaintext.len() > MAX_ADVERT_LINK_BYTES
}

/// Encode one link packet into the bytes handed to a bearer. `None` on an encoding failure.
pub(crate) fn encode_packet(packet: &LinkPacket) -> Option<Vec<u8>> {
    postcard::to_allocvec(packet).ok()
}

/// Frame one application record into the link packets that carry it.
///
/// This is the ONLY place record framing is decided: postcard-encode the [`Wire`] record, then
/// either emit a single `Data` packet or split the plaintext at [`MAX_RECORD_PLAINTEXT`] into
/// ordered `DataFrag`s. `encrypt` advances the Noise ratchet per piece and must be called in
/// order; a failure mid-record abandons the remainder (the ratchet would desync) and returns the
/// successfully framed prefix.
pub(crate) fn frame_record<E>(record: &Wire, mut encrypt: E) -> Vec<Vec<u8>>
where
    E: FnMut(&[u8]) -> Option<Vec<u8>>,
{
    let Ok(plaintext) = postcard::to_allocvec(record) else {
        return Vec::new();
    };
    // Fits one Noise message: send as a single Data record (the common case).
    if plaintext.len() <= MAX_RECORD_PLAINTEXT {
        let Some(ct) = encrypt(&plaintext) else {
            return Vec::new();
        };
        return encode_packet(&LinkPacket::Data(ct))
            .map(|bytes| vec![bytes])
            .unwrap_or_default();
    }
    // Too large for one Noise message, so fragment across several rather than silently
    // dropped. Each piece is independently encrypted; the peer reassembles (§20).
    let pieces: Vec<&[u8]> = plaintext.chunks(MAX_RECORD_PLAINTEXT).collect();
    if pieces.len() > MAX_RECORD_FRAGMENTS {
        return Vec::new();
    }
    let cnt = pieces.len() as u16;
    let mut framed = Vec::with_capacity(pieces.len());
    for (i, piece) in pieces.into_iter().enumerate() {
        let Some(ct) = encrypt(piece) else {
            break; // ratchet would desync; abandon the rest of this record
        };
        if let Some(bytes) = encode_packet(&LinkPacket::DataFrag {
            idx: i as u16,
            cnt,
            ct,
        }) {
            framed.push(bytes);
        }
    }
    framed
}

/// Decode an attacker-controlled link packet, rejecting anything outside the framing envelope.
pub(crate) fn decode_link_packet(bytes: &[u8]) -> Option<LinkPacket> {
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

/// Bounds half of fragment reassembly: is this decrypted piece inside the accepted envelope,
/// given what is already buffered? The ordering/reset state machine stays with the link state in
/// [`crate::node`]; this pins the SIZE envelope, which is the wire-visible part.
pub(crate) fn fragment_bounds_ok(cnt: u16, piece_len: usize, buffered_len: usize) -> bool {
    usize::from(cnt) <= MAX_RECORD_FRAGMENTS
        && piece_len <= MAX_RECORD_PLAINTEXT
        && buffered_len.saturating_add(piece_len) <= MAX_REASSEMBLED_RECORD
}

/// Encode the Noise-handshake [`LinkAuth`] payload claiming our own address.
pub(crate) fn encode_link_auth(address: PubKeyBytes) -> Vec<u8> {
    postcard::to_allocvec(&LinkAuth { address }).expect("auth encode")
}

// --- forward-secret session plaintext (DESIGN.md §25) ------------------------

/// The plaintext inside a forward-secret session message: what the ratchet
/// encrypts, so `content_type` rides end-to-end like the body.
#[derive(Serialize, Deserialize)]
pub(crate) struct SessionInner {
    pub(crate) content_type: String,
    pub(crate) body: Vec<u8>,
}

/// Reserved content-type for a content-less re-establishment ping sent to heal a desynced
/// ratchet (DESIGN.md §25). The receiver rebuilds the session as a side effect and does not
/// surface it as a user message.
pub(crate) const SESSION_ESTABLISH_CT: &str = "hop.session.establish";

// --- built-in service wire bodies (DESIGN.md §29) ----------------------------

/// The built-in identity service (DESIGN.md §29): call it on any address to learn that
/// node's display name + kind. Answered by the node itself, not the app.
pub const SERVICE_IDENTIFY: &str = "hop.identify";

/// The built-in telemetry sink (OTel-over-Hop, DESIGN.md §40): a device exports a
/// [`TelemetryBatch`](crate::telemetry::TelemetryBatch) to a collector's address. One-way and
/// fire-and-forget (no response); the node decodes + bounds-checks it and surfaces it via
/// [`Node::take_telemetry`](crate::node::Node::take_telemetry). Statically sealed to the
/// collector like any addressed service.
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
/// (a device by default), so callers fall back to the short address. A relay sets its name
/// to its region domain. Carries the full `address` so a caller can resolve a short trace
/// hop it received against the responder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub name: Option<String>,
    pub kind: NodeKind,
    pub address: PubKeyBytes,
}

// --- transparent carrier streaming (DESIGN.md §20) ---------------------------

/// A bundle whose encoding exceeds this is carried as a stream of `STREAM_CHUNK`-sized
/// chunks (transparently); anything smaller goes as one bundle. Sized to fit comfortably
/// in one link record on every bearer (well under the 1 MiB frame cap).
pub(crate) const STREAM_CHUNK: usize = 48 * 1024;

/// A fresh stream id: our monotonic sequence in the high 8 bytes, our short address in the low 8.
/// Unique per node and stable to decode, so a receiver can attribute chunks without a lookup.
pub(crate) fn derive_stream_id(stream_seq: u64, address: &PubKeyBytes) -> StreamId {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&stream_seq.to_be_bytes());
    let short: ShortAddr = short_addr(address);
    id[8..].copy_from_slice(&short);
    id
}

/// Split an encoded bundle into the ordered `Payload::Carrier` chunks that carry it, pinning the
/// chunk boundaries, the `seq` numbering, and where `fin` lands.
pub(crate) fn carrier_chunk_payloads(
    encoded: &[u8],
    stream_id: StreamId,
    chunk_bytes: usize,
) -> Vec<Payload> {
    let chunks: Vec<&[u8]> = encoded.chunks(chunk_bytes).collect();
    let count = chunks.len();
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| Payload::Carrier {
            stream_id,
            seq: index as u64,
            bytes: chunk.to_vec(),
            fin: index + 1 == count,
        })
        .collect()
}

/// Feature-scoped parser entry point for cargo-fuzz. Production receives the same checks through
/// [`Node::on_data`](crate::node::Node), while the private packet enum remains outside the public
/// protocol API.
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

// Layout-pinning tests live OUTSIDE this file on purpose: this file is hashed by the wire-version
// guard, so test churn here would demand a BUNDLE_VERSION bump. See `wire_emit_tests.rs`.
#[cfg(test)]
#[path = "wire_emit_tests.rs"]
mod tests;
