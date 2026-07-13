//! # hop-core
//!
//! The pure-Rust core of Hop, a delay-tolerant mesh network. Everything
//! deterministic lives here — bundle codec, crypto, store-and-forward, routing,
//! and link framing — so it runs identically in unit tests, the `hop-sim`
//! simulator, and on-device via `hop-ffi`. Only the BLE bearer is native.
//!
//! See `DESIGN.md` at the repo root for the full protocol specification.

pub mod app;
pub mod bundle;
pub mod crypto;
pub mod discover;
pub mod error;
pub mod hps;
pub mod link;
pub mod node;
pub mod reach;
pub mod relay;
pub mod route;
pub mod routing;
pub mod session;
pub mod store;
pub mod stream;
pub mod util;

pub use error::{Error, Result};

/// Application namespace on the shared Hop fabric. See DESIGN.md §17.
///
/// Every Hop-enabled app advertises the **same** BLE service UUID and relays for
/// every other app — the fabric is shared, not per-app, so a single app is never
/// alone on the mesh. `AppId` tags each bundle and advert so an app can
/// demultiplex its own traffic; relays forward all apps' traffic regardless and
/// can't read sealed payloads. Derive a stable id from a reverse-DNS app name via
/// [`app_id`].
pub type AppId = [u8; 16];

/// The shared/default namespace. Traffic tagged here is fabric-wide (e.g. peer
/// discovery common to all apps).
pub const FABRIC_APP: AppId = [0u8; 16];

/// Derive a stable [`AppId`] from an application name (e.g. "com.example.jobs").
pub fn app_id(name: &str) -> AppId {
    let mut id = [0u8; 16];
    id.copy_from_slice(&blake3::hash(name.as_bytes()).as_bytes()[..16]);
    id
}

/// A compact 8-byte form of an [`AppId`], stamped into each trace hop alongside the
/// node's short address so a route shows *which app carried it* (DESIGN.md §27) — e.g.
/// a relay hop carries [`relay_app_id`]'s short form.
pub type ShortApp = [u8; 8];

/// The 8-byte short form of an app id.
pub fn short_app(app: &AppId) -> ShortApp {
    let mut s = [0u8; 8];
    s.copy_from_slice(&app[..8]);
    s
}

/// Reverse-DNS name of the Hop relay daemon's app identity.
pub const RELAY_APP_NAME: &str = "sh.hopme.relay";

/// Well-known [`AppId`] for the Hop relay daemon, so a relay-carried hop is labeled
/// "Hop Relay" in traces rather than an opaque address.
pub fn relay_app_id() -> AppId {
    app_id(RELAY_APP_NAME)
}

/// Common imports for working with hop-core.
pub mod prelude {
    pub use crate::app::{AppKeys, AppSecret, JOIN_EPOCH_MS};
    pub use crate::bundle::TraceHop;
    pub use crate::bundle::{
        Bundle, BundleFlags, BundleId, BundleOpts, Destination, Payload, StreamId, StreamKind,
    };
    pub use crate::crypto::{
        seal, short_addr, verify, Identity, PubKeyBytes, Sealed, ShortAddr, XPubKeyBytes,
    };
    pub use crate::discover::{Advert, AdvertBody, AdvertId, AdvertKind, Directory};
    pub use crate::error::{Error, Result};
    pub use crate::link::{
        fragment, Bearer, BearerEvent, Frame, LinkHandshake, LinkId, LinkSession, Reassembler, Role,
    };
    pub use crate::node::{
        HnsLookup, HnsResult, IdentityRecord, Node, NodeKind, ServiceReqItem, ServiceRespItem,
        SERVICE_IDENTIFY,
    };
    pub use crate::relay::RelayScorer;
    pub use crate::route::RouteTable;
    pub use crate::routing::{
        BundleMeta, ForwardDecision, GatewayBeacon, PeerId, Router, SprayAndWait,
    };
    pub use crate::store::{HaveSet, MemoryStore, Store};
    pub use crate::stream::{StreamBuffer, StreamReassembler};
    pub use crate::util::{compress, decompress};
    pub use crate::{app_id, relay_app_id, short_app, AppId, ShortApp, FABRIC_APP, RELAY_APP_NAME};
}
