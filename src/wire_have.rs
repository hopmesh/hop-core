//! `HaveSet`, the custody-beacon set that rides `Wire::Have` (DESIGN.md §35).
//!
//! ## Why this is its own file
//!
//! This type decides emitted bytes, so the wire-version guard must hash it. It used to live in
//! `store.rs`, which meant the guard hashed the ENTIRE persistence layer: the `Store` trait, the
//! in-memory backend, eviction and expiry policy, KV. None of that can move a wire byte, so every
//! ordinary storage change tripped the guard as a false wire bump, and
//! `vectors/wire-source-manifest.txt` warns in its own header that this "degrades the version into
//! a build counter". It fired for real when the dead `Store::split_copies` / `set_copies` methods
//! were deleted, a change that touched no bytes at all.
//!
//! Splitting the byte-deciding type out is the same move the manifest already records twice
//! (`node.rs -> wire_emit.rs`, `access.rs -> wire_stamp.rs`). `store::HaveSet` re-exports it, so no
//! caller changes.

use serde::{Deserialize, Serialize};

use crate::bundle::BundleId;

/// What a node knows it currently holds, used by routing to avoid re-offering bundles a peer
/// already has. Serializable so it can ride a `Wire::Have` custody beacon (DESIGN.md §35): a node
/// tells a directly-connected peer what it holds so the peer suppresses re-offering those, cutting
/// duplicate-ingress COGS.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaveSet {
    pub ids: Vec<BundleId>,
}
