//! Wire-byte determination for §35 carriage stamps.
//!
//! Everything in this module decides bytes that leave the machine: the [`CarriageStamp`] struct
//! layout carried on `bundle::Envelope::access`, the two domain separators, the hint derivation,
//! and the exact preimage a tenant signs. It is deliberately separated from [`crate::access`],
//! whose remaining lines are admission POLICY (which tenants are authorized, which are revoked,
//! how stale a stamp may be) and decide no byte at all.
//!
//! `core/hop-core/vectors/wire-source-manifest.txt` names this file, not `access.rs`. The split is
//! the whole point: adding a revocation rule or tightening a freshness bound is not a wire change
//! and must not demand a `BUNDLE_VERSION` bump, while anything below is. This mirrors the
//! `node.rs -> wire_emit.rs` narrowing, whose precedent is explicit that "a replay bound in the
//! state machine is not a wire change".
//!
//! WIRE DISCIPLINE for this file:
//! - [`CarriageStamp`]'s fields are postcard-encoded in declaration order. Reordering, inserting,
//!   or retyping a field silently changes the envelope bytes. Append, never insert.
//! - Both domain separators are hashed/signed inputs. Changing a byte of either invalidates every
//!   stamp in flight and is a hard wire break.
//! - [`HINT_BYTES`] is the on-wire width of the hint field; [`CARRIAGE_EPOCH_MS`] determines the
//!   `epoch` VALUE emitted for a given clock, so both the hint and the signature move with it.
//! - [`TenantId`]'s width is the hint preimage, so it decides emitted hint bytes even though the
//!   tenant id itself never appears on the wire.
//! - Any edit here is a wire change. Bump `BUNDLE_VERSION` (`crate::bundle`) and regenerate the
//!   deterministic corpus.
//!
//! What is NOT here, on purpose: the keyserver, the denylist, the current/previous acceptance
//! window, and the attribution helpers. Those choose whether to ACCEPT a stamp, never how one is
//! shaped. See [`crate::access`].

use serde::{Deserialize, Serialize};

use crate::bundle::BundleId;
use crate::crypto::Identity;

/// The billed identity: an app or org, never a person (§35). Opaque 16 bytes, minted by the
/// account service (e.g. a UUID). Never on the wire itself, but its width is the hint preimage.
pub type TenantId = [u8; 16];

/// Bytes of the rotating key-hint carried on the wire. A selector, not an identity: it buckets
/// tenants for O(1) relay lookup and rotates each epoch. Wider = fewer collisions (cheaper
/// verify) but smaller within-epoch anonymity set; the temporal unlinkability comes from
/// rotation, and full unlinkability is the blind-token Phase-2.
pub const HINT_BYTES: usize = 4;

/// The hint rotation period. Coarse (hours) so a still-valid stamp survives mesh transit, and so
/// the relay's precompute table turns over rarely. This decides the `epoch` value emitted for a
/// given wall clock, so it moves both the hint and the signed message: it is wire, not policy.
/// The acceptance WINDOW around the epoch is policy and lives in [`crate::access`].
pub const CARRIAGE_EPOCH_MS: u64 = 3_600_000; // 1 hour

/// Domain separator for the rotating hint.
const HINT_CONTEXT: &str = "hop carriage hint v1";
/// Domain separator for the per-bundle carriage signature.
const STAMP_CONTEXT: &[u8] = b"hop carriage stamp v1";

/// The rotating epoch index for a wall-clock time.
pub fn epoch_of(now_ms: u64) -> u64 {
    now_ms / CARRIAGE_EPOCH_MS
}

/// The rotating hint for a tenant in an epoch: `H(context || tenant_id || epoch)[..HINT_BYTES]`.
/// Deterministic, so the tenant (which knows its id) and the relay (whose keyserver knows every
/// tenant id) agree, while a network observer that does not know the id sees only a value that
/// rotates each epoch.
pub fn carriage_hint(tenant: &TenantId, epoch: u64) -> [u8; HINT_BYTES] {
    let mut km = Vec::with_capacity(16 + 8);
    km.extend_from_slice(tenant);
    km.extend_from_slice(&epoch.to_le_bytes());
    let h = blake3::derive_key(HINT_CONTEXT, &km);
    let mut hint = [0u8; HINT_BYTES];
    hint.copy_from_slice(&h[..HINT_BYTES]);
    hint
}

/// The message a tenant signs to bind a stamp to one bundle in one epoch.
pub(crate) fn stamp_message(bundle_id: &BundleId, epoch: u64) -> Vec<u8> {
    let mut msg = STAMP_CONTEXT.to_vec();
    msg.extend_from_slice(bundle_id);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg
}

/// The per-bundle credential on `bundle::Envelope::access`. Reveals nothing but a rotating
/// pseudonym; the signature is the authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarriageStamp {
    pub hint: [u8; HINT_BYTES],
    /// Ed25519 by the tenant key over `STAMP_CONTEXT || bundle_id || epoch`.
    pub sig: Vec<u8>,
    /// The epoch the hint + sig were computed for. Coarse global time, not identifying; carried
    /// so a relay verifies against the exact epoch rather than guessing (it still bounds guessing
    /// to {current, previous} to reject a stale or future epoch).
    pub epoch: u64,
}

/// Sender side: the tenant id + key a node stamps its originated bundles with. Configured once
/// (the app ships it or fetches it from the account service). Keys MUST be **app-scoped, never
/// per-user**: a per-device key makes the (rotating) hint a per-user tracking handle within an
/// epoch, defeating the §39 anonymity the rotation is there to protect.
///
/// This is the ONLY producer of stamp bytes, which is why it sits in the watched file rather than
/// beside the policy: swapping what [`Self::stamp`] puts in a field would move wire bytes without
/// touching [`stamp_message`] at all.
pub struct Stamper {
    tenant: TenantId,
    key: Identity,
}

impl Stamper {
    pub fn new(tenant: TenantId, key: Identity) -> Self {
        Self { tenant, key }
    }

    /// Stamp one bundle for the epoch of `now_ms`.
    pub fn stamp(&self, bundle_id: &BundleId, now_ms: u64) -> CarriageStamp {
        let epoch = epoch_of(now_ms);
        CarriageStamp {
            hint: carriage_hint(&self.tenant, epoch),
            sig: self.key.sign(&stamp_message(bundle_id, epoch)).to_vec(),
            epoch,
        }
    }

    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
}

// Layout-pinning tests live OUTSIDE this file on purpose: this file is hashed by the wire-version
// guard, so test churn here would demand a BUNDLE_VERSION bump. See `wire_stamp_tests.rs`.
#[cfg(test)]
#[path = "wire_stamp_tests.rs"]
mod tests;
