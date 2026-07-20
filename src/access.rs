//! Carriage stamps: per-bundle backbone access + metering attribution (DESIGN.md §35).
//!
//! §35's Relay Access Token authorizes a tenant at *link* setup, but a store-and-forward mesh
//! delivers a tenant's bundles to relays over *other* devices' connections (couriers != tenant).
//! Attribution therefore has to ride the *bundle*. A [`CarriageStamp`] is that per-bundle
//! credential, and it deliberately reveals NOTHING about the tenant to the network.
//!
//! ## What is on the wire, and what is not
//!
//! A stamp is a **rotating key-hint** plus a **signature**, nothing else:
//! ```text
//! CarriageStamp {
//!   hint: [u8; HINT_BYTES]  // H("hop carriage hint v1" || tenant_id || epoch)[..HINT_BYTES]
//!   sig:  [u8; 64]          // Ed25519(tenant key, "hop carriage stamp v1" || bundle_id || epoch)
//! }
//! ```
//! - No app id, no tenant id, no public key ever appears on the wire. A passive observer sees an
//!   opaque `hint` that **rotates every epoch**, so it cannot link a tenant's bundles across
//!   epochs (the same §39 discipline as mailbox-tag rotation: an observer who does not already
//!   know the tenant ids sees only a rotating pseudonym; one who enumerates them gets at most the
//!   k-anonymity of the bucket, and full unlinkability is the blind-token Phase-2).
//! - The `hint` is an O(1) **selector**, not the authorization: it narrows verification to the
//!   handful of tenants whose id hashes into the same epoch bucket (a keyserver precompute table,
//!   [`KeyedAccess::refresh`]). The authorization is the **signature**, which only the tenant's
//!   key can produce over this exact bundle id, so a relay cannot fabricate attribution and a
//!   captured stamp cannot be lifted onto another bundle. An unauthenticated bundle whose hint
//!   hits no known tenant is rejected after an O(1) lookup, never an N-key loop.
//!
//! ## Placement and the verify-at-the-meter rule
//!
//! The stamp rides the mutable, unsigned [`bundle::Envelope`], so it is excluded from BOTH the
//! private content id and the wire id: identical content dedups regardless of access material,
//! and a custodian holding a tenant key can re-stamp a stripped bundle without forking its id.
//! Because the bundle's own integrity checks do not cover the envelope, **every point that reads
//! a stamp for a billing or admission decision MUST call [`AccessPolicy::admit`] (which verifies
//! the signature), never trust the recovered tenant from a bare field**, or an attacker rewrites
//! who-pays. Tenants are apps or orgs, never people (§33/§39 k-anonymity), and the meter never
//! opens the sealed body.
//!
//! ## What lives here, and what does not
//!
//! The stamp's LAYOUT (the [`CarriageStamp`] struct, both domain separators, the hint derivation,
//! the signed preimage, and [`Stamper`], the only thing that emits one) lives in
//! [`crate::wire_stamp`], which the wire-version guard hashes. This file holds the POLICY that
//! reads a stamp: the keyserver, the denylist, the epoch acceptance window, and the attribution
//! entry points. None of it can move a byte on the wire, so it is deliberately NOT hashed: a new
//! revocation rule or a tightened freshness bound must not demand a `BUNDLE_VERSION` bump.
//!
//! Everything moved is re-exported below, so `access::CarriageStamp` and friends keep working.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::bundle::BundleId;
use crate::crypto::{self, PubKeyBytes};
use crate::wire_stamp::stamp_message;

pub use crate::wire_stamp::{
    carriage_hint, epoch_of, CarriageStamp, Stamper, TenantId, CARRIAGE_EPOCH_MS, HINT_BYTES,
};

/// The relay's keylist: which tenants are authorized, and the public key that verifies each
/// one's stamps. This IS "an unauthed key cannot ride": a stamp whose signer is not in the
/// keyserver never verifies. In production the fleet syncs this from the account service; a
/// self-hosted fleet supplies its own, which is why a commercial stamp means nothing to a
/// private fleet and vice versa (the cryptographic partition).
#[derive(Clone, Debug, Default)]
pub struct KeyServer {
    tenants: HashMap<TenantId, PubKeyBytes>,
}

impl KeyServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, tenant: TenantId, pubkey: PubKeyBytes) {
        self.tenants.insert(tenant, pubkey);
    }

    pub fn len(&self) -> usize {
        self.tenants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tenants.is_empty()
    }

    /// Precompute `{hint -> [tenant]}` for one epoch, so admission is an O(1) hint lookup plus an
    /// O(bucket) signature check, never an O(N) scan of the whole keylist per bundle.
    fn bucket_table(&self, epoch: u64) -> HashMap<[u8; HINT_BYTES], Vec<TenantId>> {
        let mut table: HashMap<[u8; HINT_BYTES], Vec<TenantId>> = HashMap::new();
        for tenant in self.tenants.keys() {
            table
                .entry(carriage_hint(tenant, epoch))
                .or_default()
                .push(*tenant);
        }
        table
    }
}

/// Relay-side admission policy for foreign (not-ours) bundles.
///
/// `Open` is the default everywhere: devices and open/self-hosted relays take custody of any
/// verifiable bundle, unmetered, exactly as before this module existed. `Keyed` is the hosted
/// backbone's policy (§35): custody requires a stamp whose signer is in the keyserver.
#[derive(Clone, Debug, Default)]
pub enum AccessPolicy {
    #[default]
    Open,
    Keyed(KeyedAccess),
}

/// The `Keyed` policy: the keyserver, an emergency denylist, and the precomputed hint tables for
/// the current + previous epoch (refreshed by the host as the clock rolls, [`Self::refresh`]).
#[derive(Clone, Debug)]
pub struct KeyedAccess {
    server: KeyServer,
    denied: HashSet<TenantId>,
    /// The epoch `current` was computed for; `previous` is for `epoch - 1`.
    epoch: u64,
    current: HashMap<[u8; HINT_BYTES], Vec<TenantId>>,
    previous: HashMap<[u8; HINT_BYTES], Vec<TenantId>>,
}

impl KeyedAccess {
    /// Build a keyed policy. Call [`Self::refresh`] with the node's clock before serving so the
    /// hint tables are populated for the current epoch.
    pub fn new(server: KeyServer, denied: HashSet<TenantId>) -> Self {
        Self {
            server,
            denied,
            epoch: 0,
            current: HashMap::new(),
            previous: HashMap::new(),
        }
    }

    /// Ensure the hint tables cover the epoch of `now_ms` (and the one before it). Cheap when the
    /// epoch has not rolled; on a roll it recomputes at most two tables. The host calls this on a
    /// timer (e.g. each tick); admission then reads the tables with no per-bundle scan.
    pub fn refresh(&mut self, now_ms: u64) {
        let epoch = epoch_of(now_ms);
        if !self.current.is_empty() && self.epoch == epoch {
            return;
        }
        if self.epoch + 1 == epoch && !self.current.is_empty() {
            // Rolled forward one epoch: yesterday's current becomes previous.
            self.previous = std::mem::take(&mut self.current);
        } else {
            self.previous = self.server.bucket_table(epoch.saturating_sub(1));
        }
        self.current = self.server.bucket_table(epoch);
        self.epoch = epoch;
    }

    /// Attribute a stamp to its tenant against its OWN claimed epoch, WITHOUT the current/previous
    /// freshness bound. For the durable path only (a spooled bundle re-ingested for offline
    /// delivery carries a legitimately-old stamp). Still fully verifies the signature (the epoch is
    /// signed, so it cannot be forged), so who-pays stays authenticated; it only relaxes the
    /// replay-window bound, safe here because the bundle was already admitted once with a fresh
    /// stamp and its delivery is deduped elsewhere. O(keyserver) hashing, only on the
    /// low-frequency re-ingest path, never the hot ingress path.
    fn attribute(&self, stamp: &CarriageStamp, bundle_id: &BundleId) -> Option<TenantId> {
        let msg = stamp_message(bundle_id, stamp.epoch);
        for (tenant, pk) in &self.server.tenants {
            if self.denied.contains(tenant) {
                continue;
            }
            if carriage_hint(tenant, stamp.epoch) == stamp.hint
                && crypto::verify(pk, &msg, &stamp.sig)
            {
                return Some(*tenant);
            }
        }
        None
    }

    /// Look up + verify a stamp for `bundle_id` at `now_ms`, returning the billed tenant.
    fn resolve(
        &self,
        stamp: &CarriageStamp,
        bundle_id: &BundleId,
        now_ms: u64,
    ) -> Option<TenantId> {
        let now_epoch = epoch_of(now_ms);
        // Accept only the current or immediately-previous epoch: a stale (long-expired) or future
        // stamp is refused, which bounds replay to the ~2h hint window.
        let table = if stamp.epoch == now_epoch {
            &self.current
        } else if stamp.epoch + 1 == now_epoch {
            &self.previous
        } else {
            return None;
        };
        let candidates = table.get(&stamp.hint)?;
        let msg = stamp_message(bundle_id, stamp.epoch);
        for tenant in candidates {
            if self.denied.contains(tenant) {
                continue;
            }
            if let Some(pk) = self.server.tenants.get(tenant) {
                if crypto::verify(pk, &msg, &stamp.sig) {
                    return Some(*tenant);
                }
            }
        }
        None
    }
}

/// The admission verdict for one foreign bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Take custody. `Some(tenant)` under a keyed policy (attributable); `None` under `Open`.
    Granted(Option<TenantId>),
    /// Refuse custody: no store, no forward, no spool.
    Refused,
}

impl AccessPolicy {
    /// Decide admission for a foreign bundle. Under `Keyed` this VERIFIES the stamp signature, so
    /// callers can trust the returned tenant for billing.
    pub fn admit(&self, stamp: Option<&CarriageStamp>, id: &BundleId, now_ms: u64) -> Admit {
        match self {
            AccessPolicy::Open => Admit::Granted(None),
            AccessPolicy::Keyed(k) => match stamp {
                Some(s) => match k.resolve(s, id, now_ms) {
                    Some(tenant) => Admit::Granted(Some(tenant)),
                    None => Admit::Refused,
                },
                None => Admit::Refused,
            },
        }
    }

    /// Attribute a (durable, possibly-old) stamp to its tenant, verifying the signature against
    /// its own signed epoch. `None` under `Open` (devices never meter) or if the stamp does not
    /// verify. Use only on the durable re-ingest path; the hot ingress path uses `admit`.
    pub fn attribute(&self, stamp: &CarriageStamp, id: &BundleId) -> Option<TenantId> {
        match self {
            AccessPolicy::Open => None,
            AccessPolicy::Keyed(k) => k.attribute(stamp, id),
        }
    }

    /// Refresh any epoch-derived state (the `Keyed` hint tables). No-op under `Open`.
    pub fn refresh(&mut self, now_ms: u64) {
        if let AccessPolicy::Keyed(k) = self {
            k.refresh(now_ms);
        }
    }
}

/// Per-tenant usage totals, the §35 metering atoms: attributed bundles (count + sealed payload
/// bytes). Accumulated by the node at the billing hook, drained by the relay's flush loop into
/// the durable ledger (§37).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub bundles: u64,
    pub payload_bytes: u64,
}

impl Usage {
    pub fn add(&mut self, other: &Usage) {
        self.bundles = self.bundles.saturating_add(other.bundles);
        self.payload_bytes = self.payload_bytes.saturating_add(other.payload_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    const TENANT: TenantId = [7u8; 16];

    fn keyed(server: KeyServer, denied: HashSet<TenantId>, now_ms: u64) -> AccessPolicy {
        let mut k = KeyedAccess::new(server, denied);
        k.refresh(now_ms);
        AccessPolicy::Keyed(k)
    }

    fn one_tenant() -> (Stamper, KeyServer) {
        let key = Identity::generate();
        let mut server = KeyServer::new();
        server.insert(TENANT, key.address());
        (Stamper::new(TENANT, key), server)
    }

    #[test]
    fn hint_hides_the_tenant_and_rotates_each_epoch() {
        let h0 = carriage_hint(&TENANT, 100);
        let h1 = carriage_hint(&TENANT, 101);
        assert_ne!(h0, h1, "hint rotates per epoch");
        // A different tenant in the same epoch gets a different hint (bucketing), and neither
        // hint is derivable from wire bytes alone without the tenant id.
        assert_ne!(carriage_hint(&[9u8; 16], 100), h0);
    }

    #[test]
    fn a_valid_stamp_resolves_to_its_tenant() {
        let now = 500 * CARRIAGE_EPOCH_MS + 123;
        let (stamper, server) = one_tenant();
        let policy = keyed(server, HashSet::new(), now);
        let id = [1u8; 32];
        let stamp = stamper.stamp(&id, now);
        assert_eq!(
            policy.admit(Some(&stamp), &id, now),
            Admit::Granted(Some(TENANT))
        );
    }

    #[test]
    fn open_admits_everything_keyed_needs_a_valid_stamp() {
        let now = 10 * CARRIAGE_EPOCH_MS;
        let (stamper, server) = one_tenant();
        let id = [2u8; 32];
        assert_eq!(
            AccessPolicy::Open.admit(None, &id, now),
            Admit::Granted(None)
        );
        let policy = keyed(server, HashSet::new(), now);
        assert_eq!(policy.admit(None, &id, now), Admit::Refused);
        assert_eq!(
            policy.admit(Some(&stamper.stamp(&id, now)), &id, now),
            Admit::Granted(Some(TENANT))
        );
    }

    #[test]
    fn a_stamp_is_bound_to_exactly_one_bundle_id() {
        let now = 3 * CARRIAGE_EPOCH_MS;
        let (stamper, server) = one_tenant();
        let policy = keyed(server, HashSet::new(), now);
        let stamp = stamper.stamp(&[1u8; 32], now);
        // Lifted onto another bundle: the signature no longer covers it.
        assert_eq!(policy.admit(Some(&stamp), &[2u8; 32], now), Admit::Refused);
    }

    #[test]
    fn an_unknown_signer_never_resolves() {
        let now = 7 * CARRIAGE_EPOCH_MS;
        // A tenant NOT in the keyserver: even a well-formed self-stamp is refused.
        let rogue = Stamper::new(TENANT, Identity::generate());
        let policy = keyed(KeyServer::new(), HashSet::new(), now);
        let id = [3u8; 32];
        assert_eq!(
            policy.admit(Some(&rogue.stamp(&id, now)), &id, now),
            Admit::Refused
        );
    }

    #[test]
    fn a_forged_hint_with_a_wrong_key_is_refused() {
        // Attacker knows the victim's TENANT id (so can compute the right hint) but not the key.
        let now = 4 * CARRIAGE_EPOCH_MS;
        let (_, server) = one_tenant(); // server maps TENANT -> the real key
        let policy = keyed(server, HashSet::new(), now);
        let id = [5u8; 32];
        let attacker = Identity::generate();
        let forged = CarriageStamp {
            hint: carriage_hint(&TENANT, epoch_of(now)), // correct bucket
            sig: attacker.sign(&stamp_message(&id, epoch_of(now))).to_vec(), // wrong signer
            epoch: epoch_of(now),
        };
        assert_eq!(policy.admit(Some(&forged), &id, now), Admit::Refused);
    }

    #[test]
    fn a_denied_tenant_is_refused_even_with_a_valid_stamp() {
        let now = 9 * CARRIAGE_EPOCH_MS;
        let (stamper, server) = one_tenant();
        let mut denied = HashSet::new();
        denied.insert(TENANT);
        let policy = keyed(server, denied, now);
        let id = [6u8; 32];
        assert_eq!(
            policy.admit(Some(&stamper.stamp(&id, now)), &id, now),
            Admit::Refused
        );
    }

    #[test]
    fn the_previous_epoch_is_accepted_but_older_and_future_are_not() {
        let (stamper, server) = one_tenant();
        let e = 1000u64;
        let stamped_at = e * CARRIAGE_EPOCH_MS + 10;
        let stamp = stamper.stamp(&[8u8; 32], stamped_at);
        // Verified one epoch later: accepted (transit + skew window).
        let policy = keyed(server.clone(), HashSet::new(), (e + 1) * CARRIAGE_EPOCH_MS);
        assert_eq!(
            policy.admit(Some(&stamp), &[8u8; 32], (e + 1) * CARRIAGE_EPOCH_MS),
            Admit::Granted(Some(TENANT))
        );
        // Two epochs later: refused (bounds replay).
        let old = keyed(server.clone(), HashSet::new(), (e + 2) * CARRIAGE_EPOCH_MS);
        assert_eq!(
            old.admit(Some(&stamp), &[8u8; 32], (e + 2) * CARRIAGE_EPOCH_MS),
            Admit::Refused
        );
        // A future-epoch stamp: refused.
        let future = keyed(server, HashSet::new(), (e - 5) * CARRIAGE_EPOCH_MS);
        assert_eq!(
            future.admit(Some(&stamp), &[8u8; 32], (e - 5) * CARRIAGE_EPOCH_MS),
            Admit::Refused
        );
    }

    #[test]
    fn two_fabrics_with_different_keyservers_reject_each_other() {
        // The cryptographic partition: fleet A's keyserver does not know fleet B's tenant, so B's
        // stamp is an unknown signer to A, and vice versa.
        let now = 2 * CARRIAGE_EPOCH_MS;
        let (stamper_a, server_a) = one_tenant();
        let key_b = Identity::generate();
        let mut server_b = KeyServer::new();
        let tenant_b: TenantId = [11u8; 16];
        server_b.insert(tenant_b, key_b.address());
        let stamper_b = Stamper::new(tenant_b, key_b);
        let id = [12u8; 32];
        let fleet_a = keyed(server_a, HashSet::new(), now);
        let fleet_b = keyed(server_b, HashSet::new(), now);
        assert!(matches!(
            fleet_a.admit(Some(&stamper_a.stamp(&id, now)), &id, now),
            Admit::Granted(Some(_))
        ));
        assert_eq!(
            fleet_a.admit(Some(&stamper_b.stamp(&id, now)), &id, now),
            Admit::Refused
        );
        assert!(matches!(
            fleet_b.admit(Some(&stamper_b.stamp(&id, now)), &id, now),
            Admit::Granted(Some(_))
        ));
        assert_eq!(
            fleet_b.admit(Some(&stamper_a.stamp(&id, now)), &id, now),
            Admit::Refused
        );
    }

    #[test]
    fn refresh_rolls_epochs_without_a_full_recompute() {
        let (stamper, server) = one_tenant();
        let mut k = KeyedAccess::new(server, HashSet::new());
        k.refresh(5 * CARRIAGE_EPOCH_MS);
        // A stamp made in epoch 5, checked after a single-epoch roll to 6: previous table carries.
        let s5 = stamper.stamp(&[1u8; 32], 5 * CARRIAGE_EPOCH_MS);
        k.refresh(6 * CARRIAGE_EPOCH_MS);
        let policy = AccessPolicy::Keyed(k);
        assert_eq!(
            policy.admit(Some(&s5), &[1u8; 32], 6 * CARRIAGE_EPOCH_MS),
            Admit::Granted(Some(TENANT))
        );
    }

    #[test]
    fn usage_addition_saturates() {
        let mut u = Usage {
            bundles: u64::MAX - 1,
            payload_bytes: 10,
        };
        u.add(&Usage {
            bundles: 5,
            payload_bytes: 7,
        });
        assert_eq!(u.bundles, u64::MAX);
        assert_eq!(u.payload_bytes, 17);
    }
}
