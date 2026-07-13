//! Self-certifying reachability records: a node signs "I, address X, am reachable at `<endpoint>`"
//! with its identity key, and anyone verifies that signature against X. This is the DNS-free,
//! cacheable, gossip-able binding of a Hop address to a network location.
//!
//! It is the address -> location half of endpoint discovery. The name -> address half is separate:
//! either the name IS the address (self-certifying, `hops://<address>`), or a domain's TLS cert binds
//! `myaddress.com -> X` when the record is served from `https://myaddress.com/.well-known/hop`. Either
//! way this record needs NO external trust anchor: the claimed `address` is the very key that signs it,
//! so a forged claim (someone else's address, a tampered endpoint) simply fails the signature check.
//!
//! ## Revocation model (why there is no revocation list)
//!
//! A self-certifying record has no issuing authority, so there is no CA to publish a CRL/OCSP against
//! and nothing a third party could revoke on the signer's behalf. Revocation is instead **expiry +
//! re-signing**, the same model as short-lived TLS certificates: a record is only trusted for
//! `ttl_secs` from `issued_at` (enforced in [`ReachRecord::verify`]), and the holder keeps a live
//! record fresh by re-signing before it lapses. To retire an endpoint, stop re-signing and let the
//! last record expire; to move, sign a new record (a strictly-newer `issued_at` supersedes the old
//! one for the same address). Publishers therefore choose a TTL that bounds their own worst-case
//! staleness: **short TTLs (minutes to a few hours) are the revocation granularity** and are cheap
//! because signing is one Ed25519 op (hop-endpoint re-signs hourly, see `WELL_KNOWN_RESIGN`). Key
//! compromise is out of scope of the record itself (a stolen identity key can sign valid records for
//! its own address until the address is abandoned), exactly as a stolen TLS key can, and is handled at
//! the identity layer, not here.

use crate::crypto::{self, Identity, PubKeyBytes};
use serde::{Deserialize, Serialize};

/// Domain separator so a reach-record signature can never be confused with any other signed blob
/// this identity produces (prekeys, bundles, hps records).
const REACH_CONTEXT: &[u8] = b"hop/reach-record/v1\0";

/// The signed content: who is reachable where, when, and for how long.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ReachClaim {
    /// The signer's Hop address (Ed25519 public key). The record self-certifies against this.
    pub address: PubKeyBytes,
    /// Opaque endpoint spec the app interprets, e.g. `wss://myaddress.com/_hop` or `1.2.3.4:9944`.
    pub endpoint: String,
    /// Unix seconds when signed. A newer record supersedes an older one for the same address.
    pub issued_at: u64,
    /// Seconds the record stays valid from `issued_at`.
    pub ttl_secs: u32,
}

/// A signed reachability record: the claim plus an Ed25519 signature by `claim.address`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ReachRecord {
    pub claim: ReachClaim,
    /// Ed25519 signature over the domain-separated, postcard-encoded claim (64 bytes).
    pub sig: Vec<u8>,
}

/// The exact bytes signed/verified: a domain prefix + the deterministic postcard encoding of the
/// claim. Single-purpose by the prefix; stable by postcard's determinism.
fn signing_bytes(claim: &ReachClaim) -> Vec<u8> {
    let mut v = Vec::from(REACH_CONTEXT);
    v.extend_from_slice(&postcard::to_allocvec(claim).unwrap_or_default());
    v
}

impl ReachRecord {
    /// Sign a reachability claim with `id`'s identity key. `now_secs` stamps `issued_at`.
    pub fn sign(
        id: &Identity,
        endpoint: impl Into<String>,
        ttl_secs: u32,
        now_secs: u64,
    ) -> ReachRecord {
        let claim = ReachClaim {
            address: id.address(),
            endpoint: endpoint.into(),
            issued_at: now_secs,
            ttl_secs,
        };
        let sig = id.sign(&signing_bytes(&claim)).to_vec();
        ReachRecord { claim, sig }
    }

    /// Serialize for a well-known body, gossip, or cache.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Parse and VERIFY. The signature must be by `claim.address`; when `now_secs` is supplied the
    /// record must be unexpired. Returns the verified record, or `None` on malformed / bad-signature /
    /// expired. Self-certifying: no external key or anchor is consulted.
    pub fn verify(bytes: &[u8], now_secs: Option<u64>) -> Option<ReachRecord> {
        let rec: ReachRecord = postcard::from_bytes(bytes).ok()?;
        if !crypto::verify(&rec.claim.address, &signing_bytes(&rec.claim), &rec.sig) {
            return None;
        }
        if let Some(now) = now_secs {
            let expiry = rec
                .claim
                .issued_at
                .saturating_add(rec.claim.ttl_secs as u64);
            if now > expiry {
                return None;
            }
        }
        Some(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_verifies_round_trip() {
        let id = Identity::generate();
        let rec = ReachRecord::sign(&id, "wss://myaddress.com/_hop", 3600, 1_000);
        let got = ReachRecord::verify(&rec.to_bytes(), Some(1_500)).expect("valid record verifies");
        assert_eq!(got.claim.address, id.address());
        assert_eq!(got.claim.endpoint, "wss://myaddress.com/_hop");
    }

    #[test]
    fn rejects_tampered_endpoint() {
        let id = Identity::generate();
        let mut rec = ReachRecord::sign(&id, "wss://good.com/_hop", 3600, 1_000);
        rec.claim.endpoint = "wss://evil.com/_hop".into(); // the signature no longer covers this
        assert!(ReachRecord::verify(&rec.to_bytes(), None).is_none());
    }

    #[test]
    fn cannot_forge_someone_elses_address() {
        // Sign as the attacker, then claim to be `real`. The sig won't verify against real's key.
        let real = Identity::generate();
        let attacker = Identity::generate();
        let mut rec = ReachRecord::sign(&attacker, "wss://evil.com/_hop", 3600, 1_000);
        rec.claim.address = real.address();
        assert!(ReachRecord::verify(&rec.to_bytes(), None).is_none());
    }

    #[test]
    fn rejects_expired_but_accepts_within_ttl() {
        let id = Identity::generate();
        let rec = ReachRecord::sign(&id, "1.2.3.4:9944", 60, 1_000);
        assert!(
            ReachRecord::verify(&rec.to_bytes(), Some(1_030)).is_some(),
            "within ttl"
        );
        assert!(
            ReachRecord::verify(&rec.to_bytes(), Some(2_000)).is_none(),
            "past issued_at + ttl"
        );
    }
}
