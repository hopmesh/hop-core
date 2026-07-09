//! App-scoped key material (DESIGN.md §17, §32).
//!
//! The Hop fabric is shared: every app advertises the same BLE service UUID and relays for
//! every other app, so a lone app is never alone on the mesh. To keep one app's `hps://`
//! channels/services from being discovered or joined by a *different* app, each app embeds a
//! 32-byte **app secret** (host-supplied at node construction, like the identity seed). All
//! app-scoping key material derives deterministically from it.
//!
//! Crucially the public [`AppId`] fingerprint is for **demux/filtering only** — it travels in
//! cleartext in every bundle/advert header and proves nothing at runtime. Access control is the
//! MAC ([`AppKeys::join_proof`]) and discovery confidentiality is the AEAD key
//! ([`AppKeys::disc_key`]); both come from the secret, so only same-secret apps interoperate.
//! Two developers who share the secret get interop; otherwise their topics are mutually
//! invisible and unjoinable.

use crate::{AppId, FABRIC_APP};

/// A 32-byte app secret. Supplied by the host at node construction; never persisted by core
/// (re-derived each launch, like the identity seed).
pub type AppSecret = [u8; 32];

/// All app-scoped key material, derived from the app secret.
#[derive(Clone)]
pub struct AppKeys {
    /// The raw secret (kept so we can re-derive / compare).
    pub secret: AppSecret,
    /// Public 16-byte fingerprint — the [`AppId`] stamped on bundles/adverts. Demux only.
    pub id: AppId,
    /// ChaCha20Poly1305 key that encrypts `hps://` discovery-advert bodies so a foreign app
    /// can't even enumerate topic names. `None` on the fabric namespace (open by design).
    pub disc_key: Option<[u8; 32]>,
    /// Keyed-BLAKE3 MAC key proving knowledge of the secret in the subscribe/join/invite
    /// handshake. `None` on the fabric namespace.
    pub mac_key: Option<[u8; 32]>,
}

impl AppKeys {
    /// Derive all key material from a 32-byte app secret.
    pub fn from_secret(secret: AppSecret) -> Self {
        let mut id = [0u8; 16];
        id.copy_from_slice(&blake3::derive_key("hop.app.id.v1", &secret)[..16]);
        Self {
            secret,
            id,
            disc_key: Some(blake3::derive_key("hop.app.disc.v1", &secret)),
            mac_key: Some(blake3::derive_key("hop.app.mac.v1", &secret)),
        }
    }

    /// The reserved fabric namespace: open by design (no secret), so peer discovery / prekeys
    /// flood across every app. Discovery confidentiality and handshake proofs are disabled.
    pub fn fabric() -> Self {
        Self {
            secret: [0u8; 32],
            id: FABRIC_APP,
            disc_key: None,
            mac_key: None,
        }
    }

    /// A label-only app id with no secret key material — used by infra (the relay daemon) to
    /// stamp a recognizable [`AppId`] on trace hops without enabling `hps://` isolation (a relay
    /// carries every app's traffic regardless). Behaves like the fabric for isolation purposes.
    pub fn label_only(id: AppId) -> Self {
        Self {
            secret: [0u8; 32],
            id,
            disc_key: None,
            mac_key: None,
        }
    }

    /// True if this is the open fabric namespace (no app isolation).
    pub fn is_fabric(&self) -> bool {
        self.id == FABRIC_APP
    }

    /// Proof of secret knowledge for an `hps://` handshake, binding the topic `path` and the
    /// requester's address to a coarse time bucket (replay-bounded). Returns a zero proof on
    /// the fabric namespace (no isolation there).
    pub fn join_proof(&self, path: &str, requester: &[u8; 32], epoch_bucket: u64) -> [u8; 32] {
        match self.mac_key {
            None => [0u8; 32],
            Some(k) => {
                let mut h = blake3::Hasher::new_keyed(&k);
                h.update(b"hop.hps.join.v1");
                h.update(&self.id);
                h.update(path.as_bytes());
                h.update(requester);
                h.update(&epoch_bucket.to_le_bytes());
                *h.finalize().as_bytes()
            }
        }
    }

    /// Verify a join proof against the current or previous time bucket (clock-skew tolerant).
    /// Always true on the fabric namespace.
    pub fn verify_join_proof(
        &self,
        proof: &[u8; 32],
        path: &str,
        requester: &[u8; 32],
        now_bucket: u64,
    ) -> bool {
        if self.mac_key.is_none() {
            return true;
        }
        let prev = now_bucket.saturating_sub(1);
        constant_time_eq(proof, &self.join_proof(path, requester, now_bucket))
            || constant_time_eq(proof, &self.join_proof(path, requester, prev))
    }

    /// Opaque per-topic tag used in publish envelopes so a foreign app (which can open the
    /// public broadcast envelope) can't tell which topic a broadcast is for. Same-app
    /// subscribers recompute it from a known path to match. Falls back to a hash of the path
    /// on the fabric namespace.
    pub fn topic_tag(&self, path: &str) -> [u8; 16] {
        let bytes = match self.mac_key {
            Some(k) => {
                let mut h = blake3::Hasher::new_keyed(&k);
                h.update(b"hop.hps.topic.v1");
                h.update(path.as_bytes());
                *h.finalize().as_bytes()
            }
            None => *blake3::hash(path.as_bytes()).as_bytes(),
        };
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&bytes[..16]);
        tag
    }
}

/// The bucket width for join-proof replay bounding (~3h). Coarse enough that the host need not
/// remember nonces; current+previous are accepted for skew.
pub const JOIN_EPOCH_MS: u64 = 3 * 60 * 60 * 1000;

/// Constant-time 32-byte comparison (proofs/MACs).
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_secrets_diverge() {
        let a = AppKeys::from_secret([1u8; 32]);
        let b = AppKeys::from_secret([2u8; 32]);
        assert_ne!(a.id, b.id);
        assert_ne!(a.disc_key, b.disc_key);
        assert_ne!(a.mac_key, b.mac_key);
    }

    #[test]
    fn same_secret_is_deterministic() {
        let a = AppKeys::from_secret([7u8; 32]);
        let b = AppKeys::from_secret([7u8; 32]);
        assert_eq!(a.id, b.id);
        assert_eq!(a.topic_tag("lobby"), b.topic_tag("lobby"));
    }

    #[test]
    fn join_proof_verifies_same_app_rejects_foreign() {
        let app = AppKeys::from_secret([9u8; 32]);
        let foreign = AppKeys::from_secret([8u8; 32]);
        let who = [3u8; 32];
        let proof = app.join_proof("lobby", &who, 100);
        assert!(app.verify_join_proof(&proof, "lobby", &who, 100));
        assert!(app.verify_join_proof(&proof, "lobby", &who, 101)); // previous-bucket tolerance
        assert!(!app.verify_join_proof(&proof, "lobby", &who, 200)); // too old
        assert!(!app.verify_join_proof(&proof, "other", &who, 100)); // wrong path
                                                                     // A foreign app can't forge a proof this host accepts.
        let forged = foreign.join_proof("lobby", &who, 100);
        assert!(!app.verify_join_proof(&forged, "lobby", &who, 100));
    }

    #[test]
    fn fabric_has_no_isolation() {
        let f = AppKeys::fabric();
        assert!(f.is_fabric());
        assert_eq!(f.join_proof("x", &[0u8; 32], 0), [0u8; 32]);
        assert!(f.verify_join_proof(&[1u8; 32], "x", &[0u8; 32], 0)); // always accepts
    }
}
