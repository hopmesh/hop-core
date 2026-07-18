//! `hps://` pub/sub primitives — services & channels (DESIGN.md §32).
//!
//! `hps://` is publish/subscribe, distinct from request/response `hops://`. A topic lives at a
//! path on any node. Two cryptographic concerns are kept separate:
//!
//! - **Confidentiality** — a symmetric **content key**, handed to members at subscribe time;
//!   anyone holding it can decrypt (read) and, for a channel, encrypt (write).
//! - **Authenticity** — every published message is **signed by its sender**. For a *channel*
//!   each member signs with their own device identity (so readers see a verified sender). For a
//!   *service* only the owner's **signing key** produces a valid broadcast, so a leaked content
//!   key lets someone read but never forge a broadcast.
//!
//! This module is the crypto + config layer; the node registry, subscribe/publish wire flow,
//! and ACK-based reach build on top.

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::{Identity, PubKeyBytes};
use crate::AppId;

/// A well-known keypair every node holds, used only to seal/open the *envelope* of a broadcast
/// bundle (DESIGN.md §32). Its secret is public (derived from a constant), so any node can open
/// a broadcast — confidentiality of the actual message is the content key inside, not this. A
/// broadcast can't be addressed to one recipient, so we seal to this shared key instead.
pub fn broadcast_identity() -> Identity {
    let seed = blake3::hash(b"hop.hps.broadcast.v1");
    Identity::from_secret_bytes(seed.as_bytes())
}

/// A 32-byte symmetric content key (read/write membership for a topic).
pub type ContentKey = [u8; 32];

/// What kind of topic a path hosts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceKind {
    /// Anyone with the content key reads AND writes; each post signed by its writer's identity.
    Channel,
    /// Only the owner broadcasts (signed by the service key); subscribers read.
    Service,
}

/// Who may obtain a topic's keys (DESIGN.md §32). Confidentiality/authenticity are unchanged;
/// this governs **key handoff** only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessMode {
    /// Keys handed out to anyone who asks (anonymous membership).
    Open,
    /// Requester asks; the host approves before keys are handed off.
    RequestToJoin,
    /// The host initiates an invite to a destination; the destination accepts, then gets keys.
    Invite,
}

/// Whether a topic announces itself for discovery (DESIGN.md §32).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Visibility {
    /// Reachable only by known `address+path` or an invite — never advertised.
    Private,
    /// Host broadcasts an (app-encrypted) discovery advert so same-app peers can browse it.
    Discoverable,
}

/// The decrypted descriptor inside a discoverable topic's advert (DESIGN.md §32). Encrypted
/// under the publisher app's discovery key — never carries the content key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicMeta {
    pub path: String,
    pub kind: ServiceKind,
    pub title: String,
    pub summary: String,
    pub tags: Vec<String>,
    pub access: AccessMode,
    /// A `Service`'s verify key, so a browser can pre-verify broadcasts; `None` for a channel.
    pub service_pubkey: Option<[u8; 32]>,
}

/// The persisted configuration for a topic registered at a path. Holds the secret material, so
/// it lives only in the host node's store — never sent on the wire as-is.
#[derive(Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub kind: ServiceKind,
    /// Symmetric key for confidentiality (handed to members on subscribe).
    pub content_key: ContentKey,
    /// ed25519 seed of the service signing key — `Some` for a `Service` (only the owner can
    /// broadcast), `None` for a `Channel` (members sign with their own identities).
    pub signing_seed: Option<[u8; 32]>,
    /// Who may obtain the keys (DESIGN.md §32).
    pub access: AccessMode,
    /// Whether the topic is advertised for discovery.
    pub visibility: Visibility,
    /// Rekey generation; bumped by selective rotation (revocation). Starts at 0.
    pub epoch: u32,
    /// Optional metadata shown in discovery (title/summary/tags).
    pub title: String,
    pub summary: String,
    pub tags: Vec<String>,
}

impl ServiceConfig {
    /// Generate fresh keys for a new topic with default access (Open) and visibility (Private).
    pub fn new(kind: ServiceKind) -> Self {
        Self::new_with(kind, AccessMode::Open, Visibility::Private)
    }

    /// Generate fresh keys for a new topic with explicit access + visibility.
    pub fn new_with(kind: ServiceKind, access: AccessMode, visibility: Visibility) -> Self {
        let mut content_key = [0u8; 32];
        OsRng.fill_bytes(&mut content_key);
        let signing_seed = match kind {
            ServiceKind::Service => {
                let mut s = [0u8; 32];
                OsRng.fill_bytes(&mut s);
                Some(s)
            }
            ServiceKind::Channel => None,
        };
        Self {
            kind,
            content_key,
            signing_seed,
            access,
            visibility,
            epoch: 0,
            title: String::new(),
            summary: String::new(),
            tags: Vec::new(),
        }
    }

    /// Mint a fresh content key (and, for a Service, a fresh signing key) and bump the epoch —
    /// the core of selective-rotation revocation (DESIGN.md §32). Retained members are re-keyed;
    /// removed ones simply never receive the new key.
    pub fn rotate(&mut self) {
        let mut ck = [0u8; 32];
        OsRng.fill_bytes(&mut ck);
        self.content_key = ck;
        if self.kind == ServiceKind::Service {
            let mut s = [0u8; 32];
            OsRng.fill_bytes(&mut s);
            self.signing_seed = Some(s);
        }
        self.epoch = self.epoch.saturating_add(1);
    }

    /// Build the discovery descriptor for this topic at `path`.
    pub fn meta(&self, path: &str) -> TopicMeta {
        TopicMeta {
            path: path.to_string(),
            kind: self.kind,
            title: self.title.clone(),
            summary: self.summary.clone(),
            tags: self.tags.clone(),
            access: self.access,
            service_pubkey: self.service_pubkey(),
        }
    }

    /// The public key subscribers use to verify a *service's* broadcasts (`None` for a channel).
    pub fn service_pubkey(&self) -> Option<[u8; 32]> {
        self.signing_seed
            .map(|s| SigningKey::from_bytes(&s).verifying_key().to_bytes())
    }
}

/// Encrypt `plaintext` under the content `key`, returning `(nonce, ciphertext)`.
pub fn seal_content(key: &ContentKey, plaintext: &[u8]) -> ([u8; 12], Vec<u8>) {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(&Nonce::from(nonce), plaintext)
        .expect("chacha20poly1305 encrypt");
    (nonce, ct)
}

/// Decrypt a content-keyed message; `None` if the key is wrong or the ciphertext was tampered.
pub fn open_content(key: &ContentKey, nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    cipher.decrypt(&Nonce::from(*nonce), ciphertext).ok()
}

/// The bytes a publish signature covers. Binding the app, outer sender, opaque topic tag, and exact
/// key epoch prevents a valid publication from being rewrapped under another envelope identity or
/// replayed into another app, topic, or generation.
pub fn publish_signing_bytes(
    app: &AppId,
    sender: &PubKeyBytes,
    topic_tag: &[u8; 16],
    epoch: u32,
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Vec<u8> {
    publish_msg(app, sender, topic_tag, epoch, nonce, ciphertext)
}

fn publish_msg(
    app: &AppId,
    sender: &PubKeyBytes,
    topic_tag: &[u8; 16],
    epoch: u32,
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        18 + app.len() + sender.len() + topic_tag.len() + 4 + 12 + ciphertext.len(),
    );
    m.extend_from_slice(b"hop.hps.publish.v2");
    m.extend_from_slice(app);
    m.extend_from_slice(sender);
    m.extend_from_slice(topic_tag);
    m.extend_from_slice(&epoch.to_le_bytes());
    m.extend_from_slice(nonce);
    m.extend_from_slice(ciphertext);
    m
}

/// Sign a published message with an ed25519 `seed` (the writer's identity for a channel, or the
/// service signing key for a service).
pub fn sign_publish(
    seed: &[u8; 32],
    app: &AppId,
    sender: &PubKeyBytes,
    topic_tag: &[u8; 16],
    epoch: u32,
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> [u8; 64] {
    SigningKey::from_bytes(seed)
        .sign(&publish_msg(
            app, sender, topic_tag, epoch, nonce, ciphertext,
        ))
        .to_bytes()
}

/// Verify a published message's signature against `pubkey` (the sender's address for a channel,
/// or the service's public key for a service broadcast).
#[allow(clippy::too_many_arguments)] // every argument is part of the signed publication context
pub fn verify_publish(
    pubkey: &[u8; 32],
    app: &AppId,
    sender: &PubKeyBytes,
    topic_tag: &[u8; 16],
    epoch: u32,
    nonce: &[u8; 12],
    ciphertext: &[u8],
    sig: &[u8; 64],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    // verify_strict, not verify: reject non-canonical / malleable signatures, matching the strict check
    // the rest of the crate uses for identity signatures (crypto::verify at crypto.rs). Non-strict
    // ed25519 admits a cofactored second S and small-order point encodings, so a keyless attacker who
    // saw one valid hps publish could mint a DIFFERENT 64-byte signature that still verifies for the same
    // message. Strict rejects those. It never rejects a signature sign_publish itself produced (those are
    // always canonical), so this only tightens against forged variants.
    vk.verify_strict(
        &publish_msg(app, sender, topic_tag, epoch, nonce, ciphertext),
        &Signature::from_bytes(sig),
    )
    .is_ok()
}

/// Stable content id for an authenticated publication, independent of the outer bundle id. A relay
/// or attacker can rewrap the same signed publication in a fresh outer bundle, but cannot change this
/// id without invalidating the publication signature.
#[allow(clippy::too_many_arguments)] // every argument is authenticated publication content
pub fn publication_id(
    app: &AppId,
    sender: &PubKeyBytes,
    topic_tag: &[u8; 16],
    epoch: u32,
    nonce: &[u8; 12],
    ciphertext: &[u8],
    sig: &[u8; 64],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hop.hps.publication-id.v1");
    hasher.update(&publish_msg(
        app, sender, topic_tag, epoch, nonce, ciphertext,
    ));
    hasher.update(sig);
    *hasher.finalize().as_bytes()
}

/// Authenticate a reach acknowledgement with the current topic content key. The MAC binds the
/// member identity and exact app/topic/epoch tuple, so an old key or copied acknowledgement cannot
/// grow another topic's retained-member set.
pub fn reach_ack_mac(
    content_key: &ContentKey,
    app: &AppId,
    member: &PubKeyBytes,
    topic_tag: &[u8; 16],
    epoch: u32,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(content_key);
    h.update(b"hop.hps.reach-ack.v1");
    h.update(app);
    h.update(member);
    h.update(topic_tag);
    h.update(&epoch.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Verify a reach acknowledgement without an early-exit byte comparison.
pub fn verify_reach_ack_mac(
    content_key: &ContentKey,
    app: &AppId,
    member: &PubKeyBytes,
    topic_tag: &[u8; 16],
    epoch: u32,
    mac: &[u8; 32],
) -> bool {
    let expected = reach_ack_mac(content_key, app, member, topic_tag, epoch);
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= expected[i] ^ mac[i];
    }
    diff == 0
}

/// Encrypt a discovery descriptor under the app discovery key, returning `(nonce, ct)` for an
/// `AdvertKind::HpsTopic`. Only same-app nodes (same `disc_key`) can read it.
pub fn seal_meta(disc_key: &[u8; 32], meta: &TopicMeta) -> ([u8; 12], Vec<u8>) {
    let plain = postcard::to_allocvec(meta).expect("serialize TopicMeta");
    seal_content(disc_key, &plain)
}

/// Decrypt a discovery descriptor; `None` if the key is wrong (foreign app) or tampered.
pub fn open_meta(disc_key: &[u8; 32], nonce: &[u8; 12], ct: &[u8]) -> Option<TopicMeta> {
    let plain = open_content(disc_key, nonce, ct)?;
    postcard::from_bytes(&plain).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_key_round_trips_and_rejects_wrong_key() {
        let cfg = ServiceConfig::new(ServiceKind::Channel);
        let (nonce, ct) = seal_content(&cfg.content_key, b"hello channel");
        assert_eq!(
            open_content(&cfg.content_key, &nonce, &ct).as_deref(),
            Some(&b"hello channel"[..])
        );
        let other = ServiceConfig::new(ServiceKind::Channel);
        assert_eq!(
            open_content(&other.content_key, &nonce, &ct),
            None,
            "wrong key can't read"
        );
        // Tampered ciphertext fails the AEAD tag.
        let mut bad = ct.clone();
        bad[0] ^= 0xff;
        assert_eq!(open_content(&cfg.content_key, &nonce, &bad), None);
    }

    #[test]
    fn service_only_owner_signature_verifies() {
        let svc = ServiceConfig::new(ServiceKind::Service);
        let seed = svc.signing_seed.unwrap();
        let pubkey = svc.service_pubkey().unwrap();
        let (nonce, ct) = seal_content(&svc.content_key, b"broadcast");
        let app = [4u8; 16];
        let sender = [5u8; 32];
        let topic_tag = [6u8; 16];
        let sig = sign_publish(&seed, &app, &sender, &topic_tag, 3, &nonce, &ct);
        assert!(verify_publish(
            &pubkey, &app, &sender, &topic_tag, 3, &nonce, &ct, &sig
        ));
        // A different signer (a subscriber who leaked-read the content key) can't forge.
        let imposter = ServiceConfig::new(ServiceKind::Service);
        let forged = sign_publish(
            &imposter.signing_seed.unwrap(),
            &app,
            &sender,
            &topic_tag,
            3,
            &nonce,
            &ct,
        );
        assert!(!verify_publish(
            &pubkey, &app, &sender, &topic_tag, 3, &nonce, &ct, &forged
        ));
        assert!(!verify_publish(
            &pubkey, &[7u8; 16], &sender, &topic_tag, 3, &nonce, &ct, &sig
        ));
        assert!(!verify_publish(
            &pubkey, &app, &[8u8; 32], &topic_tag, 3, &nonce, &ct, &sig
        ));
        assert!(!verify_publish(
            &pubkey, &app, &sender, &[9u8; 16], 3, &nonce, &ct, &sig
        ));
        assert!(!verify_publish(
            &pubkey, &app, &sender, &topic_tag, 4, &nonce, &ct, &sig
        ));
    }

    #[test]
    fn channel_has_no_service_key() {
        assert!(ServiceConfig::new(ServiceKind::Channel)
            .service_pubkey()
            .is_none());
        assert!(ServiceConfig::new(ServiceKind::Service)
            .service_pubkey()
            .is_some());
    }

    #[test]
    fn rotate_bumps_the_epoch_and_remints_keys_including_the_service_signing_key() {
        // DESIGN.md §32 selective rotation: a Service's broadcast key must ALSO rotate, not just
        // the content key, or a removed member who kept the old signing seed could keep forging
        // broadcasts after being "revoked".
        let mut svc = ServiceConfig::new(ServiceKind::Service);
        let old_content_key = svc.content_key;
        let old_seed = svc.signing_seed.unwrap();
        let old_pubkey = svc.service_pubkey().unwrap();

        svc.rotate();

        assert_eq!(svc.epoch, 1, "rotate bumps the epoch");
        assert_ne!(
            svc.content_key, old_content_key,
            "rotate remints the content key"
        );
        assert_ne!(
            svc.signing_seed.unwrap(),
            old_seed,
            "rotate remints the service signing key too"
        );
        assert_ne!(svc.service_pubkey().unwrap(), old_pubkey);

        // A broadcast signed with the OLD (revoked) seed must not verify against the NEW pubkey.
        let (nonce, ct) = seal_content(&svc.content_key, b"post-rotation");
        let app = [1u8; 16];
        let sender = [2u8; 32];
        let topic_tag = [3u8; 16];
        let forged = sign_publish(&old_seed, &app, &sender, &topic_tag, 1, &nonce, &ct);
        assert!(!verify_publish(
            &svc.service_pubkey().unwrap(),
            &app,
            &sender,
            &topic_tag,
            1,
            &nonce,
            &ct,
            &forged
        ));
    }

    #[test]
    fn rotate_on_a_channel_has_no_signing_seed_to_remint() {
        let mut chan = ServiceConfig::new(ServiceKind::Channel);
        assert!(chan.signing_seed.is_none());
        let old_content_key = chan.content_key;

        chan.rotate();

        assert_eq!(chan.epoch, 1);
        assert_ne!(chan.content_key, old_content_key);
        assert!(
            chan.signing_seed.is_none(),
            "a channel never gets a signing seed from rotate"
        );
    }

    #[test]
    fn meta_builds_the_discovery_descriptor_from_the_config() {
        let mut cfg = ServiceConfig::new_with(
            ServiceKind::Service,
            AccessMode::RequestToJoin,
            Visibility::Discoverable,
        );
        cfg.title = "Weather".to_string();
        cfg.summary = "Storm alerts".to_string();
        cfg.tags = vec!["weather".to_string(), "alerts".to_string()];

        let meta = cfg.meta("alerts/weather");

        assert_eq!(meta.path, "alerts/weather");
        assert_eq!(meta.kind, ServiceKind::Service);
        assert_eq!(meta.title, "Weather");
        assert_eq!(meta.summary, "Storm alerts");
        assert_eq!(meta.tags, vec!["weather".to_string(), "alerts".to_string()]);
        assert_eq!(meta.access, AccessMode::RequestToJoin);
        assert_eq!(meta.service_pubkey, cfg.service_pubkey());
        assert!(meta.service_pubkey.is_some());

        let chan = ServiceConfig::new(ServiceKind::Channel);
        assert_eq!(
            chan.meta("chan/path").service_pubkey,
            None,
            "a channel's descriptor carries no verify key"
        );
    }

    #[test]
    fn verify_publish_rejects_a_pubkey_that_does_not_decode_to_a_curve_point() {
        // A malformed/foreign pubkey (not just a wrong-but-valid one) must be rejected outright,
        // not panic and not fall through to a signature check against garbage. This 32-byte string
        // is a real value curve25519 rejects on decompression (it is not a point on the curve).
        let bad_pubkey: [u8; 32] = [
            34, 230, 141, 232, 28, 113, 203, 58, 213, 98, 226, 49, 72, 42, 249, 167, 171, 137, 213,
            242, 87, 155, 47, 193, 204, 237, 239, 4, 29, 77, 70, 229,
        ];
        let svc = ServiceConfig::new(ServiceKind::Service);
        let seed = svc.signing_seed.unwrap();
        let (nonce, ct) = seal_content(&svc.content_key, b"whatever");
        let app = [1u8; 16];
        let sender = [2u8; 32];
        let topic_tag = [3u8; 16];
        let sig = sign_publish(&seed, &app, &sender, &topic_tag, 0, &nonce, &ct);

        assert!(
            !verify_publish(&bad_pubkey, &app, &sender, &topic_tag, 0, &nonce, &ct, &sig),
            "an undecodable pubkey must be rejected, not panic"
        );
    }

    #[test]
    fn reach_ack_mac_binds_member_topic_app_and_exact_epoch() {
        let key = [1u8; 32];
        let app = [2u8; 16];
        let member = [3u8; 32];
        let tag = [4u8; 16];
        let mac = reach_ack_mac(&key, &app, &member, &tag, 5);

        assert!(verify_reach_ack_mac(&key, &app, &member, &tag, 5, &mac));
        assert!(!verify_reach_ack_mac(
            &[9u8; 32], &app, &member, &tag, 5, &mac
        ));
        assert!(!verify_reach_ack_mac(&key, &app, &member, &tag, 6, &mac));
    }

    #[test]
    fn seal_meta_and_open_meta_round_trip_and_reject_the_wrong_disc_key() {
        let cfg = ServiceConfig::new(ServiceKind::Channel);
        let meta = cfg.meta("chat/general");
        let disc_key: [u8; 32] = [7u8; 32];

        let (nonce, ct) = seal_meta(&disc_key, &meta);
        assert_eq!(open_meta(&disc_key, &nonce, &ct), Some(meta.clone()));

        let wrong_key: [u8; 32] = [9u8; 32];
        assert_eq!(
            open_meta(&wrong_key, &nonce, &ct),
            None,
            "a foreign app's discovery key must not decrypt someone else's descriptor"
        );
    }
}
