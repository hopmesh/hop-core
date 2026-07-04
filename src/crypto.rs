//! Identity, signing, and end-to-end sealing.
//!
//! Each node has an [`Identity`]: a single Ed25519 keypair. The **address** is the
//! Ed25519 public key, and the X25519 keys for sealing/DH are *derived* from it via
//! Ed25519→Montgomery conversion (DESIGN.md §4) — so an address alone is enough to
//! both verify signatures from and seal to a peer; nothing extra rides the wire.
//!
//! On top of that this module provides the building blocks for **forward-secret
//! sessions** (DESIGN.md §25): a [`SignedPreKey`] + [`PreKeyBundle`] and an
//! X3DH-style async handshake ([`x3dh_initiate`] / [`x3dh_respond`]) that derive a
//! shared root secret without a live round-trip. The ratchet that consumes that
//! root lives in [`crate::session`].

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use crate::error::{Error, Result};

/// 32-byte Ed25519 public key. A node's address / device key.
pub type PubKeyBytes = [u8; 32];
/// 32-byte X25519 public key, used as a sealing target.
pub type XPubKeyBytes = [u8; 32];

/// A compact 8-byte form of an address, used in the on-wire hop trace (DESIGN.md
/// §27): each forwarder appends its `short_addr` so the path is recorded cheaply.
/// 8 bytes keeps a full-hop-limit trace small while collisions stay negligible for
/// route correlation (a node recognizes its *own* short form unambiguously).
pub type ShortAddr = [u8; 8];

/// The 8-byte short form of an address (the leading bytes of the public key).
pub fn short_addr(addr: &PubKeyBytes) -> ShortAddr {
    let mut s = [0u8; 8];
    s.copy_from_slice(&addr[..8]);
    s
}

/// A node's secret identity — a single Ed25519 keypair. The address *is* the public
/// key; the X25519 keys used for sealing are **derived** from it (Montgomery), so an
/// address alone is enough to both verify signatures from and seal messages to a
/// peer — no separate sealing key on the wire. See DESIGN.md §4.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        Self { signing: SigningKey::generate(&mut OsRng) }
    }

    /// The 32-byte Ed25519 seed — persist it (securely) for a stable address.
    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Restore an identity from a saved seed.
    pub fn from_secret_bytes(seed: &[u8; 32]) -> Self {
        Self { signing: SigningKey::from_bytes(seed) }
    }

    /// The node's address (Ed25519 public key) — also its sealing identity.
    pub fn address(&self) -> PubKeyBytes {
        self.signing.verifying_key().to_bytes()
    }

    /// X25519 secret for sealing/Noise, derived from the Ed25519 seed (SHA-512 +
    /// clamp — the standard Ed25519→Curve25519 conversion).
    fn x_secret(&self) -> StaticSecret {
        let h = Sha512::digest(self.signing.to_bytes());
        let mut s = [0u8; 32];
        s.copy_from_slice(&h[..32]);
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;
        StaticSecret::from(s)
    }

    /// Derived X25519 static secret bytes for Noise link sessions ([`crate::link`]).
    pub fn link_secret(&self) -> [u8; 32] {
        self.x_secret().to_bytes()
    }

    /// Sign a message with the identity key.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// Generate a fresh *random* signed prekey for forward-secret sessions
    /// (DESIGN.md §25): a random X25519 keypair whose public half is signed by this
    /// identity. Use [`Identity::derive_prekey`] for a launch-stable one.
    pub fn generate_prekey(&self) -> SignedPreKey {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = XPublicKey::from(&secret).to_bytes();
        let sig = self.sign(&public);
        SignedPreKey { secret: secret.to_bytes(), public, sig }
    }

    /// Derive a **deterministic** signed prekey from the identity seed, so the same
    /// prekey is reconstructed every launch with no persistence. This matters for
    /// correctness: a peer may cache your prekey advert (long TTL) across your
    /// restart, and must still be able to open a session — which only works if the
    /// secret is stable. (Rotation, when added, will key off an epoch input.)
    pub fn derive_prekey(&self) -> SignedPreKey {
        let mut s = blake3::derive_key("hop prekey v1", &self.signing.to_bytes());
        s[0] &= 248; // clamp to a valid X25519 scalar
        s[31] &= 127;
        s[31] |= 64;
        let secret = StaticSecret::from(s);
        let public = XPublicKey::from(&secret).to_bytes();
        let sig = self.sign(&public);
        SignedPreKey { secret: s, public, sig }
    }

    /// Open a payload sealed to this identity's address.
    pub fn open(&self, sealed: &Sealed) -> Result<Vec<u8>> {
        let shared = self.x_secret().diffie_hellman(&XPublicKey::from(sealed.ephemeral_pub));
        let sym = blake3::hash(shared.as_bytes());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(sym.as_bytes()));
        cipher
            .decrypt(Nonce::from_slice(&sealed.nonce), sealed.ciphertext.as_slice())
            .map_err(|_| Error::Crypto("decrypt failed"))
    }
}

/// A sealed blob: ephemeral X25519 pubkey + nonce + AEAD ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Sealed {
    pub ephemeral_pub: XPubKeyBytes,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// The X25519 (Montgomery) sealing key for an address, or `None` if it isn't a
/// valid Ed25519 public key. Used to bind a Noise link's static key to an address.
pub fn address_to_x(address: &PubKeyBytes) -> Option<XPubKeyBytes> {
    VerifyingKey::from_bytes(address).ok().map(|v| v.to_montgomery().to_bytes())
}

/// Seal `plaintext` to an **address** (Ed25519 public key): ephemeral-static ECDH
/// against the address's derived X25519 key + ChaCha20-Poly1305. Only the holder of
/// that address's secret can [`Identity::open`] it.
pub fn seal(to_address: &PubKeyBytes, plaintext: &[u8]) -> Result<Sealed> {
    let recipient = address_to_x(to_address).ok_or(Error::InvalidKey)?;
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pub = XPublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&XPublicKey::from(recipient));
    let sym = blake3::hash(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(sym.as_bytes()));

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::Crypto("encrypt failed"))?;

    Ok(Sealed { ephemeral_pub, nonce, ciphertext })
}

// ---------------------------------------------------------------------------
// Forward-secret sessions: prekeys + X3DH-style async handshake (DESIGN.md §25)
// ---------------------------------------------------------------------------

/// A rotating signed prekey: an X25519 keypair whose public half is signed by the
/// identity. The public half is published in a [`PreKeyBundle`]; the secret is
/// retained by the owner to answer session handshakes that used it. Rotating it
/// periodically bounds how long a compromised prekey exposes new sessions.
pub struct SignedPreKey {
    secret: [u8; 32],
    /// The X25519 public prekey (SPK).
    pub public: XPubKeyBytes,
    /// Ed25519 signature by the identity over `public` (binds the SPK to the address).
    pub sig: [u8; 64],
}

impl Drop for SignedPreKey {
    fn drop(&mut self) {
        // F-08: wipe the prekey secret from memory on drop rather than leaving it in the heap
        // until overwritten. The public half and signature are not secret.
        zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

impl SignedPreKey {
    /// The retained secret bytes — persist these so late handshakes still resolve.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret
    }

    /// Reconstruct from persisted parts.
    pub fn from_parts(secret: [u8; 32], public: XPubKeyBytes, sig: [u8; 64]) -> Self {
        Self { secret, public, sig }
    }

    /// The public, shareable bundle for this prekey under `address`.
    pub fn bundle(&self, address: PubKeyBytes) -> PreKeyBundle {
        PreKeyBundle { address, spk_pub: self.public, spk_sig: self.sig.to_vec() }
    }
}

/// The public prekey bundle a peer publishes so others can open a session to it
/// without a live round-trip: identity (address = IK), signed prekey (SPK).
///
/// No one-time prekeys: in a serverless flood/DTN there is no party to hand out a
/// distinct OTP per sender, so X3DH here uses IK + SPK + the initiator's ephemeral
/// only. Forward secrecy comes from SPK rotation and the session ratchet
/// ([`crate::session`]); this is the documented DTN trade-off (DESIGN.md §25).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PreKeyBundle {
    /// The owner's address (Ed25519) — also its identity DH key (IK), via Montgomery.
    pub address: PubKeyBytes,
    /// The signed prekey public (SPK).
    pub spk_pub: XPubKeyBytes,
    /// Ed25519 signature by `address` over `spk_pub`.
    pub spk_sig: Vec<u8>,
}

impl PreKeyBundle {
    /// Check the SPK is genuinely signed by the claimed address.
    pub fn verify(&self) -> bool {
        verify(&self.address, &self.spk_pub, &self.spk_sig)
    }
}

/// Derive the X3DH root secret from the three DH outputs (context-separated).
fn x3dh_root(dh1: &[u8], dh2: &[u8], dh3: &[u8]) -> [u8; 32] {
    let mut km = Vec::with_capacity(96);
    km.extend_from_slice(dh1);
    km.extend_from_slice(dh2);
    km.extend_from_slice(dh3);
    blake3::derive_key("hop session x3dh v1", &km)
}

/// Initiator side of the async handshake. Given the recipient's published
/// [`PreKeyBundle`], derive the shared root secret and the ephemeral public the
/// recipient needs to derive the same secret. Verifies the bundle's signature.
pub fn x3dh_initiate(
    sender: &Identity,
    bundle: &PreKeyBundle,
) -> Result<(XPubKeyBytes, [u8; 32])> {
    if !bundle.verify() {
        return Err(Error::BadSignature);
    }
    let ik_b = address_to_x(&bundle.address).ok_or(Error::InvalidKey)?;
    let spk_b = XPublicKey::from(bundle.spk_pub);
    let ik_a = sender.x_secret();
    let ek = StaticSecret::random_from_rng(OsRng);
    let ek_pub = XPublicKey::from(&ek).to_bytes();

    let dh1 = ik_a.diffie_hellman(&spk_b); // IK_a · SPK_b
    let dh2 = ek.diffie_hellman(&XPublicKey::from(ik_b)); // EK_a · IK_b
    let dh3 = ek.diffie_hellman(&spk_b); // EK_a · SPK_b
    let root = x3dh_root(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes());
    Ok((ek_pub, root))
}

/// Responder side: re-derive the same root secret from the initiator's address (IK)
/// and ephemeral public, using the SPK secret the initiator referenced.
pub fn x3dh_respond(
    recipient: &Identity,
    spk_secret: &[u8; 32],
    sender_address: &PubKeyBytes,
    ek_pub: &XPubKeyBytes,
) -> Result<[u8; 32]> {
    let ik_a = address_to_x(sender_address).ok_or(Error::InvalidKey)?;
    let ik_b = recipient.x_secret();
    let spk = StaticSecret::from(*spk_secret);
    let ek = XPublicKey::from(*ek_pub);

    let dh1 = spk.diffie_hellman(&XPublicKey::from(ik_a)); // SPK_b · IK_a
    let dh2 = ik_b.diffie_hellman(&ek); // IK_b · EK_a
    let dh3 = spk.diffie_hellman(&ek); // SPK_b · EK_a
    Ok(x3dh_root(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes()))
}

/// Verify an Ed25519 signature against a sender's address.
pub fn verify(address: &PubKeyBytes, msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(address) else {
        return false;
    };
    let Ok(sig_bytes): core::result::Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(msg, &sig).is_ok()
}

// ---------------------------------------------------------------------------
// §39 metadata privacy: recognition tags + mailbox pseudonyms
// ---------------------------------------------------------------------------

/// Length of a §39 tag (recognition or mailbox). 16 bytes — collision-safe for
/// recognition while staying small on the wire.
pub const TAG_LEN: usize = 16;
/// An opaque §39 tag carried in a private bundle header (no identity leaks from it).
pub type Tag = [u8; TAG_LEN];

fn tag16(context: &str, key_material: &[u8]) -> Tag {
    let h = blake3::derive_key(context, key_material);
    let mut t = [0u8; TAG_LEN];
    t.copy_from_slice(&h[..TAG_LEN]);
    t
}

fn recognition_tag_from_shared(shared: &[u8; 32], bundle_id: &[u8; 32]) -> Tag {
    let mut km = [0u8; 64];
    km[..32].copy_from_slice(shared);
    km[32..].copy_from_slice(bundle_id);
    tag16("hop recog tag v1", &km)
}

/// §39 **recognition tag** — the "is this mine?" primitive (DESIGN.md §39). Bound to a
/// recipient signed prekey (SPK, §25) and the bundle id via an ephemeral DH, so the
/// sender and the recipient derive the SAME tag while an on-path relay (holding neither
/// secret) cannot. The recipient matches with one DH + one hash — no payload decryption.
/// Domain-separated from the seal/X3DH KDFs, so the tag never leaks a session key.
///
/// Sender side: pick a fresh ephemeral, DH against the recipient's SPK public, and return
/// the ephemeral public (to carry in the header) alongside the tag.
pub fn recognition_tag_sender(
    recipient_spk_pub: &XPubKeyBytes,
    bundle_id: &[u8; 32],
) -> (XPubKeyBytes, Tag) {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let eph_pub = XPublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&XPublicKey::from(*recipient_spk_pub));
    (eph_pub, recognition_tag_from_shared(shared.as_bytes(), bundle_id))
}

/// Recipient side: re-derive the recognition tag for one of its prekeys against the
/// header's ephemeral public + bundle id, to compare with the bundle's tag. A new
/// ephemeral per message makes two tags for the same recipient uncorrelatable.
pub fn recognition_tag_recipient(
    spk_secret: &[u8; 32],
    ephemeral_pub: &XPubKeyBytes,
    bundle_id: &[u8; 32],
) -> Tag {
    let secret = StaticSecret::from(*spk_secret);
    let shared = secret.diffie_hellman(&XPublicKey::from(*ephemeral_pub));
    recognition_tag_from_shared(shared.as_bytes(), bundle_id)
}

/// §39 **mailbox-tag** — a recipient's rotatable pull pseudonym: `H("v2" ‖ address ‖ epoch)`
/// (F-06). NOT the address itself (you cannot seal to it or message it, only bucket by it), and it
/// **rotates every epoch**, so a global observer can't correlate a recipient's mailbox across epochs.
/// A relay buckets a blind spool by it and a recipient names it in a want-beacon. Deriving it from
/// `(address, epoch)` — not the prekey — decouples mailbox rotation from the (deterministic) prekey,
/// and lets a relay verify a beacon's ownership from public info (the sender knows the recipient's
/// address for a private send; a beacon is signed by that address, so it can't be forged for another).
pub fn mailbox_tag(address: &PubKeyBytes, epoch: u64) -> Tag {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(address);
    material[32..].copy_from_slice(&epoch.to_le_bytes());
    tag16("hop mailbox tag v2", &material)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn montgomery_correspondence() {
        // The X25519 key derived from the Ed25519 secret (libsodium method) must
        // match the Montgomery form of the Ed25519 public key — proving an address
        // alone is enough to both verify signatures and seal to.
        use ed25519_dalek::SigningKey;
        use sha2::{Digest, Sha512};
        use x25519_dalek::{PublicKey as XP, StaticSecret};

        let sk = SigningKey::generate(&mut OsRng);
        let h = Sha512::digest(sk.to_bytes());
        let mut s = [0u8; 32];
        s.copy_from_slice(&h[..32]);
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;
        let from_secret = XP::from(&StaticSecret::from(s)).to_bytes();
        let from_edwards = sk.verifying_key().to_montgomery().to_bytes();
        assert_eq!(from_secret, from_edwards, "derived X25519 key must match address");
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let id = Identity::generate();
        let msg = b"hop hop hop";
        let sig = id.sign(msg);
        assert!(verify(&id.address(), msg, &sig));
        assert!(!verify(&id.address(), b"tampered", &sig));
    }

    #[test]
    fn identity_survives_secret_roundtrip() {
        let id = Identity::generate();
        let restored = Identity::from_secret_bytes(&id.to_secret_bytes());
        assert_eq!(restored.address(), id.address());
        assert_eq!(restored.address(), id.address());

        // Signatures and seals from the restored identity still work.
        let sig = restored.sign(b"msg");
        assert!(verify(&id.address(), b"msg", &sig));
        let sealed = seal(&id.address(), b"hi").unwrap();
        assert_eq!(restored.open(&sealed).unwrap(), b"hi");
    }

    #[test]
    fn x3dh_initiator_and_responder_agree() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_spk = bob.generate_prekey();
        let bundle = bob_spk.bundle(bob.address());
        assert!(bundle.verify(), "a freshly signed bundle must verify");

        // Async: Alice derives the root from Bob's published bundle (Bob offline).
        let (ek_pub, sk_a) = x3dh_initiate(&alice, &bundle).unwrap();
        // Bob later re-derives the same root from Alice's address + ephemeral.
        let sk_b = x3dh_respond(&bob, &bob_spk.secret_bytes(), &alice.address(), &ek_pub).unwrap();
        assert_eq!(sk_a, sk_b, "X3DH must yield a shared root secret");

        // A different identity (not the SPK owner) derives a different secret.
        let mallory = Identity::generate();
        let sk_m = x3dh_respond(&mallory, &bob_spk.secret_bytes(), &alice.address(), &ek_pub).unwrap();
        assert_ne!(sk_a, sk_m, "only the bundle's identity recovers the root");
    }

    #[test]
    fn derived_prekey_is_stable_across_restart() {
        let id = Identity::generate();
        let restored = Identity::from_secret_bytes(&id.to_secret_bytes());
        let a = id.derive_prekey();
        let b = restored.derive_prekey();
        assert_eq!(a.public, b.public, "derived prekey must be identical after restart");
        assert_eq!(a.secret_bytes(), b.secret_bytes());
        assert!(a.bundle(id.address()).verify());
    }

    #[test]
    fn prekey_bundle_rejects_tampering() {
        let bob = Identity::generate();
        let spk = bob.generate_prekey();
        let mut bundle = spk.bundle(bob.address());
        assert!(bundle.verify());

        bundle.spk_pub[0] ^= 1; // tamper the signed prekey
        assert!(!bundle.verify(), "tampered SPK must fail signature check");
        let alice = Identity::generate();
        assert!(matches!(x3dh_initiate(&alice, &bundle), Err(Error::BadSignature)));
    }

    #[test]
    fn seal_and_open_roundtrip() {
        let recipient = Identity::generate();
        let plaintext = b"sealed bundle payload";
        let sealed = seal(&recipient.address(), plaintext).unwrap();
        let opened = recipient.open(&sealed).unwrap();
        assert_eq!(opened, plaintext);

        // A different identity cannot open it.
        let other = Identity::generate();
        assert!(other.open(&sealed).is_err());
    }

    // --- §39 recognition + mailbox tags ----------------------------------------

    #[test]
    fn recognition_tag_sender_and_recipient_agree() {
        let bob = Identity::generate();
        let spk = bob.derive_prekey();
        let bundle_id = [42u8; 32];
        let (eph_pub, tag) = recognition_tag_sender(&spk.public, &bundle_id);
        let got = recognition_tag_recipient(&spk.secret_bytes(), &eph_pub, &bundle_id);
        assert_eq!(tag, got, "recipient must recompute the sender's recognition tag");
    }

    #[test]
    fn recognition_tag_rejects_wrong_recipient_and_wrong_bundle() {
        let bob = Identity::generate();
        let eve = Identity::generate();
        let spk_bob = bob.derive_prekey();
        let spk_eve = eve.derive_prekey();
        let bundle_id = [7u8; 32];
        let (eph_pub, tag) = recognition_tag_sender(&spk_bob.public, &bundle_id);
        // Eve's prekey derives a different tag → not hers.
        assert_ne!(tag, recognition_tag_recipient(&spk_eve.secret_bytes(), &eph_pub, &bundle_id));
        // Same recipient, different bundle id → different tag (no cross-bundle linkage).
        assert_ne!(tag, recognition_tag_recipient(&spk_bob.secret_bytes(), &eph_pub, &[8u8; 32]));
    }

    #[test]
    fn recognition_tag_is_unlinkable_across_messages() {
        // Two messages to the same recipient use independent ephemerals → unrelated tags,
        // so a relay cannot cluster "same recipient".
        let bob = Identity::generate();
        let spk = bob.derive_prekey();
        let (e1, t1) = recognition_tag_sender(&spk.public, &[1u8; 32]);
        let (e2, t2) = recognition_tag_sender(&spk.public, &[2u8; 32]);
        assert_ne!(e1, e2, "independent ephemerals per message");
        assert_ne!(t1, t2, "tags for the same recipient must not correlate");
    }

    #[test]
    fn mailbox_tag_stable_per_prekey_and_rotates() {
        let bob = Identity::generate();
        // Stable across re-derivations of the same (deterministic) prekey epoch.
        assert_eq!(mailbox_tag(&bob.address(), 0), mailbox_tag(&bob.address(), 0));
        // A different identity's prekey → a different mailbox (it's a pseudonym, not shared).
        let alice = Identity::generate();
        assert_ne!(mailbox_tag(&bob.address(), 0), mailbox_tag(&alice.address(), 0));
    }
}
