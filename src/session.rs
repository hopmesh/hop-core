//! Forward-secret sessions: a Double Ratchet over an X3DH-derived root (DESIGN.md
//! §25).
//!
//! [`crate::crypto`] establishes a shared root secret asynchronously (no live
//! round-trip): the initiator runs [`crypto::x3dh_initiate`] against the
//! responder's published [`crypto::PreKeyBundle`]; the responder later re-derives
//! it with [`crypto::x3dh_respond`]. This module turns that root into a
//! [`Session`] that gives every message its own key — **forward secrecy** (a
//! compromised key can't decrypt earlier messages) and **post-compromise
//! recovery** (the DH ratchet heals after a leak).
//!
//! Crucially for a delay-tolerant mesh, the ratchet tolerates **out-of-order and
//! dropped** messages: skipped message keys are retained (bounded by [`MAX_SKIP`])
//! so a later-arriving earlier message still opens.
//!
//! The responder's signed prekey doubles as its initial DH-ratchet public key
//! (standard Double Ratchet bootstrap), so the first message Alice sends already
//! rides a fresh sending chain.

use std::collections::HashMap;

use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, Key, KeyInit, Nonce,
};
use getrandom::{rand_core::UnwrapErr, SysRng};
use serde::{Deserialize, Serialize};
// x25519-dalek 3 needs a `CryptoRng` from its own rand_core (0.10), which dropped `OsRng`
// entirely; see the note in crypto.rs for why `getrandom::SysRng` is the replacement.
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use crate::crypto::XPubKeyBytes;
use crate::error::{Error, Result};

/// A fresh CSPRNG handle satisfying `x25519_dalek`'s `CryptoRng` bound.
fn dalek_rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

/// Cap on retained skipped-message keys, to bound memory against a peer that
/// claims huge message numbers.
pub const MAX_SKIP: usize = 1024;

/// Per-message header sent in the clear (and authenticated as AEAD associated
/// data): the sender's current ratchet public, the previous sending-chain length,
/// and this message's number within the current chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Sender's current DH-ratchet public key.
    pub dh: XPubKeyBytes,
    /// Number of messages in the sender's previous sending chain.
    pub pn: u32,
    /// Message number within the current sending chain.
    pub n: u32,
}

/// A ratchet-encrypted message: header (authenticated) + AEAD ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetMessage {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

/// One end of a Double Ratchet session with a single peer.
///
/// `Serialize`/`Deserialize` so the full ratchet state can be **persisted** and restored
/// across restarts — otherwise a process restart (or an iOS beacon-mode background-kill)
/// loses the session while the peer keeps theirs, desyncing the ratchet so every later
/// message fails to decrypt (DESIGN.md §25). The skipped-key map (a `HashMap` with a tuple
/// key) serializes as a sequence of entries, so it round-trips through postcard.
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    rk: [u8; 32],              // root key
    dh_self_secret: [u8; 32],  // current ratchet secret
    dh_self_pub: XPubKeyBytes, // current ratchet public
    dh_remote: Option<XPubKeyBytes>,
    cks: Option<[u8; 32]>, // sending chain key
    ckr: Option<[u8; 32]>, // receiving chain key
    ns: u32,               // messages sent in current chain
    nr: u32,               // messages received in current chain
    pn: u32,               // length of previous sending chain
    #[serde(with = "skipped_serde")]
    skipped: HashMap<(XPubKeyBytes, u32), [u8; 32]>,
}

/// postcard can't key a map on a tuple, so persist `skipped` as a flat sequence of
/// `(dh, n, mk)` entries.
mod skipped_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        m: &HashMap<(XPubKeyBytes, u32), [u8; 32]>,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let v: Vec<(XPubKeyBytes, u32, [u8; 32])> =
            m.iter().map(|((dh, n), mk)| (*dh, *n, *mk)).collect();
        v.serialize(s)
    }

    #[allow(clippy::type_complexity)] // serde helper signature mirrors the field type exactly
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<HashMap<(XPubKeyBytes, u32), [u8; 32]>, D::Error> {
        let v: Vec<(XPubKeyBytes, u32, [u8; 32])> = Vec::deserialize(d)?;
        Ok(v.into_iter().map(|(dh, n, mk)| ((dh, n), mk)).collect())
    }
}

impl Session {
    /// Initiator side. `root` is the X3DH output; `remote_dh` is the responder's
    /// signed prekey public (its initial ratchet key). Sets up a sending chain so
    /// the first message can go out immediately.
    pub fn init_initiator(root: [u8; 32], remote_dh: XPubKeyBytes) -> Self {
        let dh_self = StaticSecret::random_from_rng(&mut dalek_rng());
        let dh_self_pub = XPublicKey::from(&dh_self).to_bytes();
        let dh_out = dh_self.diffie_hellman(&XPublicKey::from(remote_dh));
        let (rk, cks) = kdf_rk(&root, dh_out.as_bytes());
        Self {
            rk,
            dh_self_secret: dh_self.to_bytes(),
            dh_self_pub,
            dh_remote: Some(remote_dh),
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    /// Responder side. `root` is the X3DH output; the signed-prekey keypair becomes
    /// the initial ratchet key. No chains yet — the responder must receive before it
    /// can send (it learns the initiator's ratchet key from the first message).
    pub fn init_responder(root: [u8; 32], spk_secret: [u8; 32], spk_public: XPubKeyBytes) -> Self {
        Self {
            rk: root,
            dh_self_secret: spk_secret,
            dh_self_pub: spk_public,
            dh_remote: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    /// Encrypt the next outbound message. Errors if there's no sending chain yet
    /// (a responder must receive at least one message first).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage> {
        let ck = self.cks.ok_or(Error::Crypto("no sending chain"))?;
        let (next, mk) = kdf_ck(&ck);
        self.cks = Some(next);
        let header = Header {
            dh: self.dh_self_pub,
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;
        let aad = postcard::to_allocvec(&header)?;
        let ciphertext = aead_encrypt(&mk, plaintext, &aad)?;
        Ok(RatchetMessage { header, ciphertext })
    }

    /// Decrypt an inbound message, performing a DH ratchet step and/or replaying
    /// skipped keys as needed. Tolerates out-of-order and dropped messages.
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>> {
        // Authentication failure must not consume skipped keys or advance either ratchet. Stage the
        // transition on a clone, then commit it only after AEAD verification succeeds.
        let mut staged = self.clone();
        let plaintext = staged.decrypt_staged(msg)?;
        *self = staged;
        Ok(plaintext)
    }

    fn decrypt_staged(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>> {
        let aad = postcard::to_allocvec(&msg.header)?;

        // A previously-skipped (out-of-order) message?
        if let Some(mk) = self.skipped.remove(&(msg.header.dh, msg.header.n)) {
            return aead_decrypt(&mk, &msg.ciphertext, &aad);
        }

        // New ratchet public → skip the rest of the current receiving chain (up to
        // the sender's stated previous length) and step the DH ratchet.
        if self.dh_remote != Some(msg.header.dh) {
            self.skip(msg.header.pn)?;
            self.dh_ratchet(msg.header.dh);
        }

        // Skip forward within the current chain to this message's number.
        self.skip(msg.header.n)?;

        let ck = self.ckr.ok_or(Error::Crypto("no receiving chain"))?;
        let (next, mk) = kdf_ck(&ck);
        self.ckr = Some(next);
        self.nr += 1;
        aead_decrypt(&mk, &msg.ciphertext, &aad)
    }

    /// Derive and stash message keys for indices `[nr, until)` of the current
    /// receiving chain, so those (earlier) messages still open if they arrive later.
    fn skip(&mut self, until: u32) -> Result<()> {
        let Some(mut ck) = self.ckr else {
            return Ok(());
        };
        let remote = self
            .dh_remote
            .ok_or(Error::Crypto("skip without remote key"))?;
        while self.nr < until {
            if self.skipped.len() >= MAX_SKIP {
                return Err(Error::Crypto("too many skipped messages"));
            }
            let (next, mk) = kdf_ck(&ck);
            self.skipped.insert((remote, self.nr), mk);
            ck = next;
            self.nr += 1;
        }
        self.ckr = Some(ck);
        Ok(())
    }

    /// Advance the DH ratchet on a newly-seen remote ratchet key: derive a fresh
    /// receiving chain from it, then a fresh sending chain under a new local key.
    fn dh_ratchet(&mut self, remote: XPubKeyBytes) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dh_remote = Some(remote);

        let cur = StaticSecret::from(self.dh_self_secret);
        let dh_recv = cur.diffie_hellman(&XPublicKey::from(remote));
        let (rk, ckr) = kdf_rk(&self.rk, dh_recv.as_bytes());
        self.rk = rk;
        self.ckr = Some(ckr);

        let next = StaticSecret::random_from_rng(&mut dalek_rng());
        self.dh_self_pub = XPublicKey::from(&next).to_bytes();
        let dh_send = next.diffie_hellman(&XPublicKey::from(remote));
        let (rk2, cks) = kdf_rk(&self.rk, dh_send.as_bytes());
        self.rk = rk2;
        self.cks = Some(cks);
        self.dh_self_secret = next.to_bytes();
    }
}

/// Root KDF: mix the current root key with a DH output → (new root, chain key).
fn kdf_rk(rk: &[u8; 32], dh: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut m = Vec::with_capacity(rk.len() + dh.len());
    m.extend_from_slice(rk);
    m.extend_from_slice(dh);
    let new_rk = blake3::derive_key("hop session root v1", &m);
    let ck = blake3::derive_key("hop session chain v1", &m);
    (new_rk, ck)
}

/// Symmetric chain KDF: chain key → (next chain key, message key).
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let next = blake3::keyed_hash(ck, &[0x01]);
    let mk = blake3::keyed_hash(ck, &[0x02]);
    (*next.as_bytes(), *mk.as_bytes())
}

/// AEAD with a single-use message key, so a fixed zero nonce is safe (the (key,
/// nonce) pair is unique because each `mk` is used exactly once). The header is
/// authenticated as associated data.
fn aead_encrypt(mk: &[u8; 32], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*mk));
    cipher
        .encrypt(&Nonce::from([0u8; 12]), Payload { msg: pt, aad })
        .map_err(|_| Error::Crypto("session encrypt failed"))
}

fn aead_decrypt(mk: &[u8; 32], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*mk));
    cipher
        .decrypt(&Nonce::from([0u8; 12]), Payload { msg: ct, aad })
        .map_err(|_| Error::Crypto("session decrypt failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{self, Identity};

    fn pair() -> (Session, Session) {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();
        let bob_spk = bob_id.generate_prekey();
        let bundle = bob_spk.bundle(bob_id.address());
        let (ek_pub, root_a) = crypto::x3dh_initiate(&alice_id, &bundle).unwrap();
        let root_b = crypto::x3dh_respond(
            &bob_id,
            &bob_spk.secret_bytes(),
            &alice_id.address(),
            &ek_pub,
        )
        .unwrap();
        (
            Session::init_initiator(root_a, bundle.spk_pub),
            Session::init_responder(root_b, bob_spk.secret_bytes(), bob_spk.public),
        )
    }

    /// Establish a session via X3DH and run a full conversation, including a
    /// direction switch (DH ratchet) and out-of-order delivery.
    #[test]
    fn ratchet_conversation_with_out_of_order() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();
        let bob_spk = bob_id.generate_prekey();
        let bundle = bob_spk.bundle(bob_id.address());

        let (ek_pub, root_a) = crypto::x3dh_initiate(&alice_id, &bundle).unwrap();
        let root_b = crypto::x3dh_respond(
            &bob_id,
            &bob_spk.secret_bytes(),
            &alice_id.address(),
            &ek_pub,
        )
        .unwrap();
        assert_eq!(root_a, root_b);

        let mut alice = Session::init_initiator(root_a, bundle.spk_pub);
        let mut bob = Session::init_responder(root_b, bob_spk.secret_bytes(), bob_spk.public);

        // Alice → Bob (first message bootstraps Bob's receiving chain).
        let m1 = alice.encrypt(b"hello bob").unwrap();
        assert_eq!(bob.decrypt(&m1).unwrap(), b"hello bob");

        // Bob → Alice (Bob now has a sending chain; triggers Alice's DH ratchet).
        let r1 = bob.encrypt(b"hi alice").unwrap();
        assert_eq!(alice.decrypt(&r1).unwrap(), b"hi alice");

        // Alice sends three; deliver out of order (3, 1, 2).
        let a1 = alice.encrypt(b"one").unwrap();
        let a2 = alice.encrypt(b"two").unwrap();
        let a3 = alice.encrypt(b"three").unwrap();
        assert_eq!(bob.decrypt(&a3).unwrap(), b"three"); // skips 1 and 2
        assert_eq!(bob.decrypt(&a1).unwrap(), b"one"); // from skipped store
        assert_eq!(bob.decrypt(&a2).unwrap(), b"two"); // from skipped store
    }

    #[test]
    fn forward_secrecy_keys_differ_per_message() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();
        let bob_spk = bob_id.generate_prekey();
        let bundle = bob_spk.bundle(bob_id.address());
        let (ek_pub, root_a) = crypto::x3dh_initiate(&alice_id, &bundle).unwrap();
        let root_b = crypto::x3dh_respond(
            &bob_id,
            &bob_spk.secret_bytes(),
            &alice_id.address(),
            &ek_pub,
        )
        .unwrap();

        let mut alice = Session::init_initiator(root_a, bundle.spk_pub);
        let mut bob = Session::init_responder(root_b, bob_spk.secret_bytes(), bob_spk.public);

        let m1 = alice.encrypt(b"same plaintext").unwrap();
        let m2 = alice.encrypt(b"same plaintext").unwrap();
        // Identical plaintext, different ciphertext → distinct per-message keys.
        assert_ne!(m1.ciphertext, m2.ciphertext);
        assert_eq!(bob.decrypt(&m1).unwrap(), b"same plaintext");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"same plaintext");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();
        let bob_spk = bob_id.generate_prekey();
        let bundle = bob_spk.bundle(bob_id.address());
        let (ek_pub, root_a) = crypto::x3dh_initiate(&alice_id, &bundle).unwrap();
        let root_b = crypto::x3dh_respond(
            &bob_id,
            &bob_spk.secret_bytes(),
            &alice_id.address(),
            &ek_pub,
        )
        .unwrap();
        let mut alice = Session::init_initiator(root_a, bundle.spk_pub);
        let mut bob = Session::init_responder(root_b, bob_spk.secret_bytes(), bob_spk.public);

        let mut m = alice.encrypt(b"secret").unwrap();
        m.ciphertext[0] ^= 0xff;
        assert!(bob.decrypt(&m).is_err());
    }

    #[test]
    fn failed_authentication_does_not_consume_a_skipped_key() {
        let (mut alice, mut bob) = pair();
        let first = alice.encrypt(b"first").unwrap();
        let second = alice.encrypt(b"second").unwrap();
        assert_eq!(bob.decrypt(&second).unwrap(), b"second");

        let mut corrupted = first.clone();
        corrupted.ciphertext[0] ^= 0x80;
        assert!(bob.decrypt(&corrupted).is_err());
        assert_eq!(
            bob.decrypt(&first).unwrap(),
            b"first",
            "a forged copy must not burn the genuine skipped-message key"
        );
    }
}
