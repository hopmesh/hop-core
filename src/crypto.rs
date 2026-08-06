//! Identity, signing, and end-to-end sealing.
//!
//! Each node has an [`Identity`]: a single Ed25519 keypair. The **address** is the
//! Ed25519 public key, and the X25519 keys for sealing/DH are *derived* from it via
//! Ed25519→Montgomery conversion (DESIGN.md §4), so an address alone is enough to
//! both verify signatures from and seal to a peer; nothing extra rides the wire.
//!
//! On top of that this module provides the building blocks for **forward-secret
//! sessions** (DESIGN.md §25): a [`SignedPreKey`] + [`PreKeyBundle`] and an
//! X3DH-style async handshake ([`x3dh_initiate`] / [`x3dh_respond`]) that derive a
//! shared root secret without a live round-trip. The ratchet that consumes that
//! root lives in [`crate::session`].

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
// ed25519-dalek 3 / x25519-dalek 3 need a `CryptoRng` from THEIR rand_core (0.10), which dropped
// `OsRng` entirely; `getrandom::SysRng` (made infallible via `UnwrapErr`) is the replacement the
// dalek crates' own docs point at. Same OS CSPRNG either way as the workspace `rand_core::OsRng`
// used elsewhere in this file for plain `RngCore::fill_bytes`; this only satisfies the newer
// `CryptoRng` bound the dalek crates now require of their key-generation entry points, so it
// changes no key material or wire bytes.
use getrandom::{rand_core::UnwrapErr, SysRng};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use crate::error::{Error, Result};

/// A fresh CSPRNG handle satisfying `{ed25519,x25519}_dalek`'s `CryptoRng` bound.
fn dalek_rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

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

/// A node's secret identity: a single Ed25519 keypair. The address *is* the public
/// key; the X25519 keys used for sealing are **derived** from it (Montgomery), so an
/// address alone is enough to both verify signatures from and seal messages to a
/// peer, with no separate sealing key on the wire. See DESIGN.md §4.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut dalek_rng()),
        }
    }

    /// The 32-byte Ed25519 seed. Persist it (securely) for a stable address.
    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Restore an identity from a saved seed.
    pub fn from_secret_bytes(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The node's address (Ed25519 public key), also its sealing identity.
    pub fn address(&self) -> PubKeyBytes {
        self.signing.verifying_key().to_bytes()
    }

    /// X25519 secret for sealing/Noise, derived from the Ed25519 seed (SHA-512 +
    /// clamp, the standard Ed25519→Curve25519 conversion).
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
        let secret = StaticSecret::random_from_rng(&mut dalek_rng());
        let public = XPublicKey::from(&secret).to_bytes();
        let sig = self.sign(&public);
        SignedPreKey {
            secret: secret.to_bytes(),
            public,
            sig,
        }
    }

    /// Derive a **deterministic** signed prekey from the identity seed, so the same
    /// prekey is reconstructed every launch with no persistence. Epoch 0 is the base
    /// (non-rotating) prekey; [`Identity::derive_prekey_epoch`] rotates it per epoch.
    /// Determinism matters for correctness: a peer may cache your prekey advert (long
    /// TTL) across your restart, and must still be able to open a session, which only
    /// works if the secret for that epoch is stably re-derivable.
    pub fn derive_prekey(&self) -> SignedPreKey {
        self.derive_prekey_epoch(0)
    }

    /// Derive the deterministic signed prekey for a given `epoch` (core-03). Keying the SPK on an
    /// epoch is what bounds compromise: a leaked SPK secret only exposes the X3DH first-message
    /// roots (and recognition tags) of sessions bootstrapped **in that epoch**, not for the life of
    /// the identity. The owner publishes the current epoch's prekey and retains a bounded window of
    /// past epochs' secrets so a message minted against a just-rotated prekey still resolves. Because
    /// this is a pure function of (seed, epoch), any past epoch's secret is re-derivable after a
    /// restart with no persistence: the same property `derive_prekey` relies on.
    pub fn derive_prekey_epoch(&self, epoch: u64) -> SignedPreKey {
        // Domain-separate per epoch so each epoch's secret is independent. Epoch 0 reproduces the
        // original "hop prekey v1" context byte-for-byte, so pre-rotation adverts/sessions are
        // unaffected (the base prekey is unchanged).
        let mut s = if epoch == 0 {
            blake3::derive_key("hop prekey v1", &self.signing.to_bytes())
        } else {
            let mut ikm = self.signing.to_bytes().to_vec();
            ikm.extend_from_slice(&epoch.to_le_bytes());
            blake3::derive_key("hop prekey epoch v1", &ikm)
        };
        s[0] &= 248; // clamp to a valid X25519 scalar
        s[31] &= 127;
        s[31] |= 64;
        let secret = StaticSecret::from(s);
        let public = XPublicKey::from(&secret).to_bytes();
        let sig = self.sign(&public);
        SignedPreKey {
            secret: s,
            public,
            sig,
        }
    }

    /// Open a payload sealed to this identity's address.
    pub fn open(&self, sealed: &Sealed) -> Result<Vec<u8>> {
        let shared = self
            .x_secret()
            .diffie_hellman(&XPublicKey::from(sealed.ephemeral_pub));
        let sym = blake3::hash(shared.as_bytes());
        let cipher = ChaCha20Poly1305::new(&Key::from(*sym.as_bytes()));
        cipher
            .decrypt(&Nonce::from(sealed.nonce), sealed.ciphertext.as_slice())
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
    VerifyingKey::from_bytes(address)
        .ok()
        .map(|v| v.to_montgomery().to_bytes())
}

/// Seal `plaintext` to an **address** (Ed25519 public key): ephemeral-static ECDH
/// against the address's derived X25519 key + ChaCha20-Poly1305. Only the holder of
/// that address's secret can [`Identity::open`] it.
pub fn seal(to_address: &PubKeyBytes, plaintext: &[u8]) -> Result<Sealed> {
    let recipient = address_to_x(to_address).ok_or(Error::InvalidKey)?;
    let ephemeral = StaticSecret::random_from_rng(&mut dalek_rng());
    let ephemeral_pub = XPublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&XPublicKey::from(recipient));
    let sym = blake3::hash(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(&Key::from(*sym.as_bytes()));

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|_| Error::Crypto("encrypt failed"))?;

    Ok(Sealed {
        ephemeral_pub,
        nonce,
        ciphertext,
    })
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
    /// The retained secret bytes. Persist these so late handshakes still resolve.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret
    }

    /// Reconstruct from persisted parts.
    pub fn from_parts(secret: [u8; 32], public: XPubKeyBytes, sig: [u8; 64]) -> Self {
        Self {
            secret,
            public,
            sig,
        }
    }

    /// The public, shareable bundle for this prekey under `address`, with no
    /// one-time prekeys. See [`Self::bundle_with_opks`] to publish a batch.
    pub fn bundle(&self, address: PubKeyBytes) -> PreKeyBundle {
        PreKeyBundle {
            address,
            spk_pub: self.public,
            spk_sig: self.sig.to_vec(),
            opks: Vec::new(),
            opk_sig: Vec::new(),
        }
    }

    /// The public, shareable bundle for this prekey plus a signed one-time prekey
    /// batch. The batch must have been minted against THIS prekey's public, which is
    /// what its signature binds.
    pub fn bundle_with_opks(
        &self,
        address: PubKeyBytes,
        batch: &OneTimePreKeyBatch,
    ) -> PreKeyBundle {
        PreKeyBundle {
            address,
            spk_pub: self.public,
            spk_sig: self.sig.to_vec(),
            opks: batch.publics.clone(),
            opk_sig: batch.sig.to_vec(),
        }
    }
}

/// Cap on one-time prekeys carried in a single published batch. The batch rides a
/// gossiped advert, so this is an attacker-controlled collection length on decode:
/// keep it small enough that verifying a forged batch is cheap and a directory entry
/// stays bounded.
pub const MAX_ONE_TIME_PREKEYS: usize = 32;

/// The public half of a **one-time prekey** (OPK): a single-use X25519 public,
/// numbered within its publisher's batch.
///
/// See [`PreKeyBundle`] for why these exist in a serverless mesh and what they do
/// and do not buy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OneTimePreKey {
    /// Batch-local identifier, echoed by the initiator so the owner knows which
    /// secret to use. Unique per publisher per batch, not globally.
    pub id: u32,
    /// The X25519 public half.
    pub public: XPubKeyBytes,
}

/// The exact bytes an OPK batch signature covers. Binds the batch to its publisher
/// AND to the SPK generation it was minted against, so a batch cannot be lifted onto
/// a rotated SPK (which would silently re-point DH4 at a key the owner has retired).
fn opk_batch_message(
    address: &PubKeyBytes,
    spk_pub: &XPubKeyBytes,
    opks: &[OneTimePreKey],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + 32 + 4 + opks.len() * 36 + 28);
    m.extend_from_slice(b"hop one-time prekey batch v1");
    m.extend_from_slice(address);
    m.extend_from_slice(spk_pub);
    m.extend_from_slice(&(opks.len() as u32).to_be_bytes());
    for opk in opks {
        m.extend_from_slice(&opk.id.to_be_bytes());
        m.extend_from_slice(&opk.public);
    }
    m
}

/// Owner-side one-time prekey batch: the retained secrets plus the public halves and
/// the signature that lets anyone verify the batch offline.
pub struct OneTimePreKeyBatch {
    secrets: Vec<(u32, [u8; 32])>,
    /// The public halves, in id order.
    pub publics: Vec<OneTimePreKey>,
    /// Ed25519 signature by the owner's address over [`opk_batch_message`].
    pub sig: [u8; 64],
}

impl Drop for OneTimePreKeyBatch {
    fn drop(&mut self) {
        // Same discipline as SignedPreKey (F-08): the whole point of an OPK is that its
        // secret stops existing, so do not leave it in the heap until overwritten.
        for (_, s) in self.secrets.iter_mut() {
            zeroize::Zeroize::zeroize(s);
        }
    }
}

impl OneTimePreKeyBatch {
    /// Mint `count` fresh one-time prekeys bound to `spk_pub`, numbered from
    /// `first_id`. Clamped to [`MAX_ONE_TIME_PREKEYS`].
    pub fn generate(
        identity: &Identity,
        spk_pub: &XPubKeyBytes,
        first_id: u32,
        count: usize,
    ) -> Self {
        let count = count.min(MAX_ONE_TIME_PREKEYS);
        let mut secrets = Vec::with_capacity(count);
        let mut publics = Vec::with_capacity(count);
        for i in 0..count {
            let id = first_id.wrapping_add(i as u32);
            let secret = StaticSecret::random_from_rng(&mut dalek_rng());
            publics.push(OneTimePreKey {
                id,
                public: XPublicKey::from(&secret).to_bytes(),
            });
            secrets.push((id, secret.to_bytes()));
        }
        let sig = identity.sign(&opk_batch_message(&identity.address(), spk_pub, &publics));
        Self {
            secrets,
            publics,
            sig,
        }
    }

    /// The retained secrets, to persist alongside the SPK secret so a late handshake
    /// that referenced one still resolves.
    pub fn secret_bytes(&self) -> Vec<(u32, [u8; 32])> {
        self.secrets.clone()
    }

    /// Reconstruct from persisted parts.
    pub fn from_parts(
        secrets: Vec<(u32, [u8; 32])>,
        publics: Vec<OneTimePreKey>,
        sig: [u8; 64],
    ) -> Self {
        Self {
            secrets,
            publics,
            sig,
        }
    }
}

/// The public prekey bundle a peer publishes so others can open a session to it
/// without a live round-trip: identity (address = IK), signed prekey (SPK), and an
/// optional batch of **one-time prekeys** (OPKs).
///
/// ## One-time prekeys without a server
///
/// Classic X3DH has a server hand each requester a distinct OPK and delete it, which
/// is what makes it one-time. A serverless flood/DTN has no such party, and this was
/// long recorded here as the reason hop shipped IK + SPK + initiator-ephemeral only.
/// That reasoning was wrong in one respect: the batch does not need a *dispenser*, it
/// needs to be *verifiable offline*, and an Ed25519 signature over the batch gives
/// that. So the mesh itself can carry OPKs, gossiped like any other advert, and a
/// sender picks one.
///
/// What that buys, precisely: with no OPK, a device compromise exposes the SPK secret
/// and therefore every session opened against that SPK generation until it rotates.
/// With an OPK, DH4 also depends on a secret the owner deletes shortly after use, so
/// the exposure window for that one session shrinks from "until SPK rotation" to
/// "until the OPK is reaped".
///
/// What it does NOT buy, and must not be claimed: **uniqueness**. Without a dispenser
/// two senders can pick the same OPK, so an OPK here is one-time *by the owner's
/// retention policy*, not by mutual exclusion. Treat it as a forward-secrecy ratchet
/// on the prekey, not as a replay defense. The owner therefore keeps a used OPK
/// secret for a bounded window rather than deleting on first use, because a DTN
/// delivers late and out of order and deleting eagerly would black-hole a legitimately
/// delayed second message. See [`crate::session`] and DESIGN.md §25.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PreKeyBundle {
    /// The owner's address (Ed25519), also its identity DH key (IK), via Montgomery.
    pub address: PubKeyBytes,
    /// The signed prekey public (SPK).
    pub spk_pub: XPubKeyBytes,
    /// Ed25519 signature by `address` over `spk_pub`.
    pub spk_sig: Vec<u8>,
    /// Published one-time prekeys, if any. Empty is valid and means "SPK only".
    pub opks: Vec<OneTimePreKey>,
    /// Ed25519 signature by `address` over [`opk_batch_message`]. Empty when `opks`
    /// is empty. Kept SEPARATE from `spk_sig` so a bundle whose OPK batch fails to
    /// verify degrades to a working SPK-only bundle instead of being discarded whole.
    pub opk_sig: Vec<u8>,
}

impl PreKeyBundle {
    /// Check the SPK is genuinely signed by the claimed address. Does NOT check the
    /// OPK batch; see [`Self::opks_verified`].
    pub fn verify(&self) -> bool {
        verify(&self.address, &self.spk_pub, &self.spk_sig)
    }

    /// Is the published OPK batch genuinely signed by this address, against this SPK?
    /// False for an empty batch (nothing to trust) and for an oversized one.
    pub fn opks_verified(&self) -> bool {
        if self.opks.is_empty() || self.opks.len() > MAX_ONE_TIME_PREKEYS {
            return false;
        }
        // A duplicate id would make "which secret answers this?" ambiguous at the owner.
        let mut ids: Vec<u32> = self.opks.iter().map(|o| o.id).collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != self.opks.len() {
            return false;
        }
        verify(
            &self.address,
            &opk_batch_message(&self.address, &self.spk_pub, &self.opks),
            &self.opk_sig,
        )
    }

    /// Drop an unverifiable OPK batch, leaving a usable SPK-only bundle. Called on
    /// ingest so a forged batch degrades reachability rather than denying it.
    pub fn strip_unverified_opks(&mut self) {
        if !self.opks_verified() {
            self.opks.clear();
            self.opk_sig.clear();
        }
    }

    /// Pick a one-time prekey to open a session with, skipping any this sender has
    /// already spent on this peer. Returns `None` for an SPK-only bundle, which is a
    /// normal, supported case and not an error.
    ///
    /// **Chosen at random among the unspent, deliberately, not "the first one".**
    /// There is no dispenser here, so senders never coordinate. If every sender walked
    /// the batch in order, every fresh sender would pick id 0 and a batch of 8 would
    /// behave exactly like a batch of 1: the recipient would burn one OPK repeatedly
    /// while seven sat unused, and the reuse this is meant to spread would be certain
    /// rather than a 1-in-8 accident. Random selection is the only way to spread load
    /// across an uncoordinated sender population.
    pub fn select_opk(&self, already_used: &dyn Fn(u32) -> bool) -> Option<OneTimePreKey> {
        if !self.opks_verified() {
            return None;
        }
        let unspent: Vec<OneTimePreKey> = self
            .opks
            .iter()
            .copied()
            .filter(|o| !already_used(o.id))
            .collect();
        if unspent.is_empty() {
            return None;
        }
        let mut pick = [0u8; 4];
        OsRng.fill_bytes(&mut pick);
        let idx = (u32::from_le_bytes(pick) as usize) % unspent.len();
        Some(unspent[idx])
    }
}

/// Derive the X3DH root secret from the DH outputs (context-separated).
///
/// `dh4` is `Some` exactly when a one-time prekey was used. The count is folded into
/// the preimage so the 3-DH and 4-DH derivations can never collide: without it, a
/// caller that dropped DH4 would land on a different-length input to the same KDF
/// label, and "different length" is not by itself a domain separation guarantee.
fn x3dh_root(dh1: &[u8], dh2: &[u8], dh3: &[u8], dh4: Option<&[u8]>) -> [u8; 32] {
    let mut km = Vec::with_capacity(129);
    km.push(if dh4.is_some() { 4u8 } else { 3u8 });
    km.extend_from_slice(dh1);
    km.extend_from_slice(dh2);
    km.extend_from_slice(dh3);
    if let Some(dh4) = dh4 {
        km.extend_from_slice(dh4);
    }
    blake3::derive_key("hop session x3dh v2", &km)
}

/// Initiator side of the async handshake. Given the recipient's published
/// [`PreKeyBundle`], derive the shared root secret and the ephemeral public the
/// recipient needs to derive the same secret. Verifies the bundle's signature.
///
/// `opk` is the one-time prekey to consume, chosen by the caller via
/// [`PreKeyBundle::select_opk`] so it can avoid respending one. `None` runs the
/// classic 3-DH handshake against SPK only.
pub fn x3dh_initiate(
    sender: &Identity,
    bundle: &PreKeyBundle,
    opk: Option<&OneTimePreKey>,
) -> Result<(XPubKeyBytes, [u8; 32])> {
    if !bundle.verify() {
        return Err(Error::BadSignature);
    }
    // Never DH against an OPK we did not authenticate: an unsigned OPK is an
    // attacker-chosen public, and folding it into the root would let whoever supplied
    // it grind DH4.
    if opk.is_some() && !bundle.opks_verified() {
        return Err(Error::BadSignature);
    }
    if let Some(opk) = opk {
        if !bundle.opks.iter().any(|o| o == opk) {
            return Err(Error::InvalidKey);
        }
    }
    let ik_b = address_to_x(&bundle.address).ok_or(Error::InvalidKey)?;
    let spk_b = XPublicKey::from(bundle.spk_pub);
    let ik_a = sender.x_secret();
    let ek = StaticSecret::random_from_rng(&mut dalek_rng());
    let ek_pub = XPublicKey::from(&ek).to_bytes();

    let dh1 = ik_a.diffie_hellman(&spk_b); // IK_a · SPK_b
    let dh2 = ek.diffie_hellman(&XPublicKey::from(ik_b)); // EK_a · IK_b
    let dh3 = ek.diffie_hellman(&spk_b); // EK_a · SPK_b
    let dh4 = opk.map(|o| ek.diffie_hellman(&XPublicKey::from(o.public))); // EK_a · OPK_b
    let root = x3dh_root(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|d| d.as_bytes().as_slice()),
    );
    Ok((ek_pub, root))
}

/// Responder side: re-derive the same root secret from the initiator's address (IK)
/// and ephemeral public, using the SPK secret the initiator referenced.
///
/// `opk_secret` must be `Some` exactly when the initiator referenced a one-time
/// prekey. A referenced-but-reaped OPK is NOT recoverable by falling back to 3-DH
/// (the roots differ by construction); the caller should treat that as a dead session
/// and answer with [`crate::bundle::Payload::SessionReset`].
pub fn x3dh_respond(
    recipient: &Identity,
    spk_secret: &[u8; 32],
    opk_secret: Option<&[u8; 32]>,
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
    let dh4 = opk_secret.map(|s| StaticSecret::from(*s).diffie_hellman(&ek)); // OPK_b · EK_a
    Ok(x3dh_root(
        dh1.as_bytes(),
        dh2.as_bytes(),
        dh3.as_bytes(),
        dh4.as_ref().map(|d| d.as_bytes().as_slice()),
    ))
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

/// Length of a §39 tag (recognition or mailbox). 16 bytes, collision-safe for
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

/// Derive a recognition tag from the ephemeral·SPK DH `shared` secret and the bundle id.
/// `pub` so a relay can verify a §39 delivery **vaccine**: the recipient reveals `shared`
/// (a value only it can compute, and which leaks nothing about it, by CDH), and a relay holding
/// the bundle checks this equals the tag it already stores before dropping its copy.
pub fn recognition_tag_from_shared(shared: &[u8; 32], bundle_id: &[u8; 32]) -> Tag {
    let mut km = [0u8; 64];
    km[..32].copy_from_slice(shared);
    km[32..].copy_from_slice(bundle_id);
    tag16("hop recog tag v1", &km)
}

/// The per-bundle **hop-count blind** for a §39 private bundle (sec-priv-r4-01).
///
/// `env.hops` is advisory (routing is bounded by the separate `hop_limit` countdown), but it is
/// cleartext and starts at 0, so the FIRST node to receive a freshly-originated bundle reads
/// `hops == 0` and knows its link peer is the origin. Links are mutually authenticated Noise XX, so
/// that peer is an identified address: a relay could attribute every bundle it received directly to
/// its sender, no matter that `src` is zeroed.
///
/// Blinding it: the sender stamps `hops = offset` instead of 0 and relays increment as before, so an
/// observer sees `offset + travelled` for an unknown offset and cannot infer proximity to the origin.
/// The offset is DERIVED from the recognition secret rather than carried, so it costs no wire bytes
/// and works for every payload variant: the recipient already computes `shared` to test the tag, so
/// it can recompute the offset and subtract to recover the exact true hop count.
///
/// Bounded to [`MAX_HOP_BLIND`] so `offset + travelled` cannot wrap a `u8` (forwarding uses
/// `saturating_add`, so a wrap would silently freeze the advisory count rather than panic).
pub fn hop_blind_from_shared(shared: &[u8; 32], bundle_id: &[u8; 32]) -> u8 {
    let mut km = [0u8; 64];
    km[..32].copy_from_slice(shared);
    km[32..].copy_from_slice(bundle_id);
    let t = tag16("hop hop-blind v1", &km);
    t[0] % (MAX_HOP_BLIND + 1)
}

/// Upper bound on the [`hop_blind_from_shared`] offset. Leaves generous headroom under `u8::MAX` for
/// the real travelled count, so the blinded value never saturates in practice.
pub const MAX_HOP_BLIND: u8 = 100;

/// Recipient side: the raw ephemeral·SPK DH `shared` secret (the recognition token) it reveals in a
/// §39 delivery vaccine. Same DH as [`recognition_tag_recipient`], returned instead of hashed.
pub fn recognition_shared(spk_secret: &[u8; 32], ephemeral_pub: &XPubKeyBytes) -> [u8; 32] {
    let secret = StaticSecret::from(*spk_secret);
    *secret
        .diffie_hellman(&XPublicKey::from(*ephemeral_pub))
        .as_bytes()
}

/// §39 **recognition tag**: the "is this mine?" primitive (DESIGN.md §39). Bound to a
/// recipient signed prekey (SPK, §25) and the bundle id via an ephemeral DH, so the
/// sender and the recipient derive the SAME tag while an on-path relay (holding neither
/// secret) cannot. The recipient matches with one DH + one hash, no payload decryption.
/// Domain-separated from the seal/X3DH KDFs, so the tag never leaks a session key.
///
/// Sender side: pick a fresh ephemeral, DH against the recipient's SPK public, and return
/// the ephemeral public (to carry in the header) alongside the tag.
pub fn recognition_tag_sender(
    recipient_spk_pub: &XPubKeyBytes,
    bundle_id: &[u8; 32],
) -> (XPubKeyBytes, Tag) {
    let (eph_pub, tag, _shared) = recognition_sender_material(recipient_spk_pub, bundle_id);
    (eph_pub, tag)
}

/// As [`recognition_tag_sender`], but also returns the `shared` DH secret.
///
/// The sender needs `shared` for anything else keyed on the recognition secret, currently the
/// hop-count blind ([`hop_blind_from_shared`]). It must NOT be derived from the tag instead: the tag
/// is cleartext on the wire, so an observer could recompute anything derived from it and undo the
/// blinding. `shared` is known only to the sender and the holder of the prekey secret.
pub fn recognition_sender_material(
    recipient_spk_pub: &XPubKeyBytes,
    bundle_id: &[u8; 32],
) -> (XPubKeyBytes, Tag, [u8; 32]) {
    let ephemeral = StaticSecret::random_from_rng(&mut dalek_rng());
    let eph_pub = XPublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&XPublicKey::from(*recipient_spk_pub));
    let shared = *shared.as_bytes();
    (
        eph_pub,
        recognition_tag_from_shared(&shared, bundle_id),
        shared,
    )
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

/// §39 **mailbox-tag**: a recipient's rotatable pull pseudonym: `H("v2" ‖ address ‖ epoch)`
/// (F-06). NOT the address itself (you cannot seal to it or message it, only bucket by it), and it
/// **rotates every epoch**, so a global observer can't correlate a recipient's mailbox across epochs.
/// A relay buckets a blind spool by it and a recipient names it in a want-beacon. Deriving it from
/// `(address, epoch)` rather than the prekey decouples mailbox rotation from the (deterministic) prekey,
/// and means a SENDER can compute the same tag from public info (it already holds the recipient's
/// address for a private send), which is what lets the header carry a routing hint at all.
///
/// A beacon's ownership is NOT verifiable, and no relay tries. That claim used to live here, on the
/// premise of an identity-signed `AdvertKind::RecvBeacon`; wire v13 replaced it with the unsigned,
/// link-local [`crate::wire_emit::Wire::RecvBeacon`], which carries only the routing prefix, so anyone
/// can claim any bucket. That is deliberate rather than a regression: under prefix routing a bucket is
/// a shared anonymity set BY DESIGN, so there is nothing coherent to own, and a false claimant just
/// drops sealed bundles it cannot recognize. What bounds bucket pollution is link authentication plus
/// the distance cap, split-horizon, and the per-peer bucket quota, all in `node.rs`. See
/// `Wire::RecvBeacon` for the full argument.
pub fn mailbox_tag(address: &PubKeyBytes, epoch: u64) -> Tag {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(address);
    material[32..].copy_from_slice(&epoch.to_le_bytes());
    tag16("hop mailbox tag v2", &material)
}

/// How many leading bytes of a mailbox-tag routing decisions key on (sec-priv-04).
///
/// The full 16-byte mailbox-tag is a *public deterministic* function of a broadly-known address, so
/// anyone who has ever learned a target's address can compute its full tag for every epoch and, if
/// routing keyed on the full tag, uniquely confirm "this exact recipient's private traffic is here".
/// Epoch rotation does nothing against such an address-knower (they just recompute the tag per epoch).
///
/// To break that unique linkage we route, spool, and match want-beacons on a short **prefix** of the
/// tag instead of the whole thing. An address-knower observing a routing/spool bucket then only learns
/// "some recipient whose tag shares this prefix is active", i.e. an **anonymity set** of every address
/// (known or unknown) that collides on the prefix, not a unique match. The full tag travels NOWHERE:
/// core-protocol-r2-02 took it out of the bundle header, and wire v13 took it out of the receiver-beacon
/// with the signed advert that used to carry it, so a bundle-capturing or beacon-observing
/// address-knower can no longer read the full deterministic tag off a copy and uniquely re-link the
/// recipient. It learns only the same anonymity-set membership the routing layer exposes, and no routing
/// *decision* is ever made on more than this prefix.
///
/// **The shipped numbers, in one place** (the guard `tools/mailbox-prefix-doc-guard.sh` derives this
/// exact sentence from the constant below and fails CI in every normative surface that disagrees with
/// it, because this prose went stale across three consecutive wire versions before anything mechanical
/// tied it to the value):
///
/// MAILBOX_ROUTE_PREFIX_BYTES = 1 => 256 buckets, anonymity set ~N/256, set of one below ~256 reachable addresses
///
/// **security-privacy-r2-03 / r19-04, honest scope of that set.** It is a large-N argument, and this
/// width is a COMPILE-TIME constant, NOT adaptive to observed N. Below ~256 reachable addresses in the
/// observed region a target's bucket is often occupied by the target ALONE, so against an
/// address-knower who computes the target's route and watches that bucket the set collapses toward one:
/// seeing the bucket active is then, with near-certainty, a per-address reachability disclosure ("this
/// specific target is reachable here this epoch"). A 1000-device fleet sits at set size ~4, which is
/// small but is not one. Do NOT rely on this prefix for meaningful anonymity against an address-knower
/// below ~256 reachable addresses; at that scale its only role is to keep routing buckets from being
/// unique KEYS on the wire, so a *passive* indexer without the address still cannot derive one. Being
/// pull-reachable at all reveals reachability to a direct peer regardless, which is the intrinsic §39
/// cost. Widening `w` adaptively as N grows (so ~N/256^w stays >= a target set size) is the real fix
/// and is tracked as future work; it is wire-affecting (the header carries this prefix, so its width is
/// part of the format), which is why it is a deliberate deferral and not an oversight.
pub const MAILBOX_ROUTE_PREFIX_BYTES: usize = 1;

// WHY 1 BYTE, AND WHEN TO CHANGE IT (sec-priv-04 follow-up, wire v12).
//
// This is the single dial controlling the recipient anonymity set, and it was set to a value that
// could not deliver on its own promise. Buckets = 256^w, and the set a recipient hides in is
// population/buckets:
//
//     w=2 (65_536 buckets)   N=1k -> 0.02    N=100k -> 1.5     N=10M -> 153
//     w=1 (256 buckets)      N=1k -> 4       N=100k -> 390     N=10M -> 39_062
//
// At w=2 the "anonymity set" was a unique identifier for every realistic near-term population: an
// adversary holding a target's (public) address computes H(address || epoch)[..2] and watches that
// bucket, and no one else is in it. The guarantee was asymptotic while the claim was present tense.
//
// The cost of w=1 is spool volume: a node pulls 1/256 of private traffic rather than 1/65_536. In a
// small network that is a small absolute number, which is exactly the regime where the anonymity
// matters most; the two curves move in opposite directions with N, which is why this is a dial and
// not a constant of nature.
//
// WIDEN TO 2 when population makes 1/256 of private traffic the dominant cost for a node, i.e. when
// N/256 is comfortably above the set size you want to promise (order 10^6 users). Doing so is a wire
// change: it alters the emitted `PrivateHeader.mailbox` width, so it rides a BUNDLE_VERSION bump.

/// The routing/spool/want-beacon key for a mailbox-tag: its [`MAILBOX_ROUTE_PREFIX_BYTES`]-byte prefix
/// (sec-priv-04). All gradient, blind-spool, and want-beacon buckets key on this, never on the full
/// tag, so an address-knower gets an anonymity set rather than a unique per-recipient confirmation.
pub type MailboxRoute = [u8; MAILBOX_ROUTE_PREFIX_BYTES];

/// Project a mailbox-tag onto its routing prefix (sec-priv-04). See [`MAILBOX_ROUTE_PREFIX_BYTES`].
pub fn mailbox_route(tag: &Tag) -> MailboxRoute {
    let mut r = [0u8; MAILBOX_ROUTE_PREFIX_BYTES];
    r.copy_from_slice(&tag[..MAILBOX_ROUTE_PREFIX_BYTES]);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn montgomery_correspondence() {
        // The X25519 key derived from the Ed25519 secret (libsodium method) must
        // match the Montgomery form of the Ed25519 public key, proving an address
        // alone is enough to both verify signatures and seal to.
        use ed25519_dalek::SigningKey;
        use sha2::{Digest, Sha512};
        use x25519_dalek::{PublicKey as XP, StaticSecret};

        let sk = SigningKey::generate(&mut dalek_rng());
        let h = Sha512::digest(sk.to_bytes());
        let mut s = [0u8; 32];
        s.copy_from_slice(&h[..32]);
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;
        let from_secret = XP::from(&StaticSecret::from(s)).to_bytes();
        let from_edwards = sk.verifying_key().to_montgomery().to_bytes();
        assert_eq!(
            from_secret, from_edwards,
            "derived X25519 key must match address"
        );
    }

    #[test]
    fn prekey_epochs_are_deterministic_and_distinct() {
        // core-03: each epoch's prekey must be re-derivable (deterministic, so a restart resolves a
        // cached advert) yet independent across epochs (so a leaked secret is bounded to its window).
        let id = Identity::generate();
        assert_eq!(
            id.derive_prekey_epoch(5).public,
            id.derive_prekey_epoch(5).public,
            "same epoch re-derives the same prekey"
        );
        assert_ne!(
            id.derive_prekey_epoch(5).public,
            id.derive_prekey_epoch(6).public,
            "different epochs derive independent prekeys"
        );
        // Epoch 0 reproduces the original base prekey byte-for-byte (no regression for pre-rotation).
        assert_eq!(id.derive_prekey().public, id.derive_prekey_epoch(0).public);
        // Each epoch's SPK is self-verifying under the identity.
        let pk = id.derive_prekey_epoch(9);
        assert!(verify(&id.address(), &pk.public, &pk.sig));
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
        let (ek_pub, sk_a) = x3dh_initiate(&alice, &bundle, None).unwrap();
        // Bob later re-derives the same root from Alice's address + ephemeral.
        let sk_b = x3dh_respond(
            &bob,
            &bob_spk.secret_bytes(),
            None,
            &alice.address(),
            &ek_pub,
        )
        .unwrap();
        assert_eq!(sk_a, sk_b, "X3DH must yield a shared root secret");

        // A different identity (not the SPK owner) derives a different secret.
        let mallory = Identity::generate();
        let sk_m = x3dh_respond(
            &mallory,
            &bob_spk.secret_bytes(),
            None,
            &alice.address(),
            &ek_pub,
        )
        .unwrap();
        assert_ne!(sk_a, sk_m, "only the bundle's identity recovers the root");
    }

    // --- one-time prekeys (DESIGN.md §25) ---------------------------------------

    /// Build Bob's published bundle plus the owner-side batch, the way a node does.
    fn bob_with_opks() -> (Identity, SignedPreKey, OneTimePreKeyBatch, PreKeyBundle) {
        let bob = Identity::generate();
        let spk = bob.generate_prekey();
        let batch = OneTimePreKeyBatch::generate(&bob, &spk.public, 0, 8);
        let bundle = spk.bundle_with_opks(bob.address(), &batch);
        (bob, spk, batch, bundle)
    }

    #[test]
    fn x3dh_with_one_time_prekey_agrees() {
        let alice = Identity::generate();
        let (bob, spk, batch, bundle) = bob_with_opks();
        assert!(bundle.opks_verified(), "a freshly minted batch must verify");

        let opk = bundle.select_opk(&|_| false).expect("an unspent opk");
        let (ek_pub, root_a) = x3dh_initiate(&alice, &bundle, Some(&opk)).unwrap();

        let opk_secret = batch
            .secret_bytes()
            .into_iter()
            .find(|(id, _)| *id == opk.id)
            .map(|(_, sec)| sec)
            .expect("owner holds the secret");
        let root_b = x3dh_respond(
            &bob,
            &spk.secret_bytes(),
            Some(&opk_secret),
            &alice.address(),
            &ek_pub,
        )
        .unwrap();
        assert_eq!(root_a, root_b, "4-DH X3DH must yield a shared root");
    }

    #[test]
    fn opk_root_cannot_collide_with_spk_only_root() {
        // The responder cannot silently "fall back" to 3-DH when it has reaped the OPK:
        // the roots must differ, so a reaped OPK is a dead session (answered with a
        // SessionReset), never a session that appears to work with weaker material.
        let alice = Identity::generate();
        let (bob, spk, batch, bundle) = bob_with_opks();
        let opk = bundle.select_opk(&|_| false).unwrap();
        let (ek_pub, root_4dh) = x3dh_initiate(&alice, &bundle, Some(&opk)).unwrap();

        let root_3dh =
            x3dh_respond(&bob, &spk.secret_bytes(), None, &alice.address(), &ek_pub).unwrap();
        assert_ne!(
            root_4dh, root_3dh,
            "dropping DH4 must not land on the same root"
        );
        let _ = batch;
    }

    #[test]
    fn opk_batch_signature_binds_the_signed_prekey() {
        // A batch lifted onto a different SPK generation must not verify: otherwise a
        // rotated-away SPK could keep attracting DH4 against keys the owner retired.
        let (bob, _spk, batch, _bundle) = bob_with_opks();
        let other_spk = bob.generate_prekey();
        let mut lifted = other_spk.bundle(bob.address());
        lifted.opks = batch.publics.clone();
        lifted.opk_sig = batch.sig.to_vec();
        assert!(
            lifted.verify(),
            "the SPK itself is still legitimately signed"
        );
        assert!(
            !lifted.opks_verified(),
            "the batch must not verify against a different SPK"
        );
    }

    #[test]
    fn forged_batch_degrades_to_spk_only_instead_of_denying_service() {
        let (bob, _spk, _batch, mut bundle) = bob_with_opks();
        // Attacker swaps in their own prekeys, keeping the (now wrong) signature.
        let mallory = Identity::generate();
        let mallory_batch = OneTimePreKeyBatch::generate(&mallory, &bundle.spk_pub, 0, 4);
        bundle.opks = mallory_batch.publics.clone();

        assert!(!bundle.opks_verified());
        bundle.strip_unverified_opks();
        assert!(bundle.opks.is_empty(), "the bad batch is dropped");
        assert!(bundle.opk_sig.is_empty());
        assert!(
            bundle.verify(),
            "Bob stays reachable SPK-only after a forged batch"
        );
        assert!(
            bundle.select_opk(&|_| false).is_none(),
            "no opk is offered once stripped"
        );
        let _ = bob;
    }

    #[test]
    fn duplicate_opk_ids_are_rejected() {
        // A duplicate id makes "which secret answers this?" ambiguous at the owner, so
        // the batch is treated as malformed rather than resolved arbitrarily.
        let bob = Identity::generate();
        let spk = bob.generate_prekey();
        let dup = OneTimePreKey {
            id: 3,
            public: [9u8; 32],
        };
        let opks = vec![dup, dup];
        let sig = bob.sign(&opk_batch_message(&bob.address(), &spk.public, &opks));
        let bundle = PreKeyBundle {
            address: bob.address(),
            spk_pub: spk.public,
            spk_sig: spk.sig.to_vec(),
            opks,
            opk_sig: sig.to_vec(),
        };
        assert!(
            !bundle.opks_verified(),
            "duplicate ids must fail even with a valid signature"
        );
    }

    #[test]
    fn select_opk_skips_ids_already_spent_on_this_peer() {
        let (_bob, _spk, _batch, bundle) = bob_with_opks();
        let first = bundle.select_opk(&|_| false).unwrap();
        let second = bundle.select_opk(&|id| id == first.id).unwrap();
        assert_ne!(
            first.id, second.id,
            "a second session must not respend the same opk"
        );
        // Exhausting every id is a supported outcome, not an error: the caller runs 3-DH.
        assert!(bundle.select_opk(&|_| true).is_none());
    }

    #[test]
    fn select_opk_spreads_across_the_batch_for_uncoordinated_senders() {
        // Senders never coordinate, so "first unspent" would make every fresh sender
        // pick the same id and collapse a batch of N to the safety of one key. Selection
        // must therefore be random. Over 64 independent draws from a batch of 8, seeing
        // only one distinct id has probability 8^-63, so this is deterministic in practice.
        let (_bob, _spk, _batch, bundle) = bob_with_opks();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            seen.insert(bundle.select_opk(&|_| false).unwrap().id);
        }
        assert!(
            seen.len() > 1,
            "fresh senders must not all land on the same OPK, saw only {seen:?}"
        );
    }

    #[test]
    fn initiate_refuses_an_opk_the_bundle_did_not_authenticate() {
        // Folding an attacker-supplied public into DH4 would let whoever supplied it
        // grind the root, so an unverified batch must be refused, not silently used.
        let alice = Identity::generate();
        let (_bob, _spk, _batch, mut bundle) = bob_with_opks();
        let planted = OneTimePreKey {
            id: 99,
            public: [7u8; 32],
        };
        bundle.opks.push(planted);
        assert!(
            !bundle.opks_verified(),
            "the batch no longer matches its sig"
        );
        assert!(matches!(
            x3dh_initiate(&alice, &bundle, Some(&planted)),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn oversized_opk_batch_is_rejected() {
        let bob = Identity::generate();
        let spk = bob.generate_prekey();
        let opks: Vec<OneTimePreKey> = (0..(MAX_ONE_TIME_PREKEYS as u32 + 1))
            .map(|id| OneTimePreKey {
                id,
                public: [id as u8; 32],
            })
            .collect();
        let sig = bob.sign(&opk_batch_message(&bob.address(), &spk.public, &opks));
        let bundle = PreKeyBundle {
            address: bob.address(),
            spk_pub: spk.public,
            spk_sig: spk.sig.to_vec(),
            opks,
            opk_sig: sig.to_vec(),
        };
        assert!(
            !bundle.opks_verified(),
            "batch cap is enforced before verify"
        );
    }

    #[test]
    fn derived_prekey_is_stable_across_restart() {
        let id = Identity::generate();
        let restored = Identity::from_secret_bytes(&id.to_secret_bytes());
        let a = id.derive_prekey();
        let b = restored.derive_prekey();
        assert_eq!(
            a.public, b.public,
            "derived prekey must be identical after restart"
        );
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
        assert!(matches!(
            x3dh_initiate(&alice, &bundle, None),
            Err(Error::BadSignature)
        ));
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
        assert_eq!(
            tag, got,
            "recipient must recompute the sender's recognition tag"
        );
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
        assert_ne!(
            tag,
            recognition_tag_recipient(&spk_eve.secret_bytes(), &eph_pub, &bundle_id)
        );
        // Same recipient, different bundle id → different tag (no cross-bundle linkage).
        assert_ne!(
            tag,
            recognition_tag_recipient(&spk_bob.secret_bytes(), &eph_pub, &[8u8; 32])
        );
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
        assert_eq!(
            mailbox_tag(&bob.address(), 0),
            mailbox_tag(&bob.address(), 0)
        );
        // A different identity's prekey → a different mailbox (it's a pseudonym, not shared).
        let alice = Identity::generate();
        assert_ne!(
            mailbox_tag(&bob.address(), 0),
            mailbox_tag(&alice.address(), 0)
        );
    }

    #[test]
    fn hop_blind_is_secret_bounded_and_per_bundle() {
        // sec-priv-r4-01. Three properties, each one a way the blind could fail to protect anything.
        let bob = Identity::generate();
        let spk = bob.generate_prekey();
        let id_a = [7u8; 32];
        let id_b = [8u8; 32];
        let (_eph, _tag, shared) = recognition_sender_material(&spk.public, &id_a);

        // 1. BOUNDED, so `blind + travelled` cannot wrap a u8 and freeze the advisory count.
        for i in 0..64u8 {
            let mut sh = shared;
            sh[0] = i;
            assert!(hop_blind_from_shared(&sh, &id_a) <= MAX_HOP_BLIND);
        }

        // 2. AGREED, or the recipient could not subtract it back off.
        assert_eq!(
            hop_blind_from_shared(&shared, &id_a),
            hop_blind_from_shared(&shared, &id_a),
        );

        // 3. PER-BUNDLE, so two bundles from one sender do not share an offset an observer could
        //    difference away to recover true distances.
        let differs = (0..32u8).any(|i| {
            let mut sh = shared;
            sh[1] = i;
            hop_blind_from_shared(&sh, &id_a) != hop_blind_from_shared(&sh, &id_b)
        });
        assert!(differs, "the blind must vary with the bundle id");
    }

    #[test]
    fn mailbox_route_is_a_prefix_and_forms_an_anonymity_set() {
        // sec-priv-04: routing keys on a short PREFIX of the mailbox-tag so an address-knower gets an
        // anonymity set instead of a unique confirmation. Prove (1) the route is exactly the prefix,
        // and (2) many distinct addresses genuinely collide onto the same route, i.e. an observer who
        // computes a target's route and sees that bucket active cannot tell WHICH address it belongs to.
        let bob = Identity::generate();
        let tag = mailbox_tag(&bob.address(), 3);
        assert_eq!(
            mailbox_route(&tag),
            tag[..MAILBOX_ROUTE_PREFIX_BYTES],
            "the route is the tag's leading prefix, nothing more"
        );

        // The prefix leaves only 256 buckets, so distinct addresses genuinely collide onto one route,
        // the anonymity set. A BIRTHDAY search finds SOME colliding pair with overwhelming probability
        // in a couple of dozen keys (√256 = 16), which is deterministically reliable (unlike waiting
        // for a hit in one SPECIFIC pre-chosen bucket, ~1/256 per try, which is flakier). We use a
        // large bound purely as a can't-hang guard; a collision is found almost immediately.
        let _ = &bob;
        let mut seen: std::collections::HashMap<[u8; MAILBOX_ROUTE_PREFIX_BYTES], PubKeyBytes> =
            std::collections::HashMap::new();
        let mut found_collision = false;
        for _ in 0..200_000 {
            let other = Identity::generate();
            let addr = other.address();
            let route = mailbox_route(&mailbox_tag(&addr, 3));
            if let Some(prev) = seen.get(&route) {
                if *prev != addr {
                    found_collision = true;
                    break;
                }
            }
            seen.insert(route, addr);
        }
        assert!(
            found_collision,
            "two distinct addresses must share a route bucket (the anonymity set)"
        );
    }
}
