//! Link layer: mutually-authenticated, encrypted sessions between adjacent nodes
//! (Noise XX), fragmentation/reassembly over a bounded-MTU bearer, and the
//! [`Bearer`] abstraction the native BLE shims implement. See DESIGN.md §4, §5, §11.

use serde::{Deserialize, Serialize};

use crate::bundle::BundleId;
use crate::crypto::{Identity, XPubKeyBytes};
use crate::error::{Error, Result};

/// Noise handshake pattern for link sessions: mutual static-key authentication
/// (XX), X25519 DH, ChaCha20-Poly1305 AEAD, BLAKE2s hashing. Both peers learn and
/// authenticate each other's X25519 static key ([`Identity::x_public`]).
pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

fn noise_err(_e: snow::Error) -> Error {
    Error::Crypto("noise link error")
}

/// One side of an in-progress Noise XX handshake. Drive it by alternately calling
/// [`write`](LinkHandshake::write) / [`read`](LinkHandshake::read) with the peer
/// until [`is_finished`](LinkHandshake::is_finished), then [`into_session`].
///
/// XX is three messages: initiator `-> e`; responder `<- e, ee, s, es`; initiator
/// `-> s, se`. After it completes, each side has authenticated the other's static
/// key and holds a fresh symmetric session.
pub struct LinkHandshake {
    inner: snow::HandshakeState,
}

impl LinkHandshake {
    /// Begin a handshake as the initiator (the side that dials).
    pub fn initiator(identity: &Identity) -> Result<Self> {
        Self::build(identity, true)
    }

    /// Begin a handshake as the responder (the side that accepts).
    pub fn responder(identity: &Identity) -> Result<Self> {
        Self::build(identity, false)
    }

    fn build(identity: &Identity, initiator: bool) -> Result<Self> {
        let params: snow::params::NoiseParams = NOISE_PARAMS
            .parse()
            .map_err(|_| Error::Crypto("noise params"))?;
        let secret = identity.link_secret();
        let builder = snow::Builder::new(params)
            .local_private_key(&secret)
            .map_err(noise_err)?;
        let inner = if initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        }
        .map_err(noise_err)?;
        Ok(Self { inner })
    }

    /// Produce the next handshake message to send to the peer (optionally carrying
    /// an early-data `payload`).
    pub fn write(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; payload.len() + 128];
        let n = self
            .inner
            .write_message(payload, &mut buf)
            .map_err(noise_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Consume a handshake message received from the peer, returning any early-data
    /// payload it carried.
    pub fn read(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; message.len() + 64];
        let n = self
            .inner
            .read_message(message, &mut buf)
            .map_err(noise_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Has the handshake completed for this side?
    pub fn is_finished(&self) -> bool {
        self.inner.is_handshake_finished()
    }

    /// The peer's authenticated X25519 static key, once the handshake has revealed
    /// it. Map this to a node identity (see [`Identity::x_public`]).
    pub fn remote_static(&self) -> Option<XPubKeyBytes> {
        self.inner
            .get_remote_static()
            .and_then(|s| s.try_into().ok())
    }

    /// Promote a finished handshake into an encrypted transport [`LinkSession`].
    pub fn into_session(self) -> Result<LinkSession> {
        let transport = self.inner.into_transport_mode().map_err(noise_err)?;
        Ok(LinkSession { inner: transport })
    }
}

/// An established, encrypted link session. Frames sent over the bearer are
/// [`encrypt`](LinkSession::encrypt)ed here; received frames are
/// [`decrypt`](LinkSession::decrypt)ed. A passive BLE sniffer sees only ciphertext.
pub struct LinkSession {
    inner: snow::TransportState,
}

impl LinkSession {
    /// Encrypt a plaintext frame for transmission to the peer.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // + AEAD tag
        let n = self
            .inner
            .write_message(plaintext, &mut buf)
            .map_err(noise_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Decrypt a ciphertext frame received from the peer.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self
            .inner
            .read_message(ciphertext, &mut buf)
            .map_err(noise_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// The peer's authenticated X25519 static key.
    pub fn remote_static(&self) -> Option<XPubKeyBytes> {
        self.inner
            .get_remote_static()
            .and_then(|s| s.try_into().ok())
    }
}

/// One fragment of a bundle on the wire. The bearer ships these opaque frames.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub bundle_id: BundleId,
    pub frag_index: u16,
    pub frag_count: u16,
    pub bytes: Vec<u8>,
}

/// Split an encoded bundle into frames no larger than `mtu` payload bytes.
pub fn fragment(bundle_id: BundleId, encoded: &[u8], mtu: usize) -> Vec<Frame> {
    assert!(mtu > 0, "mtu must be positive");
    let chunks: Vec<&[u8]> = if encoded.is_empty() {
        vec![&[]]
    } else {
        encoded.chunks(mtu).collect()
    };
    let frag_count = chunks.len() as u16;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| Frame {
            bundle_id,
            frag_index: i as u16,
            frag_count,
            bytes: bytes.to_vec(),
        })
        .collect()
}

/// Reassembles frames for a single bundle id. Bounded; callers time it out.
#[derive(Debug)]
pub struct Reassembler {
    bundle_id: BundleId,
    frag_count: u16,
    parts: Vec<Option<Vec<u8>>>,
    received: u16,
}

impl Reassembler {
    pub fn new(bundle_id: BundleId, frag_count: u16) -> Self {
        Self {
            bundle_id,
            frag_count,
            parts: vec![None; frag_count as usize],
            received: 0,
        }
    }

    /// Accept a frame. Returns the reassembled bytes once complete.
    pub fn accept(&mut self, frame: Frame) -> Option<Vec<u8>> {
        if frame.bundle_id != self.bundle_id || frame.frag_count != self.frag_count {
            return None;
        }
        let idx = frame.frag_index as usize;
        if idx >= self.parts.len() {
            return None;
        }
        if self.parts[idx].is_none() {
            self.received += 1;
        }
        self.parts[idx] = Some(frame.bytes);

        if self.received == self.frag_count {
            Some(self.parts.iter().flatten().flatten().copied().collect())
        } else {
            None
        }
    }
}

/// A bearer-assigned handle for one transport connection. Distinct from a node's
/// hop address (which is only learned after the Noise handshake authenticates it).
pub type LinkId = u64;

/// Which side of a new connection we are. The dialer (BLE central) initiates the
/// Noise handshake; the accepter (BLE peripheral) responds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// Events a bearer surfaces to the node loop.
#[derive(Clone, Debug)]
pub enum BearerEvent {
    /// A connection came up; we play `Role` on it.
    Connected(LinkId, Role),
    Disconnected(LinkId),
    /// Opaque bytes arrived on a connection (one link packet).
    Data(LinkId, Vec<u8>),
}

/// The only platform-specific surface: ship and receive opaque bytes over BLE
/// (L2CAP CoC) or any future bearer. Native shims implement this and contain no
/// protocol logic. See DESIGN.md §11–§12.
pub trait Bearer {
    fn send(&mut self, link: LinkId, bytes: &[u8]);
    fn poll_event(&mut self) -> Option<BearerEvent>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_reassemble_roundtrip() {
        let id = [3u8; 32];
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let frames = fragment(id, &data, 185);
        assert!(frames.len() > 1);

        let mut r = Reassembler::new(id, frames[0].frag_count);
        let mut out = None;
        // Deliver out of order to exercise indexing.
        for f in frames.into_iter().rev() {
            if let Some(done) = r.accept(f) {
                out = Some(done);
            }
        }
        assert_eq!(out.unwrap(), data);
    }

    #[test]
    fn empty_payload_makes_one_frame() {
        let frames = fragment([0u8; 32], &[], 185);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frag_count, 1);
    }

    #[test]
    fn noise_xx_handshake_authenticates_and_encrypts() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let mut hi = LinkHandshake::initiator(&alice).unwrap();
        let mut hr = LinkHandshake::responder(&bob).unwrap();

        // XX message flow.
        let m1 = hi.write(&[]).unwrap(); // -> e
        hr.read(&m1).unwrap();
        let m2 = hr.write(&[]).unwrap(); // <- e, ee, s, es
        hi.read(&m2).unwrap();
        let m3 = hi.write(&[]).unwrap(); // -> s, se
        hr.read(&m3).unwrap();

        assert!(hi.is_finished() && hr.is_finished());

        // Each side authenticated the other's X25519 static key = its address-bound
        // sealing key.
        assert_eq!(
            hi.remote_static().unwrap(),
            crate::crypto::address_to_x(&bob.address()).unwrap()
        );
        assert_eq!(
            hr.remote_static().unwrap(),
            crate::crypto::address_to_x(&alice.address()).unwrap()
        );

        let mut si = hi.into_session().unwrap();
        let mut sr = hr.into_session().unwrap();

        let ct = si.encrypt(b"sealed link frame").unwrap();
        assert_ne!(ct, b"sealed link frame");
        assert_eq!(sr.decrypt(&ct).unwrap(), b"sealed link frame");

        // And the reverse direction.
        let ct2 = sr.encrypt(b"ack").unwrap();
        assert_eq!(si.decrypt(&ct2).unwrap(), b"ack");
    }

    #[test]
    fn tampered_link_ciphertext_is_rejected() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mut hi = LinkHandshake::initiator(&alice).unwrap();
        let mut hr = LinkHandshake::responder(&bob).unwrap();
        hr.read(&hi.write(&[]).unwrap()).unwrap();
        hi.read(&hr.write(&[]).unwrap()).unwrap();
        hr.read(&hi.write(&[]).unwrap()).unwrap();
        let mut si = hi.into_session().unwrap();
        let mut sr = hr.into_session().unwrap();

        let mut ct = si.encrypt(b"important").unwrap();
        ct[0] ^= 0xFF; // flip a bit
        assert!(sr.decrypt(&ct).is_err());
    }
}
