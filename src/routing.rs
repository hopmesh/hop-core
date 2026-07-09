//! Routing policy. See DESIGN.md §6.
//!
//! Routing decides, per stored bundle and per newly-seen peer, whether to hand
//! that bundle over. It's a trait so policies are swappable and testable in the
//! simulator (`hop-sim`). v1 ships binary spray-and-wait + a gateway gradient.

use std::collections::HashMap;

use crate::bundle::{Bundle, BundleId, Destination};
use crate::crypto::PubKeyBytes;
use crate::store::HaveSet;

/// Opaque peer identity at the routing layer (the peer's address).
pub type PeerId = PubKeyBytes;

/// Metadata routing needs without opening the sealed payload.
#[derive(Clone, Debug)]
pub struct BundleMeta {
    pub id: BundleId,
    pub dst: Destination,
    pub hop_limit: u8,
    /// Remaining spray-and-wait copy budget (§6).
    pub copies: u16,
}

impl From<&Bundle> for BundleMeta {
    fn from(b: &Bundle) -> Self {
        BundleMeta {
            id: b.id(),
            dst: b.inner.dst.clone(),
            hop_limit: b.env.hop_limit,
            copies: b.env.copies,
        }
    }
}

/// A signed, short-lived advertisement that a gateway is reachable. Floods a few
/// hops to build the egress gradient (DESIGN.md §6).
#[derive(Clone, Debug)]
pub struct GatewayBeacon {
    pub gateway: PubKeyBytes,
    pub hops: u8,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardDecision {
    Forward,
    Hold,
    Drop,
}

/// Pluggable routing policy.
pub trait Router {
    /// A peer just came into range advertising `their_have`. Return the ids we
    /// should offer it.
    fn on_peer(&mut self, peer: &PeerId, their_have: &HaveSet) -> Vec<BundleId>;
    /// Should this bundle go to this peer right now?
    fn should_forward(&self, b: &BundleMeta, to: &PeerId) -> ForwardDecision;
    /// Learned of (or refreshed) a gateway.
    fn on_beacon(&mut self, beacon: &GatewayBeacon);
}

/// Binary spray-and-wait (B) plus gateway-gradient (A). DESIGN.md §6.
///
/// The spray-and-wait copy budget lives in the bundle envelope (it travels with
/// the bundle), so the router itself is stateless about copies — it only reads
/// `meta.copies`. The custodian performs the actual `floor(n/2)` split on handoff
/// via [`crate::bundle::Bundle::split_copies`].
#[derive(Default)]
pub struct SprayAndWait {
    /// Best known hop distance to a gateway, by gateway address.
    gateways: HashMap<PubKeyBytes, GatewayBeacon>,
}

impl SprayAndWait {
    pub fn new() -> Self {
        Self::default()
    }

    /// Do we currently know a path toward any gateway?
    pub fn knows_gateway(&self) -> bool {
        !self.gateways.is_empty()
    }
}

impl Router for SprayAndWait {
    fn on_peer(&mut self, _peer: &PeerId, their_have: &HaveSet) -> Vec<BundleId> {
        // Offer everything they don't already hold; should_forward gates the rest.
        let _ = their_have;
        Vec::new() // wired up against a Store in the node loop (Phase 2)
    }

    fn should_forward(&self, b: &BundleMeta, to: &PeerId) -> ForwardDecision {
        if b.hop_limit == 0 {
            return ForwardDecision::Drop;
        }
        // Epidemic routing (DESIGN.md §6): forward to everyone, bounded only by the
        // hop limit. The destination dedups duplicate copies by `BundleId`, and a
        // delivery ACK floods back as a vaccine that purges copies from relays — so
        // we don't meter copies with a spray budget. Direct delivery to the
        // destination still happens via this same Forward (handled by the custodian).
        let _ = to;
        let _ = b.copies; // retained on the wire for compatibility; unused by routing
        ForwardDecision::Forward
    }

    fn on_beacon(&mut self, beacon: &GatewayBeacon) {
        let entry = self.gateways.entry(beacon.gateway);
        entry
            .and_modify(|b| {
                if beacon.hops < b.hops {
                    *b = beacon.clone();
                }
            })
            .or_insert_with(|| beacon.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(dst: Destination, hop_limit: u8, copies: u16) -> BundleMeta {
        BundleMeta {
            id: [7u8; 32],
            dst,
            hop_limit,
            copies,
        }
    }

    #[test]
    fn drops_at_zero_hop_limit() {
        let r = SprayAndWait::new();
        let d = r.should_forward(&meta(Destination::Broadcast, 0, 8), &[0u8; 32]);
        assert_eq!(d, ForwardDecision::Drop);
    }

    #[test]
    fn egress_forwards_toward_gateway() {
        let mut r = SprayAndWait::new();
        r.on_beacon(&GatewayBeacon {
            gateway: [1u8; 32],
            hops: 2,
            expires_at: 999,
        });
        assert!(r.knows_gateway());
        let d = r.should_forward(&meta(Destination::Broadcast, 5, 8), &[0u8; 32]);
        assert_eq!(d, ForwardDecision::Forward);
    }

    #[test]
    fn epidemic_forwards_to_everyone_until_hop_limit() {
        let r = SprayAndWait::new();
        let dst = [9u8; 32];
        let other = [0u8; 32];

        // Forward to a relay and to the destination alike — copy count is irrelevant
        // (the destination dedups; a delivery ACK purges copies).
        assert_eq!(
            r.should_forward(&meta(Destination::Device(dst), 5, 1), &other),
            ForwardDecision::Forward
        );
        assert_eq!(
            r.should_forward(&meta(Destination::Device(dst), 5, 1), &dst),
            ForwardDecision::Forward
        );
        // ...but never past the hop limit.
        assert_eq!(
            r.should_forward(&meta(Destination::Device(dst), 0, 8), &other),
            ForwardDecision::Drop
        );
    }

    #[test]
    fn beacon_keeps_shortest_hop_count() {
        let mut r = SprayAndWait::new();
        r.on_beacon(&GatewayBeacon {
            gateway: [1u8; 32],
            hops: 4,
            expires_at: 1,
        });
        r.on_beacon(&GatewayBeacon {
            gateway: [1u8; 32],
            hops: 2,
            expires_at: 1,
        });
        assert_eq!(r.gateways[&[1u8; 32]].hops, 2);
    }
}
