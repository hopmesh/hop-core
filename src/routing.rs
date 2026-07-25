//! Routing policy. See DESIGN.md §6.
//!
//! Routing decides, per stored bundle and per candidate peer, whether to hand that
//! bundle over. v1 ships an epidemic policy whose copies are reclaimed by the §39
//! delivery vaccine rather than metered by an issuance budget.
//!
//! ## On "pluggable"
//!
//! [`Router`] is a one-method trait and [`EpidemicRouter`] is its only implementation.
//! `Node` holds that type CONCRETELY (not `Box<dyn Router>`), so swapping the policy
//! today means changing that field, not injecting one. The trait earns its keep by
//! letting `hop-sim` and the node consume the same decision function, which is what
//! stops the simulator from modelling a protocol production does not run (it did once,
//! see DESIGN.md §6). It is deliberately not advertised as an extension point, because
//! no caller can currently supply an alternative.
//!
//! `Router::on_peer` and `Router::on_beacon` used to live here alongside a
//! `GatewayBeacon` type and a gateway-distance table. Nothing ever called any of them:
//! `on_peer` returned an empty Vec with a "wired up in Phase 2" comment, and the
//! gateway gradient they served was retired when internet egress stopped being a
//! mesh-visible destination (DESIGN.md §9). Required trait methods nothing invokes are
//! a tax on every implementor, so they are gone.

use crate::bundle::{Bundle, BundleId, Destination};
use crate::crypto::PubKeyBytes;

/// Opaque peer identity at the routing layer (the peer's address).
pub type PeerId = PubKeyBytes;

/// Metadata routing needs without opening the sealed payload.
#[derive(Clone, Debug)]
pub struct BundleMeta {
    pub id: BundleId,
    pub dst: Destination,
    pub hop_limit: u8,
    /// Reserved copy budget carried in the envelope. Read by nothing: see DESIGN.md §6.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardDecision {
    Forward,
    Hold,
    Drop,
}

/// The forwarding decision function. See the module docs on what "pluggable" does and
/// does not mean here.
pub trait Router {
    /// Should this bundle go to this peer right now?
    fn should_forward(&self, b: &BundleMeta, to: &PeerId) -> ForwardDecision;
}

/// Epidemic flood, reclaimed by the §39 delivery vaccine. DESIGN.md §6.
///
/// Forward to every peer until `hop_limit` runs out; the receiver dedups by
/// [`BundleId`] and a delivery **vaccine** purges the copies once the message actually
/// lands. Copies are therefore bounded by delivery (after the fact) rather than by an
/// issuance budget (in advance).
///
/// **Was `SprayAndWait`.** The binary spray-and-wait budget it was named for is no
/// longer live: the vaccine reclaims copies more tightly than a budget can, and a
/// decrementing counter on the *unsigned* envelope is a §39 correlation handle and a
/// hop-distance oracle. `Envelope.copies` survives as reserved wire capacity that
/// nothing reads, pinned by `hop-sim`'s `the_copy_budget_is_inert`.
#[derive(Default)]
pub struct EpidemicRouter;

impl EpidemicRouter {
    pub fn new() -> Self {
        Self
    }
}

impl Router for EpidemicRouter {
    fn should_forward(&self, b: &BundleMeta, to: &PeerId) -> ForwardDecision {
        if b.hop_limit == 0 {
            return ForwardDecision::Drop;
        }
        // Forward to everyone, bounded only by the hop limit. The destination dedups
        // duplicate copies by `BundleId`, and a delivery ACK floods back as a vaccine
        // that purges copies from relays, so we do not meter copies with a spray
        // budget. Direct delivery to the destination happens via this same Forward
        // (handled by the custodian).
        let _ = to;
        let _ = b.copies; // reserved wire capacity; deliberately not a routing input
        ForwardDecision::Forward
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
        let r = EpidemicRouter::new();
        let d = r.should_forward(&meta(Destination::Broadcast, 0, 8), &[0u8; 32]);
        assert_eq!(d, ForwardDecision::Drop);
    }

    #[test]
    fn epidemic_forwards_to_everyone_until_hop_limit() {
        let r = EpidemicRouter::new();
        let dst = [9u8; 32];
        let other = [0u8; 32];

        // Forward to a relay and to the destination alike; the copy count is irrelevant
        // (the destination dedups, and a delivery ACK purges copies).
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
    fn the_copy_budget_is_not_a_routing_input() {
        // Pins the §6 contract at the decision function itself: a bundle down to its
        // last copy must forward exactly like one with a full budget. Under the old
        // spray policy `copies == 1` meant "wait phase, do not forward", which is the
        // behavior the simulator was still modelling long after the node stopped.
        let r = EpidemicRouter::new();
        let dst = [9u8; 32];
        for copies in [0u16, 1, 8, u16::MAX] {
            assert_eq!(
                r.should_forward(&meta(Destination::Device(dst), 5, copies), &[0u8; 32]),
                ForwardDecision::Forward,
                "copies={copies} must not change the decision"
            );
        }
    }
}
