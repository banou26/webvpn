//! The relay's own addresses. A client that dials one of them means a socket another session bound on this relay,
//! so the connection is turned to that socket's loopback address, and an address a socket reports is spelled as the
//! public one its peer knows.

use std::net::{IpAddr, SocketAddr};

use crate::policy::{Proto, Refusal, Session};

/// The relay's own addresses and the ports sessions hold on them.
pub(crate) struct Hairpin {
    own: Vec<IpAddr>,
}

/// A port a session bound, on record until this is dropped.
pub(crate) struct BoundPort {}

/// The socket a route onto the relay's own address leads to. A route held across an await is checked with
/// [`Hairpin::is_live`] right before it is used, since that socket may have closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lease {}

/// Where the bytes for a destination go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Route {
    /// The destination itself, or the loopback address of a socket bound on this relay.
    pub dial: SocketAddr,
    /// Set when `dial` is a socket bound on this relay.
    pub lease: Option<Lease>,
}

impl Hairpin {
    pub fn new(own_addresses: Vec<IpAddr>) -> Self {
        Self { own: own_addresses }
    }

    /// `None` when `target` is not one of the relay's own addresses, which leaves it to the policy. Otherwise the
    /// route to the socket bound on that port, or a refusal when no session holds it.
    pub fn own_route(&self, proto: Proto, target: SocketAddr) -> Option<Result<Route, Refusal>> {
        let _ = (proto, target);
        todo!()
    }

    pub fn register(&self, proto: Proto, bound: SocketAddr) -> BoundPort {
        let _ = (proto, bound);
        todo!()
    }

    pub fn is_live(&self, lease: &Lease) -> bool {
        let _ = lease;
        todo!()
    }

    /// `address` as a peer outside the relay knows it: a loopback address of a relay socket becomes the relay's
    /// public address of that family.
    pub fn public_spelling(&self, address: SocketAddr) -> SocketAddr {
        let _ = address;
        todo!()
    }
}

/// Where `session` may send for `target`: the relay's own addresses are decided here, every other by the policy.
pub(crate) fn route<S: Session>(
    hairpin: &Hairpin,
    session: &S,
    proto: Proto,
    target: SocketAddr,
) -> Result<Route, Refusal> {
    match hairpin.own_route(proto, target) {
        Some(own) => own,
        None => session.check_egress(proto, target).map(|()| Route { dial: target, lease: None }),
    }
}
