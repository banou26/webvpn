//! The WebVPN relay as a library. The server holds the sockets and moves the bytes; a [`Policy`] decides who may open
//! a session, what a credential means, which sockets and destinations are allowed, and how fast bytes move. A
//! [`Relay`] runs sessions under a policy: a carrier hands it each client's session. A relay given a [`Forwarder`]
//! also carries IP tunnels.

mod dns;
#[cfg(test)]
mod e2e;
pub mod egress;
mod flow;
mod hairpin;
mod listener;
mod metrics;
mod packet;
mod policy;
mod relay;
mod session;
mod tcp;
#[cfg(test)]
mod testing;
mod transport;
mod tunnel;
mod udp;
#[cfg(feature = "websocket")]
pub mod websocket;
#[cfg(feature = "webtransport")]
pub mod webtransport;
#[cfg(feature = "websocket")]
mod ws;

pub use metrics::{Counter, Metrics};
pub use policy::{
    same_credential, Auth, Basic, BasicHeld, BasicSession, Direction, Policy, Proto, Refusal, Session, Slot,
    SocketKind,
};
pub use relay::{Config, Relay};
pub use session::UdpCarrier;
pub use transport::{SendHalf, Transport};
pub use tunnel::{Forwarder, TunnelEnd};
