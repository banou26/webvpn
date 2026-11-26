//! The WebVPN relay as a library. The server holds the sockets and moves the bytes; a [`Policy`] decides who may open
//! a session, what a credential means, which sockets and destinations are allowed, and how fast bytes move.

mod dns;
pub mod egress;
mod hairpin;
mod listener;
mod metrics;
mod policy;
mod relay;
mod session;
mod tcp;
#[cfg(test)]
mod testing;
mod transport;
mod udp;
mod ws;

pub use metrics::{Counter, Metrics};
pub use policy::{Auth, Basic, BasicSession, Direction, Policy, Proto, Refusal, Session, Slot, SocketKind};
pub use relay::Config;
pub use transport::{SendHalf, Transport};
