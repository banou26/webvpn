//! The WebVPN relay as a library. The server holds the sockets and moves the bytes; a [`Policy`] decides who may open
//! a session, what a credential means, which sockets and destinations are allowed, and how fast bytes move.
//!
//! So far this crate holds that policy interface, the default policy [`Basic`] and the address classification it
//! uses ([`egress`]).

pub mod egress;
mod policy;

pub use policy::{Auth, Basic, BasicSession, Direction, Policy, Proto, Refusal, Session, Slot, SocketKind};
