//! The WebVPN relay as a program: one relay with the default policy on WebTransport and WebSocket, set up by
//! environment variables. The binary reads the [`Settings`] and the stop signals, and a [`Daemon`] does the rest, so a
//! test runs a whole relay in its own process.

mod daemon;
mod policy;
mod settings;

pub use daemon::{Daemon, Ports};
pub use policy::{CredentialSession, Credentials};
#[cfg(target_os = "linux")]
pub use settings::IpTunnel;
pub use settings::{CertificateFiles, Settings};
