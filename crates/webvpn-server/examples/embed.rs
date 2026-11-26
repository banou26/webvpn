//! A relay inside a program of its own: the WebSocket carrier on plain `ws://`, under a policy that takes one shared
//! credential and counts the bytes it relays. The credential comes from `RELAY_CREDENTIAL`, the address to listen on
//! from the first argument (`127.0.0.1:8443` when there is none). Ctrl+C stops the relay and prints the counts.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::net::TcpListener;
use webvpn_proto::ErrorCode;
use webvpn_server::websocket::{self, Options};
use webvpn_server::{
    Auth, Basic, BasicSession, Config, Direction, Policy, Proto, Refusal, Relay, Session, Slot, SocketKind,
};

/// Bytes relayed since the start, each way.
#[derive(Default)]
struct Counts {
    up: AtomicU64,
    down: AtomicU64,
}

/// `Basic`'s ceilings and rules, one credential a client presents before it opens a socket, and a count of the bytes
/// every session relays.
struct SharedCredential {
    basic: Basic,
    credential: Arc<[u8]>,
    counts: Arc<Counts>,
}

impl Policy for SharedCredential {
    type Session = CountedSession;

    fn auth(&self) -> Auth {
        Auth::Required
    }

    fn admit(&self, peer: IpAddr) -> Result<CountedSession, Refusal> {
        Ok(CountedSession {
            basic: self.basic.admit(peer)?,
            credential: self.credential.clone(),
            counts: self.counts.clone(),
        })
    }
}

struct CountedSession {
    basic: BasicSession,
    credential: Arc<[u8]>,
    counts: Arc<Counts>,
}

impl Session for CountedSession {
    type Permit = Slot;

    fn authenticate(&self, credential: &[u8]) -> Result<(), Refusal> {
        // Every byte is compared, so the time taken does not show how much of a credential matched.
        let differs = credential.len() != self.credential.len()
            || credential.iter().zip(self.credential.iter()).fold(0, |differs, (a, b)| differs | (a ^ b)) != 0;
        if differs {
            return Err(Refusal::new(ErrorCode::AUTH_FAILED, "the credential was not accepted"));
        }
        Ok(())
    }

    fn open_socket(&self, kind: SocketKind) -> Result<Slot, Refusal> {
        self.basic.open_socket(kind)
    }

    fn check_egress(&self, proto: Proto, target: SocketAddr) -> Result<(), Refusal> {
        self.basic.check_egress(proto, target)
    }

    fn check_bind(&self, proto: Proto, local: SocketAddr) -> Result<(), Refusal> {
        self.basic.check_bind(proto, local)
    }

    async fn relayed(&self, direction: Direction, bytes: usize) {
        let count = match direction {
            Direction::Up => &self.counts.up,
            Direction::Down => &self.counts.down,
        };
        count.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let credential = std::env::var("RELAY_CREDENTIAL").unwrap_or_default();
    if credential.is_empty() {
        bail!("RELAY_CREDENTIAL must hold the credential clients present");
    }
    let address = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8443".to_owned());

    let policy = SharedCredential {
        basic: Basic::default(),
        credential: credential.into_bytes().into(),
        counts: Arc::default(),
    };
    let relay = Relay::new(policy, Config::default());
    let listener = TcpListener::bind(&address).await.with_context(|| format!("{address} could not be taken"))?;
    println!("listening on ws://{}", listener.local_addr()?);
    let serving = tokio::spawn(websocket::serve(relay.clone(), listener, Options::default()));

    tokio::signal::ctrl_c().await?;
    println!("stopping");
    relay.stop(Duration::from_secs(5)).await;
    serving.await?;
    let Counts { up, down } = &*relay.policy().counts;
    println!("relayed {} bytes up and {} bytes down", up.load(Ordering::Relaxed), down.load(Ordering::Relaxed));
    Ok(())
}
