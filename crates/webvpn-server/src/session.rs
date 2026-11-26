//! One client's session: the hello exchange, the control stream, and the sockets the client holds.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use webvpn_proto::{ClientPacket, RelayPacket};

use crate::policy::{Auth, Refusal, Session, SocketKind};
use crate::relay::Shared;
use crate::transport::Transport;

/// How a UDP socket's packets reach the client, chosen once per session by its carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpCarrier {
    /// WebTransport: one stream both ways for each socket. A socket whose stream cannot be opened falls back to
    /// datagrams, which a WebTransport client always reads.
    Bidi,
    /// The WebSocket mux: a stream toward the client. Its client reads no datagrams from the relay, so a socket
    /// whose stream cannot be opened is refused.
    UniStreamRequired,
}

/// One UDP packet from the client, waiting for its socket. Dropping it gives its bytes back to the session's budget
/// for such packets, so it is kept until its payload has been used.
pub(crate) struct QueuedDatagram {
    pub socket: u32,
    pub remote: Option<SocketAddr>,
    pub data: Vec<u8>,
    pub reservation: OwnedSemaphorePermit,
}

/// What a socket's task shares with its session.
pub(crate) struct SessionHandle<T: Transport, S: Session> {
    pub transport: Arc<T>,
    pub policy: Arc<S>,
    pub relay: Arc<Shared>,
    pub peer: IpAddr,
    /// Frames for the client's control stream, written in order by the session.
    pub replies: mpsc::Sender<RelayPacket>,
    pub udp_carrier: UdpCarrier,
    /// The bytes of client UDP packets the session may hold queued.
    pub upload_budget: Arc<Semaphore>,
    /// This visitor's share of the resolver, when the relay looks names up.
    pub lookup_slots: Option<Arc<Semaphore>>,
}

pub(crate) type SocketFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// A socket for the session to take in, from the session itself for a request or from a listener for a connection
/// it accepted.
pub(crate) struct RegisterSocket {
    pub kind: SocketKind,
    /// The socket's control requests, which its task reads. The opening request is already in it.
    pub requests: mpsc::Sender<ClientPacket>,
    pub datagrams: mpsc::Sender<QueuedDatagram>,
    /// The socket's task, given the id the session assigned.
    pub run: Box<dyn FnOnce(u32) -> SocketFuture + Send>,
    /// Runs when the session does not take the socket in, before `run` and what it holds are dropped.
    pub refused: Box<dyn FnOnce(Refusal) + Send>,
}

/// The part of a session's setup the carrier started: the place it holds among sessions still setting up, and when
/// setup must be over.
pub(crate) struct Setup {
    pub permit: OwnedSemaphorePermit,
    pub deadline: Instant,
}

/// Runs one session until the client or the relay ends it.
///
/// `policy` is the session the relay's policy admitted. `draining` is cancelled when the relay begins to stop, which
/// sends the client `Draining` once and changes nothing else.
pub(crate) async fn run<T: Transport, S: Session>(
    transport: Arc<T>,
    policy: S,
    relay: Arc<Shared>,
    auth: Auth,
    udp_carrier: UdpCarrier,
    setup: Setup,
    draining: CancellationToken,
) -> Result<()> {
    let _ = (transport, policy, relay, auth, udp_carrier, setup, draining);
    todo!()
}
