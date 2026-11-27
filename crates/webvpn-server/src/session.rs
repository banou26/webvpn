//! One client's session: the hello exchange, the control stream, and the sockets the client holds.

use std::collections::HashMap;
use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::{self, AbortHandle, JoinError, JoinSet};
use tokio::time::Instant;
use tokio_util::task::AbortOnDropHandle;
use tracing::{debug, warn};
use webvpn_proto::{close, ClientPacket, DecodeError, ErrorCode, Hello, RelayPacket, UdpPacket};

use crate::dns::{self, MAX_LOOKUPS_PER_SESSION};
use crate::metrics::{Counter, Metrics};
use crate::policy::{Auth, Direction, Refusal, Session, SocketKind};
use crate::relay::{Shared, STOPPING};
use crate::transport::{SendHalf, Transport};

/// How a session's UDP sockets reach the client, which a carrier picks once for each session it hands to
/// [`Relay::serve`](crate::Relay::serve). It must match what the carrier's clients read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpCarrier {
    /// One stream both ways for each socket ([`Transport::open_udp_bi`]), as over WebTransport. A socket whose
    /// stream cannot be opened in time sends its packets as datagrams ([`Transport::send_datagram`]) instead, so
    /// only a carrier whose clients read datagrams from the relay may pick it.
    Bidi,
    /// One stream toward the client for each socket ([`Transport::open_uni`]), as over the WebSocket mux, whose
    /// clients send their packets as datagrams and read none. A socket whose stream cannot be opened in time is
    /// refused. Sessions on it count as [`Counter::WsSessions`].
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

/// The session never waits for room in these queues, it only `try_send`s, so one stuck socket cannot hold up the
/// routing of the whole session.
pub(crate) const PER_SOCKET_CHANNEL_BUFFER: usize = 100;

/// One queue for the packets of every upload stream of a session, as deep as the WebSocket mux's datagram queue.
const UPLOAD_CHANNEL_BUFFER: usize = 512;

/// Checked before a frame is allocated. `UdpPacket::decode` bounds the payload; this bounds the frame around it.
const MAX_UPLOAD_FRAME_BYTES: usize = 66_000;

/// The client UDP payload bytes one session holds queued, across the upload queue and every socket's queue, so that
/// the queues' item limits alone cannot hold gigabytes across sockets. A packet the budget cannot hold is dropped
/// alone; nothing waits or closes.
const UDP_UPLOAD_QUEUED_BYTES_BUDGET: usize = 32 * 1024 * 1024;

const NOT_TAKEN: &str = "the relay does not take this request";

/// How long the relay gives its `Bye` to reach the client before it closes the session anyway. It covers the wait for
/// room in the reply queue, the write and [`SendHalf::deliver`] together, so a client that reads nothing, or that
/// does not end the session once it read the `Bye`, holds a closing session no longer. A client that reads ends the
/// session within a round trip of the `Bye`, so a second covers round trips up to about 900 ms, and it stays under
/// the 2 seconds a stop waits for its sessions to end (`relay::CLOSE_WAIT`).
pub(crate) const BYE_WAIT: Duration = Duration::from_secs(1);

/// Runs one session until the client or the relay ends it, then says `Bye` and closes it.
///
/// `policy` is the session the relay's policy admitted. The relay's `stopping` sends the client `Draining` once and
/// changes nothing else; its `closing` ends the session with `RESTARTING`. Every end closes the session here, with
/// the matching `webvpn_proto::close` code, after a `Bye` with the same code whenever the control stream can carry
/// it. A session whose setup fails or that breaks the protocol ends in `Err`.
pub(crate) async fn run<T: Transport, S: Session>(
    transport: Arc<T>,
    policy: S,
    relay: Arc<Shared>,
    auth: Auth,
    udp_carrier: UdpCarrier,
    setup: Setup,
) -> Result<()> {
    let hello = Hello::new(relay.features(auth), relay.config.agent.clone());
    let mut control = None;
    let greeted = tokio::select! {
        greeted = tokio::time::timeout_at(setup.deadline, greet(&*transport, &mut control, hello)) => {
            greeted.unwrap_or(Err(Closing::SETUP_FAILED))
        }
        closing = cut(&relay) => Err(closing),
    };
    drop(setup.permit);
    let mut reader = match greeted {
        Ok(reader) => reader,
        Err(closing) => return closing.close(&*transport, control.as_mut()).await,
    };
    let send = control.expect("a greeting holds the control stream");
    relay.metrics.count(Counter::Sessions);
    if udp_carrier == UdpCarrier::UniStreamRequired {
        relay.metrics.count(Counter::WsSessions);
    }

    let (replies, mut reply_queue) = mpsc::channel(100);
    let mut writer = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut send = send;
        while let Some(packet) = reply_queue.recv().await {
            write(&mut send, &packet).await?;
            if matches!(packet, RelayPacket::Bye { .. }) {
                send.deliver().await;
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    }));

    let lookup_slots = relay.dns.as_ref().map(|dns| dns.visitor_slots(transport.remote_ip()));
    let (register, mut register_queue) = mpsc::channel(100);
    let mut state = State {
        sockets: Registry::new(relay.config.max_sockets_per_session, relay.metrics.clone()),
        handle: Arc::new(SessionHandle {
            transport,
            policy: Arc::new(policy),
            relay: relay.clone(),
            replies,
            udp_carrier,
            upload_budget: Arc::new(Semaphore::new(UDP_UPLOAD_QUEUED_BYTES_BUDGET)),
            lookup_slots,
        }),
        auth,
        authenticated: false,
        register,
        lookups: JoinSet::new(),
    };
    let (upload_sender, mut upload_queue) = mpsc::channel(UPLOAD_CHANNEL_BUFFER);
    let accepting = AbortOnDropHandle::new(tokio::spawn(accept_upload_streams(state.handle.clone(), upload_sender)));

    let mut writer_done = false;
    let serving = async {
        let mut drain_announced = false;
        loop {
            tokio::select! {
                // A failed write is a client that went away, which ends the session as any other end does.
                _ = &mut writer, if !writer_done => {
                    writer_done = true;
                    break Closing::ENDED;
                }
                _ = relay.stopping.cancelled(), if !drain_announced => {
                    drain_announced = true;
                    state.handle.reply(RelayPacket::Draining).await;
                }
                Some(registered) = register_queue.recv() => {
                    if let Err(refusal) = state.sockets.register(&*state.handle.policy, registered) {
                        debug!(code = refusal.code.0, "the session did not take in a listener's connection");
                    }
                }
                Some(_) = state.lookups.join_next(), if !state.lookups.is_empty() => {}
                Some(joined) = state.sockets.tasks.join_next_with_id(), if !state.sockets.tasks.is_empty() => {
                    state.sockets.reap(joined);
                }
                read = reader.next() => match read {
                    Ok(Some(packet)) => {
                        if let Err(closing) = state.dispatch(packet).await {
                            break closing;
                        }
                    }
                    Ok(None) => break Closing::ENDED,
                    Err(_) => break Closing::UNREADABLE,
                },
                Some(queued) = upload_queue.recv() => state.sockets.deliver(queued, &state.handle.relay.metrics),
                datagram = state.handle.transport.recv_datagram() => {
                    let Ok(datagram) = datagram else { break Closing::ENDED };
                    state.datagram(&datagram);
                }
            }
        }
    };
    // Raced rather than one more branch of the loop, which may be waiting on a client that reads nothing.
    let closing = tokio::select! {
        closing = serving => closing,
        closing = cut(&relay) => closing,
    };

    // The `Bye` goes behind the replies already queued, and the close goes out while the session's streams are still
    // open, so the client reads why before any of its sockets ends.
    if !writer_done {
        let said = async {
            state.handle.reply(closing.bye()).await;
            let _ = (&mut writer).await;
        };
        writer_done = tokio::time::timeout(BYE_WAIT, said).await.is_ok();
    }
    state.handle.transport.close(closing.0, closing.1).await;

    register_queue.close();
    while register_queue.try_recv().is_ok() {}
    state.sockets.tasks.abort_all();
    while let Some(joined) = state.sockets.tasks.join_next_with_id().await {
        state.sockets.reap(joined);
    }
    // A listener may have reserved a place in the queue before it closed, and can fill it until it is reaped, so
    // only now is no registration left to come.
    while register_queue.try_recv().is_ok() {}
    accepting.abort();
    let _ = accepting.await;
    state.lookups.shutdown().await;
    if !writer_done {
        writer.abort();
        let _ = writer.await;
    }
    closing.result()
}

/// Closes a session that never ran, before any hello: says `Bye` with `code` and `reason` on a control stream opened
/// for it alone, within [`BYE_WAIT`], then closes the carrier with the same code and reason.
pub(crate) async fn refuse(transport: &impl Transport, code: u32, reason: &str) {
    let said = async {
        let (mut send, _recv) = transport.control_stream().await?;
        say_bye(&mut send, code, reason).await?;
        anyhow::Ok(())
    };
    let _ = tokio::time::timeout(BYE_WAIT, said).await;
    transport.close(code, reason).await;
}

/// Writes `Bye` as the last frame of the control stream and waits for the carrier to deliver it. Unbounded: the
/// caller bounds it with [`BYE_WAIT`].
async fn say_bye(send: &mut impl SendHalf, code: u32, reason: &str) -> std::io::Result<()> {
    write(send, &RelayPacket::Bye { code, reason: reason.to_owned() }).await?;
    send.deliver().await;
    Ok(())
}

/// Resolves once the relay's stop gave up waiting for this session, which then closes with `RESTARTING`. Counted as
/// [`Counter::DrainCapCloses`].
async fn cut(relay: &Shared) -> Closing {
    relay.closing.cancelled().await;
    relay.metrics.count(Counter::DrainCapCloses);
    Closing::RESTARTING
}

/// A reason for the relay to close the session: the `close` code the client reads, and a reason for a person.
struct Closing(u32, &'static str);

impl Closing {
    const ENDED: Self = Self(close::NORMAL, "the session ended");
    const RESTARTING: Self = Self(close::RESTARTING, STOPPING);
    const SETUP_FAILED: Self = Self(close::PROTOCOL_ERROR, "the session setup failed");
    const UNREADABLE: Self = Self(close::PROTOCOL_ERROR, "a control frame could not be read");

    fn bye(&self) -> RelayPacket {
        RelayPacket::Bye { code: self.0, reason: self.1.to_owned() }
    }

    /// What `run` ends with: `Err` for a session that failed its setup or broke the protocol.
    fn result(&self) -> Result<()> {
        match self.0 {
            close::NORMAL | close::RESTARTING => Ok(()),
            _ => Err(anyhow!(self.1)),
        }
    }

    /// Says `Bye` on `send`, the control stream when the session has it, within [`BYE_WAIT`], then closes the session.
    async fn close<T: Transport>(self, transport: &T, send: Option<&mut T::Send>) -> Result<()> {
        if let Some(send) = send {
            let _ = tokio::time::timeout(BYE_WAIT, say_bye(send, self.0, self.1)).await;
        }
        transport.close(self.0, self.1).await;
        self.result()
    }
}

/// Opens the control stream into `control`, writes the relay's hello and reads the client's, which must be its first
/// frame.
async fn greet<T: Transport>(
    transport: &T,
    control: &mut Option<T::Send>,
    hello: Hello,
) -> Result<ControlReader<T::Recv>, Closing> {
    let (send, recv) = transport.control_stream().await.map_err(|_| Closing::SETUP_FAILED)?;
    let send = control.insert(send);
    write(send, &RelayPacket::Hello(hello)).await.map_err(|_| Closing::SETUP_FAILED)?;
    let mut reader = ControlReader { recv, buf: Vec::new() };
    match reader.next().await {
        Ok(Some(ClientPacket::Hello(hello))) if hello.compatible() => Ok(reader),
        Ok(Some(ClientPacket::Hello(_))) => {
            Err(Closing(close::VERSION_MISMATCH, "the client's version does not suit the relay"))
        }
        _ => Err(Closing::SETUP_FAILED),
    }
}

async fn write(send: &mut (impl AsyncWrite + Unpin), packet: &RelayPacket) -> std::io::Result<()> {
    let mut frame = Vec::new();
    packet.encode(&mut frame);
    send.write_all(&frame).await?;
    send.flush().await
}

/// Reads the client's frames off the control stream.
struct ControlReader<R> {
    recv: R,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> ControlReader<R> {
    /// The next packet, or `None` once the stream ended or failed.
    ///
    /// The control loop polls this in a `select!` and drops it whenever another branch is ready first, so it loses
    /// nothing when dropped: `read_buf` keeps what it read, and a frame leaves the buffer only when it is returned.
    async fn next(&mut self) -> Result<Option<ClientPacket>, DecodeError> {
        loop {
            if let Some((packet, taken)) = ClientPacket::decode(&self.buf)? {
                self.buf.drain(..taken);
                return Ok(Some(packet));
            }
            match self.recv.read_buf(&mut self.buf).await {
                Ok(0) | Err(_) => return Ok(None),
                Ok(_) => {}
            }
        }
    }
}

impl<T: Transport, S: Session> SessionHandle<T, S> {
    /// Queues a frame for the control stream. The writer task drains the queue, so this waits only on the client
    /// reading its control stream.
    pub(crate) async fn reply(&self, packet: RelayPacket) {
        let _ = self.replies.send(packet).await;
    }

    /// Answers the requests left in a socket's queue once its task reads it no more, as the session answers a request
    /// for a socket that is gone: `Ok` for one that ends a socket, `UNKNOWN_SOCKET` for any other. The queue is closed
    /// first, so the session answers every later request itself.
    pub(crate) async fn answer_left(&self, requests: &mut mpsc::Receiver<ClientPacket>) {
        requests.close();
        while let Ok(request) = requests.try_recv() {
            if let Some(answer) = answer_as_gone(request) {
                self.reply(answer).await;
            }
        }
    }
}

/// The answer to a request on an open socket, as for a socket that is gone: `Ok` for one that ends a socket,
/// `UNKNOWN_SOCKET` for any other. None for a request that is not on an open socket.
pub(crate) fn answer_as_gone(request: ClientPacket) -> Option<RelayPacket> {
    Some(match request {
        ClientPacket::TcpClose { id, .. }
        | ClientPacket::TcpReset { id, .. }
        | ClientPacket::TcpUnlisten { id, .. }
        | ClientPacket::UdpClose { id, .. } => RelayPacket::Ok { id },
        ClientPacket::TcpSetOption { id, .. }
        | ClientPacket::UdpSetOption { id, .. }
        | ClientPacket::UdpConnect { id, .. }
        | ClientPacket::UdpDisconnect { id, .. } => {
            error(id, Refusal::new(ErrorCode::UNKNOWN_SOCKET, "no open socket has this id"))
        }
        _ => return None,
    })
}

/// What the session's control loop holds between requests.
struct State<T: Transport, S: Session> {
    handle: Arc<SessionHandle<T, S>>,
    auth: Auth,
    authenticated: bool,
    sockets: Registry<S::Permit>,
    /// Given to each listener, for the connections it accepts.
    register: mpsc::Sender<RegisterSocket>,
    lookups: JoinSet<()>,
}

impl<T: Transport, S: Session> State<T, S> {
    /// Answers one request, or hands it to what answers it. `Err` closes the session.
    async fn dispatch(&mut self, packet: ClientPacket) -> Result<(), Closing> {
        let reply = match packet {
            ClientPacket::Hello(_) => return Err(Closing(close::PROTOCOL_ERROR, "the client sent a second hello")),
            ClientPacket::Auth { id, credential } => Some(self.authenticate(id, &credential)),
            ClientPacket::AuthClear { id } => {
                self.handle.policy.clear_auth();
                self.authenticated = false;
                self.handle.relay.metrics.count(Counter::AuthCleared);
                Some(RelayPacket::Ok { id })
            }
            ClientPacket::TcpConnect { id, .. } => self.open(id, SocketKind::Tcp, true, packet),
            ClientPacket::TcpConnectName { id, .. } => {
                self.open(id, SocketKind::Tcp, self.handle.relay.dns.is_some(), packet)
            }
            ClientPacket::TcpListen { id, .. } => {
                self.open(id, SocketKind::TcpListener, self.handle.relay.config.listen, packet)
            }
            ClientPacket::UdpBind { id, .. } => self.open(id, SocketKind::Udp, true, packet),
            ClientPacket::TcpClose { id, socket }
            | ClientPacket::TcpReset { id, socket }
            | ClientPacket::TcpUnlisten { id, socket }
            | ClientPacket::UdpClose { id, socket } => self.sockets.end(id, socket, packet),
            ClientPacket::TcpSetOption { id, socket, .. }
            | ClientPacket::UdpSetOption { id, socket, .. }
            | ClientPacket::UdpConnect { id, socket, .. }
            | ClientPacket::UdpDisconnect { id, socket } => {
                self.sockets.forward(id, socket, packet, &self.handle.relay.metrics)
            }
            ClientPacket::DnsQuery { id, query } => self.lookup(id, query),
            ClientPacket::Unknown { id: Some(id), .. } => {
                Some(error(id, Refusal::new(ErrorCode::UNSUPPORTED, NOT_TAKEN)))
            }
            ClientPacket::Unknown { id: None, .. } => None,
        };
        if let Some(reply) = reply {
            self.handle.reply(reply).await;
        }
        Ok(())
    }

    fn authenticate(&mut self, id: u32, credential: &[u8]) -> RelayPacket {
        if self.auth == Auth::None {
            return error(id, Refusal::new(ErrorCode::UNSUPPORTED, "the relay takes no credentials"));
        }
        let metrics = &self.handle.relay.metrics;
        match self.handle.policy.authenticate(credential) {
            Ok(()) => {
                self.authenticated = true;
                metrics.count(Counter::AuthAccepted);
                RelayPacket::Ok { id }
            }
            Err(refusal) => {
                metrics.count(Counter::AuthRefused);
                error(id, refusal)
            }
        }
    }

    /// Why the session may not open what a request asks for, given whether the relay offers it.
    fn refusal_to_open(&self, offered: bool) -> Option<Refusal> {
        if !offered {
            Some(Refusal::new(ErrorCode::UNSUPPORTED, NOT_TAKEN))
        } else if self.auth == Auth::Required && !self.authenticated {
            Some(Refusal::new(ErrorCode::AUTH_REQUIRED, "the relay takes this request only after a credential"))
        } else {
            None
        }
    }

    /// Takes in the socket `request` opens, with the request waiting in its queue for its task to answer. Gives the
    /// session's own answer when the socket is refused.
    fn open(&mut self, id: u32, kind: SocketKind, offered: bool, request: ClientPacket) -> Option<RelayPacket> {
        if let Some(refusal) = self.refusal_to_open(offered) {
            return Some(error(id, refusal));
        }
        let (requests, request_queue) = mpsc::channel(PER_SOCKET_CHANNEL_BUFFER);
        requests.try_send(request).expect("a new queue has room");
        let (datagrams, datagram_queue) = mpsc::channel(PER_SOCKET_CHANNEL_BUFFER);
        let handle = self.handle.clone();
        let run: Box<dyn FnOnce(u32) -> SocketFuture + Send> = match kind {
            SocketKind::Tcp => Box::new(move |socket| Box::pin(crate::tcp::connect(handle, socket, request_queue))),
            SocketKind::TcpListener => {
                let register = self.register.clone();
                Box::new(move |socket| Box::pin(crate::listener::listen(handle, socket, request_queue, register)))
            }
            SocketKind::Udp => {
                let queue = datagrams.clone();
                Box::new(move |socket| Box::pin(crate::udp::bind(handle, socket, request_queue, datagram_queue, queue)))
            }
        };
        // The session answers a refused request itself, under the request's id.
        let register = RegisterSocket { kind, requests, datagrams, run, refused: Box::new(|_| {}) };
        self.sockets.register(&*self.handle.policy, register).err().map(|refusal| error(id, refusal))
    }

    /// Starts a lookup, which answers itself. Gives the session's own answer when it may not start.
    fn lookup(&mut self, id: u32, query: Vec<u8>) -> Option<RelayPacket> {
        if let Some(refusal) = self.refusal_to_open(self.handle.relay.dns.is_some()) {
            return Some(error(id, refusal));
        }
        if let Err(refusal) = dns::check_query(&query, &self.handle.relay.metrics) {
            return Some(error(id, refusal));
        }
        if self.lookups.len() >= MAX_LOOKUPS_PER_SESSION {
            self.handle.relay.metrics.count(Counter::DnsRefused);
            return Some(error(id, Refusal::new(ErrorCode::CAPACITY, "the session has too many lookups waiting")));
        }
        let handle = self.handle.clone();
        self.lookups.spawn(async move {
            let (Some(dns), Some(slots)) = (&handle.relay.dns, &handle.lookup_slots) else { return };
            let reply = match dns.lookup(slots, query).await {
                Some(answer) => {
                    // An answer is up to 64 KiB the relay delivers, so it is metered as a socket's bytes are.
                    handle.policy.relayed(Direction::Down, answer.len()).await;
                    handle.relay.metrics.count(Counter::DnsAnswered);
                    RelayPacket::DnsAnswer { id, answer }
                }
                None => {
                    handle.relay.metrics.count(Counter::DnsFailed);
                    error(id, Refusal::new(ErrorCode::LOOKUP_FAILED, "the resolver did not answer"))
                }
            };
            handle.reply(reply).await;
        });
        None
    }

    /// Queues a UDP packet the client sent outside any stream for its socket.
    fn datagram(&self, datagram: &[u8]) {
        let metrics = &self.handle.relay.metrics;
        match UdpPacket::decode(datagram) {
            Ok(packet) => {
                if let Some(queued) = reserve(&packet, &self.handle.upload_budget, metrics) {
                    self.sockets.deliver(queued, metrics);
                }
            }
            Err(error) => debug!("a client UDP datagram could not be read: {error}"),
        }
    }
}

pub(crate) fn error(id: u32, refusal: Refusal) -> RelayPacket {
    RelayPacket::Error { id, code: refusal.code, message: refusal.message.into_owned() }
}

/// The sockets of one session.
///
/// Ids rise through the session and are never used twice: the client holds a stream whose socket it does not know
/// yet and routes UDP packets by id, so a reused id could join a stale stream or a late packet to the next socket
/// given that id.
struct Registry<P> {
    sockets: HashMap<u32, Entry<P>>,
    tasks: JoinSet<Result<()>>,
    task_sockets: HashMap<task::Id, u32>,
    next_id: u32,
    max: usize,
    metrics: Arc<Metrics>,
}

struct Entry<P> {
    kind: SocketKind,
    requests: mpsc::Sender<ClientPacket>,
    datagrams: mpsc::Sender<QueuedDatagram>,
    /// Stops the task only. Reaping it then removes the entry and gives the permit back.
    abort: AbortHandle,
    _permit: P,
}

impl<P> Registry<P> {
    fn new(max: usize, metrics: Arc<Metrics>) -> Self {
        Self { sockets: HashMap::new(), tasks: JoinSet::new(), task_sockets: HashMap::new(), next_id: 0, max, metrics }
    }

    /// Takes a socket in under the next id, or refuses it when the session holds as many sockets as it allows, the
    /// policy refuses a permit, or the ids are spent. A refusal calls `refused` before what `run` holds is dropped,
    /// and leaves the session as it was.
    fn register<S: Session<Permit = P>>(&mut self, policy: &S, register: RegisterSocket) -> Result<u32, Refusal> {
        let RegisterSocket { kind, requests, datagrams, run, refused } = register;
        let admitted = if self.sockets.len() >= self.max {
            Err(Refusal::new(ErrorCode::CAPACITY, "the session holds as many sockets as it allows"))
        } else {
            policy.open_socket(kind).and_then(|permit| {
                let socket =
                    self.next_id().ok_or(Refusal::new(ErrorCode::CAPACITY, "the session has no socket id left"))?;
                Ok((socket, permit))
            })
        };
        let (socket, permit) = match admitted {
            Ok(admitted) => admitted,
            Err(refusal) => {
                refused(refusal.clone());
                return Err(refusal);
            }
        };
        let abort = self.tasks.spawn(run(socket));
        self.task_sockets.insert(abort.id(), socket);
        self.sockets.insert(socket, Entry { kind, requests, datagrams, abort, _permit: permit });
        self.metrics.count(Counter::SocketsOpened);
        Ok(socket)
    }

    fn next_id(&mut self) -> Option<u32> {
        let id = self.next_id;
        self.next_id = id.checked_add(1)?;
        Some(id)
    }

    /// Removes the socket whose task ended, which gives its permit back.
    fn reap(&mut self, joined: Result<(task::Id, Result<()>), JoinError>) {
        let task = match &joined {
            Ok((task, _)) => *task,
            Err(error) => error.id(),
        };
        let Some(socket) = self.task_sockets.remove(&task) else { return };
        self.sockets.remove(&socket);
        self.metrics.count(Counter::SocketsClosed);
        match joined {
            Ok((_, Err(error))) => debug!(socket, "a socket's task failed: {error:#}"),
            Err(error) if error.is_panic() => warn!(socket, "a socket's task panicked"),
            _ => {}
        }
    }

    /// The socket `request` names, when it is of the kind the request is for. A socket of another kind is not the
    /// one the client means, so its task is never handed the request.
    fn of_kind(&self, socket: u32, request: &ClientPacket) -> Option<&Entry<P>> {
        self.sockets.get(&socket).filter(|entry| Some(entry.kind) == kind_of(request))
    }

    /// Hands a request the client awaits to its socket's task, which answers it. When the task cannot take it, the
    /// session's own answer: `BUSY` when its queue is full, and `UNKNOWN_SOCKET` when the socket is gone or ending.
    fn forward(&self, id: u32, socket: u32, request: ClientPacket, metrics: &Metrics) -> Option<RelayPacket> {
        let refusal = match self.of_kind(socket, &request).map(|entry| entry.requests.try_send(request)) {
            Some(Ok(())) => return None,
            Some(Err(TrySendError::Full(_))) => {
                metrics.count(Counter::ControlDroppedFull);
                Refusal::new(ErrorCode::BUSY, "the socket has too many requests waiting")
            }
            None | Some(Err(TrySendError::Closed(_))) => {
                Refusal::new(ErrorCode::UNKNOWN_SOCKET, "no open socket has this id")
            }
        };
        Some(error(id, refusal))
    }

    /// Hands a request that ends a socket to its task, which answers it. When the task cannot take it, the session
    /// answers `Ok` itself: a full queue is a task stuck, which is aborted, and a socket gone or ending is answered
    /// so that a repeated or late close never waits.
    fn end(&self, id: u32, socket: u32, request: ClientPacket) -> Option<RelayPacket> {
        if self.sockets.get(&socket).is_some_and(|entry| Some(entry.kind) != kind_of(&request)) {
            return Some(error(id, Refusal::new(ErrorCode::UNKNOWN_SOCKET, "no open socket of this kind has this id")));
        }
        if let Some(entry) = self.sockets.get(&socket) {
            match entry.requests.try_send(request) {
                Ok(()) => return None,
                Err(TrySendError::Full(_)) => entry.abort.abort(),
                Err(TrySendError::Closed(_)) => {}
            }
        }
        Some(RelayPacket::Ok { id })
    }

    /// Hands a client UDP packet to its socket's queue. A packet for a socket that is gone arrived after it closed,
    /// and is dropped; one the queue has no room for is dropped and counted.
    fn deliver(&self, queued: QueuedDatagram, metrics: &Metrics) {
        if let Some(entry) = self.sockets.get(&queued.socket) {
            if entry.datagrams.try_send(queued).is_err() {
                metrics.count(Counter::UdpDroppedChannel);
            }
        }
    }
}

/// A session dropped before its teardown reaped its sockets still counts them as closed, which the open sockets gauge
/// reads.
impl<P> Drop for Registry<P> {
    fn drop(&mut self) {
        self.metrics.add(Counter::SocketsClosed, self.sockets.len() as u64);
    }
}

/// The kind of socket a request on an open socket is for.
fn kind_of(request: &ClientPacket) -> Option<SocketKind> {
    match request {
        ClientPacket::TcpClose { .. } | ClientPacket::TcpReset { .. } | ClientPacket::TcpSetOption { .. } => {
            Some(SocketKind::Tcp)
        }
        ClientPacket::TcpUnlisten { .. } => Some(SocketKind::TcpListener),
        ClientPacket::UdpClose { .. }
        | ClientPacket::UdpConnect { .. }
        | ClientPacket::UdpDisconnect { .. }
        | ClientPacket::UdpSetOption { .. } => Some(SocketKind::Udp),
        _ => None,
    }
}

/// `packet` as a socket's queue holds it, its payload's bytes taken from `budget`. `None`, counted, when the budget
/// is spent: that one packet is dropped, and nothing waits or closes.
fn reserve(packet: &UdpPacket, budget: &Arc<Semaphore>, metrics: &Metrics) -> Option<QueuedDatagram> {
    let bytes = u32::try_from(packet.data.len()).ok();
    let Some(reservation) = bytes.and_then(|bytes| budget.clone().try_acquire_many_owned(bytes).ok()) else {
        metrics.count(Counter::UdpUploadShed);
        return None;
    };
    Some(QueuedDatagram { socket: packet.socket, remote: packet.remote, data: packet.data.to_vec(), reservation })
}

/// Takes in the streams a client opens for UDP sockets whose own stream did not reach it, and reads each into
/// `queue`, until the session ends.
async fn accept_upload_streams<T: Transport, S: Session>(
    handle: Arc<SessionHandle<T, S>>,
    queue: mpsc::Sender<QueuedDatagram>,
) {
    // The readers belong to this set rather than running detached: each holds a QUIC receive stream, which keeps
    // the connection referenced, and QUIC sends its close promptly only once they are dropped.
    let mut readers = JoinSet::new();
    loop {
        tokio::select! {
            accepted = handle.transport.accept_uni() => {
                let Ok(mut stream) = accepted else { break };
                let (queue, budget) = (queue.clone(), handle.upload_budget.clone());
                let metrics = handle.relay.metrics.clone();
                readers.spawn(async move {
                    if let Err(error) = read_upload_stream(&mut stream, &queue, &budget, &metrics).await {
                        debug!("a UDP upload stream ended: {error:#}");
                    }
                });
            }
            Some(_) = readers.join_next(), if !readers.is_empty() => {}
        }
    }
}

/// Reads a stream a client opened for a UDP socket: the socket id once, which routing does not use since every
/// packet names its own socket, then `[u32 length][UdpPacket]` until the client finishes it. A frame over the limit
/// ends this stream only; a packet that cannot be read, or that the budget cannot hold, is dropped alone.
pub(crate) async fn read_upload_stream(
    stream: &mut (impl AsyncRead + Unpin),
    queue: &mpsc::Sender<QueuedDatagram>,
    budget: &Arc<Semaphore>,
    metrics: &Metrics,
) -> Result<()> {
    stream.read_exact(&mut [0; 4]).await?;
    let mut frame = Vec::new();
    loop {
        let mut length = [0; 4];
        if let Err(error) = stream.read_exact(&mut length).await {
            return if error.kind() == ErrorKind::UnexpectedEof { Ok(()) } else { Err(error.into()) };
        }
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_UPLOAD_FRAME_BYTES {
            bail!("an upload frame is over the limit");
        }
        frame.resize(length, 0);
        stream.read_exact(&mut frame).await?;
        match UdpPacket::decode(&frame) {
            Ok(packet) => {
                // A full queue drops the packet rather than stall this reader, which would hold back the stream's
                // flow credit.
                if let Some(queued) = reserve(&packet, budget, metrics) {
                    if queue.try_send(queued).is_err() {
                        metrics.count(Counter::UdpDroppedChannel);
                    }
                }
            }
            Err(error) => debug!("a UDP upload frame could not be read: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use webvpn_proto::{features, TcpOption, UdpOption, MAX_CLIENT_FRAME_BYTES, VERSION};

    use super::*;
    use crate::policy::{Proto, Slot};
    use crate::relay::Config;
    use crate::testing::{self, Client, Control, WAIT};

    const SITE: &str = "192.0.2.7:443";
    const ANY: &str = "0.0.0.0:0";
    const ACCEPTED: &[u8] = b"accepted";
    const SETUP_TIME: Duration = Duration::from_secs(10);

    fn address(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn in_use() -> Refusal {
        Refusal::new(ErrorCode::CAPACITY, "the credential's sessions are all open")
    }

    /// A policy for these tests: it accepts one credential, refuses any other with a code of its own, and opens at
    /// most `max_sockets` sockets, none by default, so that no test reaches a socket's task.
    #[derive(Clone, Default)]
    struct Probe {
        max_sockets: usize,
        sockets: Arc<AtomicUsize>,
        cleared: Arc<AtomicUsize>,
        /// How many times a socket was asked for.
        asked: Arc<AtomicUsize>,
    }

    impl Probe {
        fn opening(max_sockets: usize) -> Self {
            Self { max_sockets, ..Self::default() }
        }

        fn held(&self) -> usize {
            self.sockets.load(Ordering::SeqCst)
        }
    }

    impl Session for Probe {
        type Permit = Slot;

        fn authenticate(&self, credential: &[u8]) -> Result<(), Refusal> {
            if credential == ACCEPTED {
                Ok(())
            } else {
                Err(in_use())
            }
        }

        fn clear_auth(&self) {
            self.cleared.fetch_add(1, Ordering::SeqCst);
        }

        fn open_socket(&self, _kind: SocketKind) -> Result<Slot, Refusal> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            Slot::take(&self.sockets, self.max_sockets)
                .ok_or(Refusal::new(ErrorCode::REFUSED, "the test opens no more sockets"))
        }

        fn check_egress(&self, _proto: Proto, _target: SocketAddr) -> Result<(), Refusal> {
            Err(Refusal::new(ErrorCode::REFUSED, "the test reaches nothing"))
        }

        fn check_bind(&self, _proto: Proto, _local: SocketAddr) -> Result<(), Refusal> {
            Ok(())
        }
    }

    /// One session under test, driven from the client's side.
    struct Harness {
        client: Client,
        control: Control,
        /// The relay's hello.
        hello: Hello,
        relay: Arc<Shared>,
        policy: Probe,
        setup_slots: Arc<Semaphore>,
        ended: JoinHandle<Result<()>>,
    }

    impl Harness {
        /// A session whose relay wrote its hello, which the client has not answered yet.
        async fn start(config: Config, auth: Auth, udp_carrier: UdpCarrier) -> Self {
            Self::start_with(Probe::default(), config, auth, udp_carrier).await
        }

        async fn start_with(policy: Probe, config: Config, auth: Auth, udp_carrier: UdpCarrier) -> Self {
            let (transport, mut client) = testing::session(IpAddr::from([192, 0, 2, 1]));
            let relay = Shared::new(config);
            let setup_slots = Arc::new(Semaphore::new(1));
            let setup = Setup {
                permit: setup_slots.clone().try_acquire_owned().unwrap(),
                deadline: Instant::now() + SETUP_TIME,
            };
            let ended = tokio::spawn(run(Arc::new(transport), policy.clone(), relay.clone(), auth, udp_carrier, setup));
            let mut control = client.control().await;
            let Some(RelayPacket::Hello(hello)) = control.next().await else { panic!("the relay's first frame") };
            Self { client, control, hello, relay, policy, setup_slots, ended }
        }

        /// A session past its hello exchange.
        async fn open(config: Config, auth: Auth) -> Self {
            let mut harness = Self::start(config, auth, UdpCarrier::Bidi).await;
            harness.control.send(client_hello()).await;
            harness
        }

        /// Sends a request and reads the frame that answers it.
        async fn ask(&mut self, request: ClientPacket) -> RelayPacket {
            self.control.send(request).await;
            self.control.next().await.expect("the relay answers")
        }

        /// Sends each request and reads the error that answers it, as its id and code.
        async fn codes(&mut self, requests: impl IntoIterator<Item = ClientPacket>) -> Vec<(u32, ErrorCode)> {
            let mut codes = Vec::new();
            for request in requests {
                codes.push(code(&self.ask(request).await));
            }
            codes
        }
    }

    /// What the session ended with, once it ended.
    async fn ended(session: JoinHandle<Result<()>>) -> Result<()> {
        timeout(WAIT, session).await.expect("the session ends in time").expect("the session does not panic")
    }

    /// The next socket task to end.
    async fn next_ended(registry: &mut Registry<Slot>) -> Result<(task::Id, Result<()>), JoinError> {
        timeout(WAIT, registry.tasks.join_next_with_id()).await.expect("a task ends in time").expect("a task")
    }

    fn client_hello() -> ClientPacket {
        ClientPacket::Hello(Hello::new(0, "client under test"))
    }

    /// The id and code of an `Error`.
    fn code(reply: &RelayPacket) -> (u32, ErrorCode) {
        match reply {
            RelayPacket::Error { id, code, .. } => (*id, *code),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    /// A request for each kind of socket, under ids from `first` up.
    fn openers(first: u32) -> [ClientPacket; 3] {
        [
            ClientPacket::TcpConnect { id: first, remote: address(SITE) },
            ClientPacket::TcpListen { id: first + 1, local: address(ANY) },
            ClientPacket::UdpBind { id: first + 2, local: address(ANY) },
        ]
    }

    #[tokio::test]
    async fn the_relay_s_hello_offers_what_its_config_and_auth_mode_allow() {
        let offers = [
            (true, Auth::None, features::LISTEN),
            (true, Auth::Optional, features::LISTEN | features::AUTH),
            (false, Auth::Required, features::AUTH | features::AUTH_REQUIRED),
        ];
        for (listen, auth, offered) in offers {
            let config = Config { agent: "relay under test".into(), listen, ..Config::default() };
            let harness = Harness::start(config, auth, UdpCarrier::Bidi).await;
            assert_eq!(harness.hello, Hello::new(offered, "relay under test"));
        }
    }

    #[tokio::test]
    async fn a_finished_setup_gives_its_slot_back_and_counts_the_session() {
        for (udp_carrier, ws_sessions) in [(UdpCarrier::Bidi, 0), (UdpCarrier::UniStreamRequired, 1)] {
            let mut harness = Harness::start(Config::default(), Auth::None, udp_carrier).await;
            assert_eq!(harness.setup_slots.available_permits(), 0);
            harness.control.send(client_hello()).await;
            assert_eq!(harness.ask(ClientPacket::AuthClear { id: 1 }).await, RelayPacket::Ok { id: 1 });
            assert_eq!(harness.setup_slots.available_permits(), 1);
            let metrics = &harness.relay.metrics;
            assert_eq!((metrics.get(Counter::Sessions), metrics.get(Counter::WsSessions)), (1, ws_sessions));
        }
    }

    #[tokio::test]
    async fn a_client_hello_of_another_minor_version_closes_with_version_mismatch() {
        let mut harness = Harness::start(Config::default(), Auth::None, UdpCarrier::Bidi).await;
        let hello = Hello { minor: VERSION.1 + 1, ..Hello::new(0, "client under test") };
        harness.control.send(ClientPacket::Hello(hello)).await;
        assert_eq!(testing::bye(&mut harness.control, &mut harness.client).await.0, close::VERSION_MISMATCH);
        assert!(ended(harness.ended).await.is_err());
        assert_eq!(harness.setup_slots.available_permits(), 1);
        assert_eq!(harness.relay.metrics.get(Counter::Sessions), 0);
    }

    #[tokio::test]
    async fn a_first_frame_that_is_not_a_hello_closes_with_protocol_error() {
        let mut harness = Harness::start(Config::default(), Auth::None, UdpCarrier::Bidi).await;
        harness.control.send(ClientPacket::AuthClear { id: 1 }).await;
        assert_eq!(testing::bye(&mut harness.control, &mut harness.client).await.0, close::PROTOCOL_ERROR);
        assert!(ended(harness.ended).await.is_err());
    }

    #[tokio::test]
    async fn a_second_hello_or_an_unreadable_frame_closes_with_protocol_error() {
        let mut second_hello = Vec::new();
        client_hello().encode(&mut second_hello);
        // A `TcpConnect` header announcing one byte more than a client frame may hold.
        let mut too_long = vec![0x10];
        too_long.extend_from_slice(&(MAX_CLIENT_FRAME_BYTES as u32 + 1).to_be_bytes());
        for frame in [second_hello, too_long] {
            let mut harness = Harness::open(Config::default(), Auth::None).await;
            harness.control.write(&frame).await;
            assert_eq!(testing::bye(&mut harness.control, &mut harness.client).await.0, close::PROTOCOL_ERROR);
            assert!(ended(harness.ended).await.is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_setup_past_its_deadline_closes_with_protocol_error() {
        let mut harness = Harness::start(Config::default(), Auth::None, UdpCarrier::Bidi).await;
        tokio::time::advance(SETUP_TIME + Duration::from_secs(1)).await;
        assert_eq!(testing::bye(&mut harness.control, &mut harness.client).await.0, close::PROTOCOL_ERROR);
        assert!(ended(harness.ended).await.is_err());
        assert_eq!(harness.setup_slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn a_credential_is_accepted_refused_with_the_policy_s_code_and_cleared() {
        let mut harness = Harness::open(Config::default(), Auth::Optional).await;
        let accepted = harness.ask(ClientPacket::Auth { id: 1, credential: ACCEPTED.to_vec() }).await;
        assert_eq!(accepted, RelayPacket::Ok { id: 1 });
        let refused = harness.ask(ClientPacket::Auth { id: 2, credential: b"another".to_vec() }).await;
        assert_eq!(refused, error(2, in_use()));
        assert_eq!(harness.ask(ClientPacket::AuthClear { id: 3 }).await, RelayPacket::Ok { id: 3 });

        let metrics = &harness.relay.metrics;
        let counted = [Counter::AuthAccepted, Counter::AuthRefused, Counter::AuthCleared].map(|of| metrics.get(of));
        assert_eq!(counted, [1, 1, 1]);
        assert_eq!(harness.policy.cleared.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_relay_that_requires_a_credential_opens_nothing_before_one_is_accepted() {
        let mut harness = Harness::open(Config::default(), Auth::Required).await;
        assert_eq!(harness.codes(openers(1)).await, [1, 2, 3].map(|id| (id, ErrorCode::AUTH_REQUIRED)));

        let accepted = harness.ask(ClientPacket::Auth { id: 10, credential: ACCEPTED.to_vec() }).await;
        assert_eq!(accepted, RelayPacket::Ok { id: 10 });
        // A refused credential leaves the session as it was, authenticated.
        let refused = harness.ask(ClientPacket::Auth { id: 11, credential: b"another".to_vec() }).await;
        assert_eq!(code(&refused), (11, ErrorCode::CAPACITY));
        // Past the requirement, the probe's own refusal answers, so no socket's task starts.
        assert_eq!(harness.codes(openers(20)).await, [20, 21, 22].map(|id| (id, ErrorCode::REFUSED)));

        assert_eq!(harness.ask(ClientPacket::AuthClear { id: 30 }).await, RelayPacket::Ok { id: 30 });
        assert_eq!(harness.codes(openers(40)).await, [40, 41, 42].map(|id| (id, ErrorCode::AUTH_REQUIRED)));
    }

    #[tokio::test]
    async fn a_relay_whose_policy_takes_no_credentials_answers_auth_unsupported() {
        let mut harness = Harness::open(Config::default(), Auth::None).await;
        let reply = harness.ask(ClientPacket::Auth { id: 1, credential: ACCEPTED.to_vec() }).await;
        assert_eq!(code(&reply), (1, ErrorCode::UNSUPPORTED));
        assert_eq!(harness.relay.metrics.get(Counter::AuthAccepted), 0);
        assert_eq!(harness.codes(openers(2)).await, [2, 3, 4].map(|id| (id, ErrorCode::REFUSED)));
    }

    #[tokio::test]
    async fn an_unknown_request_is_answered_unsupported_and_one_without_an_id_is_ignored() {
        let mut harness = Harness::open(Config::default(), Auth::None).await;
        harness.control.send(ClientPacket::Unknown { kind: 0x7f, id: None }).await;
        let reply = harness.ask(ClientPacket::Unknown { kind: 0x7f, id: Some(5) }).await;
        assert_eq!(code(&reply), (5, ErrorCode::UNSUPPORTED));
    }

    #[tokio::test]
    async fn a_request_the_client_awaits_on_no_socket_is_answered_unknown_socket() {
        let mut harness = Harness::open(Config::default(), Auth::None).await;
        let requests = [
            ClientPacket::TcpSetOption { id: 1, socket: 9, option: TcpOption::NoDelay(true) },
            ClientPacket::UdpSetOption { id: 2, socket: 9, option: UdpOption::Ttl(64) },
            ClientPacket::UdpConnect { id: 3, socket: 9, remote: address(SITE) },
            ClientPacket::UdpDisconnect { id: 4, socket: 9 },
        ];
        assert_eq!(harness.codes(requests).await, [1, 2, 3, 4].map(|id| (id, ErrorCode::UNKNOWN_SOCKET)));
    }

    #[tokio::test]
    async fn a_request_that_ends_a_socket_is_answered_ok_also_when_there_is_no_socket() {
        let mut harness = Harness::open(Config::default(), Auth::None).await;
        // Twice, since a repeated close is answered as the first was.
        for first in [1, 11] {
            let ends = [
                ClientPacket::TcpClose { id: first, socket: 9 },
                ClientPacket::TcpReset { id: first + 1, socket: 9 },
                ClientPacket::TcpUnlisten { id: first + 2, socket: 9 },
                ClientPacket::UdpClose { id: first + 3, socket: 9 },
            ];
            for (id, request) in (first..).zip(ends) {
                assert_eq!(harness.ask(request).await, RelayPacket::Ok { id });
            }
        }
    }

    #[tokio::test]
    async fn requests_for_what_the_relay_has_off_are_answered_unsupported_even_before_a_credential() {
        let mut harness = Harness::open(Config { listen: false, ..Config::default() }, Auth::Required).await;
        let query = vec![0; 12];
        let requests = [
            ClientPacket::DnsQuery { id: 1, query: query.clone() },
            ClientPacket::TcpConnectName { id: 2, port: 443, query },
            ClientPacket::TcpListen { id: 3, local: address(ANY) },
        ];
        assert_eq!(harness.codes(requests).await, [1, 2, 3].map(|id| (id, ErrorCode::UNSUPPORTED)));
    }

    #[tokio::test]
    async fn a_query_over_512_bytes_is_refused_and_one_of_512_goes_to_the_resolver() {
        let nobody = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let config = Config { dns_upstream: Some(format!("http://{nobody}/dns-query")), ..Config::default() };
        let mut harness = Harness::open(config, Auth::None).await;
        let lookups = [
            ClientPacket::DnsQuery { id: 1, query: vec![0; dns::MAX_QUERY_BYTES] },
            ClientPacket::DnsQuery { id: 2, query: vec![0; dns::MAX_QUERY_BYTES + 1] },
        ];
        assert_eq!(harness.codes(lookups).await, [(1, ErrorCode::LOOKUP_FAILED), (2, ErrorCode::REFUSED)]);
        let metrics = &harness.relay.metrics;
        assert_eq!((metrics.get(Counter::DnsFailed), metrics.get(Counter::DnsRefused)), (1, 1));
    }

    #[tokio::test]
    async fn the_relay_s_stop_sends_draining_once_and_the_session_carries_on() {
        let mut harness = Harness::open(Config::default(), Auth::None).await;
        harness.relay.stopping.cancel();
        assert_eq!(harness.control.next().await, Some(RelayPacket::Draining));
        for id in [7, 8] {
            assert_eq!(harness.ask(ClientPacket::AuthClear { id }).await, RelayPacket::Ok { id });
        }
        assert!(!harness.ended.is_finished());
    }

    #[tokio::test]
    async fn a_request_queued_behind_the_end_of_its_socket_is_answered_as_for_a_socket_that_is_gone() {
        let mut harness = Harness::start_with(Probe::opening(8), Config::default(), Auth::None, UdpCarrier::Bidi).await;
        harness.control.send(client_hello()).await;
        let local = address("127.0.0.1:0");
        let RelayPacket::Socket { socket: udp, .. } = harness.ask(ClientPacket::UdpBind { id: 1, local }).await else {
            panic!("the bind was not answered with its socket");
        };
        let RelayPacket::Socket { socket: listener, local: listening, .. } =
            harness.ask(ClientPacket::TcpListen { id: 2, local }).await
        else {
            panic!("the listen was not answered with its socket");
        };
        let _peer = tokio::net::TcpStream::connect(listening).await.unwrap();
        let Some(RelayPacket::Accepted { socket: tcp, .. }) = harness.control.next().await else {
            panic!("the connection was not announced");
        };

        // One write, so the session hands each socket both of its requests before the socket's task reads the first.
        let mut queued = Vec::new();
        for request in [
            ClientPacket::UdpClose { id: 10, socket: udp },
            ClientPacket::UdpSetOption { id: 11, socket: udp, option: UdpOption::Ttl(64) },
            ClientPacket::TcpUnlisten { id: 12, socket: listener },
            ClientPacket::TcpUnlisten { id: 13, socket: listener },
            ClientPacket::TcpClose { id: 14, socket: tcp },
            ClientPacket::TcpSetOption { id: 15, socket: tcp, option: TcpOption::NoDelay(true) },
        ] {
            request.encode(&mut queued);
        }
        harness.control.write(&queued).await;

        let mut answered = Vec::new();
        for _ in 0..6 {
            answered.push(match harness.control.next().await.expect("the relay answers") {
                RelayPacket::Ok { id } => (id, None),
                RelayPacket::Error { id, code, .. } => (id, Some(code.0)),
                other => panic!("expected an answer, got {other:?}"),
            });
        }
        answered.sort();
        let gone = Some(ErrorCode::UNKNOWN_SOCKET.0);
        assert_eq!(answered, [(10, None), (11, gone), (12, None), (13, None), (14, None), (15, gone)]);
    }

    #[tokio::test]
    async fn packets_for_no_socket_are_dropped_and_an_oversized_upload_frame_ends_only_its_stream() {
        let mut harness = Harness::open(Config::default(), Auth::None).await;
        let mut datagram = Vec::new();
        UdpPacket { socket: 9, remote: Some(address(SITE)), data: b"lost" }.encode(&mut datagram);
        harness.client.send_datagram(datagram);
        harness.client.send_datagram(vec![0xff; 3]);

        let mut upload = harness.client.open_uni();
        let mut head = 9u32.to_be_bytes().to_vec();
        head.extend_from_slice(&(MAX_UPLOAD_FRAME_BYTES as u32 + 1).to_be_bytes());
        upload.write_all(&head).await.unwrap();
        // The relay drops the stream on the length alone, so the client reads its end with no frame bytes sent.
        let read = timeout(WAIT, upload.read(&mut [0; 1])).await.expect("the relay drops the stream");
        assert_eq!(read.unwrap(), 0);

        assert_eq!(harness.ask(ClientPacket::AuthClear { id: 1 }).await, RelayPacket::Ok { id: 1 });
    }

    fn framed(socket: u32, data: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        UdpPacket { socket, remote: None, data }.encode_framed(&mut frame);
        frame
    }

    /// What `read_upload_stream` makes of `wire`, and the packets it queued.
    async fn read_upload(wire: &[u8], budget: &Arc<Semaphore>, metrics: &Metrics) -> (Result<()>, Vec<QueuedDatagram>) {
        let (queue, mut queued) = mpsc::channel(8);
        let read = read_upload_stream(&mut &wire[..], &queue, budget, metrics).await;
        (read, std::iter::from_fn(|| queued.try_recv().ok()).collect())
    }

    #[tokio::test]
    async fn an_upload_stream_queues_each_packet_under_its_own_socket_id() {
        let mut wire = 7u32.to_be_bytes().to_vec();
        wire.extend(framed(7, b"hello"));
        wire.extend(framed(8, b"world"));
        let (read, queued) = read_upload(&wire, &Arc::new(Semaphore::new(1024)), &Metrics::default()).await;
        assert!(read.is_ok());
        let queued: Vec<_> = queued.iter().map(|packet| (packet.socket, packet.data.as_slice())).collect();
        assert_eq!(queued, [(7, &b"hello"[..]), (8, &b"world"[..])]);
    }

    #[tokio::test]
    async fn an_unreadable_upload_frame_is_dropped_alone() {
        let mut wire = 3u32.to_be_bytes().to_vec();
        // A frame of three bytes, which hold no packet.
        wire.extend([0, 0, 0, 3, 0xff, 0xff, 0xff]);
        wire.extend(framed(3, b"ok"));
        let (read, queued) = read_upload(&wire, &Arc::new(Semaphore::new(1024)), &Metrics::default()).await;
        assert!(read.is_ok());
        assert_eq!(queued.iter().map(|packet| packet.data.as_slice()).collect::<Vec<_>>(), [b"ok"]);
    }

    #[tokio::test]
    async fn the_upload_budget_sheds_a_packet_it_cannot_hold_and_takes_bytes_back_once_used() {
        let budget = Arc::new(Semaphore::new(8));
        let metrics = Metrics::default();
        let mut wire = 5u32.to_be_bytes().to_vec();
        wire.extend(framed(5, b"aaaaaa"));
        wire.extend(framed(5, b"bbbbbb"));
        let (read, queued) = read_upload(&wire, &budget, &metrics).await;
        assert!(read.is_ok());
        assert_eq!(queued.iter().map(|packet| packet.data.as_slice()).collect::<Vec<_>>(), [b"aaaaaa"]);
        assert_eq!(metrics.get(Counter::UdpUploadShed), 1);
        assert_eq!(budget.available_permits(), 2);
        drop(queued);
        assert_eq!(budget.available_permits(), 8);
    }

    /// Sets its flag when dropped.
    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// A socket whose task runs until it is aborted.
    fn pending() -> RegisterSocket {
        RegisterSocket {
            kind: SocketKind::Udp,
            requests: mpsc::channel(1).0,
            datagrams: mpsc::channel(1).0,
            run: Box::new(|_| Box::pin(std::future::pending())),
            refused: Box::new(|_| {}),
        }
    }

    /// A `refused` that hands its refusal to the receiver.
    fn telling() -> (Box<dyn FnOnce(Refusal) + Send>, oneshot::Receiver<Refusal>) {
        let (tell, told) = oneshot::channel();
        (Box::new(move |refusal| drop(tell.send(refusal))), told)
    }

    async fn abort_and_reap(registry: &mut Registry<Slot>, socket: u32) {
        registry.sockets[&socket].abort.abort();
        let joined = next_ended(registry).await;
        registry.reap(joined);
    }

    #[tokio::test]
    async fn socket_ids_rise_and_are_never_used_twice() {
        let policy = Probe::opening(8);
        let mut registry = Registry::new(8, Arc::default());
        let first = registry.register(&policy, pending()).unwrap();
        let second = registry.register(&policy, pending()).unwrap();
        assert_eq!((first, second), (0, 1));
        abort_and_reap(&mut registry, first).await;
        assert_eq!(registry.register(&policy, pending()).unwrap(), 2);
    }

    #[tokio::test]
    async fn an_exhausted_id_space_refuses_only_the_new_socket() {
        let policy = Probe::opening(8);
        let mut registry = Registry::new(8, Arc::default());
        registry.next_id = u32::MAX - 1;
        assert_eq!(registry.register(&policy, pending()).unwrap(), u32::MAX - 1);
        // Twice, since the ids stay spent.
        for _ in 0..2 {
            let (refused, mut told) = telling();
            let refusal = registry.register(&policy, RegisterSocket { refused, ..pending() }).unwrap_err();
            assert_eq!(refusal.code, ErrorCode::CAPACITY);
            assert_eq!(told.try_recv().unwrap(), refusal);
        }
        assert_eq!((registry.sockets.len(), registry.tasks.len(), policy.held()), (1, 1, 1));
    }

    #[tokio::test]
    async fn the_session_s_ceiling_refuses_one_socket_more_without_asking_the_policy() {
        let policy = Probe::opening(8);
        let mut registry = Registry::new(2, Arc::default());
        for _ in 0..2 {
            registry.register(&policy, pending()).unwrap();
        }
        let (refused, mut told) = telling();
        let refusal = registry.register(&policy, RegisterSocket { refused, ..pending() }).unwrap_err();
        assert_eq!(refusal.code, ErrorCode::CAPACITY);
        assert_eq!(told.try_recv().unwrap(), refusal);
        assert_eq!(policy.held(), 2);
        assert_eq!(policy.asked.load(Ordering::SeqCst), 2);

        abort_and_reap(&mut registry, 0).await;
        assert_eq!(registry.register(&policy, pending()).unwrap(), 2);
    }

    #[tokio::test]
    async fn a_permit_the_policy_refuses_is_told_while_the_socket_is_still_whole() {
        let policy = Probe::opening(0);
        let mut registry = Registry::new(8, Arc::default());
        let dropped = Arc::new(AtomicBool::new(false));
        let (probe, seen) = (DropProbe(dropped.clone()), dropped.clone());
        let (tell, mut told) = oneshot::channel();
        let register = RegisterSocket {
            run: Box::new(move |_| {
                drop(probe);
                Box::pin(std::future::pending())
            }),
            refused: Box::new(move |refusal| drop(tell.send((refusal, seen.load(Ordering::SeqCst))))),
            ..pending()
        };
        let refusal = registry.register(&policy, register).unwrap_err();
        assert_eq!(refusal.code, ErrorCode::REFUSED);
        assert_eq!(told.try_recv().unwrap(), (refusal, false));
        assert!(dropped.load(Ordering::SeqCst));
        assert!(registry.tasks.is_empty() && registry.sockets.is_empty());
    }

    #[tokio::test]
    async fn aborting_a_socket_drops_its_future_and_its_permit_once_reaped() {
        let policy = Probe::opening(8);
        let mut registry = Registry::new(8, Arc::default());
        let dropped = Arc::new(AtomicBool::new(false));
        let probe = DropProbe(dropped.clone());
        let run: Box<dyn FnOnce(u32) -> SocketFuture + Send> = Box::new(move |_| {
            Box::pin(async move {
                let _probe = probe;
                std::future::pending::<Result<()>>().await
            })
        });
        let socket = registry.register(&policy, RegisterSocket { run, ..pending() }).unwrap();
        tokio::task::yield_now().await;
        assert!(!dropped.load(Ordering::SeqCst));

        registry.sockets[&socket].abort.abort();
        let joined = next_ended(&mut registry).await;
        assert!(joined.as_ref().is_err_and(JoinError::is_cancelled));
        assert!(dropped.load(Ordering::SeqCst));
        // The entry, and the permit in it, outlive the task until it is reaped.
        assert_eq!((registry.sockets.len(), policy.held()), (1, 1));
        registry.reap(joined);
        assert_eq!((registry.sockets.len(), policy.held()), (0, 0));
    }

    #[tokio::test]
    async fn a_full_request_queue_answers_busy_and_keeps_the_socket_or_aborts_it_for_a_close() {
        let policy = Probe::opening(8);
        let metrics = Metrics::default();
        let mut registry = Registry::new(8, Arc::default());
        let (requests, mut queue) = mpsc::channel(1);
        let socket = registry.register(&policy, RegisterSocket { requests, ..pending() }).unwrap();
        let disconnect = |id| ClientPacket::UdpDisconnect { id, socket };

        // With room, the request waits for the socket's task, which answers it.
        assert_eq!(registry.forward(1, socket, disconnect(1), &metrics), None);
        let busy = registry.forward(2, socket, disconnect(2), &metrics);
        assert_eq!(busy.as_ref().map(code), Some((2, ErrorCode::BUSY)));
        assert_eq!(metrics.get(Counter::ControlDroppedFull), 1);
        tokio::task::yield_now().await;
        assert!(!registry.sockets[&socket].abort.is_finished());
        assert_eq!(queue.try_recv().ok(), Some(disconnect(1)));
        assert!(queue.try_recv().is_err());

        // A full queue is a task that does not read it, which only an abort ends.
        assert_eq!(registry.forward(3, socket, disconnect(3), &metrics), None);
        let close = ClientPacket::UdpClose { id: 4, socket };
        assert_eq!(registry.end(4, socket, close), Some(RelayPacket::Ok { id: 4 }));
        let joined = next_ended(&mut registry).await;
        assert!(joined.as_ref().is_err_and(JoinError::is_cancelled));
        registry.reap(joined);
        assert!(registry.sockets.is_empty());
    }

    #[tokio::test]
    async fn a_packet_its_socket_has_no_room_for_is_dropped_and_counted() {
        let policy = Probe::opening(8);
        let metrics = Metrics::default();
        let budget = Arc::new(Semaphore::new(1024));
        let mut registry = Registry::new(8, Arc::default());
        let (datagrams, mut queue) = mpsc::channel(1);
        let socket = registry.register(&policy, RegisterSocket { datagrams, ..pending() }).unwrap();
        let packet = UdpPacket { socket, remote: None, data: b"data" };
        for _ in 0..3 {
            registry.deliver(reserve(&packet, &budget, &metrics).unwrap(), &metrics);
        }
        assert_eq!(metrics.get(Counter::UdpDroppedChannel), 2);
        // A dropped packet gives its bytes back at once.
        assert_eq!(budget.available_permits(), 1024 - 4);
        assert_eq!(queue.try_recv().unwrap().data, b"data");

        let stray = UdpPacket { socket: socket + 1, ..packet };
        registry.deliver(reserve(&stray, &budget, &metrics).unwrap(), &metrics);
        assert_eq!(metrics.get(Counter::UdpDroppedChannel), 2);
    }
}
