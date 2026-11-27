//! A TCP socket: the connection the relay holds for a client, and the two pumps between it and the socket's stream.

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use socket2::{SockRef, Socket, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, timeout, timeout_at, Instant};
use tracing::debug;
use webvpn_proto::{ClientPacket, ErrorCode, RelayPacket, TcpOption};

use crate::dns::{check_query, first_a_record};
use crate::hairpin;
use crate::metrics::Counter;
use crate::policy::{Direction, Proto, Refusal, Session};
use crate::session::{error, SessionHandle};
use crate::transport::{open_bi_with_prefix, SendHalf, Transport};

/// The largest send or receive buffer a client may set on one socket, so that the relay's ceiling on sockets also
/// bounds the kernel memory they hold.
pub(crate) const MAX_CLIENT_SOCKET_BUFFER_BYTES: usize = 256 * 1024;

const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

// Bounds a connect from its request to its reply, which a lookup, the connect and the stream's setup (5 + 8 + 5
// seconds) would otherwise exceed: the protocol's limit on the relay's answer to a connect (spec/protocol.md, Limits),
// under the 12 seconds a client's library waits for it.
const TCP_SETUP_TIMEOUT: Duration = Duration::from_secs(10);

// After a close (not a reset) the relay keeps writing to the peer what the client sent before it, as Node's destroy()
// leaves the kernel to send what was written, and then closes. Past this limit it resets the peer, so a cut upload
// never reads as whole.
const DRAIN_LIMIT: Duration = Duration::from_secs(5);

// A client library's plain destroy() never ends its stream, and a drain holds the stream's credit: draining until the
// end or the limit made 320 sockets destroyed in waves of 32 take 15 s instead of 0.3 s in Firefox 151 and Chromium,
// which allow 100 open streams (measured 2026-11-10). So a drain also ends when nothing arrives just after the close,
// or when it later goes quiet. The first wait adds two round trips: an app's end() then destroy() sends the close
// ahead of its data, which trailed it by up to 1.8 round trips (548 ms at a 300 ms round trip in Chromium; 100 ms
// alone delivered nothing on 4 of 8 sockets at a 100 ms round trip, measured 2026-11-11).
const DRAIN_FIRST_QUIET: Duration = Duration::from_millis(100);
const DRAIN_QUIET: Duration = Duration::from_secs(1);

// A socket whose peer reset waits this long for the client's close, which follows the reset of its stream, before it
// ends itself. Chrome 156 fails the upload with an error of its own once the STOP_SENDING of that end arrives, and
// that error reached the app ahead of the peer's reset in 5 to 17 sockets of 32 when the relay did not wait
// (measured 2026-11-11).
const PEER_RESET_CLOSE_LIMIT: Duration = Duration::from_secs(5);

// A socket's stream is reset this long plus two round trips after its peer's reset, since a reset drops what the
// client has not read yet and a peer's last bytes come just ahead of its reset. Over WebTransport, against a peer that
// answers and resets right behind its answer (Node reads all of it, measured 2026-11-11): resetting at once lost a
// 1 KiB answer in 62 of 64 sockets in Chromium 149 and Firefox 151; 100 ms lost part of a 64 KiB answer in 59 of 64
// sockets opened 32 at a time in Chromium; 250 ms lost none of 64 in either.
const PEER_RESET_GRACE: Duration = Duration::from_millis(250);

/// Runs a socket a client asked for. `requests` yields its `TcpConnect` or `TcpConnectName` first.
pub(crate) async fn connect<T: Transport, S: Session>(
    session: Arc<SessionHandle<T, S>>,
    socket: u32,
    mut requests: mpsc::Receiver<ClientPacket>,
) -> Result<()> {
    let setup_deadline = Instant::now() + TCP_SETUP_TIMEOUT;
    let (id, target) = match requests.recv().await {
        Some(ClientPacket::TcpConnect { id, remote }) => (id, Ok(remote)),
        Some(ClientPacket::TcpConnectName { id, port, query }) => (id, resolve(&session, port, query).await),
        _ => bail!("a TCP socket's first request is not a connect"),
    };
    let connected = async {
        let route = hairpin::route(&session.relay.hairpin, &*session.policy, Proto::Tcp, target?)?;
        let deadline = setup_deadline.min(Instant::now() + TCP_CONNECT_TIMEOUT);
        let connected = timeout_at(deadline, TcpStream::connect(route.dial)).await;
        connected.unwrap_or_else(|_| Err(ErrorKind::TimedOut.into())).map_err(|failure| Refusal::from_io(&failure))
    };
    let connection = match connected.await {
        Ok(connection) => connection,
        Err(refusal) => {
            let code = refusal.code.0;
            session.reply(error(id, refusal)).await;
            bail!("the socket did not connect: code {code}");
        }
    };
    let streams = match open_bi_with_prefix(&*session.transport, socket, Some(setup_deadline)).await {
        Ok(streams) => streams,
        Err(failure) => {
            let refusal = Refusal::new(ErrorCode::NO_STREAM, "the socket's stream could not be opened in time");
            session.reply(error(id, refusal)).await;
            return Err(failure);
        }
    };
    run(&session, socket, Origin::Connect(id), requests, connection, streams).await
}

/// Runs a socket one of the client's listeners accepted: announces it with `Accepted`, then moves its bytes. A
/// connection whose stream cannot be opened, or whose peer reset it before the announcement, is never announced.
pub(crate) async fn accepted<T: Transport, S: Session>(
    session: Arc<SessionHandle<T, S>>,
    socket: u32,
    listener: u32,
    connection: TcpStream,
    requests: mpsc::Receiver<ClientPacket>,
) -> Result<()> {
    let streams = open_bi_with_prefix(&*session.transport, socket, None).await?;
    run(&session, socket, Origin::Listener(listener), requests, connection, streams).await
}

/// The address the first A record of the answer to `query` names, at `port`. No refusal names the query.
async fn resolve<T: Transport, S: Session>(
    session: &SessionHandle<T, S>,
    port: u16,
    query: Vec<u8>,
) -> Result<SocketAddr, Refusal> {
    check_query(&query, &session.relay.metrics)?;
    let answer = match (&session.relay.dns, &session.lookup_slots) {
        (Some(dns), Some(slots)) => dns.lookup(slots, query).await,
        _ => None,
    };
    session.relay.metrics.count(if answer.is_some() { Counter::DnsAnswered } else { Counter::DnsFailed });
    let answer = answer.ok_or(Refusal::new(ErrorCode::LOOKUP_FAILED, "the resolver did not answer"))?;
    let address = first_a_record(&answer).ok_or(Refusal::new(ErrorCode::NAME_NOT_FOUND, "the name has no address"))?;
    Ok(SocketAddr::from((address, port)))
}

/// Whose socket is announced: the client's connect, by its request id, or one of its listeners', by its socket id.
#[derive(Debug, Clone, Copy)]
enum Origin {
    Connect(u32),
    Listener(u32),
}

/// Announces the socket, then moves its bytes both ways until both ended or the client closed it.
async fn run<T, S, W, R>(
    session: &SessionHandle<T, S>,
    socket: u32,
    origin: Origin,
    mut requests: mpsc::Receiver<ClientPacket>,
    connection: TcpStream,
    (mut download, mut upload): (W, R),
) -> Result<()>
where
    T: Transport,
    S: Session,
    W: SendHalf,
    R: AsyncRead + Unpin + Send + 'static,
{
    let metrics = &session.relay.metrics;
    // a peer reset after the connect fails getpeername (ENOTCONN), and a connect is still owed its reply
    let (local, peer) = match connection.local_addr().and_then(|local| Ok((local, connection.peer_addr()?))) {
        Ok((local, peer)) => {
            (session.relay.hairpin.public_spelling(local), session.relay.hairpin.public_spelling(peer))
        }
        Err(failure) => {
            if let Origin::Connect(id) = origin {
                session.reply(error(id, Refusal::from_io(&failure))).await;
            }
            bail!("the peer reset the connection before its announcement: {failure}");
        }
    };
    match origin {
        Origin::Connect(id) => session.reply(RelayPacket::Socket { id, socket, local, remote: Some(peer) }).await,
        Origin::Listener(listener) => {
            session.reply(RelayPacket::Accepted { listener, socket, local, remote: peer }).await;
            metrics.count(Counter::InboundAnnounced);
        }
    }

    // a second descriptor of the connection's kernel socket, taken before the split, so options set on it apply to
    // the connection
    let options = SockRef::from(&connection).try_clone().context("the socket's descriptor could not be duplicated")?;
    let (mut peer_read, mut peer_write) = connection.into_split();
    let inbound = matches!(origin, Origin::Listener(_));
    // Linux hands a reset's error to the first read or write that meets it, and later reads see an end, so a write
    // that met it first tells the read side that the end is a reset.
    let peer_failed = &AtomicBool::new(false);

    let to_client = &mut download;
    let mut down = Box::pin(async move {
        let mut buf = vec![0; 64 * 1024];
        let peer_reset = loop {
            match peer_read.read(&mut buf).await {
                Ok(0) => break peer_failed.load(Ordering::Relaxed),
                Ok(n) => {
                    metrics.add(Counter::BytesDown, n as u64);
                    if inbound {
                        metrics.add(Counter::InboundBytes, n as u64);
                    }
                    session.policy.relayed(Direction::Down, n).await;
                    if to_client.write_all(&buf[..n]).await.is_err() {
                        return false;
                    }
                }
                Err(_) => break true,
            }
        };
        if peer_reset {
            sleep((PEER_RESET_GRACE + 2 * session.transport.rtt()).min(DRAIN_QUIET)).await;
            to_client.fail();
        } else {
            let _ = to_client.shutdown().await;
        }
        peer_reset
    });

    let (start_drain, mut drain_started) = oneshot::channel::<Duration>();
    let to_peer = &mut peer_write;
    let mut up = Box::pin(async move {
        let mut buf = vec![0; 64 * 1024];
        // set once draining: how long a read may wait with nothing arriving before the drain ends
        let mut quiet: Option<Duration> = None;
        loop {
            // biased, so bytes already there always come ahead of the quiet limit
            let read = tokio::select! {
                biased;
                first_quiet = &mut drain_started, if quiet.is_none() => {
                    quiet = Some(first_quiet.unwrap_or(DRAIN_FIRST_QUIET));
                    continue;
                }
                read = upload.read(&mut buf) => read,
                _ = sleep(quiet.unwrap_or_default()), if quiet.is_some() => break,
            };
            let Ok(n @ 1..) = read else { break };
            if quiet.is_some() {
                quiet = Some(DRAIN_QUIET);
            }
            metrics.add(Counter::BytesUp, n as u64);
            session.policy.relayed(Direction::Up, n).await;
            if to_peer.write_all(&buf[..n]).await.is_err() {
                peer_failed.store(true, Ordering::Relaxed);
                return upload;
            }
        }
        let _ = to_peer.shutdown().await;
        upload
    });

    let (mut down_ended, mut up_ended, mut requests_closed) = (false, false, false);
    // An answer goes out through a place reserved in its own arm, so a client that stalls its own control stream
    // cannot hold this socket's pumps.
    let mut pending: Option<RelayPacket> = None;
    // the id of the client's TcpClose or TcpReset
    let mut close: Option<u32> = None;
    let (mut drain, mut abort, mut download_failed) = (false, false, false);
    // the client's stream, held until the download has ended, whose reset must reach the client ahead of the
    // STOP_SENDING that dropping this sends (see SendHalf::abandon)
    let mut finished_upload = None;
    while !(down_ended && up_ended) {
        tokio::select! {
            request = requests.recv(), if !requests_closed && pending.is_none() => match request {
                Some(ClientPacket::TcpClose { id, .. }) => {
                    close = Some(id);
                    drain = true;
                    break;
                }
                Some(ClientPacket::TcpReset { id, .. }) => {
                    close = Some(id);
                    abort = true;
                    metrics.count(Counter::TcpResets);
                    break;
                }
                Some(ClientPacket::TcpSetOption { id, option, .. }) => {
                    pending = Some(match apply(&options, option) {
                        Ok(()) => RelayPacket::Ok { id },
                        Err(refusal) => error(id, refusal),
                    });
                }
                // the session hands a socket only the requests of its kind
                Some(_) => {}
                None => requests_closed = true,
            },
            permit = session.replies.reserve(), if pending.is_some() => match permit {
                Ok(permit) => permit.send(pending.take().expect("an answer is pending")),
                Err(_) => {
                    pending = None;
                    requests_closed = true;
                }
            },
            failed = &mut down, if !down_ended => {
                down_ended = true;
                download_failed = failed;
            }
            stream = &mut up, if !up_ended => {
                up_ended = true;
                finished_upload = Some(stream);
            }
        }
    }

    drop(down);
    if let Some(answer) = pending {
        session.reply(answer).await;
    }
    if download_failed && close.is_none() && !requests_closed {
        let client_close = async {
            while let Some(request) = requests.recv().await {
                if let ClientPacket::TcpClose { id, .. } | ClientPacket::TcpReset { id, .. } = request {
                    return Some(id);
                }
            }
            None
        };
        close = timeout(PEER_RESET_CLOSE_LIMIT, client_close).await.unwrap_or(None);
    }
    // answered ahead of any drain, so the client's close does not wait on it
    if let Some(id) = close {
        session.reply(RelayPacket::Ok { id }).await;
    }
    session.answer_left(&mut requests).await;
    if drain && !up_ended {
        let first_quiet = (DRAIN_FIRST_QUIET + 2 * session.transport.rtt()).min(DRAIN_QUIET);
        let _ = start_drain.send(first_quiet);
        match timeout(DRAIN_LIMIT, &mut up).await {
            Ok(stream) => finished_upload = Some(stream),
            Err(_) => abort = true,
        }
    }
    // Set only when the client asked for this close. The reset comes after the drain, since Firefox 151 stopped sending
    // a stream's upload once its download was reset (an app's end() then destroy() delivered 64 KiB of 4 MiB, measured
    // 2026-11-10), and before the client's stream drops, whose STOP_SENDING must not come first (see
    // SendHalf::abandon).
    if close.is_some() {
        download.abandon();
    }
    drop(up);
    drop(finished_upload);
    if abort {
        // No shutdown of the write side first, which would put a FIN ahead of the RST and read as a clean end to the
        // peer. `options` stays the last descriptor of the kernel socket, so its close with SO_LINGER 0 sends the RST.
        if let Err(failure) = options.set_linger(Some(Duration::ZERO)) {
            debug!(socket, "a reset's linger was not applied: {failure}");
        }
        peer_write.forget();
    }
    Ok(())
}

/// Sets `option` on the connection. A buffer size is cut to [`MAX_CLIENT_SOCKET_BUFFER_BYTES`].
fn apply(socket: &Socket, option: TcpOption) -> Result<(), Refusal> {
    let applied = match option {
        TcpOption::NoDelay(on) => socket.set_nodelay(on),
        TcpOption::Ttl(ttl) => socket.set_ttl(ttl),
        TcpOption::KeepAlive { enabled: false, .. } => socket.set_keepalive(false),
        TcpOption::KeepAlive { enabled: true, initial_delay_seconds } => {
            let keepalive = TcpKeepalive::new();
            socket.set_tcp_keepalive(&match initial_delay_seconds {
                0 => keepalive,
                seconds => keepalive.with_time(Duration::from_secs(seconds.into())),
            })
        }
        TcpOption::SendBufferSize(bytes) => {
            socket.set_send_buffer_size((bytes as usize).min(MAX_CLIENT_SOCKET_BUFFER_BYTES))
        }
        TcpOption::RecvBufferSize(bytes) => {
            socket.set_recv_buffer_size((bytes as usize).min(MAX_CLIENT_SOCKET_BUFFER_BYTES))
        }
        TcpOption::Unknown(_) => {
            return Err(Refusal::new(ErrorCode::UNSUPPORTED, "the relay does not know this option"));
        }
    };
    applied.map_err(|failure| Refusal::from_io(&failure))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use tokio::io::{duplex, AsyncWrite, DuplexStream, ReadBuf};
    use tokio::net::{TcpListener, TcpSocket};
    use tokio::sync::{watch, Semaphore};
    use tokio::task::JoinHandle;

    use super::*;
    use crate::policy::{Basic, BasicSession, Policy, SocketKind};
    use crate::relay::{Config, Shared};
    use crate::session::UdpCarrier;
    use crate::testing::{self, Opened, WAIT};

    pub(crate) const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    /// The relay's own address, where a test sets one.
    pub(crate) const PUBLIC: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    const MIB: usize = 1 << 20;
    const NO_RTT: Duration = Duration::ZERO;

    pub(crate) async fn within<F: Future>(future: F) -> F::Output {
        timeout(WAIT, future).await.expect("in time")
    }

    /// A session's handle over `transport`, and the queue its replies go to.
    pub(crate) fn handle<T: Transport, S: Session>(
        transport: T,
        policy: S,
        config: Config,
    ) -> (Arc<SessionHandle<T, S>>, mpsc::Receiver<RelayPacket>) {
        let relay = Shared::new(config);
        let (replies, replied) = mpsc::channel(16);
        let lookup_slots = relay.dns.as_ref().map(|dns| dns.visitor_slots(CLIENT));
        let handle = SessionHandle {
            transport: Arc::new(transport),
            policy: Arc::new(policy),
            relay,
            replies,
            udp_carrier: UdpCarrier::Bidi,
            upload_budget: Arc::new(Semaphore::new(0)),
            lookup_slots,
        };
        (Arc::new(handle), replied)
    }

    /// The policy of a relay that reaches loopback addresses.
    pub(crate) fn local() -> BasicSession {
        Basic { allow_private_targets: true, ..Basic::default() }.admit(CLIENT).unwrap()
    }

    /// The id and code of an `Error`.
    pub(crate) fn code(reply: &RelayPacket) -> (u32, ErrorCode) {
        match reply {
            RelayPacket::Error { id, code, .. } => (*id, *code),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    /// A carrier with a fixed round trip, on which no stream opens.
    struct Distant(Duration);

    impl Transport for Distant {
        type Send = DuplexStream;
        type Recv = DuplexStream;

        fn remote_ip(&self) -> IpAddr {
            CLIENT
        }

        fn rtt(&self) -> Duration {
            self.0
        }

        async fn close(&self, _code: u32, _reason: &str) {}

        fn send_datagram(&self, _data: Vec<u8>) -> Result<()> {
            bail!("no datagrams")
        }

        async fn control_stream(&self) -> Result<(DuplexStream, DuplexStream)> {
            bail!("no room for a stream")
        }

        async fn open_bi(&self) -> Result<(DuplexStream, DuplexStream)> {
            bail!("no room for a stream")
        }

        async fn open_uni(&self) -> Result<DuplexStream> {
            bail!("no room for a stream")
        }

        async fn open_udp_bi(&self) -> Result<(DuplexStream, DuplexStream)> {
            bail!("no room for a stream")
        }

        async fn recv_datagram(&self) -> Result<Vec<u8>> {
            std::future::pending().await
        }

        async fn accept_uni(&self) -> Result<DuplexStream> {
            std::future::pending().await
        }
    }

    /// A policy that reaches every address and notes the bytes it is asked to relay each way. It lets them move once
    /// its gate is open, at `pace` bytes a second when set.
    #[derive(Clone)]
    struct Probe {
        asked: Arc<[AtomicUsize; 2]>,
        gate: watch::Receiver<bool>,
        pace: Option<f64>,
    }

    impl Probe {
        fn open() -> Self {
            Self::gated(true).0
        }

        fn gated(open: bool) -> (Self, watch::Sender<bool>) {
            let (gate, opened) = watch::channel(open);
            (Self { asked: Arc::default(), gate: opened, pace: None }, gate)
        }

        /// The bytes asked for, up then down.
        fn asked(&self) -> [usize; 2] {
            self.asked.each_ref().map(|asked| asked.load(Ordering::SeqCst))
        }
    }

    impl Session for Probe {
        type Permit = ();

        fn open_socket(&self, _kind: SocketKind) -> Result<(), Refusal> {
            Ok(())
        }

        fn check_egress(&self, _proto: Proto, _target: SocketAddr) -> Result<(), Refusal> {
            Ok(())
        }

        fn check_bind(&self, _proto: Proto, _local: SocketAddr) -> Result<(), Refusal> {
            Ok(())
        }

        fn relayed(&self, direction: Direction, bytes: usize) -> impl Future<Output = ()> + Send {
            self.asked[direction as usize].fetch_add(bytes, Ordering::SeqCst);
            let mut gate = self.gate.clone();
            let pace = self.pace.map_or(Duration::ZERO, |rate| Duration::from_secs_f64(bytes as f64 / rate));
            async move {
                let _ = gate.wait_for(|open| *open).await;
                sleep(pace).await;
            }
        }
    }

    type Events = Arc<Mutex<Vec<&'static str>>>;

    /// The relay's ends of a socket's stream, noting when the download finishes, fails or is reset and when the
    /// upload is let go.
    struct Download(DuplexStream, Events);
    struct Upload(DuplexStream, Events);

    impl AsyncWrite for Download {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let done = Pin::new(&mut self.0).poll_shutdown(cx);
            if done.is_ready() {
                self.1.lock().unwrap().push("download finished");
            }
            done
        }
    }

    impl SendHalf for Download {
        fn fail(&mut self) {
            self.1.lock().unwrap().push("download failed");
        }

        fn abandon(&mut self) {
            self.1.lock().unwrap().push("download reset");
        }
    }

    impl AsyncRead for Upload {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl Drop for Upload {
        fn drop(&mut self) {
            self.1.lock().unwrap().push("upload dropped");
        }
    }

    /// The client's side of a socket's control requests.
    struct Control {
        requests: mpsc::Sender<ClientPacket>,
        replies: mpsc::Receiver<RelayPacket>,
    }

    impl Control {
        async fn ask(&mut self, request: ClientPacket) -> RelayPacket {
            self.requests.send(request).await.unwrap();
            within(self.replies.recv()).await.expect("an answer")
        }

        /// Sends the client's `TcpClose`, or its `TcpReset`, under id 9, and reads the `Ok` that answers it at once.
        async fn end(&mut self, reset: bool) {
            let request = match reset {
                true => ClientPacket::TcpReset { id: 9, socket: 7 },
                false => ClientPacket::TcpClose { id: 9, socket: 7 },
            };
            self.requests.send(request).await.unwrap();
            let answer = timeout(Duration::from_secs(2), self.replies.recv()).await.expect("the answer at once");
            assert_eq!(answer, Some(RelayPacket::Ok { id: 9 }));
        }
    }

    /// Socket 7, relayed to a local peer once its connect was answered, driven from the client's side.
    struct Relayed {
        control: Control,
        /// The client's side of the stream.
        upload: DuplexStream,
        download: DuplexStream,
        peer: TcpStream,
        task: JoinHandle<Result<()>>,
        events: Events,
        session: Arc<SessionHandle<Distant, Probe>>,
    }

    /// A loopback connection: the relay's end and the peer's. Tiny buffers make the relay's writes wait at once when
    /// the peer does not read.
    async fn pair(tiny_buffers: bool) -> (TcpStream, TcpStream) {
        let listen = TcpSocket::new_v4().unwrap();
        let dial = TcpSocket::new_v4().unwrap();
        if tiny_buffers {
            listen.set_recv_buffer_size(4096).unwrap();
            dial.set_send_buffer_size(4096).unwrap();
        }
        listen.bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let listener = listen.listen(1).unwrap();
        let (dialed, accepted) = tokio::join!(dial.connect(listener.local_addr().unwrap()), listener.accept());
        (dialed.unwrap(), accepted.unwrap().0)
    }

    /// Relays `connection` over a carrier with this round trip.
    async fn relayed(policy: Probe, (connection, peer): (TcpStream, TcpStream), rtt: Duration) -> Relayed {
        let (session, mut replies) = handle(Distant(rtt), policy, Config::default());
        let (requests, queue) = mpsc::channel(10);
        let (upload, relay_upload) = duplex(64 * 1024);
        let (relay_download, download) = duplex(64 * 1024);
        let events = Events::default();
        let streams = (Download(relay_download, events.clone()), Upload(relay_upload, events.clone()));
        let held = session.clone();
        let task = tokio::spawn(async move { run(&held, 7, Origin::Connect(1), queue, connection, streams).await });
        let announced = within(replies.recv()).await;
        assert!(matches!(announced, Some(RelayPacket::Socket { id: 1, socket: 7, .. })), "{announced:?}");
        Relayed { control: Control { requests, replies }, upload, download, peer, task, events, session }
    }

    /// Starts `connect` for `request`: the reply it sends first, its task, and the queue for its later requests.
    async fn start<T: Transport, S: Session>(
        session: &Arc<SessionHandle<T, S>>,
        replies: &mut mpsc::Receiver<RelayPacket>,
        socket: u32,
        request: ClientPacket,
    ) -> (RelayPacket, JoinHandle<Result<()>>, mpsc::Sender<ClientPacket>) {
        let (requests, queue) = mpsc::channel(4);
        requests.try_send(request).unwrap();
        let task = tokio::spawn(connect(session.clone(), socket, queue));
        (within(replies.recv()).await.expect("a reply"), task, requests)
    }

    /// The socket's task, which ends without an error within `limit`.
    async fn ends(task: JoinHandle<Result<()>>, limit: Duration) {
        timeout(limit, task).await.expect("the socket ends in time").unwrap().unwrap();
    }

    /// What the peer reads until its end: the byte count at a clean end, the error at a reset.
    async fn count_until_end(mut peer: TcpStream) -> std::io::Result<usize> {
        let mut buf = vec![0; 64 * 1024];
        let mut total = 0;
        loop {
            match peer.read(&mut buf).await? {
                0 => return Ok(total),
                n => total += n,
            }
        }
    }

    /// Writes `chunks` of 64 KiB, or fewer once the relay lets the client's stream go.
    fn flood(mut upload: DuplexStream, chunks: usize) -> JoinHandle<()> {
        tokio::spawn(async move {
            let chunk = vec![1; 64 * 1024];
            for _ in 0..chunks {
                if upload.write_all(&chunk).await.is_err() {
                    return;
                }
            }
        })
    }

    fn reset(peer: TcpStream) {
        SockRef::from(&peer).set_linger(Some(Duration::ZERO)).unwrap();
        drop(peer);
    }

    async fn first_event(events: &Events) -> &'static str {
        within(async {
            loop {
                if let Some(event) = events.lock().unwrap().first() {
                    return *event;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
    }

    #[tokio::test]
    async fn a_connect_is_answered_with_both_addresses_and_carries_bytes_and_ends_both_ways() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let (transport, mut client) = testing::session(CLIENT);
        let config = Config { own_addresses: vec![PUBLIC], ..Config::default() };
        let (session, mut replies) = handle(transport, local(), config);
        let (reply, task, _requests) =
            start(&session, &mut replies, 5, ClientPacket::TcpConnect { id: 3, remote: target }).await;
        let (mut peer, relay_end) = within(listener.accept()).await.unwrap();
        let (local, remote) = (SocketAddr::new(PUBLIC, relay_end.port()), Some(SocketAddr::new(PUBLIC, target.port())));
        assert_eq!(reply, RelayPacket::Socket { id: 3, socket: 5, local, remote });

        let stream = client.next_stream().await;
        assert_eq!(stream.opened, Opened::Bi);
        let (mut download, mut upload) = (stream.recv, stream.send.expect("a stream both ways"));
        let mut head = [0; 4];
        within(download.read_exact(&mut head)).await.unwrap();
        assert_eq!(u32::from_be_bytes(head), 5);

        upload.write_all(b"request").await.unwrap();
        let mut up = [0; 7];
        within(peer.read_exact(&mut up)).await.unwrap();
        peer.write_all(b"answer").await.unwrap();
        let mut down = [0; 6];
        within(download.read_exact(&mut down)).await.unwrap();
        assert_eq!((&up, &down), (b"request", b"answer"));

        // the peer's end finishes the client's stream, and the client's finish reaches the peer
        peer.shutdown().await.unwrap();
        assert_eq!(within(download.read(&mut [0; 1])).await.unwrap(), 0);
        upload.shutdown().await.unwrap();
        assert_eq!(within(peer.read(&mut [0; 1])).await.unwrap(), 0);
        ends(task, WAIT).await;
        assert!(replies.try_recv().is_err(), "a socket that ended by itself answers nothing more");
        let metrics = &session.relay.metrics;
        assert_eq!((metrics.get(Counter::BytesUp), metrics.get(Counter::BytesDown)), (7, 6));
    }

    fn query(id: u8) -> Vec<u8> {
        [&[0, id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0][..], &[4, b'h', b'o', b's', b't', 0, 0, 1, 0, 1]].concat()
    }

    /// The address of a local DNS over HTTPS resolver that answers by a query's id: 1 with an A record of 127.0.0.1,
    /// 2 with no record, and any other with an HTTP error.
    async fn resolver() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(resolve_one(stream));
            }
        });
        format!("http://{address}/dns-query")
    }

    async fn resolve_one(mut stream: TcpStream) -> std::io::Result<()> {
        let mut request = Vec::new();
        let query = loop {
            let mut chunk = [0; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            request.extend_from_slice(&chunk[..read]);
            let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") else { continue };
            let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
            let length = head.lines().find_map(|line| line.strip_prefix("content-length: ")?.parse().ok());
            if let Some(query) = request.get(end + 4..end + 4 + length.unwrap_or(0)) {
                break query.to_vec();
            }
        };
        let (status, answer) = match query[1] {
            1 => {
                let mut answer = query;
                answer[2..4].copy_from_slice(&[0x81, 0x80]);
                answer[7] = 1;
                answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
                ("200 OK", answer)
            }
            2 => {
                let mut answer = query;
                answer[2..4].copy_from_slice(&[0x81, 0x83]);
                ("200 OK", answer)
            }
            _ => ("502 Bad Gateway", Vec::new()),
        };
        let length = answer.len();
        let head = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/dns-message\r\ncontent-length: {length}\r\n\
             connection: close\r\n\r\n"
        );
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(&answer).await
    }

    #[tokio::test]
    async fn a_name_connects_to_its_first_address_or_answers_why_it_cannot() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (transport, _client) = testing::session(CLIENT);
        let config = Config { dns_upstream: Some(resolver().await), ..Config::default() };
        let (session, mut replies) = handle(transport, local(), config);
        let name = |id: u8| ClientPacket::TcpConnectName { id: id.into(), port, query: query(id) };

        let (resolved, _task, _requests) = start(&session, &mut replies, 1, name(1)).await;
        let target = SocketAddr::from(([127, 0, 0, 1], port));
        assert!(matches!(resolved, RelayPacket::Socket { id: 1, remote: Some(remote), .. } if remote == target));
        within(listener.accept()).await.unwrap();
        let (no_address, ..) = start(&session, &mut replies, 2, name(2)).await;
        assert_eq!(code(&no_address), (2, ErrorCode::NAME_NOT_FOUND));
        let (failed, ..) = start(&session, &mut replies, 3, name(3)).await;
        assert_eq!(code(&failed), (3, ErrorCode::LOOKUP_FAILED));
        let mut long = query(1);
        long.resize(crate::dns::MAX_QUERY_BYTES + 1, 0);
        let request = ClientPacket::TcpConnectName { id: 4, port, query: long };
        let (refused, ..) = start(&session, &mut replies, 4, request).await;
        assert_eq!(code(&refused), (4, ErrorCode::REFUSED));
        let metrics = &session.relay.metrics;
        let counted = [Counter::DnsAnswered, Counter::DnsFailed, Counter::DnsRefused].map(|of| metrics.get(of));
        assert_eq!(counted, [2, 1, 1], "the long query never reached the resolver");
    }

    #[tokio::test]
    async fn a_target_the_policy_refuses_and_a_peer_that_refuses_answer_their_codes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap();
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let public_only = Basic::default().admit(CLIENT).unwrap();
        for (policy, target, refused) in
            [(public_only, open, ErrorCode::REFUSED), (local(), closed, ErrorCode::CONNECTION_REFUSED)]
        {
            let (session, mut replies) = handle(Distant(NO_RTT), policy, Config::default());
            let (reply, task, _) =
                start(&session, &mut replies, 1, ClientPacket::TcpConnect { id: 1, remote: target }).await;
            assert_eq!(code(&reply), (1, refused));
            assert!(within(task).await.unwrap().is_err());
        }
        let dialed = timeout(Duration::from_millis(100), listener.accept()).await;
        assert!(dialed.is_err(), "a target the policy refuses is never dialed");
    }

    // A listener with no room left in its accept queue drops a further connection's handshake, which then waits.
    #[tokio::test(start_paused = true)]
    async fn a_connect_past_its_limit_answers_timed_out() {
        let full = TcpSocket::new_v4().unwrap();
        full.bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let full = full.listen(0).unwrap();
        let target = full.local_addr().unwrap();
        let _queued = std::net::TcpStream::connect(target).unwrap();
        let (session, mut replies) = handle(Distant(NO_RTT), local(), Config::default());
        let (requests, queue) = mpsc::channel(1);
        requests.try_send(ClientPacket::TcpConnect { id: 1, remote: target }).unwrap();
        let started = Instant::now();
        let ended = timeout(TCP_CONNECT_TIMEOUT + WAIT, connect(session, 1, queue)).await.expect("the limit ends it");
        assert!(ended.is_err());
        assert_eq!(code(&replies.try_recv().unwrap()), (1, ErrorCode::TIMED_OUT));
        assert_eq!(started.elapsed(), TCP_CONNECT_TIMEOUT);
    }

    #[tokio::test]
    async fn a_stream_that_cannot_open_answers_no_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (session, mut replies) = handle(Distant(NO_RTT), local(), Config::default());
        let request = ClientPacket::TcpConnect { id: 1, remote: listener.local_addr().unwrap() };
        let (reply, task, _) = start(&session, &mut replies, 1, request).await;
        assert_eq!(code(&reply), (1, ErrorCode::NO_STREAM));
        assert!(within(task).await.unwrap().is_err());
    }

    #[tokio::test]
    async fn options_are_set_on_the_connection_and_one_the_relay_does_not_know_is_refused() {
        let (connection, peer) = pair(false).await;
        let options = SockRef::from(&connection).try_clone().unwrap();
        let mut relayed = relayed(Probe::open(), (connection, peer), NO_RTT).await;
        let set = |option| ClientPacket::TcpSetOption { id: 2, socket: 7, option };
        let wide = 4 * MIB as u32;
        for option in [
            TcpOption::NoDelay(true),
            TcpOption::Ttl(42),
            TcpOption::KeepAlive { enabled: true, initial_delay_seconds: 30 },
            TcpOption::SendBufferSize(wide),
            TcpOption::RecvBufferSize(wide),
        ] {
            assert_eq!(relayed.control.ask(set(option)).await, RelayPacket::Ok { id: 2 }, "{option:?}");
        }
        assert!(options.nodelay().unwrap());
        assert_eq!(options.ttl().unwrap(), 42);
        assert!(options.keepalive().unwrap());
        // Linux doubles the size it is given
        assert!(options.send_buffer_size().unwrap() <= 2 * MAX_CLIENT_SOCKET_BUFFER_BYTES);
        assert!(options.recv_buffer_size().unwrap() <= 2 * MAX_CLIENT_SOCKET_BUFFER_BYTES);

        // the system refuses a TTL of 0
        assert_eq!(code(&relayed.control.ask(set(TcpOption::Ttl(0))).await), (2, ErrorCode::OTHER));
        assert_eq!(code(&relayed.control.ask(set(TcpOption::Unknown(9))).await), (2, ErrorCode::UNSUPPORTED));
    }

    #[tokio::test]
    async fn the_policy_is_asked_before_bytes_move_either_way() {
        let (probe, gate) = Probe::gated(false);
        let mut relayed = relayed(probe.clone(), pair(false).await, NO_RTT).await;
        relayed.upload.write_all(b"up").await.unwrap();
        relayed.peer.write_all(b"down!").await.unwrap();
        let (mut up, mut down) = ([0; 2], [0; 5]);
        let held = Duration::from_millis(200);
        assert!(timeout(held, relayed.peer.read_exact(&mut up)).await.is_err(), "the upload waits on the policy");
        assert!(timeout(held, relayed.download.read_exact(&mut down)).await.is_err(), "so does the download");
        assert_eq!(probe.asked(), [2, 5]);

        gate.send(true).unwrap();
        within(relayed.peer.read_exact(&mut up)).await.unwrap();
        within(relayed.download.read_exact(&mut down)).await.unwrap();
        assert_eq!((&up, &down), (b"up", b"down!"));
        let metrics = &relayed.session.relay.metrics;
        assert_eq!((metrics.get(Counter::BytesUp), metrics.get(Counter::BytesDown)), (2, 5));
    }

    #[tokio::test]
    async fn an_answer_waits_for_room_without_holding_the_pumps() {
        let mut relayed = relayed(Probe::open(), pair(false).await, NO_RTT).await;
        let replies = &relayed.session.replies;
        let room = replies.capacity();
        for _ in 0..room {
            replies.try_send(RelayPacket::Draining).unwrap();
        }
        let requests = &relayed.control.requests;
        requests.send(ClientPacket::TcpSetOption { id: 4, socket: 7, option: TcpOption::NoDelay(true) }).await.unwrap();
        within(async {
            while requests.capacity() < requests.max_capacity() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await;

        relayed.upload.write_all(b"ping").await.unwrap();
        within(relayed.peer.read_exact(&mut [0; 4])).await.unwrap();
        relayed.peer.write_all(b"pong").await.unwrap();
        within(relayed.download.read_exact(&mut [0; 4])).await.unwrap();
        for _ in 0..room {
            assert_eq!(within(relayed.control.replies.recv()).await, Some(RelayPacket::Draining));
        }
        assert_eq!(within(relayed.control.replies.recv()).await, Some(RelayPacket::Ok { id: 4 }));
    }

    #[tokio::test]
    async fn a_close_delivers_what_the_client_sent_before_it() {
        let Relayed { mut control, mut upload, peer, task, session, .. } =
            relayed(Probe::open(), pair(false).await, NO_RTT).await;
        let peer = tokio::spawn(count_until_end(peer));
        let data = vec![1; 4 * MIB];

        upload.write_all(&data[..MIB]).await.unwrap();
        control.end(false).await;
        // a relay that dropped the stream at the close fails these writes; the pause is shorter than the quiet limit
        let _ = upload.write_all(&data[MIB..5 * MIB / 2]).await;
        sleep(Duration::from_millis(300)).await;
        let _ = upload.write_all(&data[5 * MIB / 2..]).await;
        let _ = upload.shutdown().await;

        let delivered = timeout(Duration::from_secs(10), peer).await.expect("the peer sees the end").unwrap();
        assert_eq!(delivered.expect("a clean end"), 4 * MIB);
        ends(task, WAIT).await;
        assert_eq!(session.relay.metrics.get(Counter::BytesUp), 4 * MIB as u64);
    }

    #[tokio::test]
    async fn a_drain_counts_quiet_only_while_it_waits_on_the_client() {
        let Relayed { mut control, mut upload, peer, task, .. } =
            relayed(Probe::open(), pair(true).await, NO_RTT).await;
        // one read, more than the tiny buffers hold
        let chunk = vec![1; 60 * 1024];

        control.end(false).await;
        upload.write_all(&chunk).await.unwrap();
        // the peer takes nothing for longer than the quiet limit, and the rest follows its first read within that limit
        sleep(DRAIN_QUIET + Duration::from_millis(500)).await;
        let peer = tokio::spawn(count_until_end(peer));
        sleep(Duration::from_millis(300)).await;
        let _ = upload.write_all(&chunk).await;
        let _ = upload.shutdown().await;

        let delivered = within(peer).await.unwrap();
        assert_eq!(delivered.expect("a clean end"), 2 * chunk.len());
        ends(task, WAIT).await;
    }

    #[tokio::test]
    async fn a_drain_resets_a_peer_that_stopped_reading_at_its_limit() {
        let Relayed { mut control, upload, peer, task, .. } = relayed(Probe::open(), pair(true).await, NO_RTT).await;
        // far more than the relay and the tiny buffers hold, so only the limit ends the drain
        let writer = flood(upload, 64);
        sleep(Duration::from_millis(200)).await;

        let started = Instant::now();
        control.end(false).await;
        ends(task, DRAIN_LIMIT + WAIT).await;
        let held = started.elapsed();
        assert!(held >= DRAIN_LIMIT && held < DRAIN_LIMIT + Duration::from_secs(3), "the drain held for {held:?}");
        // a reset, so a cut upload never reads as whole
        let end = within(count_until_end(peer)).await;
        assert_eq!(end.expect_err("the peer saw a clean end").kind(), ErrorKind::ConnectionReset);
        within(writer).await.unwrap();
    }

    #[tokio::test]
    async fn a_drain_resets_a_reading_peer_at_its_limit() {
        // paced to 1 MiB a second, so the limit lands while the peer keeps up with what it gets
        let paced = Probe { pace: Some(MIB as f64), ..Probe::open() };
        let Relayed { mut control, upload, peer, task, .. } = relayed(paced, pair(false).await, NO_RTT).await;
        let peer = tokio::spawn(count_until_end(peer));
        // 10 MiB, which the pace moves in 10 seconds, past the limit
        let writer = flood(upload, 160);
        sleep(Duration::from_millis(200)).await;

        control.end(false).await;
        ends(task, DRAIN_LIMIT + WAIT).await;
        let end = within(peer).await.unwrap();
        assert_eq!(end.expect_err("the peer saw a clean end").kind(), ErrorKind::ConnectionReset);
        within(writer).await.unwrap();
    }

    #[tokio::test]
    async fn a_close_with_nothing_in_flight_ends_at_once() {
        // the client's stream stays open, as a plain destroy() leaves it
        let Relayed { mut control, upload: _upload, peer, task, .. } =
            relayed(Probe::open(), pair(false).await, NO_RTT).await;
        let started = Instant::now();
        control.end(false).await;
        ends(task, WAIT).await;
        assert!(started.elapsed() < DRAIN_QUIET, "a quiet stream held its drain for {:?}", started.elapsed());
        // a clean end, as Node's destroy() sends
        assert_eq!(within(count_until_end(peer)).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_drain_resets_the_download_only_once_the_upload_is_done_with() {
        let Relayed { mut control, mut upload, peer, task, events, .. } =
            relayed(Probe::open(), pair(true).await, NO_RTT).await;
        // one read, more than the tiny buffers hold, so the drain waits on a peer that is not reading yet
        let chunk = vec![1; 60 * 1024];
        upload.write_all(&chunk).await.unwrap();
        control.end(false).await;
        sleep(Duration::from_millis(300)).await;
        let seen = events.lock().unwrap().clone();
        assert!(seen.is_empty(), "{seen:?} while the drain still writes");

        let peer = tokio::spawn(count_until_end(peer));
        let _ = upload.write_all(&chunk).await;
        let _ = upload.shutdown().await;
        ends(task, WAIT).await;
        assert_eq!(*events.lock().unwrap(), ["download reset", "upload dropped"]);
        let delivered = within(peer).await.unwrap();
        assert_eq!(delivered.expect("a clean end"), 2 * chunk.len());
    }

    #[tokio::test]
    async fn a_drain_waits_on_data_that_trails_the_close_by_a_round_trip() {
        let rtt = Duration::from_millis(400);
        let Relayed { mut control, mut upload, peer, task, .. } = relayed(Probe::open(), pair(false).await, rtt).await;
        let peer = tokio::spawn(count_until_end(peer));

        control.end(false).await;
        sleep(Duration::from_millis(300)).await;
        let chunk = vec![1; 60 * 1024];
        let _ = upload.write_all(&chunk).await;
        let _ = upload.shutdown().await;

        let delivered = within(peer).await.unwrap();
        assert_eq!(delivered.expect("a clean end"), chunk.len());
        ends(task, WAIT).await;
    }

    // A client's socket library reads a peer's reset as ECONNRESET, where a finished stream reads as the peer's own
    // close.
    #[tokio::test]
    async fn a_peer_reset_fails_the_download_after_its_last_bytes() {
        let Relayed { mut control, upload: _upload, mut download, mut peer, task, events, .. } =
            relayed(Probe::open(), pair(false).await, NO_RTT).await;
        peer.write_all(&[2; 32 * 1024]).await.unwrap();
        let started = Instant::now();
        reset(peer);
        assert_eq!(first_event(&events).await, "download failed");
        assert!(started.elapsed() >= PEER_RESET_GRACE, "the stream failed {:?} after the reset", started.elapsed());

        control.end(false).await;
        ends(task, WAIT).await;
        let mut received = Vec::new();
        within(download.read_to_end(&mut received)).await.unwrap();
        assert_eq!(received.len(), 32 * 1024, "the peer's last bytes reach the client");
        assert!(!events.lock().unwrap().contains(&"download finished"));
    }

    // A peer that reset while the client kept writing, with the read side held by a client that does not read yet, so
    // only the relay's writes meet the reset; the client then reads its download.
    async fn reset_under_writes(
        mut peer: TcpStream,
        upload: DuplexStream,
        mut download: DuplexStream,
    ) -> JoinHandle<()> {
        peer.write_all(&vec![1; 192 * 1024]).await.unwrap();
        let writer = flood(upload, 64);
        sleep(Duration::from_millis(200)).await;
        reset(peer);
        sleep(Duration::from_millis(200)).await;
        tokio::spawn(async move {
            let mut buf = vec![0; 64 * 1024];
            while download.read(&mut buf).await.is_ok_and(|n| n > 0) {}
        });
        writer
    }

    #[tokio::test]
    async fn a_peer_reset_a_write_meets_first_holds_the_upload_until_the_client_closes() {
        let Relayed { mut control, upload, download, peer, task, events, .. } =
            relayed(Probe::open(), pair(false).await, NO_RTT).await;
        let writer = reset_under_writes(peer, upload, download).await;
        assert_eq!(first_event(&events).await, "download failed");
        sleep(Duration::from_millis(300)).await;
        assert_eq!(*events.lock().unwrap(), ["download failed"]);

        control.end(false).await;
        ends(task, WAIT).await;
        assert_eq!(events.lock().unwrap().last(), Some(&"upload dropped"));
        within(writer).await.unwrap();
    }

    #[tokio::test]
    async fn a_peer_reset_ends_the_socket_itself_once_the_client_is_past_its_limit() {
        let Relayed { mut control, upload, download, peer, task, events, .. } =
            relayed(Probe::open(), pair(false).await, NO_RTT).await;
        let writer = reset_under_writes(peer, upload, download).await;
        assert_eq!(first_event(&events).await, "download failed");
        let failed = Instant::now();

        ends(task, PEER_RESET_CLOSE_LIMIT + Duration::from_secs(2)).await;
        let waited = failed.elapsed();
        assert!(waited >= PEER_RESET_CLOSE_LIMIT - Duration::from_millis(100), "it waited {waited:?} for the client");
        assert_eq!(*events.lock().unwrap(), ["download failed", "upload dropped"]);
        assert!(control.replies.try_recv().is_err(), "an end the client did not ask for answers nothing");
        within(writer).await.unwrap();
    }

    // A half open client still writing to a peer that ended and then reset, as a client's write gets EPIPE at once.
    #[tokio::test]
    async fn a_peer_that_ended_before_a_write_met_its_reset_ends_the_socket_at_once() {
        let Relayed { mut control, upload, mut peer, task, events, .. } =
            relayed(Probe::open(), pair(false).await, NO_RTT).await;
        peer.shutdown().await.unwrap();
        assert_eq!(first_event(&events).await, "download finished");
        let writer = flood(upload, 64);
        sleep(Duration::from_millis(200)).await;
        reset(peer);

        ends(task, Duration::from_secs(2)).await;
        assert_eq!(*events.lock().unwrap(), ["download finished", "upload dropped"]);
        assert!(control.replies.try_recv().is_err(), "an end the client did not ask for answers nothing");
        within(writer).await.unwrap();
    }

    #[tokio::test]
    async fn a_reset_drops_what_is_in_flight_at_once() {
        let Relayed { mut control, upload, peer, task, events, session, .. } =
            relayed(Probe::open(), pair(true).await, NO_RTT).await;
        let writer = flood(upload, 64);
        sleep(Duration::from_millis(200)).await;

        control.end(true).await;
        ends(task, Duration::from_secs(2)).await;
        assert_eq!(*events.lock().unwrap(), ["download reset", "upload dropped"]);
        let end = within(count_until_end(peer)).await;
        assert_eq!(end.expect_err("the peer saw a clean end").kind(), ErrorKind::ConnectionReset);
        assert_eq!(session.relay.metrics.get(Counter::TcpResets), 1);
        within(writer).await.unwrap();
    }

    #[tokio::test]
    async fn a_reset_reaches_the_peer_with_no_finish_ahead_of_it() {
        let Relayed { mut control, upload: _upload, mut peer, task, .. } =
            relayed(Probe::open(), pair(false).await, NO_RTT).await;
        control.end(true).await;
        ends(task, WAIT).await;
        let read = within(peer.read(&mut [0; 1024])).await;
        assert_eq!(read.expect_err("the peer saw a clean end before the reset").kind(), ErrorKind::ConnectionReset);
    }

    // Linux getpeername fails with ENOTCONN once a peer's reset closed the socket.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_reset_before_the_announcement_answers_a_connect_with_the_error_and_announces_no_accept() {
        for origin in [Origin::Connect(3), Origin::Listener(99)] {
            let (mut connection, peer) = pair(false).await;
            reset(peer);
            let read = within(connection.read(&mut [0; 16])).await;
            assert_eq!(read.unwrap_err().kind(), ErrorKind::ConnectionReset);

            let (session, mut replies) = handle(Distant(NO_RTT), Probe::open(), Config::default());
            let (_requests, queue) = mpsc::channel(1);
            let streams = (duplex(1024).0, duplex(1024).0);
            let ended = within(run(&session, 7, origin, queue, connection, streams)).await;
            assert!(ended.is_err(), "a reset connection is not relayed");
            match origin {
                Origin::Connect(_) => assert_eq!(code(&replies.try_recv().unwrap()).0, 3),
                Origin::Listener(_) => assert!(replies.try_recv().is_err(), "{origin:?} was announced"),
            }
            assert_eq!(session.relay.metrics.get(Counter::InboundAnnounced), 0);
        }
    }
}
