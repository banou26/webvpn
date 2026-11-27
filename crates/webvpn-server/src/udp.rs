//! A UDP socket: the socket the relay holds for a client, and the two pumps between it and the client.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Result};
use socket2::{SockAddr, SockRef};
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::debug;
use webvpn_proto::{ClientPacket, ErrorCode, RelayPacket, UdpOption, UdpPacket, MAX_UDP_PAYLOAD_BYTES};

use crate::hairpin::{Hairpin, Lease};
use crate::metrics::Counter;
use crate::policy::{Direction, Proto, Refusal, Session};
use crate::session::{error, read_upload_stream, QueuedDatagram, SessionHandle, UdpCarrier};
use crate::tcp::MAX_CLIENT_SOCKET_BUFFER_BYTES;
use crate::transport::{open_udp_bi_with_prefix, open_uni_with_prefix, SendHalf, Transport};

/// Tries at locking the port of a port-0 bind: another socket on the host can take the port between the disconnect
/// that frees it and the bind that locks it.
const UDP_PORT_LOCK_ATTEMPTS: usize = 3;

/// Linux's number for EAFNOSUPPORT.
const EAFNOSUPPORT: i32 = 97;

/// Runs a socket a client asked for. `requests` yields its `UdpBind` first. `datagrams` yields the client's packets
/// for this socket that came outside its own stream, and `queue` is where the socket puts the ones its stream
/// brings.
pub(crate) async fn bind<T: Transport, S: Session>(
    session: Arc<SessionHandle<T, S>>,
    socket: u32,
    mut requests: mpsc::Receiver<ClientPacket>,
    mut datagrams: mpsc::Receiver<QueuedDatagram>,
    queue: mpsc::Sender<QueuedDatagram>,
) -> Result<()> {
    let Some(ClientPacket::UdpBind { id, local }) = requests.recv().await else {
        bail!("a UDP socket's first request is not its bind");
    };
    if let Err(refusal) = session.policy.check_bind(Proto::Udp, local) {
        session.reply(error(id, refusal)).await;
        bail!("the policy refused a UDP bind");
    }
    let (udp, bound) = match bind_port_locked(local).await {
        Ok(bound) => bound,
        Err(failure) => {
            session.reply(error(id, Refusal::from_io(&failure))).await;
            bail!("a UDP bind failed: {:?}", failure.kind());
        }
    };
    // Declared after the socket, so the record goes before the system frees the port.
    let bound_port = session.relay.hairpin.register(Proto::Udp, bound);
    let hairpin = &session.relay.hairpin;
    let metrics = &session.relay.metrics;

    let reply = RelayPacket::Socket { id, socket, local: hairpin.public_spelling(bound), remote: None };
    let (mut stream, upload) = match session.udp_carrier {
        UdpCarrier::Bidi => {
            session.reply(reply).await;
            match open_udp_bi_with_prefix(&*session.transport, socket).await {
                Ok((send, recv)) => (Some(send), Some(recv)),
                Err(failure) => {
                    debug!(socket, "a UDP socket's stream did not open, so it falls back to datagrams: {failure:#}");
                    (None, None)
                }
            }
        }
        UdpCarrier::UniStreamRequired => match open_uni_with_prefix(&*session.transport, socket).await {
            Ok(send) => {
                session.reply(reply).await;
                (Some(send), None)
            }
            Err(_) => {
                let refusal = Refusal::new(ErrorCode::NO_STREAM, "the socket's stream could not be opened in time");
                session.reply(error(id, refusal)).await;
                bail!("a UDP socket's stream did not open");
            }
        },
    };

    // The lease of the route the socket is connected over, when that route leads to a socket bound on this relay.
    let connected = Mutex::new(None::<Lease>);

    let mut download = Box::pin(async {
        let mut buffer = vec![0; MAX_UDP_PAYLOAD_BYTES];
        loop {
            let (size, from) = match udp.recv_from(&mut buffer).await {
                Ok(received) => received,
                Err(failure) => {
                    debug!(socket, "a UDP receive failed: {:?}", failure.kind());
                    continue;
                }
            };
            metrics.add(Counter::BytesDown, size as u64);
            session.policy.relayed(Direction::Down, size).await;
            if connected.lock().unwrap().is_some_and(|lease| !hairpin.is_live(&lease)) && udp.peer_addr().is_ok() {
                debug!(socket, "the relay socket a UDP socket is connected to closed, so it closes too");
                return;
            }
            let packet = UdpPacket { socket, remote: Some(hairpin.public_spelling(from)), data: &buffer[..size] };
            let mut frame = Vec::new();
            match stream.as_mut() {
                Some(stream) => {
                    packet.encode_framed(&mut frame);
                    if let Err(failure) = stream.write_all(&frame).await {
                        metrics.count(Counter::UdpDeliverFailed);
                        debug!(socket, "a UDP socket's stream write failed: {:?}", failure.kind());
                        return;
                    }
                    metrics.add(Counter::UdpBytesDelivered, size as u64);
                }
                None => {
                    packet.encode(&mut frame);
                    match session.transport.send_datagram(frame) {
                        Ok(()) => metrics.add(Counter::UdpBytesDelivered, size as u64),
                        Err(failure) => {
                            metrics.count(Counter::UdpDroppedSend);
                            debug!(socket, "a UDP datagram toward the client was dropped: {failure:#}");
                        }
                    }
                }
            }
        }
    });

    let mut upload_pump = Box::pin(async {
        while let Some(queued) = datagrams.recv().await {
            // The reservation lives to the end of this pass, so the session's budget gets the bytes back only once
            // the packet is sent.
            let QueuedDatagram { socket: named, remote, data, reservation: _reservation } = queued;
            if named != socket {
                metrics.count(Counter::UdpUploadIdMismatch);
                continue;
            }
            let is_connected = udp.peer_addr().is_ok();
            let sent = if is_connected {
                session.policy.relayed(Direction::Up, data.len()).await;
                send_revalidated(&udp, None, || *connected.lock().unwrap(), hairpin, &data).await
            } else {
                let Some(remote) = remote else {
                    debug!(socket, "a packet with no destination, on a socket with no peer, was dropped");
                    continue;
                };
                let route = match crate::hairpin::route(hairpin, &*session.policy, Proto::Udp, remote) {
                    Ok(route) => route,
                    Err(refusal) => {
                        debug!(socket, code = refusal.code.0, "a packet to a refused destination was dropped");
                        continue;
                    }
                };
                session.policy.relayed(Direction::Up, data.len()).await;
                send_revalidated(&udp, Some(route.dial), || route.lease, hairpin, &data).await
            };
            match sent {
                LeaseSend::Sent(sent) => {
                    metrics.add(Counter::BytesUp, sent as u64);
                    metrics.add(Counter::UdpBytesDelivered, sent as u64);
                }
                LeaseSend::Stale if is_connected => {
                    debug!(socket, "the relay socket a UDP socket is connected to closed, so it closes too");
                    return;
                }
                LeaseSend::Stale => debug!(socket, "a packet to a relay socket that closed was dropped"),
                LeaseSend::Failed(failure) => {
                    metrics.count(Counter::UdpSendFailed);
                    debug!(socket, "a UDP send failed: {:?}", failure.kind());
                }
            }
        }
    });

    let mut upload_reader = Box::pin(async {
        if let Some(mut upload) = upload {
            if let Err(failure) = read_upload_stream(&mut upload, &queue, &session.upload_budget, metrics).await {
                debug!(socket, "a UDP socket's upload half ended: {failure:#}");
            }
        }
        std::future::pending::<()>().await
    });

    // A reply waits in a branch of its own, so a client that stops reading its control stream holds up this
    // socket's requests and never its pumps.
    let mut staged: Option<RelayPacket> = None;
    let mut closing = None;
    // set when the socket ends without the client asking, which the client is then told
    let mut ended_alone = None;
    let ended = loop {
        tokio::select! {
            request = requests.recv(), if staged.is_none() => match request {
                Some(ClientPacket::UdpClose { id, .. }) => {
                    closing = Some(id);
                    break Ok(());
                }
                Some(ClientPacket::UdpConnect { id, remote, .. }) => {
                    staged = Some(answer(id, connect(&udp, hairpin, &*session.policy, &connected, remote).await));
                }
                Some(ClientPacket::UdpDisconnect { id, .. }) => {
                    let (disconnected, lost_port) = disconnect(&udp, bound, &connected);
                    if lost_port {
                        // answered here, since the branch that sends staged replies ends with the loop
                        session.reply(answer(id, disconnected)).await;
                        ended_alone = Some(ErrorCode::ADDRESS_NOT_AVAILABLE);
                        break Ok(());
                    }
                    if disconnected.is_ok() {
                        metrics.count(Counter::UdpDisconnects);
                    }
                    staged = Some(answer(id, disconnected));
                }
                Some(ClientPacket::UdpSetOption { id, option, .. }) => {
                    staged = Some(answer(id, set_option(&udp, &*session.policy, option)));
                }
                // the session hands a socket only the requests of its kind
                Some(_) => {}
                None => break Ok(()),
            },
            permit = session.replies.reserve(), if staged.is_some() => match permit {
                Ok(permit) => permit.send(staged.take().expect("a reply is staged")),
                Err(_) => break Err(anyhow!("the session's control stream closed")),
            },
            () = &mut download => {
                ended_alone = Some(ErrorCode::OTHER);
                break Ok(());
            }
            () = &mut upload_pump => {
                ended_alone = Some(ErrorCode::OTHER);
                break Ok(());
            }
            () = &mut upload_reader => unreachable!("the upload reader waits forever once its stream ends"),
        }
    };

    drop(download);
    if closing.is_some() {
        if let Some(stream) = stream.as_mut() {
            stream.abandon();
        }
    }
    drop((upload_pump, upload_reader));
    // The port is free before the close is answered, so a client may bind it again at once.
    drop(bound_port);
    drop(udp);
    if let Some(id) = closing {
        session.reply(RelayPacket::Ok { id }).await;
    }
    if let Some(code) = ended_alone {
        session.reply(RelayPacket::Closed { socket, code }).await;
    }
    session.answer_left(&mut requests).await;
    ended
}

/// Binds as BSD does: port 0 takes a free port, any other port is bound exactly or refused. A named port is never
/// swapped for a free one: the policy decides which ports a client may bind, and the system refuses one that is
/// taken.
async fn bind_port_locked(local: SocketAddr) -> std::io::Result<(UdpSocket, SocketAddr)> {
    let mut attempt = 1;
    loop {
        let udp = UdpSocket::bind(local).await?;
        let bound = udp.local_addr()?;
        // A named port is locked already, and a second bind of a bound socket fails with EINVAL.
        if local.port() != 0 {
            return Ok((udp, bound));
        }
        // Only a bind that names its port locks it: a port-0 socket loses its port on a later disconnect, so the
        // port it was given is bound again by number.
        match kernel_disconnect(&udp).and_then(|()| SockRef::from(&udp).bind(&SockAddr::from(bound))) {
            Ok(()) => return Ok((udp, bound)),
            Err(failure) if failure.kind() == ErrorKind::AddrInUse && attempt < UDP_PORT_LOCK_ATTEMPTS => attempt += 1,
            Err(failure) => return Err(failure),
        }
    }
}

/// Drops the socket's peer, as connect(2) with AF_UNSPEC does (udp(7)).
fn kernel_disconnect(udp: &UdpSocket) -> std::io::Result<()> {
    // SAFETY: `try_init` zeroes the storage, so it holds a whole address whose family is AF_UNSPEC.
    let (_, unspecified) = unsafe { SockAddr::try_init(|_, _| Ok(())) }?;
    match SockRef::from(udp).connect(&unspecified) {
        // some systems report EAFNOSUPPORT once they have dropped the peer already
        Err(failure) if failure.raw_os_error() == Some(EAFNOSUPPORT) => Ok(()),
        done => done,
    }
}

/// Drops the socket's peer, and says whether the socket lost its port doing so, in which case it must close alone:
/// the client was told that port.
fn disconnect(udp: &UdpSocket, bound: SocketAddr, connected: &Mutex<Option<Lease>>) -> (Result<(), Refusal>, bool) {
    if udp.peer_addr().is_err() {
        // never connected, or disconnected already: a disconnect now would free the port
        return (Ok(()), false);
    }
    if let Err(failure) = kernel_disconnect(udp) {
        return (Err(Refusal::from_io(&failure)), false);
    }
    // the lease goes only once the peer is gone
    *connected.lock().unwrap() = None;
    if udp.local_addr().is_ok_and(|local| local.port() == bound.port()) {
        return (Ok(()), false);
    }
    match SockRef::from(udp).bind(&SockAddr::from(bound)) {
        Ok(()) => (Ok(()), false),
        Err(failure) => (Err(Refusal::from_io(&failure)), true),
    }
}

async fn connect<S: Session>(
    udp: &UdpSocket,
    hairpin: &Hairpin,
    policy: &S,
    connected: &Mutex<Option<Lease>>,
    remote: SocketAddr,
) -> Result<(), Refusal> {
    let route = crate::hairpin::route(hairpin, policy, Proto::Udp, remote)?;
    udp.connect(route.dial).await.map_err(|failure| Refusal::from_io(&failure))?;
    *connected.lock().unwrap() = route.lease;
    Ok(())
}

fn set_option<S: Session>(udp: &UdpSocket, policy: &S, option: UdpOption) -> Result<(), Refusal> {
    let buffer = |bytes: u32| (bytes as usize).min(MAX_CLIENT_SOCKET_BUFFER_BYTES);
    let applied = match option {
        // Whether a datagram leaves as a broadcast is up to the system at send time, not to a destination the policy
        // can be asked about (a network's broadcast address looks like any other), so broadcast goes on only for a
        // policy that lets the limited broadcast address through.
        UdpOption::Broadcast(on) => {
            if on {
                policy.check_egress(Proto::Udp, SocketAddr::from((Ipv4Addr::BROADCAST, 0)))?;
            }
            udp.set_broadcast(on)
        }
        UdpOption::Ttl(ttl) => udp.set_ttl(ttl),
        UdpOption::MulticastTtlV4(ttl) => udp.set_multicast_ttl_v4(ttl),
        UdpOption::MulticastLoopV4(on) => udp.set_multicast_loop_v4(on),
        UdpOption::MulticastLoopV6(on) => udp.set_multicast_loop_v6(on),
        UdpOption::AddMembershipV4 { group, interface } => {
            policy.check_egress(Proto::Udp, SocketAddr::from((group, 0)))?;
            udp.join_multicast_v4(group, interface)
        }
        UdpOption::DropMembershipV4 { group, interface } => udp.leave_multicast_v4(group, interface),
        UdpOption::AddMembershipV6 { group, interface } => {
            policy.check_egress(Proto::Udp, SocketAddr::from((group, 0)))?;
            udp.join_multicast_v6(&group, interface)
        }
        UdpOption::DropMembershipV6 { group, interface } => udp.leave_multicast_v6(&group, interface),
        UdpOption::SendBufferSize(bytes) => SockRef::from(udp).set_send_buffer_size(buffer(bytes)),
        UdpOption::RecvBufferSize(bytes) => SockRef::from(udp).set_recv_buffer_size(buffer(bytes)),
        UdpOption::Unknown(_) => {
            return Err(Refusal::new(ErrorCode::UNSUPPORTED, "the relay does not know this option"));
        }
    };
    applied.map_err(|failure| Refusal::from_io(&failure))
}

fn answer(id: u32, done: Result<(), Refusal>) -> RelayPacket {
    match done {
        Ok(()) => RelayPacket::Ok { id },
        Err(refusal) => error(id, refusal),
    }
}

enum LeaseSend {
    Sent(usize),
    /// The socket bound on this relay that the route led to has closed.
    Stale,
    Failed(std::io::Error),
}

/// Sends `data` to `target`, or to the socket's peer when it is `None`. The lease is checked after `writable`, the
/// only await, and right before the send, which does not wait, so a relay socket that closed while the packet waited
/// on pacing never receives it. No lease sends unchecked.
async fn send_revalidated(
    udp: &UdpSocket,
    target: Option<SocketAddr>,
    lease: impl Fn() -> Option<Lease>,
    hairpin: &Hairpin,
    data: &[u8],
) -> LeaseSend {
    loop {
        if let Err(failure) = udp.writable().await {
            return LeaseSend::Failed(failure);
        }
        if lease().is_some_and(|lease| !hairpin.is_live(&lease)) {
            return LeaseSend::Stale;
        }
        let sent = match target {
            Some(target) => udp.try_send_to(data, target),
            None => udp.try_send(data),
        };
        match sent {
            Ok(sent) => return LeaseSend::Sent(sent),
            Err(failure) if failure.kind() == ErrorKind::WouldBlock => continue,
            Err(failure) => return LeaseSend::Failed(failure),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, DuplexStream};
    use tokio::sync::Semaphore;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    use super::*;
    use crate::policy::{Basic, BasicSession, Policy, SocketKind};
    use crate::relay::{Config, Shared};
    use crate::testing::{self, Client, MemoryTransport, Opened, STREAM_BUFFER, WAIT};

    const SOCKET: u32 = 7;
    const OWN: &str = "203.0.113.7";

    fn sa(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// A policy for these tests: it allows every destination but `refuses`, and records each pacing call before it
    /// waits on that direction's gate.
    struct Probe {
        refuses: Option<SocketAddr>,
        up: Semaphore,
        down: Semaphore,
        paced: Mutex<Vec<(Direction, usize)>>,
    }

    impl Probe {
        fn with_gates(permits: usize) -> Self {
            let gate = || Semaphore::new(permits);
            Self { refuses: None, up: gate(), down: gate(), paced: Mutex::default() }
        }

        fn open() -> Self {
            Self::with_gates(Semaphore::MAX_PERMITS)
        }

        /// Paces nothing through until the test adds permits.
        fn holding() -> Self {
            Self::with_gates(0)
        }

        fn refusing(target: SocketAddr) -> Self {
            Self { refuses: Some(target), ..Self::open() }
        }

        fn paced(&self) -> Vec<(Direction, usize)> {
            self.paced.lock().unwrap().clone()
        }
    }

    impl Session for Probe {
        type Permit = ();

        fn open_socket(&self, _kind: SocketKind) -> Result<(), Refusal> {
            Ok(())
        }

        fn check_egress(&self, _proto: Proto, target: SocketAddr) -> Result<(), Refusal> {
            match self.refuses {
                Some(refused) if refused == target => Err(Refusal::new(ErrorCode::REFUSED, "the test refuses it")),
                _ => Ok(()),
            }
        }

        fn check_bind(&self, _proto: Proto, _local: SocketAddr) -> Result<(), Refusal> {
            Ok(())
        }

        async fn relayed(&self, direction: Direction, bytes: usize) {
            self.paced.lock().unwrap().push((direction, bytes));
            let gate = match direction {
                Direction::Up => &self.up,
                Direction::Down => &self.down,
            };
            gate.acquire().await.expect("the gate stays open").forget();
        }
    }

    /// How a socket under test is opened.
    struct Opening<S> {
        policy: S,
        relay: Arc<Shared>,
        carrier: UdpCarrier,
        refuse_streams: bool,
        local: SocketAddr,
        budget: usize,
    }

    impl<S: Session> Opening<S> {
        fn new(policy: S) -> Self {
            Self {
                policy,
                relay: Shared::new(Config::default()),
                carrier: UdpCarrier::Bidi,
                refuse_streams: false,
                local: sa("127.0.0.1:0"),
                budget: 1 << 20,
            }
        }

        /// Sends the bind and reads what answers it.
        async fn start(self) -> (Harness<S>, RelayPacket) {
            let (mut transport, client) = testing::session(IpAddr::from([127, 0, 0, 1]));
            transport.refuse_streams = self.refuse_streams;
            let (replies, reply_queue) = mpsc::channel(16);
            let handle = Arc::new(SessionHandle {
                transport: Arc::new(transport),
                policy: Arc::new(self.policy),
                relay: self.relay,
                replies,
                udp_carrier: self.carrier,
                upload_budget: Arc::new(Semaphore::new(self.budget)),
                lookup_slots: None,
            });
            let (requests, request_queue) = mpsc::channel(16);
            let (datagrams, datagram_queue) = mpsc::channel(16);
            requests.send(ClientPacket::UdpBind { id: 1, local: self.local }).await.unwrap();
            let task = tokio::spawn(bind(handle.clone(), SOCKET, request_queue, datagram_queue, datagrams.clone()));
            let mut harness = Harness { client, replies: reply_queue, requests, datagrams, handle, task };
            let reply = harness.reply().await;
            (harness, reply)
        }

        /// Binds, and takes the socket's stream both ways.
        async fn bind(self) -> (Harness<S>, SocketAddr, UdpStream) {
            let (mut harness, reply) = self.start().await;
            let RelayPacket::Socket { id: 1, socket: SOCKET, local, remote: None } = reply else {
                panic!("expected the socket, got {reply:?}");
            };
            let stream = UdpStream::take(&mut harness.client, Opened::UdpBi).await;
            (harness, local, stream)
        }
    }

    /// A socket under test, driven from its client's side.
    struct Harness<S: Session> {
        client: Client,
        replies: mpsc::Receiver<RelayPacket>,
        requests: mpsc::Sender<ClientPacket>,
        datagrams: mpsc::Sender<QueuedDatagram>,
        handle: Arc<SessionHandle<MemoryTransport, S>>,
        task: JoinHandle<Result<()>>,
    }

    impl<S: Session> Harness<S> {
        async fn reply(&mut self) -> RelayPacket {
            timeout(WAIT, self.replies.recv()).await.expect("the socket answers in time").expect("a reply")
        }

        async fn ask(&mut self, request: ClientPacket) -> RelayPacket {
            self.requests.send(request).await.unwrap();
            self.reply().await
        }

        async fn set(&mut self, id: u32, option: UdpOption) -> RelayPacket {
            self.ask(ClientPacket::UdpSetOption { id, socket: SOCKET, option }).await
        }

        /// Hands the socket a packet as the session does with one that came outside the socket's stream.
        async fn queue(&self, remote: SocketAddr, data: &[u8]) {
            let reservation = self.handle.upload_budget.clone().try_acquire_many_owned(data.len() as u32).unwrap();
            let queued = QueuedDatagram { socket: SOCKET, remote: Some(remote), data: data.to_vec(), reservation };
            self.datagrams.send(queued).await.unwrap();
        }

        fn metric(&self, counter: Counter) -> u64 {
            self.handle.relay.metrics.get(counter)
        }

        async fn ended(&mut self) -> Result<()> {
            timeout(WAIT, &mut self.task).await.expect("the socket ends in time").expect("the socket does not panic")
        }
    }

    /// A socket's stream, from the client's side.
    struct UdpStream {
        send: Option<DuplexStream>,
        recv: DuplexStream,
    }

    impl UdpStream {
        /// The next stream the relay opened, which must be `opened` for this socket. The client writes its own side's
        /// socket id at once, as a client does.
        async fn take(client: &mut Client, opened: Opened) -> Self {
            let stream = client.next_stream().await;
            assert_eq!(stream.opened, opened);
            let mut stream = Self { send: stream.send, recv: stream.recv };
            let mut prefix = [0; 4];
            timeout(WAIT, stream.recv.read_exact(&mut prefix)).await.unwrap().unwrap();
            assert_eq!(u32::from_be_bytes(prefix), SOCKET);
            if let Some(send) = stream.send.as_mut() {
                send.write_all(&SOCKET.to_be_bytes()).await.unwrap();
            }
            stream
        }

        async fn send_as(&mut self, socket: u32, remote: Option<SocketAddr>, data: &[u8]) {
            let mut frame = Vec::new();
            UdpPacket { socket, remote, data }.encode_framed(&mut frame);
            self.send.as_mut().expect("a stream both ways").write_all(&frame).await.unwrap();
        }

        async fn send(&mut self, remote: Option<SocketAddr>, data: &[u8]) {
            self.send_as(SOCKET, remote, data).await;
        }

        async fn next(&mut self) -> (Option<SocketAddr>, Vec<u8>) {
            let read = async {
                let mut length = [0; 4];
                self.recv.read_exact(&mut length).await.unwrap();
                let mut frame = vec![0; u32::from_be_bytes(length) as usize];
                self.recv.read_exact(&mut frame).await.unwrap();
                let packet = UdpPacket::decode(&frame).unwrap();
                assert_eq!(packet.socket, SOCKET);
                (packet.remote, packet.data.to_vec())
            };
            timeout(WAIT, read).await.expect("a packet in time")
        }
    }

    async fn outside() -> (UdpSocket, SocketAddr) {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = udp.local_addr().unwrap();
        (udp, address)
    }

    async fn receive(udp: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buffer = [0; 2048];
        let (size, from) = timeout(WAIT, udp.recv_from(&mut buffer)).await.expect("a datagram in time").unwrap();
        (buffer[..size].to_vec(), from)
    }

    async fn until(done: impl Fn() -> bool) {
        let waited = timeout(WAIT, async {
            while !done() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        waited.await.expect("the condition holds in time");
    }

    fn code(reply: &RelayPacket) -> (u32, ErrorCode) {
        match reply {
            RelayPacket::Error { id, code, .. } => (*id, *code),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    /// A session of the default policy, which may reach private addresses when `private` is set.
    fn admitted(private: bool) -> BasicSession {
        Basic { allow_private_targets: private, ..Basic::default() }.admit(IpAddr::from([127, 0, 0, 1])).unwrap()
    }

    #[tokio::test]
    async fn a_bind_answers_with_the_address_it_took() {
        let (_any, reply) = Opening::new(Probe::open()).start().await;
        let RelayPacket::Socket { id: 1, socket: SOCKET, local, remote: None } = reply else { panic!("{reply:?}") };
        assert_eq!(local.ip(), ip("127.0.0.1"));
        assert_ne!(local.port(), 0, "port 0 takes a free port");

        let wanted = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let (_named, reply) = Opening { local: wanted, ..Opening::new(Probe::open()) }.start().await;
        assert!(matches!(reply, RelayPacket::Socket { local, .. } if local == wanted), "{reply:?}");

        let (_held, taken) = outside().await;
        let (mut refused, reply) = Opening { local: taken, ..Opening::new(Probe::open()) }.start().await;
        assert_eq!(code(&reply), (1, ErrorCode::ADDRESS_IN_USE));
        assert!(refused.ended().await.is_err());
    }

    #[tokio::test]
    async fn a_bind_the_policy_refuses_is_answered_with_the_policy_s_code() {
        let (mut refused, reply) = Opening { local: sa("127.0.0.1:53"), ..Opening::new(admitted(false)) }.start().await;
        assert_eq!(code(&reply), (1, ErrorCode::REFUSED));
        assert!(refused.ended().await.is_err());
    }

    #[tokio::test]
    async fn a_packet_goes_each_way_on_the_stream_and_names_its_source() {
        let (harness, local, mut stream) = Opening::new(Probe::open()).bind().await;
        let (peer, peer_address) = outside().await;

        stream.send(Some(peer_address), b"up").await;
        assert_eq!(receive(&peer).await, (b"up".to_vec(), local));
        peer.send_to(b"down", local).await.unwrap();
        assert_eq!(stream.next().await, (Some(peer_address), b"down".to_vec()));

        // A packet that names another socket is dropped, and the next passes.
        stream.send_as(SOCKET + 1, Some(peer_address), b"astray").await;
        stream.send(Some(peer_address), b"again").await;
        assert_eq!(receive(&peer).await.0, b"again");
        assert_eq!(harness.metric(Counter::UdpUploadIdMismatch), 1);
        let counted = [Counter::BytesUp, Counter::BytesDown, Counter::UdpBytesDelivered].map(|c| harness.metric(c));
        assert_eq!(counted, [7, 4, 11]);
    }

    #[tokio::test]
    async fn a_socket_whose_stream_cannot_open_falls_back_to_datagrams() {
        let (mut harness, reply) = Opening { refuse_streams: true, ..Opening::new(Probe::open()) }.start().await;
        let RelayPacket::Socket { local, .. } = reply else { panic!("{reply:?}") };
        let (peer, peer_address) = outside().await;

        peer.send_to(b"down", local).await.unwrap();
        let datagram = harness.client.datagram().await;
        let packet = UdpPacket::decode(&datagram).unwrap();
        assert_eq!((packet.socket, packet.remote, packet.data), (SOCKET, Some(peer_address), &b"down"[..]));

        harness.queue(peer_address, b"up").await;
        assert_eq!(receive(&peer).await, (b"up".to_vec(), local));
    }

    #[tokio::test]
    async fn the_stream_only_carrier_sends_on_a_stream_toward_the_client_or_refuses_the_socket() {
        let opening = || Opening { carrier: UdpCarrier::UniStreamRequired, ..Opening::new(Probe::open()) };
        let (mut harness, reply) = opening().start().await;
        let RelayPacket::Socket { local, .. } = reply else { panic!("{reply:?}") };
        let mut stream = UdpStream::take(&mut harness.client, Opened::Uni).await;
        let (peer, peer_address) = outside().await;
        peer.send_to(b"down", local).await.unwrap();
        assert_eq!(stream.next().await, (Some(peer_address), b"down".to_vec()));
        harness.queue(peer_address, b"up").await;
        assert_eq!(receive(&peer).await, (b"up".to_vec(), local));

        let (mut refused, reply) = Opening { refuse_streams: true, ..opening() }.start().await;
        assert_eq!(code(&reply), (1, ErrorCode::NO_STREAM));
        assert!(refused.ended().await.is_err());
    }

    #[tokio::test]
    async fn a_client_that_does_not_read_holds_back_only_its_own_direction() {
        const PAYLOAD: usize = 1000;
        let (harness, local, mut stream) = Opening::new(Probe::open()).bind().await;
        let (peer, peer_address) = outside().await;
        // The length, the socket id, an IPv4 address and the payload's length come ahead of each payload. The pump
        // counts a datagram before it writes it, so it stops on the first one the stream has no room for.
        let frame = 4 + 4 + 7 + 4 + PAYLOAD;
        let stalled = ((STREAM_BUFFER / frame + 1) * PAYLOAD) as u64;
        for _ in 0..STREAM_BUFFER / frame + 5 {
            peer.send_to(&[0; PAYLOAD], local).await.unwrap();
        }
        until(|| harness.metric(Counter::BytesDown) == stalled).await;

        stream.send(Some(peer_address), b"through").await;
        assert_eq!(receive(&peer).await, (b"through".to_vec(), local));
        assert_eq!(harness.metric(Counter::BytesDown), stalled);
    }

    #[tokio::test]
    async fn a_connected_socket_sends_with_no_address_and_a_disconnect_keeps_its_port() {
        let (mut harness, local, mut stream) = Opening::new(Probe::open()).bind().await;
        let (peer, peer_address) = outside().await;
        let (other, other_address) = outside().await;

        let connect = ClientPacket::UdpConnect { id: 2, socket: SOCKET, remote: peer_address };
        assert_eq!(harness.ask(connect).await, RelayPacket::Ok { id: 2 });
        stream.send(None, b"to the peer").await;
        assert_eq!(receive(&peer).await, (b"to the peer".to_vec(), local));
        // The system takes a connected socket's datagrams from its peer only.
        other.send_to(b"stray", local).await.unwrap();
        peer.send_to(b"reply", local).await.unwrap();
        assert_eq!(stream.next().await, (Some(peer_address), b"reply".to_vec()));

        assert_eq!(harness.ask(ClientPacket::UdpDisconnect { id: 3, socket: SOCKET }).await, RelayPacket::Ok { id: 3 });
        assert_eq!(harness.metric(Counter::UdpDisconnects), 1);
        stream.send(None, b"nowhere").await;
        stream.send(Some(other_address), b"after").await;
        assert_eq!(receive(&other).await, (b"after".to_vec(), local), "the port the client was told is kept");
        assert!(peer.try_recv_from(&mut [0; 16]).is_err(), "a packet with no address went nowhere");

        // With no peer left, a disconnect changes nothing.
        assert_eq!(harness.ask(ClientPacket::UdpDisconnect { id: 4, socket: SOCKET }).await, RelayPacket::Ok { id: 4 });
        other.send_to(b"kept", local).await.unwrap();
        assert_eq!(stream.next().await, (Some(other_address), b"kept".to_vec()));
    }

    #[tokio::test]
    async fn a_destination_the_policy_refuses_is_dropped_and_the_next_packet_passes() {
        let (refused, refused_address) = outside().await;
        let (passed, passed_address) = outside().await;
        let (mut harness, _, mut stream) = Opening::new(Probe::refusing(refused_address)).bind().await;

        stream.send(Some(refused_address), b"refused").await;
        stream.send(Some(passed_address), b"passed").await;
        assert_eq!(receive(&passed).await.0, b"passed");
        // The pump sends in order and loopback delivers at once, so a sent packet would be there by now.
        assert!(refused.try_recv_from(&mut [0; 16]).is_err());

        let connect = ClientPacket::UdpConnect { id: 2, socket: SOCKET, remote: refused_address };
        assert_eq!(code(&harness.ask(connect).await), (2, ErrorCode::REFUSED));
    }

    // Two sockets bound to [::] on a relay that holds IPv6: an app that matches replies by address (STUN, uTP, a DHT)
    // needs the reply to come from the address it dialed.
    #[tokio::test]
    async fn a_hairpin_reply_comes_from_the_address_the_sender_dialed() {
        let relay = Shared::new(Config { own_addresses: vec![ip(OWN), ip("3000:1:2::1")], ..Config::default() });
        let opening = || Opening { relay: relay.clone(), local: sa("[::]:0"), ..Opening::new(Probe::open()) };
        let (_a, _, mut a) = opening().bind().await;
        let (_b, b_local, mut b) = opening().bind().await;
        let b_port = b_local.port();
        for (dialed, reply_from) in [
            (OWN, "[::ffff:203.0.113.7]"),
            ("[::ffff:203.0.113.7]", "[::ffff:203.0.113.7]"),
            ("[3000:1:2::1]", "[3000:1:2::1]"),
        ] {
            a.send(Some(sa(&format!("{dialed}:{b_port}"))), b"x").await;
            let (a_as_b_sees_it, _) = b.next().await;
            b.send(a_as_b_sees_it, b"y").await;
            let (reply, _) = a.next().await;
            assert_eq!(reply, Some(sa(&format!("{reply_from}:{b_port}"))), "a reply to {dialed}");
        }
    }

    #[tokio::test]
    async fn a_socket_connected_onto_a_relay_socket_that_closed_ends_at_its_next_send() {
        let relay = Shared::new(Config { own_addresses: vec![ip(OWN)], ..Config::default() });
        let (mut a, _, mut a_stream) = Opening { relay: relay.clone(), ..Opening::new(Probe::holding()) }.bind().await;
        let (mut b, b_local, mut b_stream) = Opening { relay, ..Opening::new(Probe::open()) }.bind().await;

        let connect =
            ClientPacket::UdpConnect { id: 2, socket: SOCKET, remote: sa(&format!("{OWN}:{}", b_local.port())) };
        assert_eq!(a.ask(connect).await, RelayPacket::Ok { id: 2 });
        a.handle.policy.up.add_permits(1);
        a_stream.send(None, b"first").await;
        assert_eq!(b_stream.next().await.1, b"first");

        // The route was live when the packet left for pacing, and is not by the time it is sent.
        a_stream.send(None, b"second").await;
        until(|| a.handle.policy.paced().len() == 2).await;
        assert_eq!(b.ask(ClientPacket::UdpClose { id: 2, socket: SOCKET }).await, RelayPacket::Ok { id: 2 });
        a.handle.policy.up.add_permits(1);
        assert!(a.ended().await.is_ok());
        assert_eq!(a.metric(Counter::BytesUp), 5, "the second packet was not sent");
    }

    #[tokio::test]
    async fn a_send_checks_the_lease_right_before_it_goes() {
        let hairpin = Hairpin::new(vec![ip(OWN)]);
        let (receiver, target) = outside().await;
        let (sender, _) = outside().await;
        let bound = hairpin.register(Proto::Udp, target);
        let route =
            crate::hairpin::route(&hairpin, &Probe::open(), Proto::Udp, sa(&format!("{OWN}:{}", target.port())));
        let route = route.unwrap();
        assert!(route.lease.is_some());

        let to_target = || send_revalidated(&sender, Some(route.dial), || route.lease, &hairpin, b"ping");
        assert!(matches!(to_target().await, LeaseSend::Sent(4)));
        assert_eq!(receive(&receiver).await.0, b"ping");
        sender.connect(route.dial).await.unwrap();
        let connected = || send_revalidated(&sender, None, || route.lease, &hairpin, b"hi");
        assert!(matches!(connected().await, LeaseSend::Sent(2)));
        assert!(matches!(send_revalidated(&sender, None, || None, &hairpin, b"x").await, LeaseSend::Sent(1)));

        drop(bound);
        assert!(matches!(to_target().await, LeaseSend::Stale));
        assert!(matches!(connected().await, LeaseSend::Stale));
        assert!(matches!(send_revalidated(&sender, None, || None, &hairpin, b"x").await, LeaseSend::Sent(1)));
    }

    #[tokio::test]
    async fn a_disconnect_keeps_the_port_and_drops_the_lease_only_with_the_peer() {
        let (udp, bound) = bind_port_locked(sa("127.0.0.1:0")).await.unwrap();
        let hairpin = Hairpin::new(vec![ip(OWN)]);
        let _bound = hairpin.register(Proto::Udp, bound);
        let route = hairpin.own_route(Proto::Udp, sa(&format!("{OWN}:{}", bound.port()))).unwrap().unwrap();
        let connected = Mutex::new(route.lease);

        assert_eq!(disconnect(&udp, bound, &connected), (Ok(()), false));
        assert!(connected.lock().unwrap().is_some(), "a socket with no peer keeps its lease");

        let (_peer, peer_address) = outside().await;
        udp.connect(peer_address).await.unwrap();
        assert_eq!(disconnect(&udp, bound, &connected), (Ok(()), false));
        assert!(connected.lock().unwrap().is_none());
        assert!(udp.peer_addr().is_err());
        assert_eq!(udp.local_addr().unwrap(), bound);
    }

    #[tokio::test]
    async fn a_port_0_bind_locks_the_port_it_was_given_against_a_kernel_disconnect() {
        let (_peer, peer_address) = outside().await;
        // The control: a port the system gave is lost on a disconnect, with or without a peer.
        for connected in [false, true] {
            let unlocked = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            if connected {
                unlocked.connect(peer_address).await.unwrap();
            }
            kernel_disconnect(&unlocked).unwrap();
            assert_eq!(unlocked.local_addr().unwrap().port(), 0, "connected: {connected}");
        }

        for connected in [false, true] {
            let (udp, bound) = bind_port_locked(sa("127.0.0.1:0")).await.unwrap();
            assert_ne!(bound.port(), 0);
            if connected {
                udp.connect(peer_address).await.unwrap();
            }
            kernel_disconnect(&udp).unwrap();
            assert_eq!(udp.local_addr().unwrap(), bound, "connected: {connected}");
        }
    }

    #[tokio::test]
    async fn options_are_applied_and_buffer_sizes_clamped() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let policy = Probe::open();
        for option in [
            UdpOption::Ttl(7),
            UdpOption::MulticastLoopV4(false),
            UdpOption::SendBufferSize(u32::MAX),
            UdpOption::RecvBufferSize(u32::MAX),
        ] {
            set_option(&udp, &policy, option).unwrap();
        }
        assert_eq!(udp.ttl().unwrap(), 7);
        assert!(!udp.multicast_loop_v4().unwrap());
        // Linux doubles the size it is given, and reports that.
        let sizes = [SockRef::from(&udp).send_buffer_size().unwrap(), SockRef::from(&udp).recv_buffer_size().unwrap()];
        assert_eq!(sizes, [2 * MAX_CLIENT_SOCKET_BUFFER_BYTES; 2]);
    }

    #[tokio::test]
    async fn options_are_answered_and_an_unknown_one_is_unsupported() {
        let (mut harness, ..) = Opening::new(Probe::open()).bind().await;
        let options = [UdpOption::Ttl(64), UdpOption::MulticastTtlV4(2), UdpOption::RecvBufferSize(1 << 30)];
        for (id, option) in (2..).zip(options) {
            assert_eq!(harness.set(id, option).await, RelayPacket::Ok { id });
        }
        assert_eq!(code(&harness.set(9, UdpOption::Unknown(42)).await), (9, ErrorCode::UNSUPPORTED));
    }

    #[tokio::test]
    async fn broadcast_and_multicast_groups_follow_the_policy() {
        let (mut harness, ..) = Opening::new(admitted(false)).bind().await;
        assert_eq!(code(&harness.set(2, UdpOption::Broadcast(true)).await), (2, ErrorCode::REFUSED));
        assert_eq!(harness.set(3, UdpOption::Broadcast(false)).await, RelayPacket::Ok { id: 3 });
        let v4 = UdpOption::AddMembershipV4 { group: "239.1.2.3".parse().unwrap(), interface: Ipv4Addr::UNSPECIFIED };
        assert_eq!(code(&harness.set(4, v4).await), (4, ErrorCode::REFUSED));
        let v6 = UdpOption::AddMembershipV6 { group: "ff02::1:3".parse().unwrap(), interface: 0 };
        assert_eq!(code(&harness.set(5, v6).await), (5, ErrorCode::REFUSED));

        let (mut harness, ..) = Opening::new(admitted(true)).bind().await;
        assert_eq!(harness.set(2, UdpOption::Broadcast(true)).await, RelayPacket::Ok { id: 2 });
    }

    #[tokio::test]
    async fn each_direction_waits_on_the_pacing_hook() {
        let (harness, local, mut stream) = Opening::new(Probe::holding()).bind().await;
        let (peer, peer_address) = outside().await;
        let policy = &harness.handle.policy;

        stream.send(Some(peer_address), b"up").await;
        until(|| policy.paced() == [(Direction::Up, 2)]).await;
        assert_eq!(harness.metric(Counter::BytesUp), 0, "held in the hook");
        policy.up.add_permits(1);
        assert_eq!(receive(&peer).await.0, b"up");

        peer.send_to(b"down!", local).await.unwrap();
        until(|| policy.paced().len() == 2).await;
        assert_eq!(policy.paced()[1], (Direction::Down, 5));
        assert_eq!(harness.metric(Counter::UdpBytesDelivered), 2, "held in the hook");
        policy.down.add_permits(1);
        assert_eq!(stream.next().await, (Some(peer_address), b"down!".to_vec()));
    }

    #[tokio::test]
    async fn the_upload_budget_sheds_a_packet_it_cannot_hold_and_frees_once_one_is_sent() {
        let (harness, _, mut stream) = Opening { budget: 8, ..Opening::new(Probe::holding()) }.bind().await;
        let (peer, peer_address) = outside().await;
        let budget = harness.handle.upload_budget.clone();

        stream.send(Some(peer_address), b"aaaaaa").await;
        until(|| harness.handle.policy.paced().len() == 1).await;
        assert_eq!(budget.available_permits(), 2, "held while it waits on pacing");
        stream.send(Some(peer_address), b"bbbbbb").await;
        until(|| harness.metric(Counter::UdpUploadShed) == 1).await;

        harness.handle.policy.up.add_permits(2);
        assert_eq!(receive(&peer).await.0, b"aaaaaa");
        until(|| budget.available_permits() == 8).await;
        stream.send(Some(peer_address), b"cccccc").await;
        assert_eq!(receive(&peer).await.0, b"cccccc");
    }

    #[tokio::test]
    async fn a_close_ends_the_socket_and_its_stream_and_frees_the_port_before_it_is_answered() {
        let (mut harness, local, mut stream) = Opening::new(Probe::open()).bind().await;
        // A full reply queue holds the answer back, so the port must be free while the answer still waits.
        let mut held = 0;
        while harness.handle.replies.try_send(RelayPacket::Draining).is_ok() {
            held += 1;
        }
        harness.requests.send(ClientPacket::UdpClose { id: 2, socket: SOCKET }).await.unwrap();
        until(|| std::net::UdpSocket::bind(local).is_ok()).await;
        for _ in 0..held {
            assert_eq!(harness.reply().await, RelayPacket::Draining);
        }
        assert_eq!(harness.reply().await, RelayPacket::Ok { id: 2 });
        assert!(harness.ended().await.is_ok());
        let read = timeout(WAIT, stream.recv.read(&mut [0; 1])).await.expect("the stream ends in time");
        assert_eq!(read.unwrap(), 0);
    }
}
