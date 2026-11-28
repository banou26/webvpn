//! An IP tunnel: the end a forwarder gave a client, and the pumps between it and the tunnel's stream.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::Instant;
use webvpn_proto::{ip, ClientPacket, ErrorCode, RelayPacket};

use crate::flow::{Flows, MAX_FLOWS};
use crate::metrics::Counter;
use crate::packet;
use crate::policy::{Direction, Proto, Refusal, Session};
use crate::session::{error, SessionHandle};
use crate::transport::{open_ip_bi_with_prefix, SendHalf, Transport};

/// Where a relay's IP tunnels send their packets and where the packets for them come from, such as a TUN device. A
/// relay has one, in [`Config::forwarder`](crate::Config::forwarder), and offers tunnels only with one.
///
/// The relay does every check and all the accounting: a packet reaches [`send`](Self::send) only once its frame,
/// its header, its source and its destination passed, and the policy metered it.
pub trait Forwarder: Send + Sync + 'static {
    /// The largest packet a tunnel carries, its `mtu`, which the client is told. At least 1280: a forwarder under it
    /// has its tunnels refused.
    fn mtu(&self) -> u16;

    /// Gives a new tunnel its end. Called once the policy gave the tunnel its permit; a refusal, `CAPACITY` when no
    /// address is free for example, reaches the client under the request's id.
    fn attach(&self) -> Result<TunnelEnd, Refusal>;

    /// One whole packet from a tunnel toward its destination. It is called on the async runtime and must return at
    /// once, never waiting: a forwarder that cannot take the packet now drops it, as a link does.
    fn send(&self, packet: &[u8]);

    /// The ports the forwarder's network sends to tunnels, from the first to the last, when it gives tunnels public
    /// ports. The relay binds no socket of its own there: what anyone sends to such a port reaches a tunnel.
    fn public_ports(&self) -> Option<RangeInclusive<u16>> {
        None
    }
}

/// Refuses to bind a UDP socket or a listener on one of the ports `forwarder` sends to tunnels.
pub(crate) fn check_bind(forwarder: Option<&dyn Forwarder>, local: SocketAddr) -> Result<(), Refusal> {
    match forwarder.and_then(|forwarder| forwarder.public_ports()) {
        Some(ports) if ports.contains(&local.port()) => {
            Err(Refusal::new(ErrorCode::ADDRESS_IN_USE, "the port is one of the relay's IP tunnels'"))
        }
        _ => Ok(()),
    }
}

/// One tunnel's end, as a [`Forwarder`] attached it.
///
/// The relay holds it while the tunnel is open and drops it when the tunnel ends, however it ends, which closes
/// `packets`: the forwarder takes the addresses back once its sender reads as closed (`Sender::is_closed`, or
/// `Sender::closed` resolving). A forwarder that drops the sender ends the tunnel, and the client is told `Closed`.
#[derive(Debug)]
pub struct TunnelEnd {
    /// The client's IPv4 address, for a tunnel that carries IPv4.
    pub ipv4: Option<Ipv4Addr>,
    /// The client's IPv6 address, for a tunnel that carries IPv6. At least one of the two is set.
    pub ipv6: Option<Ipv6Addr>,
    /// The tunnel's public ports, `ports` of them from `first_port` on, or `ports` 0 for none: a TCP or UDP packet that
    /// reaches the relay's public address on one of them reaches the tunnel's IPv4 address on the same port, as the
    /// forwarder's network maps it. The relay gives them to the client only with an IPv4 address in
    /// [`Config::own_addresses`](crate::Config::own_addresses), which it names as the public one, and only when the
    /// policy lets the session bind every one of them, in TCP and in UDP ([`Session::check_bind`]). Otherwise the
    /// tunnel has none.
    pub first_port: u16,
    pub ports: u16,
    /// The packets that arrive for those addresses, each one whole packet of at most the `mtu`. The forwarder sends
    /// with `try_send` and drops a packet the channel has no room for, so a slow client never holds it.
    pub packets: mpsc::Receiver<Vec<u8>>,
}

/// The bytes of packets one tunnel holds toward its client, beyond what its stream holds. Short, as a link's queue
/// is, so that what flows through the tunnel learns of a slow client from loss within a few dozen milliseconds:
/// about 44 packets of 1500 bytes, 50 ms at 10 Mbit/s.
const QUEUE_BYTES: usize = 64 * 1024;

/// Runs a tunnel a client asked for. `requests` yields its `IpOpen` first.
pub(crate) async fn open<T: Transport, S: Session>(
    session: Arc<SessionHandle<T, S>>,
    socket: u32,
    mut requests: mpsc::Receiver<ClientPacket>,
) -> Result<()> {
    let Some(ClientPacket::IpOpen { id }) = requests.recv().await else {
        bail!("a tunnel's first request is not its open");
    };
    let Some(forwarder) = session.relay.config.forwarder.clone() else {
        bail!("a tunnel opened on a relay with no forwarder");
    };
    let mtu = forwarder.mtu();
    let attached = if mtu < ip::MIN_MTU {
        Err(Refusal::new(ErrorCode::OTHER, "the relay's forwarder carries packets under 1280 bytes"))
    } else {
        forwarder.attach()
    };
    let mut end = match attached {
        Ok(end) => end,
        Err(refusal) => {
            let code = refusal.code.0;
            session.reply(error(id, refusal)).await;
            bail!("the tunnel was not attached: code {code}");
        }
    };
    let streams = match open_ip_bi_with_prefix(&*session.transport, socket).await {
        Ok(streams) => streams,
        Err(failure) => {
            let refusal = Refusal::new(ErrorCode::NO_STREAM, "the tunnel's stream could not be opened in time");
            session.reply(error(id, refusal)).await;
            return Err(failure);
        }
    };
    let public_ipv4 = public_address(&session, &end);
    if public_ipv4.is_none() {
        (end.first_port, end.ports) = (0, 0);
    }
    let opened = RelayPacket::IpTunnel {
        id,
        socket,
        mtu,
        ipv4: end.ipv4,
        ipv6: end.ipv6,
        public_ipv4,
        public_ipv6: None,
        first_port: end.first_port,
        ports: end.ports,
    };
    session.reply(opened).await;
    run(&session, &*forwarder, socket, usize::from(mtu), requests, end, streams).await;
    Ok(())
}

/// The relay's public IPv4 address, when the tunnel has public ports, the relay has such an address and the policy
/// lets the session bind each of the ports there, in TCP and in UDP.
fn public_address<T: Transport, S: Session>(session: &SessionHandle<T, S>, end: &TunnelEnd) -> Option<Ipv4Addr> {
    if end.ports == 0 || end.ipv4.is_none() {
        return None;
    }
    let public = session.relay.hairpin.own_addresses().into_iter().find_map(|address| match address {
        IpAddr::V4(address) => Some(address),
        IpAddr::V6(_) => None,
    })?;
    let mut ports = (0..end.ports).map(|offset| end.first_port.wrapping_add(offset));
    let bound = ports.all(|port| {
        let local = SocketAddr::from((public, port));
        [Proto::Tcp, Proto::Udp].into_iter().all(|proto| session.policy.check_bind(proto, local).is_ok())
    });
    bound.then_some(public)
}

/// Moves packets both ways until the client closes the tunnel, its stream ends or the forwarder ends it.
async fn run<T: Transport, S: Session>(
    session: &SessionHandle<T, S>,
    forwarder: &dyn Forwarder,
    socket: u32,
    mtu: usize,
    mut requests: mpsc::Receiver<ClientPacket>,
    mut end: TunnelEnd,
    (mut send, mut recv): (T::Send, T::Recv),
) {
    let metrics = &session.relay.metrics;
    let (ipv4, ipv6) = (end.ipv4, end.ipv6);
    let budget = Arc::new(Semaphore::new(QUEUE_BYTES));
    let (queue, mut queued) = mpsc::unbounded_channel();
    let flows = Mutex::new(Flows::new(MAX_FLOWS, end.first_port, end.ports));

    let mut from_forwarder = Box::pin(async {
        while let Some(packet) = end.packets.recv().await {
            if packet.len() > mtu {
                metrics.count(Counter::IpDroppedTooLong);
                continue;
            }
            if let Err(dropped) = flows.lock().unwrap().admit(&packet, ipv4, ipv6, Instant::now()) {
                metrics.count(dropped);
                continue;
            }
            // an empty packet still takes a place, so the queue's bytes bound its packets too
            let charge = packet.len().max(1) as u32;
            match budget.clone().try_acquire_many_owned(charge) {
                Ok(reservation) => drop(queue.send((packet, reservation))),
                Err(_) => metrics.count(Counter::IpDroppedQueueFull),
            }
        }
    });

    let to_client = &mut send;
    let mut writer = Box::pin(async move {
        let mut frame = Vec::new();
        while let Some((packet, _reservation)) = queued.recv().await {
            // Counted and metered as it leaves the queue, so a packet the full queue drops is neither. While a policy
            // that paces waits here, the packet keeps its place in the queue, so the queue fills and drops the newest,
            // and the forwarder's channel stays empty.
            metrics.add(Counter::BytesDown, packet.len() as u64);
            session.policy.relayed(Direction::Down, packet.len()).await;
            frame.clear();
            ip::encode(&packet, &mut frame);
            if to_client.write_all(&frame).await.is_err() {
                return;
            }
            metrics.count(Counter::IpPacketsDown);
        }
    });

    let mut from_client = Box::pin(async {
        let mut rate = session.relay.config.max_tunnel_packets_per_second.map(PacketRate::new);
        let mut buf = vec![0; mtu];
        loop {
            let Ok(length) = recv.read_u16().await else { return };
            let length = usize::from(length);
            if length > mtu {
                metrics.count(Counter::IpDroppedTooLong);
                let skipped = tokio::io::copy(&mut (&mut recv).take(length as u64), &mut tokio::io::sink()).await;
                if skipped.ok() != Some(length as u64) {
                    return;
                }
                continue;
            }
            let packet = &mut buf[..length];
            if recv.read_exact(packet).await.is_err() {
                return;
            }
            if rate.as_mut().is_some_and(|rate| !rate.take()) {
                metrics.count(Counter::IpDroppedRate);
                continue;
            }
            let ((proto, target), header) = match packet::check(packet, ipv4, ipv6) {
                Ok(checked) => checked,
                Err(dropped) => {
                    metrics.count(dropped);
                    continue;
                }
            };
            // The relay's own addresses are never asked about (see `Session::check_egress`), and a tunnel reaches no
            // socket bound on them.
            let own = session.relay.hairpin.own_route(proto, target).is_some();
            if own || session.policy.check_egress(proto, target).is_err() {
                metrics.count(Counter::IpDroppedRefused);
                continue;
            }
            metrics.add(Counter::BytesUp, length as u64);
            session.policy.relayed(Direction::Up, length).await;
            flows.lock().unwrap().sent(&header, Instant::now());
            forwarder.send(packet);
            metrics.count(Counter::IpPacketsUp);
        }
    });

    let mut closing = None;
    let ended_alone = loop {
        tokio::select! {
            request = requests.recv() => match request {
                Some(ClientPacket::IpClose { id, .. }) => {
                    closing = Some(id);
                    break false;
                }
                // the session hands a tunnel only the requests of its kind
                Some(_) => {}
                None => break false,
            },
            () = &mut from_forwarder => break true,
            () = &mut writer => break true,
            () = &mut from_client => break true,
        }
    };

    drop((from_forwarder, writer, from_client));
    if closing.is_some() {
        send.abandon();
    }
    // The addresses go back before the client is answered, so a tunnel it opens next may be given them.
    drop(end);
    drop((send, recv));
    if let Some(id) = closing {
        session.reply(RelayPacket::Ok { id }).await;
    }
    if ended_alone {
        session.reply(RelayPacket::Closed { socket, code: ErrorCode::OTHER }).await;
    }
    session.answer_left(&mut requests).await;
}

/// A ceiling on the packets one tunnel takes from its client, as a bucket of a second's worth that refills as time
/// passes. A packet costs the relay a check and a send whatever its size, so a stream of tiny ones, cheap in bytes,
/// is bounded here.
struct PacketRate {
    per_second: f64,
    tokens: f64,
    at: Instant,
}

impl PacketRate {
    fn new(per_second: u32) -> Self {
        let per_second = f64::from(per_second);
        Self { per_second, tokens: per_second, at: Instant::now() }
    }

    /// Whether one more packet passes now.
    fn take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + (now - self.at).as_secs_f64() * self.per_second).min(self.per_second);
        self.at = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    use tokio::io::{AsyncRead, DuplexStream};
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use webvpn_proto::{features, Hello};

    use super::*;
    use crate::packet::tests::{ports, ports_back, v4, v6, CLIENT_V4, CLIENT_V6};
    use crate::policy::{Auth, Proto, Slot, SocketKind};
    use crate::relay::{Config, Shared};
    use crate::session::{run, Setup, UdpCarrier};
    use crate::testing::{self, Client, Control, Opened, TestForwarder, PUBLIC_PORTS, WAIT};

    const MTU: u16 = 1400;
    const SITE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
    const REFUSED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 66);
    const OWN: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
    const UDP: u8 = 17;
    const TCP: u8 = 6;
    const ICMP: u8 = 1;
    const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 254);
    /// The one port the test's policy refuses to bind, in UDP only.
    const REFUSED_PORT: u16 = PUBLIC_PORTS + 5;

    /// A policy that refuses one destination, notes what it is asked and the bytes it meters each way, accepts the
    /// credential `ok`, and holds a permit for each open socket.
    #[derive(Clone, Default)]
    struct Metered {
        held: Arc<AtomicUsize>,
        kinds: Arc<Mutex<Vec<SocketKind>>>,
        asked: Arc<Mutex<Vec<(Proto, SocketAddr)>>>,
        up: Arc<AtomicUsize>,
        down: Arc<AtomicUsize>,
        /// When set, how long it holds each packet toward the client before letting it move, as a policy that paces.
        pace_down: Arc<Mutex<Option<Duration>>>,
    }

    impl Metered {
        fn held(&self) -> usize {
            self.held.load(Ordering::SeqCst)
        }

        fn metered(&self) -> [usize; 2] {
            [self.up.load(Ordering::SeqCst), self.down.load(Ordering::SeqCst)]
        }
    }

    impl Session for Metered {
        type Permit = Slot;

        fn authenticate(&self, credential: &[u8]) -> Result<(), Refusal> {
            if credential == b"ok" {
                Ok(())
            } else {
                Err(Refusal::new(ErrorCode::AUTH_FAILED, "not the test's credential"))
            }
        }

        fn open_socket(&self, kind: SocketKind) -> Result<Slot, Refusal> {
            self.kinds.lock().unwrap().push(kind);
            Ok(Slot::take(&self.held, usize::MAX).expect("no ceiling"))
        }

        fn check_egress(&self, proto: Proto, target: SocketAddr) -> Result<(), Refusal> {
            self.asked.lock().unwrap().push((proto, target));
            if target.ip() == REFUSED {
                Err(Refusal::new(ErrorCode::REFUSED, "the test refuses this destination"))
            } else {
                Ok(())
            }
        }

        fn check_bind(&self, proto: Proto, local: SocketAddr) -> Result<(), Refusal> {
            if (proto, local) == (Proto::Udp, SocketAddr::from((OWN, REFUSED_PORT))) {
                Err(Refusal::new(ErrorCode::REFUSED, "the test refuses this port"))
            } else {
                Ok(())
            }
        }

        fn relayed(&self, direction: Direction, bytes: usize) -> impl std::future::Future<Output = ()> + Send {
            let metered = if direction == Direction::Up { &self.up } else { &self.down };
            metered.fetch_add(bytes, Ordering::SeqCst);
            let pace = (*self.pace_down.lock().unwrap()).filter(|_| direction == Direction::Down);
            async move {
                if let Some(pace) = pace {
                    tokio::time::sleep(pace).await;
                }
            }
        }
    }

    /// One session under test, past its hello exchange, on a relay with a forwarder.
    struct Harness {
        client: Client,
        control: Control,
        hello: Hello,
        relay: Arc<Shared>,
        policy: Metered,
        forwarder: Arc<TestForwarder>,
        ended: JoinHandle<anyhow::Result<()>>,
    }

    /// A session on a relay set up by `config`, with `forwarder` as its forwarder when there is one. A config with no
    /// own address is given `OWN`.
    async fn start(config: Config, forwarder: Option<TestForwarder>, auth: Auth, refuse_streams: bool) -> Harness {
        let offered = forwarder.is_some();
        let forwarder = Arc::new(forwarder.unwrap_or(TestForwarder::new(MTU, 0)));
        let own_addresses =
            if config.own_addresses.is_empty() { vec![OWN.into()] } else { config.own_addresses.clone() };
        let config =
            Config { forwarder: offered.then(|| forwarder.clone() as Arc<dyn Forwarder>), own_addresses, ..config };
        let (mut transport, mut client) = testing::session(IpAddr::from([192, 0, 2, 1]));
        transport.refuse_streams = refuse_streams;
        let relay = Shared::new(config);
        let policy = Metered::default();
        let setup = Setup {
            permit: Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            deadline: Instant::now() + WAIT,
        };
        let ended =
            tokio::spawn(run(Arc::new(transport), policy.clone(), relay.clone(), auth, UdpCarrier::Bidi, setup));
        let mut control = client.control().await;
        let Some(RelayPacket::Hello(hello)) = control.next().await else { panic!("the relay's first frame") };
        control.send(ClientPacket::Hello(Hello::new(0, "client under test"))).await;
        Harness { client, control, hello, relay, policy, forwarder, ended }
    }

    /// A session on a relay with a forwarder of `max_tunnels`, and the default settings otherwise.
    async fn tunnelling(max_tunnels: usize) -> Harness {
        start(Config::default(), Some(TestForwarder::new(MTU, max_tunnels)), Auth::None, false).await
    }

    /// A tunnel's stream, from the client's side.
    struct Tunnel {
        socket: u32,
        /// The public address and ports the relay named: the address, the first port and how many.
        public: (Option<Ipv4Addr>, u16, u16),
        send: DuplexStream,
        recv: DuplexStream,
    }

    impl Tunnel {
        async fn send(&mut self, packet: &[u8]) {
            self.send_frame(packet).await;
        }

        async fn send_frame(&mut self, packet: &[u8]) {
            let mut frame = Vec::new();
            ip::encode(packet, &mut frame);
            self.send.write_all(&frame).await.unwrap();
        }

        async fn next(&mut self) -> Vec<u8> {
            read_frame(&mut self.recv).await.expect("a packet in time")
        }
    }

    /// The next packet on a tunnel's stream, or `None` once the stream ended.
    async fn read_frame(recv: &mut (impl AsyncRead + Unpin)) -> Option<Vec<u8>> {
        timeout(WAIT, async {
            let length = recv.read_u16().await.ok()?;
            let mut packet = vec![0; usize::from(length)];
            recv.read_exact(&mut packet).await.ok()?;
            Some(packet)
        })
        .await
        .expect("the relay writes in time")
    }

    impl Harness {
        async fn ask(&mut self, request: ClientPacket) -> RelayPacket {
            self.control.send(request).await;
            self.control.next().await.expect("the relay answers")
        }

        /// Opens a tunnel with request `id`, which must be given the addresses of the forwarder's tunnel `index`.
        async fn open(&mut self, id: u32, index: usize) -> Tunnel {
            let answer = self.ask(ClientPacket::IpOpen { id }).await;
            let RelayPacket::IpTunnel {
                id: answered, socket, mtu, ipv4, ipv6, public_ipv4, public_ipv6, first_port, ports
            } = answer
            else {
                panic!("the open was not answered with its tunnel");
            };
            let (v4, v6) = TestForwarder::addresses(index);
            assert_eq!((answered, mtu, ipv4, ipv6, public_ipv6), (id, MTU, Some(v4), Some(v6), None));
            if ports == 0 {
                assert_eq!((public_ipv4, first_port), (None, 0), "a tunnel without ports names none");
            }
            let stream = self.client.next_stream().await;
            assert_eq!(stream.opened, Opened::IpBi);
            let mut recv = stream.recv;
            let mut named = [0; 4];
            timeout(WAIT, recv.read_exact(&mut named)).await.expect("the socket id in time").unwrap();
            assert_eq!(u32::from_be_bytes(named), socket);
            let send = stream.send.expect("a tunnel's stream goes both ways");
            Tunnel { socket, public: (public_ipv4, first_port, ports), send, recv }
        }

        fn count(&self, counter: Counter) -> u64 {
            self.relay.metrics.get(counter)
        }

        /// Resolves once the policy holds `permits`.
        async fn permits(&self, permits: usize) {
            eventually(|| self.policy.held() == permits).await;
        }
    }

    async fn eventually(done: impl Fn() -> bool) {
        let waited = async {
            while !done() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        timeout(WAIT, waited).await.expect("in time");
    }

    fn code(reply: &RelayPacket) -> (u32, ErrorCode) {
        match reply {
            RelayPacket::Error { id, code, .. } => (*id, *code),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    /// A UDP packet from the tunnel's IPv4 address to `target` at port 53.
    fn udp_to(target: Ipv4Addr) -> Vec<u8> {
        v4(CLIENT_V4, target, UDP, 0, &[], &ports(53))
    }

    /// A UDP packet from the forwarder's tunnel `tunnel` to `SITE` at port 53.
    fn udp_from(tunnel: usize) -> Vec<u8> {
        v4(TestForwarder::addresses(tunnel).0, SITE, UDP, 0, &[], &ports(53))
    }

    /// The answer to [`udp_from`] toward the forwarder's tunnel `tunnel`, `bytes` long, holding `index` past its
    /// header.
    fn toward_client(tunnel: usize, index: u16, bytes: usize) -> Vec<u8> {
        let mut payload = ports_back(53);
        payload.extend_from_slice(&index.to_be_bytes());
        payload.resize(bytes - 20, 0);
        v4(SITE, TestForwarder::addresses(tunnel).0, UDP, 0, &[], &payload)
    }

    /// An ICMP message of `kind` whose second word holds `identifier`, followed by `rest`.
    fn icmp(kind: u8, identifier: u16, rest: &[u8]) -> Vec<u8> {
        let mut message = vec![kind, 0, 0, 0];
        message.extend(identifier.to_be_bytes());
        message.extend([0, 1]);
        message.extend(rest);
        message
    }

    /// A session that may hold both tunnels of a forwarder that gives each of them 4 public ports, with `config`.
    async fn with_ports(config: Config) -> Harness {
        let mut forwarder = TestForwarder::new(MTU, 2);
        forwarder.ports = 4;
        start(Config { max_tunnels_per_session: 2, ..config }, Some(forwarder), Auth::None, false).await
    }

    /// A UDP packet from `SITE` to the forwarder's tunnel `tunnel` at `port`.
    fn udp_toward(tunnel: usize, port: u16) -> Vec<u8> {
        v4(SITE, TestForwarder::addresses(tunnel).0, UDP, 0, &[], &ports(port))
    }

    #[tokio::test]
    async fn a_packet_to_a_public_port_reaches_the_tunnel_and_its_answer_goes_back() {
        let mut harness = with_ports(Config::default()).await;
        let mut tunnel = harness.open(1, 0).await;
        assert_eq!(tunnel.public, (Some(OWN), PUBLIC_PORTS, 4));

        let past = udp_toward(0, PUBLIC_PORTS + 4);
        let inbound = udp_toward(0, PUBLIC_PORTS + 3);
        assert!(harness.forwarder.deliver(0, past));
        assert!(harness.forwarder.deliver(0, inbound.clone()));
        assert_eq!(tunnel.next().await, inbound);
        eventually(|| harness.count(Counter::IpPacketsDown) == 1).await;
        assert_eq!(harness.count(Counter::IpDroppedUnasked), 1, "one port past the block");

        let answer = v4(CLIENT_V4, SITE, UDP, 0, &[], &ports_back(PUBLIC_PORTS + 3));
        tunnel.send(&answer).await;
        assert_eq!(harness.forwarder.sent(1).await, [answer]);
        // the peer's next packet belongs to the flow it began
        assert!(harness.forwarder.deliver(0, udp_toward(0, PUBLIC_PORTS + 3)));
        assert_eq!(tunnel.next().await, udp_toward(0, PUBLIC_PORTS + 3));
    }

    #[tokio::test]
    async fn a_socket_is_not_bound_on_a_port_the_forwarder_sends_to_tunnels() {
        // two tunnels of four ports each: the eight ports from PUBLIC_PORTS on
        let mut harness = with_ports(Config::default()).await;
        let local = |port| SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        harness.control.send(ClientPacket::TcpListen { id: 1, local: local(PUBLIC_PORTS) }).await;
        assert_eq!(code(&harness.control.next().await.unwrap()), (1, ErrorCode::ADDRESS_IN_USE));
        harness.control.send(ClientPacket::UdpBind { id: 2, local: local(PUBLIC_PORTS + 7) }).await;
        assert_eq!(code(&harness.control.next().await.unwrap()), (2, ErrorCode::ADDRESS_IN_USE));
        harness.control.send(ClientPacket::UdpBind { id: 3, local: local(0) }).await;
        assert!(matches!(harness.control.next().await, Some(RelayPacket::Socket { id: 3, .. })), "any free port binds");

        let forwarder: &dyn Forwarder = &*harness.forwarder;
        for outside in [PUBLIC_PORTS - 1, PUBLIC_PORTS + 8] {
            assert!(check_bind(Some(forwarder), local(outside)).is_ok(), "{outside}");
        }
        assert!(check_bind(None, local(PUBLIC_PORTS)).is_ok(), "a relay with no forwarder binds any port");
        let none = TestForwarder::new(MTU, 2);
        assert!(check_bind(Some(&none), local(PUBLIC_PORTS)).is_ok(), "so does one whose tunnels have no ports");
    }

    #[tokio::test]
    async fn a_tunnel_whose_ports_the_policy_refuses_to_bind_has_none_and_takes_only_answers() {
        let mut harness = with_ports(Config::default()).await;
        let given = harness.open(1, 0).await;
        // the second tunnel's block holds the one port the policy refuses, in UDP only
        let mut refused = harness.open(2, 1).await;
        assert_eq!(given.public, (Some(OWN), PUBLIC_PORTS, 4));
        assert_eq!(refused.public, (None, 0, 0));
        assert!(harness.forwarder.deliver(1, udp_toward(1, PUBLIC_PORTS + 4)));
        eventually(|| harness.count(Counter::IpDroppedUnasked) == 1).await;
        refused.send(&udp_from(1)).await;
        harness.forwarder.sent(1).await;
        assert!(harness.forwarder.deliver(1, toward_client(1, 1, 100)));
        assert_eq!(refused.next().await, toward_client(1, 1, 100));
    }

    #[tokio::test]
    async fn a_relay_without_an_own_ipv4_address_gives_no_public_ports() {
        let config = Config { own_addresses: vec!["2001:db8::7".parse().unwrap()], ..Config::default() };
        let mut harness = with_ports(config).await;
        let tunnel = harness.open(1, 0).await;
        assert_eq!(tunnel.public, (None, 0, 0));
        assert!(harness.forwarder.deliver(0, udp_toward(0, PUBLIC_PORTS)));
        eventually(|| harness.count(Counter::IpDroppedUnasked) == 1).await;
    }

    #[tokio::test]
    async fn a_relay_offers_tunnels_only_with_a_forwarder_and_without_one_answers_unsupported() {
        let harness = tunnelling(1).await;
        assert_ne!(harness.hello.features & features::IP, 0);

        let mut without = start(Config::default(), None, Auth::Required, false).await;
        assert_eq!(without.hello.features & features::IP, 0);
        // unsupported comes ahead of the credential, as for any request the relay has off
        assert_eq!(code(&without.ask(ClientPacket::IpOpen { id: 1 }).await), (1, ErrorCode::UNSUPPORTED));
        assert_eq!(without.policy.held(), 0);
    }

    #[tokio::test]
    async fn a_tunnel_opens_with_its_addresses_and_mtu_and_carries_a_metered_packet_each_way() {
        let mut harness = tunnelling(1).await;
        let mut tunnel = harness.open(1, 0).await;
        assert_eq!(*harness.policy.kinds.lock().unwrap(), [SocketKind::IpTunnel]);
        assert_eq!((harness.policy.held(), harness.count(Counter::SocketsOpened)), (1, 1));

        let up = udp_to(SITE);
        tunnel.send(&up).await;
        assert_eq!(harness.forwarder.sent(1).await, std::slice::from_ref(&up));
        assert_eq!(*harness.policy.asked.lock().unwrap(), [(Proto::Udp, SocketAddr::from((SITE, 53)))]);

        // one longer than the tunnel's mtu is dropped
        assert!(harness.forwarder.deliver(0, toward_client(0, 6, usize::from(MTU) + 1)));
        let down = toward_client(0, 7, 600);
        assert!(harness.forwarder.deliver(0, down.clone()));
        assert_eq!(tunnel.next().await, down);
        eventually(|| harness.count(Counter::IpPacketsDown) == 1).await;
        assert_eq!(harness.policy.metered(), [up.len(), down.len()]);
        let counted = [Counter::IpPacketsUp, Counter::BytesUp, Counter::BytesDown, Counter::IpDroppedTooLong];
        assert_eq!(counted.map(|of| harness.count(of)), [1, up.len() as u64, down.len() as u64, 1]);
    }

    #[tokio::test]
    async fn packets_that_fail_a_check_are_dropped_and_counted_and_the_stream_stays_in_step() {
        let mut harness = tunnelling(1).await;
        let mut tunnel = harness.open(1, 0).await;
        tunnel.send(&v4(Ipv4Addr::new(198, 18, 0, 9), SITE, UDP, 0, &[], &ports(53))).await;
        tunnel.send(&udp_to(REFUSED)).await;
        tunnel.send(&udp_to(OWN)).await;
        tunnel.send_frame(&vec![0x45; usize::from(MTU) + 1]).await;
        tunnel.send(&[0x45, 0, 0]).await;
        let icmp = v4(CLIENT_V4, SITE, ICMP, 0, &[], &[8, 0, 0, 0]);
        let ipv6 = v6(CLIENT_V6, "2001:db8::9".parse().unwrap(), UDP, &ports(53));
        tunnel.send(&icmp).await;
        tunnel.send(&ipv6).await;

        let passed = icmp.len() + ipv6.len();
        assert_eq!(harness.forwarder.sent(2).await, [icmp, ipv6]);
        let dropped = [
            Counter::IpDroppedSource,
            Counter::IpDroppedRefused,
            Counter::IpDroppedTooLong,
            Counter::IpDroppedHeader,
            Counter::IpPacketsUp,
        ];
        assert_eq!(dropped.map(|of| harness.count(of)), [1, 2, 1, 1, 2]);
        // the policy is asked about the refused destination and the packets that passed, never about the relay's own
        // address or a packet that failed its checks
        let asked: Vec<_> = harness.policy.asked.lock().unwrap().iter().map(|(proto, at)| (*proto, at.ip())).collect();
        let site_v6 = "2001:db8::9".parse().unwrap();
        assert_eq!(asked, [(Proto::Udp, REFUSED.into()), (Proto::Other(ICMP), SITE.into()), (Proto::Udp, site_v6)]);
        assert_eq!(harness.policy.metered()[0], passed);
    }

    #[tokio::test(start_paused = true)]
    async fn packets_past_the_rate_ceiling_are_dropped_before_the_policy_is_asked() {
        let config = Config { max_tunnel_packets_per_second: Some(3), ..Config::default() };
        let mut harness = start(config, Some(TestForwarder::new(MTU, 1)), Auth::None, false).await;
        let mut tunnel = harness.open(1, 0).await;
        for _ in 0..5 {
            tunnel.send(&udp_to(SITE)).await;
        }
        eventually(|| harness.count(Counter::IpDroppedRate) == 2).await;
        assert_eq!(harness.forwarder.sent(3).await.len(), 3);
        assert_eq!(harness.policy.asked.lock().unwrap().len(), 3);

        // a third of a second gives one packet more
        tokio::time::advance(Duration::from_millis(340)).await;
        tunnel.send(&udp_to(SITE)).await;
        tunnel.send(&udp_to(SITE)).await;
        assert_eq!(harness.forwarder.sent(4).await.len(), 4);
        eventually(|| harness.count(Counter::IpDroppedRate) == 3).await;
    }

    #[tokio::test]
    async fn without_a_rate_ceiling_every_packet_passes() {
        let config = Config { max_tunnel_packets_per_second: None, ..Config::default() };
        let mut harness = start(config, Some(TestForwarder::new(MTU, 1)), Auth::None, false).await;
        let mut tunnel = harness.open(1, 0).await;
        for _ in 0..50 {
            tunnel.send(&udp_to(SITE)).await;
        }
        assert_eq!(harness.forwarder.sent(50).await.len(), 50);
        assert_eq!(harness.count(Counter::IpDroppedRate), 0);
    }

    #[tokio::test]
    async fn a_client_that_reads_nothing_loses_the_newest_packets_and_holds_neither_the_forwarder_nor_the_session() {
        let config = Config { max_tunnels_per_session: 2, ..Config::default() };
        let mut harness = start(config, Some(TestForwarder::new(MTU, 2)), Auth::None, false).await;
        let mut stuck = harness.open(1, 0).await;
        let mut other = harness.open(2, 1).await;
        stuck.send(&udp_from(0)).await;
        other.send(&udp_from(1)).await;
        harness.forwarder.sent(2).await;
        const SENT: u16 = 200;
        for index in 0..SENT {
            assert!(harness.forwarder.deliver(0, toward_client(0, index, 1400)), "the forwarder waits on no tunnel");
        }
        // every packet was taken from the forwarder, and so queued or dropped: nothing waits between the two
        eventually(|| harness.forwarder.waiting(0) == 0).await;
        let dropped = harness.count(Counter::IpDroppedQueueFull);
        assert!(dropped > 0);

        assert_eq!(harness.ask(ClientPacket::AuthClear { id: 3 }).await, RelayPacket::Ok { id: 3 });
        let unstuck = toward_client(1, 0, 100);
        assert!(harness.forwarder.deliver(1, unstuck.clone()));
        assert_eq!(other.next().await, unstuck);

        // what got through is in order, and starts with every packet the empty queue had room for: the newest were
        // dropped, never the oldest
        let mut through = Vec::new();
        for _ in 0..u64::from(SENT) - dropped {
            let packet = stuck.next().await;
            through.push(u16::from_be_bytes([packet[28], packet[29]]));
        }
        let fitted = (QUEUE_BYTES / 1400) as u16;
        assert_eq!(through[..usize::from(fitted)], (0..fitted).collect::<Vec<_>>());
        assert!(through.windows(2).all(|pair| pair[0] < pair[1]), "{through:?}");
        eventually(|| harness.count(Counter::IpPacketsDown) == u64::from(SENT) - dropped + 1).await;
        assert_eq!(harness.count(Counter::IpDroppedQueueFull), dropped);
        // only what reached the stream is metered and counted: what got through, and the other tunnel's packet
        let delivered = (u64::from(SENT) - dropped) * 1400 + 100;
        assert_eq!((harness.policy.metered()[1] as u64, harness.count(Counter::BytesDown)), (delivered, delivered));
    }

    #[tokio::test]
    async fn under_a_policy_that_paces_the_short_queue_fills_and_the_forwarder_s_channel_stays_empty() {
        let mut harness = tunnelling(1).await;
        let mut tunnel = harness.open(1, 0).await;
        tunnel.send(&udp_from(0)).await;
        harness.forwarder.sent(1).await;
        // a minute a packet, far longer than the test runs
        *harness.policy.pace_down.lock().unwrap() = Some(Duration::from_secs(60));
        const SENT: u16 = 200;
        for index in 0..SENT {
            assert!(harness.forwarder.deliver(0, toward_client(0, index, 1400)));
        }
        eventually(|| harness.forwarder.waiting(0) == 0).await;
        // the packet the policy holds keeps its place in the queue, so the queue drops the newest at once
        let fitted = (QUEUE_BYTES / 1400) as u64;
        assert_eq!(harness.count(Counter::IpDroppedQueueFull), u64::from(SENT) - fitted);
        // and only that packet is metered and counted yet
        eventually(|| harness.policy.metered()[1] == 1400).await;
        assert_eq!(harness.count(Counter::BytesDown), 1400);
    }

    #[tokio::test]
    async fn ip_close_answers_ok_once_the_addresses_are_back_and_again_for_a_tunnel_gone() {
        let mut harness = tunnelling(1).await;
        let mut tunnel = harness.open(1, 0).await;
        let close = ClientPacket::IpClose { id: 2, socket: tunnel.socket };
        assert_eq!(harness.ask(close).await, RelayPacket::Ok { id: 2 });
        assert_eq!(harness.forwarder.held(), 0);
        assert_eq!(read_frame(&mut tunnel.recv).await, None);
        harness.permits(0).await;
        eventually(|| harness.count(Counter::SocketsClosed) == 1).await;

        let again = ClientPacket::IpClose { id: 3, socket: tunnel.socket };
        assert_eq!(harness.ask(again).await, RelayPacket::Ok { id: 3 });
        // the next tunnel is given the same addresses under a new id
        let next = harness.open(4, 0).await;
        assert!(next.socket > tunnel.socket);
    }

    #[tokio::test]
    async fn a_tunnel_the_forwarder_ends_is_told_closed_and_gives_its_permit_back() {
        let mut harness = tunnelling(1).await;
        let tunnel = harness.open(1, 0).await;
        harness.forwarder.end(0);
        let closed = RelayPacket::Closed { socket: tunnel.socket, code: ErrorCode::OTHER };
        assert_eq!(harness.control.next().await, Some(closed));
        harness.permits(0).await;
    }

    #[tokio::test]
    async fn a_tunnel_whose_client_finishes_its_stream_ends_and_gives_everything_back() {
        let mut harness = tunnelling(1).await;
        let mut tunnel = harness.open(1, 0).await;
        tunnel.send.shutdown().await.unwrap();
        let closed = RelayPacket::Closed { socket: tunnel.socket, code: ErrorCode::OTHER };
        assert_eq!(harness.control.next().await, Some(closed));
        harness.forwarder.holds(0).await;
        harness.permits(0).await;
    }

    #[tokio::test]
    async fn a_tunnel_ends_with_its_session_however_the_session_ends_and_gives_everything_back() {
        for end in ["client", "dropped", "stop"] {
            let mut harness = tunnelling(1).await;
            let _tunnel = harness.open(1, 0).await;
            assert_eq!(harness.forwarder.held(), 1);
            match end {
                "client" => harness.control.finish().await,
                "dropped" => harness.ended.abort(),
                _ => harness.relay.closing.cancel(),
            }
            harness.forwarder.holds(0).await;
            harness.permits(0).await;
        }
    }

    #[tokio::test]
    async fn a_relay_that_requires_a_credential_opens_a_tunnel_only_after_one() {
        let mut harness = start(Config::default(), Some(TestForwarder::new(MTU, 1)), Auth::Required, false).await;
        assert_eq!(code(&harness.ask(ClientPacket::IpOpen { id: 1 }).await), (1, ErrorCode::AUTH_REQUIRED));
        assert_eq!((harness.policy.held(), harness.forwarder.held()), (0, 0));
        let accepted = harness.ask(ClientPacket::Auth { id: 2, credential: b"ok".to_vec() }).await;
        assert_eq!(accepted, RelayPacket::Ok { id: 2 });
        harness.open(3, 0).await;
    }

    #[tokio::test]
    async fn a_tunnel_the_forwarder_or_the_carrier_cannot_give_is_refused_and_keeps_nothing() {
        let mut full = tunnelling(0).await;
        assert_eq!(code(&full.ask(ClientPacket::IpOpen { id: 1 }).await), (1, ErrorCode::CAPACITY));
        full.permits(0).await;

        let mut small = start(Config::default(), Some(TestForwarder::new(1279, 1)), Auth::None, false).await;
        assert_eq!(code(&small.ask(ClientPacket::IpOpen { id: 1 }).await), (1, ErrorCode::OTHER));
        assert_eq!(small.forwarder.held(), 0);

        let mut no_room = start(Config::default(), Some(TestForwarder::new(MTU, 1)), Auth::None, true).await;
        assert_eq!(code(&no_room.ask(ClientPacket::IpOpen { id: 1 }).await), (1, ErrorCode::NO_STREAM));
        no_room.forwarder.holds(0).await;
        no_room.permits(0).await;
    }

    #[tokio::test]
    async fn a_tunnel_counts_as_one_of_the_session_s_sockets_and_takes_only_its_own_requests() {
        let config = Config { max_sockets_per_session: 1, max_tunnels_per_session: 2, ..Config::default() };
        let mut harness = start(config, Some(TestForwarder::new(MTU, 2)), Auth::None, false).await;
        let mut tunnel = harness.open(1, 0).await;
        assert_eq!(code(&harness.ask(ClientPacket::IpOpen { id: 2 }).await), (2, ErrorCode::CAPACITY));
        assert_eq!(harness.policy.held(), 1);

        let socket = tunnel.socket;
        let other_kinds = [ClientPacket::TcpClose { id: 3, socket }, ClientPacket::UdpClose { id: 3, socket }];
        for request in other_kinds {
            assert_eq!(code(&harness.ask(request).await), (3, ErrorCode::UNKNOWN_SOCKET));
        }
        tunnel.send(&udp_to(SITE)).await;
        assert_eq!(harness.forwarder.sent(1).await.len(), 1);
    }

    #[tokio::test]
    async fn a_session_holds_one_tunnel_by_default_and_one_past_its_ceiling_takes_nothing() {
        let mut harness = tunnelling(2).await;
        let tunnel = harness.open(1, 0).await;
        assert_eq!(code(&harness.ask(ClientPacket::IpOpen { id: 2 }).await), (2, ErrorCode::CAPACITY));
        // refused before the policy and the forwarder are asked
        assert_eq!(*harness.policy.kinds.lock().unwrap(), [SocketKind::IpTunnel]);
        assert_eq!((harness.policy.held(), harness.forwarder.held()), (1, 1));

        let close = ClientPacket::IpClose { id: 3, socket: tunnel.socket };
        assert_eq!(harness.ask(close).await, RelayPacket::Ok { id: 3 });
        harness.permits(0).await;
        let _reopened = harness.open(4, 0).await;
        // the ceiling counts tunnels only
        let bind = ClientPacket::UdpBind { id: 5, local: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)) };
        assert!(matches!(harness.ask(bind).await, RelayPacket::Socket { id: 5, .. }));

        let config = Config { max_tunnels_per_session: 2, ..Config::default() };
        let mut two = start(config, Some(TestForwarder::new(MTU, 3)), Auth::None, false).await;
        let _held = (two.open(1, 0).await, two.open(2, 1).await);
        assert_eq!(code(&two.ask(ClientPacket::IpOpen { id: 3 }).await), (3, ErrorCode::CAPACITY));
        assert_eq!((two.policy.held(), two.forwarder.held()), (2, 2));
    }

    #[tokio::test]
    async fn only_an_answer_to_a_flow_the_tunnel_sent_reaches_its_client_and_is_metered() {
        let mut harness = tunnelling(1).await;
        let mut tunnel = harness.open(1, 0).await;
        tunnel.send(&udp_to(SITE)).await;
        harness.forwarder.sent(1).await;

        let answer = toward_client(0, 1, 100);
        let mut other_port = answer.clone();
        other_port[21] += 1;
        let other_source = v4(Ipv4Addr::new(203, 0, 113, 10), CLIENT_V4, UDP, 0, &[], &answer[20..]);
        let other_protocol = v4(SITE, CLIENT_V4, TCP, 0, &[], &answer[20..]);
        for unasked in [other_port, other_source, other_protocol, answer.clone()] {
            assert!(harness.forwarder.deliver(0, unasked));
        }
        assert_eq!(tunnel.next().await, answer);
        eventually(|| harness.count(Counter::IpPacketsDown) == 1).await;
        assert_eq!(harness.count(Counter::IpDroppedUnasked), 3);
        assert_eq!(harness.policy.metered()[1], answer.len());
    }

    #[tokio::test]
    async fn nothing_reaches_a_tunnel_that_sent_nothing() {
        let mut harness = tunnelling(1).await;
        let mut tunnel = harness.open(1, 0).await;
        assert!(harness.forwarder.deliver(0, toward_client(0, 1, 100)));
        eventually(|| harness.count(Counter::IpDroppedUnasked) == 1).await;

        tunnel.send(&udp_to(SITE)).await;
        harness.forwarder.sent(1).await;
        let answer = toward_client(0, 2, 100);
        assert!(harness.forwarder.deliver(0, answer.clone()));
        assert_eq!(tunnel.next().await, answer);
        assert_eq!(harness.policy.metered()[1], answer.len());
    }

    #[tokio::test]
    async fn an_echo_reply_reaches_the_client_only_with_its_request_s_identifier() {
        let mut harness = tunnelling(1).await;
        let mut tunnel = harness.open(1, 0).await;
        tunnel.send(&v4(CLIENT_V4, SITE, ICMP, 0, &[], &icmp(8, 7, &[]))).await;
        harness.forwarder.sent(1).await;

        let reply = v4(SITE, CLIENT_V4, ICMP, 0, &[], &icmp(0, 7, &[]));
        assert!(harness.forwarder.deliver(0, v4(SITE, CLIENT_V4, ICMP, 0, &[], &icmp(0, 8, &[]))));
        assert!(harness.forwarder.deliver(0, reply.clone()));
        assert_eq!(tunnel.next().await, reply);
        assert_eq!(harness.count(Counter::IpDroppedUnasked), 1);
    }

    #[tokio::test]
    async fn a_time_exceeded_about_a_packet_the_tunnel_sent_reaches_its_client() {
        let mut harness = tunnelling(1).await;
        let mut tunnel = harness.open(1, 0).await;
        let sent = udp_to(SITE);
        tunnel.send(&sent).await;
        harness.forwarder.sent(1).await;

        let about_another = v4(CLIENT_V4, SITE, UDP, 0, &[], &ports(54));
        assert!(harness.forwarder.deliver(0, v4(ROUTER, CLIENT_V4, ICMP, 0, &[], &icmp(11, 0, &about_another))));
        let exceeded = v4(ROUTER, CLIENT_V4, ICMP, 0, &[], &icmp(11, 0, &sent[..28]));
        assert!(harness.forwarder.deliver(0, exceeded.clone()));
        assert_eq!(tunnel.next().await, exceeded);
        assert_eq!(harness.count(Counter::IpDroppedUnasked), 1);
    }

    #[tokio::test]
    async fn a_peer_that_answered_a_tunnel_reaches_no_later_tunnel_given_its_address() {
        let mut harness = tunnelling(1).await;
        let mut first = harness.open(1, 0).await;
        first.send(&udp_to(SITE)).await;
        harness.forwarder.sent(1).await;
        assert!(harness.forwarder.deliver(0, toward_client(0, 1, 100)));
        assert_eq!(first.next().await, toward_client(0, 1, 100));
        let close = ClientPacket::IpClose { id: 2, socket: first.socket };
        assert_eq!(harness.ask(close).await, RelayPacket::Ok { id: 2 });

        let mut second = harness.open(3, 0).await;
        assert!(harness.forwarder.deliver(0, toward_client(0, 2, 100)));
        eventually(|| harness.count(Counter::IpDroppedUnasked) == 1).await;
        // the second tunnel's own flow, to another port of the same peer, still gets its answers
        second.send(&v4(CLIENT_V4, SITE, UDP, 0, &[], &ports(54))).await;
        harness.forwarder.sent(2).await;
        let own = v4(SITE, CLIENT_V4, UDP, 0, &[], &ports_back(54));
        assert!(harness.forwarder.deliver(0, own.clone()));
        assert_eq!(second.next().await, own);
        assert_eq!(harness.count(Counter::IpDroppedUnasked), 1);
    }
}
