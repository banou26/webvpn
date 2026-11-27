use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;

use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{HardwareAddress, IpCidr, IpEndpoint};
use webvpn_proto::ErrorCode;

const EPHEMERAL: RangeInclusive<u16> = 49152..=65535;
const QUEUED_PACKETS: usize = 512;
// a socket the page let go of keeps its connection until it ends in order, at most this long
const RELEASED_MS: i64 = 60_000;
const KEEP_ALIVE_DEFAULT_SECONDS: u64 = 7200;
const UDP_BYTES_PER_SLOT: usize = 256;
const UDP_MIN_SLOTS: usize = 16;
const UNSEEN: (u8, usize, usize) = (u8::MAX, 0, 0);

const TCP: u8 = 6;
const ICMP: u8 = 1;
const ICMPV6: u8 = 58;
const RST: u8 = 0x04;

/// A call's outcome: a WebVPN `ErrorCode` for what a session's socket would have failed with.
pub type Result<T> = std::result::Result<T, ErrorCode>;

/// What a stack is given of its tunnel.
#[derive(Debug, Clone)]
pub struct Config {
    /// The tunnel's IPv4 address, for a tunnel that carries IPv4.
    pub ipv4: Option<Ipv4Addr>,
    /// The tunnel's IPv6 address, for a tunnel that carries IPv6.
    pub ipv6: Option<Ipv6Addr>,
    /// The largest packet the tunnel carries.
    pub mtu: usize,
    /// The first of the tunnel's public ports, which no private port is taken from.
    pub first_port: u16,
    /// How many public ports the tunnel holds, 0 for none.
    pub ports: u16,
    /// Seeds the initial sequence numbers and the private ports: different for every stack.
    pub seed: u64,
    /// How long a connect waits for the peer before it fails with `TIMED_OUT`.
    pub connect_timeout_ms: u32,
}

/// The sizes, in bytes, of a socket's receive and send buffers. They are fixed when the socket is made, and a TCP
/// socket's receive buffer is the most its window ever offers.
#[derive(Debug, Clone, Copy)]
pub struct Buffers {
    pub receive: usize,
    pub send: usize,
}

/// The port space a call looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// What a UDP send did with a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    Queued,
    /// The send buffer was full, or the stack has no address of the peer's family: dropped, as a network drops.
    Dropped,
}

#[derive(Default)]
struct Link {
    incoming: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct Received(Vec<u8>);

struct Sending<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::RxToken for Received {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for Sending<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

impl Device for Link {
    type RxToken<'a> = Received;
    type TxToken<'a> = Sending<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Received, Sending<'_>)> {
        let packet = self.incoming.pop_front()?;
        Some((Received(packet), Sending(&mut self.outgoing)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Sending<'_>> {
        Some(Sending(&mut self.outgoing))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

struct Tcp {
    handle: SocketHandle,
    error: Option<ErrorCode>,
    connect_by: Option<Instant>,
    /// The state the last poll left the socket in.
    state: tcp::State,
    /// A reset arrived for the connection since the last poll.
    reset: bool,
    /// The page closed or aborted it, so a connect that ends was not refused.
    ended_here: bool,
    released_at: Option<Instant>,
}

struct Listener {
    port: u16,
    backlog: usize,
    buffers: Buffers,
    /// Sockets listening on the port, or taking a connection that is not established yet.
    waiting: Vec<SocketHandle>,
    accepted: VecDeque<u32>,
}

enum Kind {
    Tcp(Tcp),
    Listener(Listener),
    Udp { handle: SocketHandle, port: u16 },
}

struct Entry {
    kind: Kind,
    seen: (u8, usize, usize),
}

/// The client's end of one IP tunnel: smoltcp on the tunnel's addresses and MTU, with TCP and UDP sockets named by
/// ids. The page owns the clock and the tunnel: it hands packets in with `input`, calls `poll` with the time, sends
/// what `output` gives, and polls again when `poll` asked, after every packet in and after every socket call.
pub struct Stack {
    config: Config,
    link: Link,
    interface: Interface,
    sockets: SocketSet<'static>,
    entries: Vec<Option<Entry>>,
    events: VecDeque<u32>,
    now: Instant,
    next_port: u32,
}

/// The number a TCP state goes by outside this crate, in smoltcp's order: 0 closed, 1 listen, 2 SYN sent, 3 SYN
/// received, 4 established, 5 FIN wait 1, 6 FIN wait 2, 7 close wait, 8 closing, 9 last ACK, 10 time wait.
pub fn state_number(state: tcp::State) -> u8 {
    use tcp::State::*;
    match state {
        Closed => 0,
        Listen => 1,
        SynSent => 2,
        SynReceived => 3,
        Established => 4,
        FinWait1 => 5,
        FinWait2 => 6,
        CloseWait => 7,
        Closing => 8,
        LastAck => 9,
        TimeWait => 10,
    }
}

struct Header<'a> {
    protocol: u8,
    source: IpAddr,
    destination: IpAddr,
    payload: &'a [u8],
}

// reads only the fixed header, so it also reads the cut packet an ICMP error quotes
fn header(packet: &[u8]) -> Option<Header<'_>> {
    match packet.first()? >> 4 {
        4 => {
            let length = usize::from(packet[0] & 0x0f) * 4;
            if length < 20 || packet.len() < length {
                return None;
            }
            Some(Header {
                protocol: packet[9],
                source: Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?).into(),
                destination: Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?).into(),
                payload: &packet[length..],
            })
        }
        6 if packet.len() >= 40 => Some(Header {
            protocol: packet[6],
            source: Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?).into(),
            destination: Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?).into(),
            payload: &packet[40..],
        }),
        _ => None,
    }
}

fn ports(payload: &[u8]) -> Option<(u16, u16)> {
    let bytes = payload.get(..4)?;
    Some((u16::from_be_bytes([bytes[0], bytes[1]]), u16::from_be_bytes([bytes[2], bytes[3]])))
}

// what Linux gives a connect for an ICMP destination unreachable; "fragmentation needed" is no failure
fn unreachable(packet: &Header) -> Option<ErrorCode> {
    let (&kind, &code) = (packet.payload.first()?, packet.payload.get(1)?);
    match (packet.protocol, kind, code) {
        (ICMP, 3, 4) => None,
        (ICMP, 3, 0 | 6 | 9 | 11) | (ICMPV6, 1, 0) => Some(ErrorCode::NETWORK_UNREACHABLE),
        (ICMP, 3, 3) | (ICMPV6, 1, 4) => Some(ErrorCode::CONNECTION_REFUSED),
        (ICMP, 3, _) | (ICMPV6, 1, _) => Some(ErrorCode::HOST_UNREACHABLE),
        _ => None,
    }
}

fn endpoint(address: SocketAddr) -> IpEndpoint {
    address.into()
}

fn socket_address(endpoint: IpEndpoint) -> SocketAddr {
    SocketAddr::new(endpoint.addr.into(), endpoint.port)
}

fn tcp_socket(buffers: Buffers) -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; buffers.receive]),
        tcp::SocketBuffer::new(vec![0; buffers.send]),
    );
    socket.set_congestion_control(tcp::CongestionControl::Cubic);
    socket
}

fn packet_buffer(bytes: usize) -> udp::PacketBuffer<'static> {
    let slots = (bytes / UDP_BYTES_PER_SLOT).max(UDP_MIN_SLOTS);
    udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; slots], vec![0; bytes])
}

impl Listener {
    /// Moves the sockets whose connection is established out of `waiting`, and keeps as many sockets listening as
    /// the backlog has room for: `backlog` less the connections being opened and those waiting to be accepted.
    fn turn(&mut self, sockets: &mut SocketSet<'static>) -> Vec<SocketHandle> {
        let mut connected = Vec::new();
        let mut listening = 0;
        let mut gone = Vec::new();
        self.waiting.retain(|&handle| match sockets.get::<tcp::Socket>(handle).state() {
            tcp::State::Listen => {
                listening += 1;
                true
            }
            tcp::State::SynReceived => true,
            tcp::State::Closed => {
                gone.push(handle);
                false
            }
            _ => {
                connected.push(handle);
                false
            }
        });
        for handle in gone {
            sockets.remove(handle);
        }
        let opening = self.waiting.len() - listening + connected.len() + self.accepted.len();
        for _ in listening..self.backlog.saturating_sub(opening) {
            let mut socket = tcp_socket(self.buffers);
            if socket.listen(self.port).is_ok() {
                self.waiting.push(sockets.add(socket));
            }
        }
        connected
    }
}

impl Stack {
    /// A stack on `config`'s tunnel, at `now_ms` on the page's clock.
    pub fn new(config: Config, now_ms: i64) -> Self {
        let mut link = Link { mtu: config.mtu, ..Link::default() };
        let mut setup = InterfaceConfig::new(HardwareAddress::Ip);
        setup.random_seed = config.seed;
        let now = Instant::from_millis(now_ms);
        let mut interface = Interface::new(setup, &mut link, now);
        interface.update_ip_addrs(|addresses| {
            if let Some(ipv4) = config.ipv4 {
                addresses.push(IpCidr::new(ipv4.into(), 32)).expect("two addresses fit");
            }
            if let Some(ipv6) = config.ipv6 {
                addresses.push(IpCidr::new(ipv6.into(), 128)).expect("two addresses fit");
            }
        });
        // a tunnel has no gateway, and smoltcp sends nothing off its own network without a route through one: the
        // tunnel's own address stands in for it, which the IP medium never looks up
        if let Some(ipv4) = config.ipv4 {
            interface.routes_mut().add_default_ipv4_route(ipv4).expect("a route fits");
        }
        if let Some(ipv6) = config.ipv6 {
            interface.routes_mut().add_default_ipv6_route(ipv6).expect("a route fits");
        }
        let next_port = (config.seed % u64::from(EPHEMERAL.len() as u32)) as u32;
        Self {
            config,
            link,
            interface,
            sockets: SocketSet::new(Vec::new()),
            entries: Vec::new(),
            events: VecDeque::new(),
            now,
            next_port,
        }
    }

    /// Takes one packet from the tunnel, which the next `poll` handles. Past 512 waiting, a packet is dropped, as a
    /// full queue drops it.
    pub fn input(&mut self, packet: &[u8]) {
        if self.link.incoming.len() >= QUEUED_PACKETS {
            return;
        }
        self.inspect(packet);
        self.link.incoming.push_back(packet.to_vec());
    }

    /// The next packet for the tunnel, in order, once a `poll` made it.
    pub fn output(&mut self) -> Option<Vec<u8>> {
        self.link.outgoing.pop_front()
    }

    /// Runs the stack at `now_ms`: takes the packets `input` held, sends what is due, ends what timed out, and notes
    /// each socket that changed for `events`. Returns how many milliseconds may pass before the next poll, `None`
    /// when nothing but a packet or a socket call needs one.
    pub fn poll(&mut self, now_ms: i64) -> Option<u64> {
        self.now = Instant::from_millis(now_ms);
        self.interface.poll(self.now, &mut self.link, &mut self.sockets);
        self.maintain();
        // sends the resets of what `maintain` ended
        self.interface.poll(self.now, &mut self.link, &mut self.sockets);
        self.settle();
        self.delay()
    }

    /// The ids of the sockets and listeners that changed since the last call, at most `max` of them; the rest wait
    /// for the next call. A changed socket may have bytes or room, a new state or an error; a changed listener may
    /// have a connection to accept.
    pub fn events(&mut self, max: usize) -> Vec<u32> {
        let count = max.min(self.events.len());
        self.events.drain(..count).collect()
    }

    /// Connects to `remote` from a free private port. Fails with `NETWORK_UNREACHABLE` when the tunnel has no address
    /// of the remote's family, and with `ADDRESS_IN_USE` when no private port is free. Whether the connection is
    /// made shows in `tcp_state` and `tcp_error`.
    pub fn tcp_connect(&mut self, remote: SocketAddr, buffers: Buffers) -> Result<u32> {
        let port = self.free_port(Protocol::Tcp).ok_or(ErrorCode::ADDRESS_IN_USE)?;
        let mut socket = tcp_socket(buffers);
        socket
            .connect(self.interface.context(), endpoint(remote), port)
            .map_err(|_| ErrorCode::NETWORK_UNREACHABLE)?;
        let handle = self.sockets.add(socket);
        let connect_by = self.now + Duration::from_millis(u64::from(self.config.connect_timeout_ms));
        Ok(self.insert(Kind::Tcp(Tcp {
            handle,
            error: None,
            connect_by: Some(connect_by),
            state: tcp::State::SynSent,
            reset: false,
            ended_here: false,
            released_at: None,
        })))
    }

    /// Listens on `port` of every address of the stack. Up to `backlog` connections may be opening or waiting for
    /// `tcp_accept` at once, each on a socket of its own; one more is refused with a reset. A connection is handed
    /// over once it is established. Fails with `ADDRESS_IN_USE` when the port has a listener, and with
    /// `ADDRESS_NOT_AVAILABLE` for port 0.
    pub fn tcp_listen(&mut self, port: u16, backlog: usize, buffers: Buffers) -> Result<u32> {
        if port == 0 {
            return Err(ErrorCode::ADDRESS_NOT_AVAILABLE);
        }
        if self.entries.iter().flatten().any(|entry| matches!(&entry.kind, Kind::Listener(l) if l.port == port)) {
            return Err(ErrorCode::ADDRESS_IN_USE);
        }
        let mut listener = Listener { port, backlog: backlog.max(1), buffers, waiting: Vec::new(), accepted: VecDeque::new() };
        listener.turn(&mut self.sockets);
        Ok(self.insert(Kind::Listener(listener)))
    }

    /// The next connection `listener` accepted, oldest first.
    pub fn tcp_accept(&mut self, listener: u32) -> Option<u32> {
        let entry = self.entry_mut(listener)?;
        let Kind::Listener(listener) = &mut entry.kind else { return None };
        let accepted = listener.accepted.pop_front()?;
        entry.seen = UNSEEN;
        Some(accepted)
    }

    /// The socket's state, as `state_number` numbers it.
    pub fn tcp_state(&self, id: u32) -> Option<tcp::State> {
        let tcp = self.tcp(id)?;
        Some(self.sockets.get::<tcp::Socket>(tcp.handle).state())
    }

    /// Why the connection failed or ended abnormally: `CONNECTION_REFUSED` for a reset or an ICMP port unreachable
    /// in answer to the opening packet, `TIMED_OUT` for a connect that got no answer in time, `HOST_UNREACHABLE` or
    /// `NETWORK_UNREACHABLE` for an ICMP error about the opening packet, `CONNECTION_RESET` for a later reset.
    pub fn tcp_error(&self, id: u32) -> Option<ErrorCode> {
        self.tcp(id)?.error
    }

    /// The local and the remote address of a connection.
    pub fn tcp_endpoints(&self, id: u32) -> Option<(SocketAddr, SocketAddr)> {
        let socket = self.sockets.get::<tcp::Socket>(self.tcp(id)?.handle);
        Some((socket_address(socket.local_endpoint()?), socket_address(socket.remote_endpoint()?)))
    }

    /// Puts as much of `data` in the send buffer as fits, and returns how much that was, 0 when it is full. Fails
    /// once the socket may not send: with its error when it has one, else `OTHER`.
    pub fn tcp_send(&mut self, id: u32, data: &[u8]) -> Result<usize> {
        let tcp = self.tcp(id).ok_or(ErrorCode::UNKNOWN_SOCKET)?;
        let error = tcp.error.unwrap_or(ErrorCode::OTHER);
        let taken = self.sockets.get_mut::<tcp::Socket>(tcp.handle).send_slice(data).map_err(|_| error)?;
        self.taken(id, taken > 0);
        Ok(taken)
    }

    /// Takes received bytes into `out`: how many, 0 when none are there yet, `None` once the peer's end was read or
    /// the connection is gone. A slow taker closes the window the socket offers.
    pub fn tcp_recv(&mut self, id: u32, out: &mut [u8]) -> Option<usize> {
        let handle = self.tcp(id)?.handle;
        let length = self.sockets.get_mut::<tcp::Socket>(handle).recv_slice(out).ok()?;
        self.taken(id, length > 0);
        Some(length)
    }

    /// Ends this side in order once the send buffer is sent: a half close, after which the peer's bytes still come.
    pub fn tcp_close(&mut self, id: u32) {
        let Some(Kind::Tcp(tcp)) = self.entry_mut(id).map(|entry| &mut entry.kind) else { return };
        tcp.ended_here = true;
        let handle = tcp.handle;
        self.sockets.get_mut::<tcp::Socket>(handle).close();
    }

    /// Ends the connection at once with a reset toward the peer, dropping what was not sent.
    pub fn tcp_abort(&mut self, id: u32) {
        let Some(Kind::Tcp(tcp)) = self.entry_mut(id).map(|entry| &mut entry.kind) else { return };
        tcp.ended_here = true;
        let handle = tcp.handle;
        self.sockets.get_mut::<tcp::Socket>(handle).abort();
    }

    /// Turns Nagle's algorithm off (`true`) or on.
    pub fn tcp_set_no_delay(&mut self, id: u32, no_delay: bool) -> Result<()> {
        self.tcp_socket(id)?.set_nagle_enabled(!no_delay);
        Ok(())
    }

    /// Probes an idle connection every `seconds`, 0 for the usual two hours; `None` stops the probes.
    pub fn tcp_set_keep_alive(&mut self, id: u32, seconds: Option<u32>) -> Result<()> {
        let interval = seconds.map(|seconds| match seconds {
            0 => Duration::from_secs(KEEP_ALIVE_DEFAULT_SECONDS),
            seconds => Duration::from_secs(u64::from(seconds)),
        });
        self.tcp_socket(id)?.set_keep_alive(interval);
        Ok(())
    }

    /// Sets the hop limit of the connection's packets, 1 to 255.
    pub fn tcp_set_ttl(&mut self, id: u32, ttl: u32) -> Result<()> {
        let ttl = u8::try_from(ttl).ok().filter(|&ttl| ttl > 0).ok_or(ErrorCode::OTHER)?;
        self.tcp_socket(id)?.set_hop_limit(Some(ttl));
        Ok(())
    }

    /// A free one of the tunnel's public ports in `protocol`'s port space, the lowest first.
    pub fn public_port(&self, protocol: Protocol) -> Option<u16> {
        let first = u32::from(self.config.first_port);
        (first..first + u32::from(self.config.ports))
            .filter_map(|port| u16::try_from(port).ok())
            .find(|&port| port != 0 && !self.in_use(protocol, port))
    }

    /// Binds a UDP socket on `port` of every address of the stack, or on a free private port for 0. Fails with
    /// `ADDRESS_IN_USE` when the port is bound, or no private port is free.
    pub fn udp_bind(&mut self, port: u16, buffers: Buffers) -> Result<u32> {
        let port = match port {
            0 => self.free_port(Protocol::Udp).ok_or(ErrorCode::ADDRESS_IN_USE)?,
            port if self.in_use(Protocol::Udp, port) => return Err(ErrorCode::ADDRESS_IN_USE),
            port => port,
        };
        let mut socket = udp::Socket::new(packet_buffer(buffers.receive), packet_buffer(buffers.send));
        socket.bind(port).map_err(|_| ErrorCode::ADDRESS_NOT_AVAILABLE)?;
        let handle = self.sockets.add(socket);
        Ok(self.insert(Kind::Udp { handle, port }))
    }

    /// The port a UDP socket is bound on.
    pub fn udp_port(&self, id: u32) -> Option<u16> {
        match self.entry(id)?.kind {
            Kind::Udp { port, .. } => Some(port),
            _ => None,
        }
    }

    /// Sends one datagram to `remote`. Fails with `OTHER` when its packet would be longer than the tunnel's MTU,
    /// since the stack does not fragment.
    pub fn udp_send(&mut self, id: u32, remote: SocketAddr, data: &[u8]) -> Result<Sent> {
        let header = if remote.is_ipv4() { 28 } else { 48 };
        if data.len() + header > self.config.mtu {
            return Err(ErrorCode::OTHER);
        }
        let socket = self.udp_socket(id)?;
        Ok(match socket.send_slice(data, endpoint(remote)) {
            Ok(()) => Sent::Queued,
            Err(_) => Sent::Dropped,
        })
    }

    /// Takes the oldest datagram into `out`: its length and where it came from. A datagram that finds the receive
    /// buffer full is dropped.
    pub fn udp_recv(&mut self, id: u32, out: &mut [u8]) -> Option<(usize, SocketAddr)> {
        let (length, metadata) = self.udp_socket(id).ok()?.recv_slice(out).ok()?;
        self.taken(id, true);
        Some((length, socket_address(metadata.endpoint)))
    }

    /// Sets the hop limit of the socket's packets, 1 to 255.
    pub fn udp_set_ttl(&mut self, id: u32, ttl: u32) -> Result<()> {
        let ttl = u8::try_from(ttl).ok().filter(|&ttl| ttl > 0).ok_or(ErrorCode::OTHER)?;
        self.udp_socket(id)?.set_hop_limit(Some(ttl));
        Ok(())
    }

    /// Lets go of a socket or a listener, whose id is no longer used. A UDP socket and a listener's waiting sockets
    /// close at once, and the connections it accepted that nobody took are reset. A TCP connection is left to end as
    /// `tcp_close` or `tcp_abort` ended it, the peer's bytes dropped meanwhile, and is reset if it has not ended a
    /// minute later.
    pub fn release(&mut self, id: u32) {
        let now = self.now;
        let Some(entry) = id.checked_sub(1).and_then(|index| self.entries.get_mut(index as usize)) else { return };
        let Some(Entry { kind, seen }) = entry.take() else { return };
        match kind {
            Kind::Tcp(mut tcp) => {
                tcp.released_at.get_or_insert(now);
                *entry = Some(Entry { kind: Kind::Tcp(tcp), seen });
            }
            Kind::Listener(listener) => {
                for handle in listener.waiting {
                    self.sockets.get_mut::<tcp::Socket>(handle).abort();
                    self.orphan(handle);
                }
                for accepted in listener.accepted {
                    self.tcp_abort(accepted);
                    self.release(accepted);
                }
            }
            Kind::Udp { handle, .. } => {
                self.sockets.remove(handle);
            }
        }
    }

    fn orphan(&mut self, handle: SocketHandle) {
        let state = self.sockets.get::<tcp::Socket>(handle).state();
        let tcp = Tcp {
            handle,
            error: None,
            connect_by: None,
            state,
            reset: false,
            ended_here: true,
            released_at: Some(self.now),
        };
        self.insert(Kind::Tcp(tcp));
    }

    fn insert(&mut self, kind: Kind) -> u32 {
        let entry = Some(Entry { kind, seen: UNSEEN });
        let index = match self.entries.iter().position(Option::is_none) {
            Some(index) => {
                self.entries[index] = entry;
                index
            }
            None => {
                self.entries.push(entry);
                self.entries.len() - 1
            }
        };
        index as u32 + 1
    }

    // a socket the page took from may look as it did at the last poll once more arrives, so the next poll tells it
    fn taken(&mut self, id: u32, taken: bool) {
        if let Some(entry) = self.entry_mut(id).filter(|_| taken) {
            entry.seen = UNSEEN;
        }
    }

    fn entry(&self, id: u32) -> Option<&Entry> {
        self.entries.get(id.checked_sub(1)? as usize)?.as_ref()
    }

    fn entry_mut(&mut self, id: u32) -> Option<&mut Entry> {
        self.entries.get_mut(id.checked_sub(1)? as usize)?.as_mut()
    }

    fn tcp(&self, id: u32) -> Option<&Tcp> {
        match &self.entry(id)?.kind {
            Kind::Tcp(tcp) if tcp.released_at.is_none() => Some(tcp),
            _ => None,
        }
    }

    fn tcp_socket(&mut self, id: u32) -> Result<&mut tcp::Socket<'static>> {
        let handle = self.tcp(id).ok_or(ErrorCode::UNKNOWN_SOCKET)?.handle;
        Ok(self.sockets.get_mut::<tcp::Socket>(handle))
    }

    fn udp_socket(&mut self, id: u32) -> Result<&mut udp::Socket<'static>> {
        match self.entry(id).map(|entry| &entry.kind) {
            Some(&Kind::Udp { handle, .. }) => Ok(self.sockets.get_mut::<udp::Socket>(handle)),
            _ => Err(ErrorCode::UNKNOWN_SOCKET),
        }
    }

    fn in_use(&self, protocol: Protocol, port: u16) -> bool {
        self.entries.iter().flatten().any(|entry| match (&entry.kind, protocol) {
            (Kind::Tcp(tcp), Protocol::Tcp) => {
                let socket = self.sockets.get::<tcp::Socket>(tcp.handle);
                socket.local_endpoint().is_some_and(|local| local.port == port)
            }
            (Kind::Listener(listener), Protocol::Tcp) => listener.port == port,
            (Kind::Udp { port: bound, .. }, Protocol::Udp) => *bound == port,
            _ => false,
        })
    }

    fn is_public(&self, port: u16) -> bool {
        u32::from(port).wrapping_sub(u32::from(self.config.first_port)) < u32::from(self.config.ports)
    }

    fn free_port(&mut self, protocol: Protocol) -> Option<u16> {
        let span = EPHEMERAL.len() as u32;
        for _ in 0..span {
            self.next_port = (self.next_port + 1) % span;
            let port = EPHEMERAL.start() + self.next_port as u16;
            if !self.is_public(port) && !self.in_use(protocol, port) {
                return Some(port);
            }
        }
        None
    }

    fn find_tcp(&self, local: SocketAddr, remote: SocketAddr) -> Option<usize> {
        self.entries.iter().position(|entry| match entry.as_ref().map(|entry| &entry.kind) {
            Some(Kind::Tcp(tcp)) => {
                let socket = self.sockets.get::<tcp::Socket>(tcp.handle);
                socket.local_endpoint() == Some(endpoint(local)) && socket.remote_endpoint() == Some(endpoint(remote))
            }
            _ => false,
        })
    }

    fn tcp_at(&mut self, index: usize) -> Option<&mut Tcp> {
        match &mut self.entries.get_mut(index)?.as_mut()?.kind {
            Kind::Tcp(tcp) => Some(tcp),
            _ => None,
        }
    }

    // smoltcp tells a socket neither that a reset closed it nor of an ICMP error about its packets, so both are read
    // here, before the packet goes in
    fn inspect(&mut self, packet: &[u8]) {
        let Some(outer) = header(packet) else { return };
        match outer.protocol {
            TCP if outer.payload.get(13).is_some_and(|flags| flags & RST != 0) => {
                let Some((from, to)) = ports(outer.payload) else { return };
                let (local, remote) = (SocketAddr::new(outer.destination, to), SocketAddr::new(outer.source, from));
                if let Some(tcp) = self.find_tcp(local, remote).and_then(|index| self.tcp_at(index)) {
                    tcp.reset = true;
                }
            }
            ICMP | ICMPV6 => {
                let Some(error) = unreachable(&outer) else { return };
                let Some(quoted) = outer.payload.get(8..).and_then(header) else { return };
                let Some((from, to)) = ports(quoted.payload) else { return };
                if quoted.protocol != TCP {
                    return;
                }
                let (local, remote) = (SocketAddr::new(quoted.source, from), SocketAddr::new(quoted.destination, to));
                let Some(index) = self.find_tcp(local, remote) else { return };
                let Some(handle) = self.tcp_at(index).map(|tcp| tcp.handle) else { return };
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                if socket.state() != tcp::State::SynSent {
                    return;
                }
                socket.abort();
                if let Some(tcp) = self.tcp_at(index) {
                    tcp.error = Some(error);
                }
            }
            _ => {}
        }
    }

    fn maintain(&mut self) {
        let now = self.now;
        let mut accepted = Vec::new();
        for (index, entry) in self.entries.iter_mut().enumerate() {
            let Some(entry) = entry else { continue };
            match &mut entry.kind {
                Kind::Tcp(tcp) => {
                    let socket = self.sockets.get_mut::<tcp::Socket>(tcp.handle);
                    if socket.state() == tcp::State::SynSent && tcp.connect_by.is_some_and(|by| now >= by) {
                        tcp.error = Some(ErrorCode::TIMED_OUT);
                        socket.abort();
                    }
                    if let Some(released_at) = tcp.released_at {
                        while socket.can_recv() && socket.recv(|bytes| (bytes.len(), ())).is_ok() {}
                        if (now - released_at).total_millis() as i64 >= RELEASED_MS {
                            socket.abort();
                        }
                    }
                }
                Kind::Listener(listener) => {
                    for handle in listener.turn(&mut self.sockets) {
                        accepted.push((index, handle));
                    }
                }
                Kind::Udp { .. } => {}
            }
        }
        for (index, handle) in accepted {
            let state = self.sockets.get::<tcp::Socket>(handle).state();
            let tcp = Tcp {
                handle,
                error: None,
                connect_by: None,
                state,
                reset: false,
                ended_here: false,
                released_at: None,
            };
            let id = self.insert(Kind::Tcp(tcp));
            if let Some(Some(Entry { kind: Kind::Listener(listener), .. })) = self.entries.get_mut(index) {
                listener.accepted.push_back(id);
            }
        }
    }

    fn settle(&mut self) {
        for (index, slot) in self.entries.iter_mut().enumerate() {
            let Some(entry) = slot else { continue };
            let seen = match &mut entry.kind {
                Kind::Tcp(tcp) => {
                    let socket = self.sockets.get::<tcp::Socket>(tcp.handle);
                    let state = socket.state();
                    if state == tcp::State::Closed && tcp.state != tcp::State::Closed && tcp.error.is_none() {
                        if tcp.state == tcp::State::SynSent && !tcp.ended_here {
                            tcp.error = Some(ErrorCode::CONNECTION_REFUSED);
                        } else if tcp.reset {
                            tcp.error = Some(ErrorCode::CONNECTION_RESET);
                        }
                    }
                    tcp.state = state;
                    tcp.reset = false;
                    if tcp.released_at.is_some() {
                        if state == tcp::State::Closed {
                            self.sockets.remove(tcp.handle);
                            *slot = None;
                        }
                        continue;
                    }
                    (state_number(state), socket.recv_queue(), socket.send_queue())
                }
                Kind::Listener(listener) => (0, listener.accepted.len(), 0),
                Kind::Udp { handle, .. } => {
                    let socket = self.sockets.get::<udp::Socket>(*handle);
                    (0, socket.recv_queue(), socket.send_queue())
                }
            };
            if seen != entry.seen {
                entry.seen = seen;
                self.events.push_back(index as u32 + 1);
            }
        }
    }

    fn delay(&mut self) -> Option<u64> {
        let mut next = self.interface.poll_at(self.now, &self.sockets);
        for entry in self.entries.iter().flatten() {
            let Kind::Tcp(tcp) = &entry.kind else { continue };
            let connecting = tcp.connect_by.filter(|_| tcp.state == tcp::State::SynSent);
            let released = tcp.released_at.map(|at| at + Duration::from_millis(RELEASED_MS as u64));
            for at in connecting.into_iter().chain(released) {
                next = Some(next.map_or(at, |next| next.min(at)));
            }
        }
        next.map(|at| (at.total_millis() - self.now.total_millis()).max(0) as u64)
    }
}
