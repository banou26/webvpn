//! IP tunnels through a running `webvpnd`, over a real TUN device and a real network. `tests/ip-tunnel.sh` builds that
//! network in namespaces of its own, starts the relay and runs this test there; a plain `cargo test` skips it.
//!
//! The network: the relay's host routes the pool 13.0.0.0/29 to its TUN device, under `ip-tunnel-setup.sh`, and
//! reaches "the internet" at 11.0.0.0/24 by a veth pair, its default route, and at 12.0.0.0/24 by a second one. The
//! peer, at 11.0.0.2 and 12.0.0.2, answers ICMP echoes, writes what reaches UDP port 7002 to a file, accepts TCP on
//! port 7003 and keeps each connection open, and has nothing on UDP port 7004. It is reached at the private address
//! 10.0.0.2 too, and counts what reaches it with an address of the pool as its source. The setup keeps at most 8
//! connections that one tunnel address opens, and apart from those, 8 to its public ports. The relay's public address
//! is 11.0.0.1, and its public ports are 30000 to 30039 in blocks of 8: 13.0.0.2 holds 30000 to 30007, up to
//! 13.0.0.6, which holds 30032 to 30039.
//!
//! This test is the peer's UDP port 7001 itself, from a socket it makes in the peer's namespace, and answers each
//! datagram there with the source address it came from. socat's forking responder left a datagram that closely
//! followed another without an answer, about once in a hundred.
#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, Instant};
use webvpn_proto::{features, ip, ClientPacket, ErrorCode, Hello, RelayPacket};
use webvpn_server::webtransport::wtransport;
use webvpn_server::webtransport::wtransport::tls::{Sha256Digest, Sha256DigestFmt};
use webvpn_server::webtransport::wtransport::{Connection, Endpoint, RecvStream, SendStream};

const WAIT: Duration = Duration::from_secs(5);
/// How long a packet that must not arrive is waited for.
const QUIET: Duration = Duration::from_millis(1500);

const LOCALHOST: Ipv4Addr = Ipv4Addr::LOCALHOST;
const HTTP_PORT: u16 = 8080;
const WEBTRANSPORT_PORT: u16 = 4433;

const PEER: Ipv4Addr = Ipv4Addr::new(11, 0, 0, 2);
/// The relay host's address as the peer sees it, which tunnels' packets are translated to.
const OUTSIDE: Ipv4Addr = Ipv4Addr::new(11, 0, 0, 1);
/// The peer and the relay's host on the second interface, which the default route does not take.
const PEER_2: Ipv4Addr = Ipv4Addr::new(12, 0, 0, 2);
const OUTSIDE_2: Ipv4Addr = Ipv4Addr::new(12, 0, 0, 1);
/// A private address outside the pool that the peer holds.
const PRIVATE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// The connections the setup keeps that one tunnel address opens, and apart from those, to its public ports, from
/// `WEBVPN_IP_FLOWS_PER_ADDRESS` in tests/ip-tunnel.sh.
const FLOWS_PER_ADDRESS: u16 = 8;
/// The relay's life of a quiet open TCP flow, in seconds, after which the setup has the kernel forget it too.
const TCP_OPEN_LIFE: u32 = 7440;
/// The TUN device's own address, the pool's first host.
const DEVICE: Ipv4Addr = Ipv4Addr::new(13, 0, 0, 1);
const POOL: [Ipv4Addr; 5] = [
    Ipv4Addr::new(13, 0, 0, 2),
    Ipv4Addr::new(13, 0, 0, 3),
    Ipv4Addr::new(13, 0, 0, 4),
    Ipv4Addr::new(13, 0, 0, 5),
    Ipv4Addr::new(13, 0, 0, 6),
];

/// The public ports, from `WEBVPN_IP_PORTS` in tests/ip-tunnel.sh, in blocks of the default 8.
const PUBLIC_PORTS: (u16, u16) = (30000, 30039);
const PORTS_PER_TUNNEL: u16 = 8;

const UDP_WHO: u16 = 7001;
const UDP_SINK: u16 = 7002;
const TCP_LISTENER: u16 = 7003;
const UDP_SILENT: u16 = 7004;

const ICMP: u8 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;

async fn within<F: std::future::Future>(future: F) -> F::Output {
    timeout(WAIT, future).await.expect("done in time")
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is set by tests/ip-tunnel.sh"))
}

/// `GET path` on the relay's HTTP listener: the body.
async fn http(path: &str) -> String {
    let mut stream = within(TcpStream::connect((LOCALHOST, HTTP_PORT))).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n");
    within(stream.write_all(request.as_bytes())).await.unwrap();
    let mut answer = String::new();
    within(stream.read_to_string(&mut answer)).await.unwrap();
    answer.split_once("\r\n\r\n").expect("a whole answer").1.to_owned()
}

/// The relay's count of tunnel packets dropped for `reason`.
async fn dropped(reason: &str) -> u64 {
    let line = format!("webvpn_ip_dropped_total{{reason=\"{reason}\"}} ");
    let metrics = http("/metrics").await;
    let count = metrics.lines().find_map(|text| text.strip_prefix(line.as_str()));
    count.unwrap_or_else(|| panic!("no {line:?} in the metrics")).parse().unwrap()
}

/// The seconds the host's connection tracking still keeps the established TCP connection that `selected` names, in
/// options of `conntrack -L`. Waits until it is established.
async fn established_life(selected: &[&str]) -> u32 {
    within(async {
        loop {
            let listed = Command::new("conntrack")
                .args(["-L", "-p", "tcp"])
                .args(selected)
                .stderr(Stdio::null())
                .output()
                .await
                .unwrap();
            let text = String::from_utf8_lossy(&listed.stdout);
            if let Some(line) = text.lines().find(|line| line.contains(" ESTABLISHED ")) {
                return line.split_whitespace().nth(2).unwrap().parse().unwrap();
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
}

/// Runs `script` with `sh` in the peer's network namespace.
async fn on_peer(script: &str) {
    let status = Command::new("nsenter")
        .arg(format!("--net={}", env("WEBVPN_TEST_PEER_NETNS")))
        .args(["sh", "-c", script])
        .stdin(Stdio::null())
        .status();
    assert!(within(status).await.unwrap().success(), "{script} failed on the peer");
}

/// Runs `work` on a thread of its own in the peer's network namespace. A socket stays in the namespace it was made in,
/// so only that thread moves there.
fn in_peer<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> std::thread::JoinHandle<T> {
    std::thread::spawn(move || {
        let namespace = std::fs::File::open(env("WEBVPN_TEST_PEER_NETNS")).unwrap();
        // SAFETY: `namespace` is an open file, and the call moves this thread only.
        let moved = unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) };
        assert_eq!(moved, 0, "the test runs as root of both namespaces");
        work()
    })
}

/// A UDP socket on `port` in the peer's network namespace.
fn peer_socket(port: u16) -> UdpSocket {
    let made = in_peer(move || {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).unwrap();
        socket.set_nonblocking(true).unwrap();
        socket
    });
    UdpSocket::from_std(made.join().unwrap()).unwrap()
}

/// Waits for a thread [`in_peer`] started.
async fn joined<T>(thread: std::thread::JoinHandle<T>) -> T {
    within(async {
        while !thread.is_finished() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    thread.join().unwrap()
}

/// The public ports the relay gives a tunnel at `address`: its first port and how many.
fn block(address: Ipv4Addr) -> (u16, u16) {
    let k = u16::from(address.octets()[3]) - 2;
    (PUBLIC_PORTS.0 + k * PORTS_PER_TUNNEL, PORTS_PER_TUNNEL)
}

/// Sends a datagram from `peer` to the tunnel's first public port, and waits for it on the tunnel.
async fn to_public_port(tunnel: &mut Tunnel, peer: &UdpSocket) {
    let (address, public, from) = (tunnel.address, tunnel.first_port, peer.local_addr().unwrap().port());
    within(peer.send_to(b"in", (OUTSIDE, public))).await.unwrap();
    let arrived = |p: &Packet| from_peer(p, UDP) && p.target == address && p.ports() == (from, public);
    tunnel.expect("a datagram to a public port under its ceiling", arrived).await;
}

/// Answers each datagram on the peer's [`UDP_WHO`] with the source address it came from.
fn answer_who() {
    let socket = peer_socket(UDP_WHO);
    tokio::spawn(async move {
        let mut buf = [0; 64];
        while let Ok((_, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(from.ip().to_string().as_bytes(), from).await;
        }
    });
}

/// A session with the relay, over WebTransport on its self-signed certificate.
struct Session {
    connection: Connection,
    control: SendStream,
    replies: RecvStream,
    buf: Vec<u8>,
    next_id: u32,
}

impl Session {
    async fn open() -> Self {
        let hash = Sha256Digest::from_str_fmt(&http("/cert-hash").await, Sha256DigestFmt::BytesArray).unwrap();
        let config = wtransport::ClientConfig::builder()
            .with_bind_address((LOCALHOST, 0).into())
            .with_server_certificate_hashes([hash])
            .build();
        let endpoint = Endpoint::client(config).unwrap();
        let url = format!("https://127.0.0.1:{WEBTRANSPORT_PORT}/");
        let connection = within(endpoint.connect(url)).await.unwrap();
        let (control, replies) = within(connection.accept_bi()).await.unwrap();
        let mut session = Self { connection, control, replies, buf: Vec::new(), next_id: 1 };
        let RelayPacket::Hello(hello) = session.next().await else { panic!("the relay did not start with its hello") };
        assert_eq!(hello.features & features::IP, features::IP, "the relay offers IP tunnels");
        session.send(ClientPacket::Hello(Hello::new(0, "ip tunnel test"))).await;
        session
    }

    async fn send(&mut self, packet: ClientPacket) {
        let mut frame = Vec::new();
        packet.encode(&mut frame);
        within(self.control.write_all(&frame)).await.unwrap();
    }

    async fn next(&mut self) -> RelayPacket {
        within(async {
            loop {
                if let Some((packet, taken)) = RelayPacket::decode(&self.buf).unwrap() {
                    self.buf.drain(..taken);
                    return packet;
                }
                assert_ne!(self.replies.read_buf(&mut self.buf).await.unwrap(), 0, "the control stream ended");
            }
        })
        .await
    }

    async fn tunnel(&mut self) -> Tunnel {
        let id = self.next_id;
        self.next_id += 1;
        self.send(ClientPacket::IpOpen { id }).await;
        let RelayPacket::IpTunnel { id: answered, socket, mtu, ipv4, ipv6, public_ipv4, first_port, ports, .. } =
            self.next().await
        else {
            panic!("the tunnel was not opened");
        };
        assert_eq!((answered, mtu, ipv6), (id, 1500, None));
        let address = ipv4.expect("an IPv4 address");
        assert!(POOL.contains(&address), "{address} is not one of the pool's");
        let public = (ports > 0).then_some(OUTSIDE);
        assert_eq!((public_ipv4, first_port, ports), (public, block(address).0, block(address).1), "{address}");
        let (send, mut recv) = within(self.connection.accept_bi()).await.unwrap();
        let mut named = [0; 4];
        within(recv.read_exact(&mut named)).await.unwrap();
        assert_eq!(u32::from_be_bytes(named), socket);
        let (arrived, packets) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            loop {
                while let Some((packet, taken)) = ip::decode(&buf) {
                    let _ = arrived.send(packet.to_vec());
                    buf.drain(..taken);
                }
                if !matches!(recv.read_buf(&mut buf).await, Ok(1..)) {
                    return;
                }
            }
        });
        Tunnel { socket, address, first_port, send, packets }
    }

    async fn close(&mut self, tunnel: Tunnel) {
        let id = self.next_id;
        self.next_id += 1;
        self.send(ClientPacket::IpClose { id, socket: tunnel.socket }).await;
        assert_eq!(self.next().await, RelayPacket::Ok { id });
    }
}

struct Tunnel {
    socket: u32,
    address: Ipv4Addr,
    /// The first of its public ports, or 0 for none.
    first_port: u16,
    send: SendStream,
    packets: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl Tunnel {
    async fn send(&mut self, packet: &[u8]) {
        let mut frame = Vec::new();
        ip::encode(packet, &mut frame);
        within(self.send.write_all(&frame)).await.unwrap();
    }

    /// The first packet to arrive that `wanted` takes, skipping others.
    async fn expect(&mut self, what: &str, wanted: impl Fn(&Packet) -> bool) -> Packet {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let packet = timeout(left, self.packets.recv()).await.unwrap_or_else(|_| panic!("no {what} arrived"));
            let packet = Packet::read(&packet.expect("the tunnel's stream is open"));
            if wanted(&packet) {
                return packet;
            }
        }
    }

    /// Fails when anything arrives for a while.
    async fn quiet(&mut self, what: &str) {
        if let Ok(Some(packet)) = timeout(QUIET, self.packets.recv()).await {
            panic!("{what}: a packet arrived: {:?}", Packet::read(&packet));
        }
    }
}

/// An IPv4 packet, as far as the test reads one.
#[derive(Debug, Clone)]
struct Packet {
    source: Ipv4Addr,
    target: Ipv4Addr,
    protocol: u8,
    id: u16,
    more_fragments: bool,
    /// In bytes.
    offset: usize,
    payload: Vec<u8>,
}

impl Packet {
    fn read(bytes: &[u8]) -> Self {
        assert_eq!(bytes[0] >> 4, 4, "an IPv4 packet");
        let header = usize::from(bytes[0] & 0x0f) * 4;
        let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        assert_eq!(total, bytes.len());
        let flags = u16::from_be_bytes([bytes[6], bytes[7]]);
        Self {
            source: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
            target: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
            protocol: bytes[9],
            id: u16::from_be_bytes([bytes[4], bytes[5]]),
            more_fragments: flags & 0x2000 != 0,
            offset: usize::from(flags & 0x1fff) * 8,
            payload: bytes[header..].to_vec(),
        }
    }

    fn whole(&self) -> bool {
        !self.more_fragments && self.offset == 0
    }

    /// The source and destination ports of a whole TCP or UDP packet.
    fn ports(&self) -> (u16, u16) {
        let p = &self.payload;
        (u16::from_be_bytes([p[0], p[1]]), u16::from_be_bytes([p[2], p[3]]))
    }
}

fn checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for chunk in chunks {
        for pair in chunk.chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One IPv4 packet, or a fragment of one: `offset` in bytes, a multiple of 8.
fn ipv4(
    source: Ipv4Addr,
    target: Ipv4Addr,
    protocol: u8,
    ttl: u8,
    (id, offset, more): (u16, usize, bool),
    payload: &[u8],
) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let flags = (offset / 8) as u16 | if more { 0x2000 } else { 0 };
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&[ttl, protocol, 0, 0]);
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&target.octets());
    let sum = checksum(&[&packet]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn whole(source: Ipv4Addr, target: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    ipv4(source, target, protocol, 64, (0x4242, 0, false), payload)
}

fn icmp_echo(id: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut message = vec![8, 0, 0, 0];
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(data);
    let sum = checksum(&[&message]);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    message
}

fn pseudo(source: Ipv4Addr, target: Ipv4Addr, protocol: u8, length: usize) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&source.octets());
    header.extend_from_slice(&target.octets());
    header.extend_from_slice(&[0, protocol]);
    header.extend_from_slice(&(length as u16).to_be_bytes());
    header
}

fn udp(source: (Ipv4Addr, u16), target: (Ipv4Addr, u16), data: &[u8]) -> Vec<u8> {
    let length = 8 + data.len();
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&source.1.to_be_bytes());
    datagram.extend_from_slice(&target.1.to_be_bytes());
    datagram.extend_from_slice(&(length as u16).to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(data);
    let sum = checksum(&[&pseudo(source.0, target.0, UDP, length), &datagram]);
    datagram[6..8].copy_from_slice(&sum.to_be_bytes());
    datagram
}

fn tcp(source: (Ipv4Addr, u16), target: (Ipv4Addr, u16), sequence: u32, flags: u8) -> Vec<u8> {
    tcp_acking(source, target, (sequence, 0), flags)
}

/// A TCP segment with its sequence and acknowledgment numbers.
fn tcp_acking(source: (Ipv4Addr, u16), target: (Ipv4Addr, u16), (sequence, ack): (u32, u32), flags: u8) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&source.1.to_be_bytes());
    segment.extend_from_slice(&target.1.to_be_bytes());
    segment.extend_from_slice(&sequence.to_be_bytes());
    segment.extend_from_slice(&ack.to_be_bytes());
    segment.extend_from_slice(&[5 << 4, flags]);
    segment.extend_from_slice(&64240u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0]);
    let sum = checksum(&[&pseudo(source.0, target.0, TCP, segment.len()), &segment]);
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    segment
}

fn udp_packet(source: (Ipv4Addr, u16), target: (Ipv4Addr, u16), data: &[u8]) -> Vec<u8> {
    whole(source.0, target.0, UDP, &udp(source, target, data))
}

fn from_peer(packet: &Packet, protocol: u8) -> bool {
    packet.source == PEER && packet.protocol == protocol && packet.whole()
}

#[tokio::test]
#[ignore = "needs the network tests/ip-tunnel.sh builds"]
async fn tunnels_reach_a_real_network_and_take_only_answers() {
    answer_who();
    let mut session = Session::open().await;
    let mut first = session.tunnel().await;
    let me = first.address;

    first.send(&whole(me, PEER, ICMP, &icmp_echo(0x1234, 1, b"tunnel"))).await;
    let reply = first.expect("echo reply", |p| from_peer(p, ICMP) && p.payload[0] == 0).await;
    assert_eq!((&reply.payload[4..6], &reply.payload[8..]), (&0x1234u16.to_be_bytes()[..], &b"tunnel"[..]));
    println!("ok 1: an ICMP echo request gets its echo reply");

    first.send(&udp_packet((me, 40002), (PEER, UDP_WHO), b"who")).await;
    let answer = first.expect("UDP answer", |p| from_peer(p, UDP) && p.ports() == (UDP_WHO, 40002)).await;
    let seen = String::from_utf8_lossy(&answer.payload[8..]).trim().to_owned();
    assert_eq!(seen.parse::<IpAddr>().ok(), Some(OUTSIDE.into()), "the peer saw {seen:?}");
    first.send(&udp_packet((me, 40012), (PEER_2, UDP_WHO), b"who")).await;
    let answer = first
        .expect("UDP answer on the second interface", |p| p.source == PEER_2 && p.ports() == (UDP_WHO, 40012))
        .await;
    let seen = String::from_utf8_lossy(&answer.payload[8..]).trim().to_owned();
    assert_eq!(seen.parse::<IpAddr>().ok(), Some(OUTSIDE_2.into()), "the peer saw {seen:?} on the second interface");
    println!("ok 2: a UDP datagram gets its answer, from the address translated on either interface");

    first.send(&whole(me, PEER, TCP, &tcp((me, 40003), (PEER, TCP_LISTENER), 1000, 0x02))).await;
    let syn_ack = first
        .expect("SYN and ACK", |p| from_peer(p, TCP) && p.ports() == (TCP_LISTENER, 40003) && p.payload[13] == 0x12)
        .await;
    assert_eq!(syn_ack.payload[8..12], 1001u32.to_be_bytes(), "the SYN is acknowledged");
    let theirs = u32::from_be_bytes(syn_ack.payload[4..8].try_into().unwrap());
    first.send(&whole(me, PEER, TCP, &tcp_acking((me, 40003), (PEER, TCP_LISTENER), (1001, theirs + 1), 0x10))).await;
    let life = established_life(&["--orig-src", &me.to_string(), "--sport", "40003"]).await;
    assert!(life <= TCP_OPEN_LIFE, "the host keeps the quiet open connection {life} s");
    first.send(&whole(me, PEER, TCP, &tcp((me, 40003), (PEER, TCP_LISTENER), 1001, 0x04))).await;
    println!("ok 3: a TCP SYN gets a SYN and ACK, and the host keeps the open connection no longer than the relay");

    let expiring = ipv4(me, PEER, UDP, 1, (0x4343, 0, false), &udp((me, 40004), (PEER, UDP_WHO), b"ttl"));
    first.send(&expiring).await;
    let exceeded = first.expect("time exceeded", |p| p.protocol == ICMP && p.payload[0] == 11).await;
    assert_eq!(exceeded.source, DEVICE, "the hop is the relay's host");
    assert_eq!(&exceeded.payload[8 + 12..8 + 20], &[me.octets(), PEER.octets()].concat()[..], "it quotes the datagram");
    println!("ok 4: a time to live of 1 gets a time exceeded from the relay's host");

    let data: Vec<u8> = (0..2892u32).map(|i| i as u8).collect();
    let echo = icmp_echo(0x5678, 2, &data);
    first.send(&ipv4(me, PEER, ICMP, 64, (0x4444, 0, true), &echo[..1480])).await;
    first.send(&ipv4(me, PEER, ICMP, 64, (0x4444, 1480, false), &echo[1480..])).await;
    let mut pieces = Vec::new();
    let mut whole_reply = None;
    while whole_reply.is_none() {
        let piece =
            first.expect("a fragment of the reply", |p| p.source == PEER && p.protocol == ICMP && !p.whole()).await;
        pieces.push(piece);
        let id = pieces[0].id;
        let mut ours: Vec<_> = pieces.iter().filter(|p| p.id == id).collect();
        ours.sort_by_key(|p| p.offset);
        let mut joined = Vec::new();
        for piece in &ours {
            if piece.offset == joined.len() {
                joined.extend_from_slice(&piece.payload);
            }
        }
        if ours.last().is_some_and(|last| !last.more_fragments) && joined.len() == echo.len() {
            whole_reply = Some((ours.len(), joined));
        }
    }
    let (count, reply) = whole_reply.unwrap();
    assert!(count >= 2, "the reply came in {count} pieces");
    assert_eq!((reply[0], &reply[4..6], &reply[8..]), (0, &0x5678u16.to_be_bytes()[..], &data[..]));
    println!("ok 5: an echo of about 3000 bytes in two fragments gets its reply, in {count} fragments");

    let before = dropped("source").await;
    let other = *POOL.iter().rev().find(|&&address| address != me).unwrap();
    first.send(&udp_packet((other, 40006), (PEER, UDP_SINK), b"not mine")).await;
    sleep(QUIET).await;
    let sink = std::fs::read(env("WEBVPN_TEST_SINK")).unwrap_or_default();
    assert!(sink.is_empty(), "the peer received {} bytes", sink.len());
    assert_eq!(dropped("source").await, before + 1);
    println!("ok 6: a packet from another source is dropped and counted, the peer received nothing");

    let mut second = session.tunnel().await;
    let them = second.address;
    second.send(&udp_packet((them, 5000), (me, 6000), b"to the first")).await;
    first.send(&udp_packet((me, 6000), (them, 5000), b"to the second")).await;
    second.quiet("the second tunnel").await;
    first.quiet("the first tunnel").await;
    println!("ok 7: a second tunnel's address cannot be reached from the first");

    session.close(first).await;
    let mut third = session.tunnel().await;
    assert_ne!(third.address, me, "the address just freed was given again");
    println!("ok 9: after a close, the next tunnel gets another address than the one freed");

    let held = third.address;
    third.send(&udp_packet((held, 40008), (PEER, UDP_SILENT), b"earlier holder")).await;
    sleep(Duration::from_millis(200)).await;
    session.close(third).await;
    let mut later = loop {
        let tunnel = session.tunnel().await;
        if tunnel.address == held {
            break tunnel;
        }
        session.close(tunnel).await;
    };
    let before = dropped("unasked").await;
    on_peer(&format!("printf unasked | socat -u - UDP-SENDTO:{held}:40008,sourceport={UDP_SILENT}")).await;
    later.quiet("a datagram straight to the address").await;
    assert_eq!(dropped("unasked").await, before, "the host's rules drop it before the relay");
    on_peer(&format!("printf unasked | socat -u - UDP-SENDTO:{OUTSIDE}:40008,sourceport={UDP_SILENT}")).await;
    later.quiet("an answer to the earlier holder").await;
    assert_eq!(dropped("unasked").await, before + 1, "the relay drops the earlier holder's answer");
    println!(
        "ok 8: a datagram the peer sends unasked does not arrive, and the relay counts the one that passed the host"
    );

    // the peer is there, by the host's own route: only the host's rules keep the tunnel's echo from its reply
    let host = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    host.send_to(b"who", (PRIVATE, UDP_WHO)).await.unwrap();
    within(host.recv(&mut [0; 64])).await.expect("the peer is reached at its private address");
    let before = dropped("refused").await;
    later.send(&whole(held, PRIVATE, ICMP, &icmp_echo(0x1010, 1, b"private"))).await;
    later.quiet("an echo reply from a reserved destination").await;
    assert_eq!(dropped("refused").await, before, "the relay lets private targets through: the host's rules drop it");
    println!("ok 10: a private destination outside the pool, which the peer answers, is not reached");
    session.close(later).await;

    let sent_from = [me, them, held];
    let mut fresh = loop {
        let tunnel = session.tunnel().await;
        if !sent_from.contains(&tunnel.address) {
            break tunnel;
        }
        session.close(tunnel).await;
    };
    let address = fresh.address;
    // The peer fills the count of connections to the address's public ports, from as many source ports, and the
    // tunnel's own still pass. The reverse runs on the second tunnel, held open since check 7 left its address with no
    // connection.
    let peers: Vec<_> = (0..=FLOWS_PER_ADDRESS).map(|_| peer_socket(0)).collect();
    for peer in &peers[..usize::from(FLOWS_PER_ADDRESS)] {
        to_public_port(&mut fresh, peer).await;
    }
    for tunnel in [&mut fresh, &mut second] {
        let own = tunnel.address;
        for port in 41000..41000 + FLOWS_PER_ADDRESS {
            tunnel.send(&udp_packet((own, port), (PEER, UDP_WHO), b"who")).await;
            let answer = |p: &Packet| from_peer(p, UDP) && p.ports() == (UDP_WHO, port);
            tunnel.expect("an answer on the tunnel's own flow under its ceiling", answer).await;
        }
    }
    to_public_port(&mut second, &peers[0]).await;
    fresh.send(&udp_packet((address, 41000 + FLOWS_PER_ADDRESS), (PEER, UDP_WHO), b"who")).await;
    within(peers[usize::from(FLOWS_PER_ADDRESS)].send_to(b"in", (OUTSIDE, fresh.first_port))).await.unwrap();
    fresh.quiet("an answer or a datagram to a public port past its ceiling").await;
    println!(
        "ok 11: an address takes {FLOWS_PER_ADDRESS} connections to its public ports and {FLOWS_PER_ADDRESS} of its \
         own, either count full leaves the other open, and the next of either does not pass"
    );
    session.close(second).await;

    let before = dropped("refused").await;
    // the relay's own public address, OUTSIDE, the relay drops itself
    fresh.send(&whole(address, OUTSIDE_2, ICMP, &icmp_echo(0x1212, 1, b"host"))).await;
    fresh.send(&whole(address, OUTSIDE_2, TCP, &tcp((address, 40012), (OUTSIDE_2, HTTP_PORT), 1000, 0x02))).await;
    fresh.quiet("an answer from the relay's host").await;
    assert_eq!(dropped("refused").await, before, "the relay sends them on: the host's rules drop them");
    println!("ok 12: an echo request and a TCP SYN to the host's own address get no answer");
    session.close(fresh).await;

    public_ports(&mut session).await;

    let mut last = session.tunnel().await;
    let address = last.address;
    // connection tracking calls it invalid, and no address translation applies to such a packet
    last.send(&whole(address, PEER, TCP, &tcp((address, 40018), (PEER, TCP_LISTENER), 5555, 0x04))).await;
    sleep(QUIET).await;
    on_peer("nft list chain ip peer from_pool | grep -q 'counter packets 0 '").await;
    println!(
        "ok 18: no packet reached the peer with an address of the pool as its source, nor a TCP RST that starts no \
         connection"
    );
    // the TUN forwarder's own count is served, and no burst of these checks filled a tunnel's channel
    assert_eq!(dropped("forwarder_full").await, 0);

    // the last check, since the device is gone after it
    let deleted = Command::new("ip").args(["link", "delete", "dev", "webvpn0"]).status();
    assert!(within(deleted).await.unwrap().success(), "the device is deleted");
    assert_eq!(session.next().await, RelayPacket::Closed { socket: last.socket, code: ErrorCode::OTHER });
    let id = session.next_id;
    session.send(ClientPacket::IpOpen { id }).await;
    let refused = session.next().await;
    assert!(matches!(refused, RelayPacket::Error { id: of, code: ErrorCode::OTHER, .. } if of == id), "{refused:?}");
    println!("ok 19: a tunnel ends with its device, and the next is refused");
}

/// The checks of the tunnels' public ports. Every tunnel address is held, so each is known: the tunnels at
/// 13.0.0.3 and .4 took few connections to their public ports before, and stay far under that ceiling.
async fn public_ports(session: &mut Session) {
    let mut tunnels = Vec::new();
    for _ in 0..POOL.len() {
        tunnels.push(Some(session.tunnel().await));
    }
    let mut take = |address: Ipv4Addr| {
        tunnels.iter_mut().find(|held| held.as_ref().is_some_and(|tunnel| tunnel.address == address)).unwrap().take()
    };
    let (mut one, mut next, mut last) = (take(POOL[1]).unwrap(), take(POOL[2]).unwrap(), take(POOL[4]).unwrap());
    let rest: Vec<_> = tunnels.into_iter().flatten().collect();
    assert_eq!((one.first_port, next.first_port, last.first_port), (30008, 30016, 30032));
    let me = one.address;

    let connected = in_peer(|| std::net::TcpStream::connect_timeout(&SocketAddr::from((OUTSIDE, 30009)), WAIT));
    let opening = |p: &Packet| {
        from_peer(p, TCP) && p.target == me && p.ports().1 == 30009 && p.payload[13] & 0x12 == 0x02
    };
    let syn = one.expect("a SYN to a public port", opening).await;
    let (port, sequence) = (syn.ports().0, u32::from_be_bytes(syn.payload[4..8].try_into().unwrap()));
    one.send(&whole(me, PEER, TCP, &tcp_acking((me, 30009), (PEER, port), (7000, sequence + 1), 0x12))).await;
    let stream = joined(connected).await.expect("the peer's connection opens on the tunnel's SYN and ACK");
    assert_eq!(stream.peer_addr().unwrap(), SocketAddr::from((OUTSIDE, 30009)));
    one.expect("the peer's ACK", |p| from_peer(p, TCP) && p.ports() == (port, 30009) && p.payload[13] & 0x10 != 0)
        .await;
    let life = established_life(&["--reply-src", &me.to_string(), "--reply-port-src", "30009"]).await;
    assert!(life <= TCP_OPEN_LIFE, "the host keeps the quiet open connection to a public port {life} s");
    println!(
        "ok 13: a TCP SYN to a tunnel's public port reaches it on the same port, its SYN and ACK the peer, and the \
         host keeps the open connection no longer than the relay"
    );

    let peer = peer_socket(0);
    within(peer.send_to(b"in", (OUTSIDE, 30010))).await.unwrap();
    let datagram = one.expect("a datagram to a public port", |p| from_peer(p, UDP) && p.target == me).await;
    assert_eq!((datagram.ports().1, &datagram.payload[8..]), (30010, &b"in"[..]));
    one.send(&udp_packet((me, 30010), (PEER, datagram.ports().0), b"back")).await;
    let mut answer = [0; 16];
    let (length, from) = within(peer.recv_from(&mut answer)).await.unwrap();
    assert_eq!((&answer[..length], from), (&b"back"[..], SocketAddr::from((OUTSIDE, 30010))));
    println!("ok 14: a UDP datagram to a tunnel's public port reaches it, and its answer the peer from that port");

    within(peer.send_to(b"past", (OUTSIDE, 30016))).await.unwrap();
    let theirs = next.expect("a datagram to the next tunnel's port", |p| from_peer(p, UDP)).await;
    assert_eq!((theirs.target, theirs.ports().1), (next.address, 30016));
    one.quiet("a datagram one port past the tunnel's block").await;
    println!("ok 15: a port just past a tunnel's block reaches the tunnel that holds it, and not the first");

    let before = dropped("unasked").await;
    within(peer.send_to(b"past", (OUTSIDE, PUBLIC_PORTS.1 + 1))).await.unwrap();
    // straight to another tunnel's address: the host's rule maps only its own addresses, so this is not sent on
    within(peer.send_to(b"straight", (last.address, 30016))).await.unwrap();
    on_peer(&format!("socat -u OPEN:/dev/null TCP:{OUTSIDE}:{},connect-timeout=1 || true", PUBLIC_PORTS.1 + 1)).await;
    last.quiet("a datagram or a SYN to the port just past the range").await;
    next.quiet("a datagram to its public port straight to another tunnel's address").await;
    assert_eq!(dropped("unasked").await, before, "the host's rules drop them before the relay");
    println!("ok 16: a port past the range reaches no tunnel, and a public port is reached only by the host's address");

    let before = dropped("refused").await;
    one.send(&udp_packet((me, 40016), (OUTSIDE, 30016), b"own")).await;
    one.send(&udp_packet((me, 40017), (OUTSIDE_2, 30016), b"host")).await;
    next.quiet("a datagram from another tunnel to its public port").await;
    assert_eq!(dropped("refused").await, before + 1, "the relay drops the one to its own address");
    println!("ok 17: a tunnel does not reach another tunnel's public port");

    // held open until here, so that its end reaches no check that waits for quiet
    drop(stream);
    for tunnel in [one, next, last].into_iter().chain(rest) {
        session.close(tunnel).await;
    }
}
