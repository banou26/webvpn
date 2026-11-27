use std::net::{Ipv4Addr, SocketAddr};

use webvpn_proto::ErrorCode;
use webvpn_stack::{Buffers, Config, Protocol, Sent, Stack, TcpState as State};

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SITE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const BUFFERS: Buffers = Buffers { receive: 64 * 1024, send: 64 * 1024 };
const FIRST_PORT: u16 = 40000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Toward {
    Site,
    Client,
}

/// What the link does with a packet: deliver it after some milliseconds, or drop it.
enum Fate {
    After(i64),
    Drop,
    /// Answers the sender with this packet instead.
    Answer(Vec<u8>),
}

type Link = Box<dyn FnMut(Toward, &[u8]) -> Fate>;

/// The client's stack and a second one that plays the internet, joined by a link the test rules.
struct Net {
    client: Stack,
    site: Stack,
    now: i64,
    link: Link,
    flying: Vec<(i64, Toward, Vec<u8>)>,
}

fn config(ipv4: Ipv4Addr, ports: u16, seed: u64) -> Config {
    Config { ipv4: Some(ipv4), ipv6: None, mtu: 1500, first_port: FIRST_PORT, ports, seed, connect_timeout_ms: 10_000 }
}

impl Net {
    fn new() -> Self {
        Self::with_link(|_, _| Fate::After(1))
    }

    fn with_link(link: impl FnMut(Toward, &[u8]) -> Fate + 'static) -> Self {
        Self {
            client: Stack::new(config(CLIENT, 8, 1), 0),
            site: Stack::new(config(SITE, 0, 2), 0),
            now: 0,
            link: Box::new(link),
            flying: Vec::new(),
        }
    }

    /// One millisecond: both stacks poll, and the link moves what they sent.
    fn tick(&mut self) {
        self.client.poll(self.now);
        self.site.poll(self.now);
        for (from, toward) in [(0, Toward::Site), (1, Toward::Client)] {
            let stack = if from == 0 { &mut self.client } else { &mut self.site };
            while let Some(packet) = stack.output() {
                match (self.link)(toward, &packet) {
                    Fate::After(ms) => self.flying.push((self.now + ms, toward, packet)),
                    Fate::Drop => {}
                    Fate::Answer(answer) => {
                        let back = if toward == Toward::Site { Toward::Client } else { Toward::Site };
                        self.flying.push((self.now + 1, back, answer));
                    }
                }
            }
        }
        let now = self.now;
        let (due, flying): (Vec<_>, Vec<_>) = self.flying.drain(..).partition(|(at, ..)| *at <= now);
        self.flying = flying;
        for (_, toward, packet) in due {
            match toward {
                Toward::Site => self.site.input(&packet),
                Toward::Client => self.client.input(&packet),
            }
        }
        self.now += 1;
    }

    /// Ticks until `done` holds, at most `ms` milliseconds; whether it held.
    fn until(&mut self, ms: i64, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        for _ in 0..ms {
            if done(self) {
                return true;
            }
            self.tick();
        }
        done(self)
    }

    fn established(&mut self, client: u32) -> bool {
        self.until(2000, |net| net.client.tcp_state(client) == Some(State::Established))
    }

    /// A connection from the client to a listener of the site, and the site's end of it.
    fn connect(&mut self, port: u16) -> (u32, u32) {
        let listener = self.site.tcp_listen(port, 4, BUFFERS).unwrap();
        let client = self.client.tcp_connect(SocketAddr::new(SITE.into(), port), BUFFERS).unwrap();
        assert!(self.established(client));
        let mut site = None;
        assert!(self.until(1000, |net| {
            site = net.site.tcp_accept(listener);
            site.is_some()
        }));
        (client, site.unwrap())
    }
}

/// Moves `data` from `from` to `to` over a connection, as far as the stacks take it; returns what `to` read.
fn transfer(net: &mut Net, toward: Toward, (from, to): (u32, u32), data: &[u8], ms: i64) -> Vec<u8> {
    let mut sent = 0;
    let mut read = Vec::new();
    let mut chunk = vec![0; 16 * 1024];
    net.until(ms, |net| {
        let (sender, receiver) = match toward {
            Toward::Site => (&mut net.client, &mut net.site),
            Toward::Client => (&mut net.site, &mut net.client),
        };
        sent += sender.tcp_send(from, &data[sent..]).unwrap();
        while let Some(length @ 1..) = receiver.tcp_recv(to, &mut chunk) {
            read.extend_from_slice(&chunk[..length]);
        }
        read.len() == data.len()
    });
    read
}

fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|at| (at * 7 % 251) as u8).collect()
}

#[test]
fn connects_carries_bytes_both_ways_and_closes_in_order() {
    let mut net = Net::new();
    let (client, site) = net.connect(80);
    let (local, remote) = net.client.tcp_endpoints(client).unwrap();
    assert_eq!((local.ip(), remote), (CLIENT.into(), SocketAddr::new(SITE.into(), 80)));
    assert!(!(FIRST_PORT..FIRST_PORT + 8).contains(&local.port()), "a connect takes a private port");

    let up = pattern(200_000);
    assert_eq!(transfer(&mut net, Toward::Site, (client, site), &up, 5000), up);
    let down = pattern(300_000);
    assert_eq!(transfer(&mut net, Toward::Client, (site, client), &down, 5000), down);

    net.client.tcp_close(client);
    let mut buffer = [0; 16];
    assert!(net.until(1000, |net| net.site.tcp_recv(site, &mut buffer).is_none()), "the site reads the end");
    net.site.tcp_send(site, b"after").unwrap();
    assert_eq!(transfer(&mut net, Toward::Client, (site, client), b"", 0), b"");
    assert!(net.until(1000, |net| net.client.tcp_recv(client, &mut buffer) == Some(5)), "a half close still reads");
    net.site.tcp_close(site);
    assert!(net.until(1000, |net| net.client.tcp_recv(client, &mut buffer).is_none()));
    assert!(net.until(1000, |net| net.site.tcp_state(site) == Some(State::Closed)));
    assert_eq!((net.client.tcp_error(client), net.site.tcp_error(site)), (None, None));
}

#[test]
fn an_abort_resets_the_peer() {
    let mut net = Net::new();
    let (client, site) = net.connect(80);
    net.site.tcp_abort(site);
    assert!(net.until(1000, |net| net.client.tcp_state(client) == Some(State::Closed)));
    assert_eq!(net.client.tcp_error(client), Some(ErrorCode::CONNECTION_RESET));
    assert_eq!(net.site.tcp_error(site), None, "the side that aborted has no error");
    assert_eq!(net.client.tcp_recv(client, &mut [0; 4]), None);
    assert_eq!(net.client.tcp_send(client, b"late"), Err(ErrorCode::CONNECTION_RESET));
}

#[test]
fn a_connect_to_a_closed_port_is_refused() {
    let mut net = Net::new();
    let client = net.client.tcp_connect(SocketAddr::new(SITE.into(), 81), BUFFERS).unwrap();
    assert!(net.until(1000, |net| net.client.tcp_state(client) == Some(State::Closed)));
    assert_eq!(net.client.tcp_error(client), Some(ErrorCode::CONNECTION_REFUSED));
}

#[test]
fn a_connect_with_no_answer_times_out_at_its_limit() {
    let mut net = Net::with_link(|_, _| Fate::Drop);
    let client = net.client.tcp_connect(SocketAddr::new(SITE.into(), 80), BUFFERS).unwrap();
    assert!(!net.until(9_990, |net| net.client.tcp_state(client) == Some(State::Closed)));
    assert!(net.until(20, |net| net.client.tcp_state(client) == Some(State::Closed)));
    assert_eq!(net.client.tcp_error(client), Some(ErrorCode::TIMED_OUT));
}

#[test]
fn a_connect_closing_on_its_own_is_neither_refused_nor_reset() {
    let mut net = Net::with_link(|_, _| Fate::Drop);
    let client = net.client.tcp_connect(SocketAddr::new(SITE.into(), 80), BUFFERS).unwrap();
    net.tick();
    net.client.tcp_close(client);
    net.tick();
    assert_eq!(net.client.tcp_state(client), Some(State::Closed));
    assert_eq!(net.client.tcp_error(client), None);
}

/// An ICMP destination unreachable from a router, quoting the packet it is about.
fn icmp_unreachable(quoting: &[u8], code: u8) -> Vec<u8> {
    let router = Ipv4Addr::new(198, 51, 100, 1);
    let quoted = &quoting[..28];
    let mut icmp = vec![3, code, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(quoted);
    let sum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0];
    packet[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&router.octets());
    packet.extend_from_slice(&quoting[12..16]);
    let sum = checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(&icmp);
    packet
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes.chunks(2).map(|pair| u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0))).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[test]
fn an_icmp_error_about_the_opening_packet_fails_the_connect_with_its_reason() {
    for (code, error) in [
        (1, ErrorCode::HOST_UNREACHABLE),
        (0, ErrorCode::NETWORK_UNREACHABLE),
        (13, ErrorCode::HOST_UNREACHABLE),
    ] {
        let mut net = Net::with_link(move |toward, packet| match toward {
            Toward::Site => Fate::Answer(icmp_unreachable(packet, code)),
            Toward::Client => Fate::After(1),
        });
        let client = net.client.tcp_connect(SocketAddr::new(SITE.into(), 80), BUFFERS).unwrap();
        assert!(net.until(100, |net| net.client.tcp_state(client) == Some(State::Closed)), "code {code}");
        assert_eq!(net.client.tcp_error(client), Some(error), "code {code}");
    }
}

#[test]
fn fragmentation_needed_does_not_fail_a_connect() {
    let mut answered = false;
    let mut net = Net::with_link(move |toward, packet| match toward {
        Toward::Site if !answered => {
            answered = true;
            Fate::Answer(icmp_unreachable(packet, 4))
        }
        _ => Fate::After(1),
    });
    net.site.tcp_listen(80, 1, BUFFERS).unwrap();
    let client = net.client.tcp_connect(SocketAddr::new(SITE.into(), 80), BUFFERS).unwrap();
    assert!(net.established(client), "the SYN is sent again and answered");
}

#[test]
fn a_listener_takes_several_connections_at_once() {
    let mut net = Net::new();
    let port = net.client.public_port(Protocol::Tcp).unwrap();
    assert_eq!(port, FIRST_PORT);
    let listener = net.client.tcp_listen(port, 8, BUFFERS).unwrap();
    assert_eq!(net.client.public_port(Protocol::Tcp), Some(FIRST_PORT + 1));
    assert_eq!(net.client.tcp_listen(port, 4, BUFFERS), Err(ErrorCode::ADDRESS_IN_USE));

    let dialed: Vec<u32> = (0..6)
        .map(|_| net.site.tcp_connect(SocketAddr::new(CLIENT.into(), port), BUFFERS).unwrap())
        .collect();
    assert!(net.until(2000, |net| dialed.iter().all(|&id| net.site.tcp_state(id) == Some(State::Established))));
    let mut accepted = Vec::new();
    assert!(net.until(1000, |net| {
        accepted.extend(std::iter::from_fn(|| net.client.tcp_accept(listener)));
        accepted.len() == dialed.len()
    }));

    let mut peers: Vec<u16> = accepted.iter().map(|&id| net.client.tcp_endpoints(id).unwrap().1.port()).collect();
    let mut dialers: Vec<u16> = dialed.iter().map(|&id| net.site.tcp_endpoints(id).unwrap().0.port()).collect();
    peers.sort();
    dialers.sort();
    assert_eq!(peers, dialers);
    for &from in &dialed {
        net.site.tcp_send(from, b"hi").unwrap();
    }
    assert!(net.until(100, |net| accepted.iter().all(|&id| net.client.tcp_recv(id, &mut [0; 2]) == Some(2))));
}

#[test]
fn a_listener_refuses_what_its_backlog_has_no_room_for_until_one_is_accepted() {
    let mut net = Net::new();
    let listener = net.client.tcp_listen(FIRST_PORT, 2, BUFFERS).unwrap();
    let dial = |net: &mut Net| {
        let id = net.site.tcp_connect(SocketAddr::new(CLIENT.into(), FIRST_PORT), BUFFERS).unwrap();
        assert!(net.until(1000, |net| net.site.tcp_state(id) != Some(State::SynSent)));
        net.until(10, |_| false);
        (net.site.tcp_state(id), net.site.tcp_error(id))
    };
    for _ in 0..2 {
        assert_eq!(dial(&mut net), (Some(State::Established), None));
    }
    assert_eq!(dial(&mut net), (Some(State::Closed), Some(ErrorCode::CONNECTION_REFUSED)), "the backlog is full");
    assert!(net.client.tcp_accept(listener).is_some());
    net.tick();
    assert_eq!(dial(&mut net), (Some(State::Established), None), "accepting one made room");
}

#[test]
fn a_released_listener_resets_what_nobody_accepted() {
    let mut net = Net::new();
    let listener = net.client.tcp_listen(FIRST_PORT, 2, BUFFERS).unwrap();
    let dialed = net.site.tcp_connect(SocketAddr::new(CLIENT.into(), FIRST_PORT), BUFFERS).unwrap();
    assert!(net.until(1000, |net| net.site.tcp_state(dialed) == Some(State::Established)));
    // until the client has the connection established and waiting to be accepted
    net.until(10, |_| false);
    net.client.release(listener);
    assert!(net.until(1000, |net| net.site.tcp_state(dialed) == Some(State::Closed)));
    assert_eq!(net.site.tcp_error(dialed), Some(ErrorCode::CONNECTION_RESET));
    let again = net.site.tcp_connect(SocketAddr::new(CLIENT.into(), FIRST_PORT), BUFFERS).unwrap();
    assert!(net.until(1000, |net| net.site.tcp_state(again) == Some(State::Closed)));
    assert_eq!(net.site.tcp_error(again), Some(ErrorCode::CONNECTION_REFUSED));
}

#[test]
fn a_released_connection_still_sends_what_it_held_and_ends() {
    let mut net = Net::new();
    let (client, site) = net.connect(80);
    let data = pattern(40_000);
    assert_eq!(net.client.tcp_send(client, &data), Ok(40_000));
    net.client.tcp_close(client);
    net.client.release(client);
    let mut read = Vec::new();
    let mut chunk = [0; 4096];
    assert!(net.until(2000, |net| loop {
        match net.site.tcp_recv(site, &mut chunk) {
            Some(0) => break false,
            Some(length) => read.extend_from_slice(&chunk[..length]),
            None => break true,
        }
    }));
    assert_eq!(read, data);
    let more = pattern(300_000);
    let mut sent = 0;
    assert!(net.until(5000, |net| {
        if sent < more.len() {
            sent += net.site.tcp_send(site, &more[sent..]).unwrap();
            if sent == more.len() {
                net.site.tcp_close(site);
            }
        }
        net.site.tcp_state(site) == Some(State::Closed)
    }), "the client drains what comes, more than its window");
    assert_eq!(net.site.tcp_error(site), None);
}

#[test]
fn udp_carries_datagrams_both_ways_from_private_and_public_ports() {
    let mut net = Net::new();
    let site = net.site.udp_bind(53, BUFFERS).unwrap();
    let private = net.client.udp_bind(0, BUFFERS).unwrap();
    let port = net.client.udp_port(private).unwrap();
    assert!(port >= 49152 && !(FIRST_PORT..FIRST_PORT + 8).contains(&port));
    let public = net.client.udp_bind(net.client.public_port(Protocol::Udp).unwrap(), BUFFERS).unwrap();
    assert_eq!(net.client.udp_port(public), Some(FIRST_PORT));
    assert_eq!(net.client.udp_bind(FIRST_PORT, BUFFERS), Err(ErrorCode::ADDRESS_IN_USE));

    let target = SocketAddr::new(SITE.into(), 53);
    assert_eq!(net.client.udp_send(private, target, b"query"), Ok(Sent::Queued));
    let mut buffer = [0; 1500];
    let mut got = None;
    assert!(net.until(100, |net| {
        got = net.site.udp_recv(site, &mut buffer);
        got.is_some()
    }));
    let (length, from) = got.unwrap();
    assert_eq!((&buffer[..length], from), (&b"query"[..], SocketAddr::new(CLIENT.into(), port)));

    net.site.udp_send(site, from, b"answer").unwrap();
    net.site.udp_send(site, SocketAddr::new(CLIENT.into(), FIRST_PORT), b"to the public port").unwrap();
    assert!(net.until(100, |net| net.client.udp_recv(private, &mut buffer) == Some((6, target))));
    assert!(net.until(100, |net| net.client.udp_recv(public, &mut buffer).is_some_and(|(length, _)| length == 18)));
    assert_eq!(net.client.udp_send(private, target, &[0; 1473]), Err(ErrorCode::OTHER), "longer than the MTU");
}

#[test]
fn every_change_is_told_once_as_an_event() {
    let mut net = Net::new();
    let (client, site) = net.connect(80);
    net.tick();
    net.client.events(usize::MAX);
    net.site.tcp_send(site, b"x").unwrap();
    assert!(net.until(100, |net| net.client.events(usize::MAX).contains(&client)));
    for _ in 0..5 {
        net.tick();
        assert!(!net.client.events(usize::MAX).contains(&client), "no change, no event");
    }

    // the next byte reaches the client's queue before the page takes the first, and both polls see one byte waiting
    net.site.tcp_set_no_delay(site, true).unwrap();
    net.site.tcp_send(site, b"y").unwrap();
    net.tick();
    net.tick();
    assert!(net.client.events(usize::MAX).is_empty());
    assert_eq!(net.client.tcp_recv(client, &mut [0; 1]), Some(1));
    net.tick();
    assert!(net.client.events(usize::MAX).contains(&client), "a byte that came after one was taken is a change");
}

#[test]
fn a_poll_asks_for_the_next_one_when_a_timer_is_due() {
    let mut stack = Stack::new(config(CLIENT, 8, 1), 0);
    assert_eq!(stack.poll(0), None, "an idle stack needs no poll");
    stack.tcp_connect(SocketAddr::new(SITE.into(), 80), BUFFERS).unwrap();
    let retransmission = stack.poll(0);
    assert!(matches!(retransmission, Some(1..=10_000)), "{retransmission:?}");

    let mut stack = Stack::new(Config { connect_timeout_ms: 50, ..config(CLIENT, 8, 1) }, 0);
    stack.tcp_connect(SocketAddr::new(SITE.into(), 80), BUFFERS).unwrap();
    assert_eq!(stack.poll(0), Some(50), "the connect's limit comes before the retransmission");
}

#[test]
fn a_private_port_is_never_a_public_one() {
    let mut stack = Stack::new(Config { first_port: 49152, ports: 16383, ..config(CLIENT, 8, 1) }, 0);
    let udp = stack.udp_bind(0, BUFFERS).unwrap();
    assert_eq!(stack.udp_port(udp), Some(65535));
    assert_eq!(stack.udp_bind(0, BUFFERS), Err(ErrorCode::ADDRESS_IN_USE));
    let tcp = stack.tcp_connect(SocketAddr::new(SITE.into(), 80), BUFFERS).unwrap();
    stack.poll(0);
    assert_eq!(stack.tcp_endpoints(tcp).unwrap().0.port(), 65535);
}

#[test]
fn a_lossy_slow_link_still_delivers_everything_in_order() {
    let mut count = 0;
    let mut net = Net::with_link(move |_, _| {
        count += 1;
        if count % 10 == 0 {
            Fate::Drop
        } else {
            Fate::After(20 + (count % 7))
        }
    });
    let (client, site) = net.connect(80);
    let down = pattern(500_000);
    assert_eq!(transfer(&mut net, Toward::Client, (site, client), &down, 60_000), down);
    let up = pattern(200_000);
    assert_eq!(transfer(&mut net, Toward::Site, (client, site), &up, 60_000), up);
    assert_eq!(net.client.tcp_state(client), Some(State::Established));
}
