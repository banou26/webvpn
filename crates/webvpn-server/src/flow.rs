//! The flows an IP tunnel holds, and which packets toward its client answer one of them or begin one on a public port.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tokio::time::Instant;

use crate::metrics::Counter;
use crate::packet::{self, Dropped, Header};

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;
const ICMPV6: u8 = 58;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

// How long a flow lives after its last packet either way. RFC 5382 (REQ-5) has a NAT keep an established TCP
// connection at least 2 hours 4 minutes, and RFC 4787 (REQ-5) keep a UDP mapping at least 2 minutes and recommends 5.
// A TCP connection not answered yet or past a FIN or a RST, and a flow of another protocol, live 2 minutes: the least
// the specification promises a client, and what Linux's connection tracking keeps a TCP connection being opened or
// closed (RFC 5382 asks 4 minutes for those).
const TCP_OPEN_LIFE: Duration = Duration::from_secs(2 * 60 * 60 + 4 * 60);
const TCP_TRANSITORY_LIFE: Duration = Duration::from_secs(2 * 60);
const UDP_LIFE: Duration = Duration::from_secs(5 * 60);
const OTHER_LIFE: Duration = Duration::from_secs(2 * 60);

/// The flows one tunnel holds at most: the most a hash table of 4096 slots holds. A flow and its entry take 48 bytes
/// and a slot one more, and the index of peers for fragments as many slots of 41 bytes, so a full table costs a
/// tunnel about 360 KiB.
pub(crate) const MAX_FLOWS: usize = 3584;

/// One flow, as the tunnel sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Flow {
    protocol: u8,
    peer: IpAddr,
    ids: Ids,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Ids {
    Ports { tunnel: u16, peer: u16 },
    Echo(u16),
    None,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    seen: Instant,
    answered: bool,
    closing: bool,
    /// Whether the tunnel sent a packet of it: a full table pushes out the flows only their peers sent on first.
    sent: bool,
}

impl Entry {
    fn new(now: Instant) -> Self {
        Self { seen: now, answered: false, closing: false, sent: false }
    }

    fn life(&self, protocol: u8) -> Duration {
        match protocol {
            TCP if self.answered && !self.closing => TCP_OPEN_LIFE,
            TCP => TCP_TRANSITORY_LIFE,
            UDP => UDP_LIFE,
            _ => OTHER_LIFE,
        }
    }

    fn until(&self, protocol: u8) -> Instant {
        self.seen + self.life(protocol)
    }
}

/// What a packet names: its flow, or for a fragment after the first, which holds no ports, only its protocol and peer.
enum Names {
    Flow(Flow),
    Peer(u8, IpAddr),
}

/// The flows one tunnel holds, at most a bound of them, and the check that a packet toward its client answers one or
/// begins one on a public port.
pub(crate) struct Flows {
    capacity: usize,
    /// The tunnel's public ports: `ports` of them from `first_port` on.
    first_port: u16,
    ports: u16,
    flows: HashMap<Flow, Entry>,
    /// For each protocol and peer with a flow in `flows`, the latest any of those flows lives until, or later: a flow
    /// past a FIN keeps the life it had until the table is next swept.
    peers: HashMap<(u8, IpAddr), Instant>,
}

impl Flows {
    /// A table of at most `capacity` flows, for a tunnel whose public ports are `ports` ports from `first_port` on.
    pub(crate) fn new(capacity: usize, first_port: u16, ports: u16) -> Self {
        Self { capacity, first_port, ports, flows: HashMap::new(), peers: HashMap::new() }
    }

    /// Records or refreshes the flow of `sent`, a packet from the client that passed every check. A fragment after the
    /// first makes no flow. A new flow that finds the table full first removes the flows past their life and, if it is
    /// still full, an eighth of the table at once: first the flows only their peers sent on, then the ones nearest the
    /// end of their life.
    pub(crate) fn sent(&mut self, sent: &Header, now: Instant) {
        let Some(Names::Flow(flow)) = names(sent, true) else { return };
        let flags = tcp_flags(sent);
        let opens = flow.protocol == TCP && flags & (TCP_SYN | TCP_ACK) == TCP_SYN;
        self.begin(flow, opens, flags, now).sent = true;
    }

    /// Records `flow`, or refreshes it, starts it over when `opens` or when it is past its life, and gives its entry.
    fn begin(&mut self, flow: Flow, opens: bool, flags: u8, now: Instant) -> &mut Entry {
        if !self.flows.contains_key(&flow) && self.flows.len() >= self.capacity {
            self.make_room(now);
        }
        let entry = self.flows.entry(flow).or_insert(Entry::new(now));
        if opens || entry.until(flow.protocol) <= now {
            *entry = Entry::new(now);
        }
        touch(&mut self.peers, flow, entry, flags, now);
        entry
    }

    /// Whether `packet`, from the forwarder, may reach the client of the tunnel given `ipv4` and `ipv6`: a whole packet
    /// to one of those addresses that answers a flow the tunnel holds, or an ICMP error about a packet of one, or a TCP
    /// or UDP packet to one of the public ports, which begins a flow as a packet from the client does. An answer
    /// refreshes its flow; an error does not. A fragment after the first passes as an answer does, so a datagram to a
    /// public port in fragments passes when its first fragment comes first.
    pub(crate) fn admit(
        &mut self,
        packet: &[u8],
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        now: Instant,
    ) -> Result<(), Dropped> {
        let header = packet::read(packet, true).map_err(|_| Counter::IpDroppedDownInvalid)?;
        let own = match header.target {
            IpAddr::V4(target) => Some(target) == ipv4,
            IpAddr::V6(target) => Some(target) == ipv6,
        };
        if !own {
            return Err(Counter::IpDroppedDownDestination);
        }
        let answers = if !header.later_fragment && is_error(&header) {
            self.quotes_sent(&header, now)
        } else {
            match names(&header, false).ok_or(Counter::IpDroppedDownInvalid)? {
                Names::Peer(protocol, peer) => self.peer_alive(protocol, peer, now),
                Names::Flow(flow) => match self.flows.get_mut(&flow) {
                    Some(entry) if entry.until(flow.protocol) > now => {
                        entry.answered = true;
                        touch(&mut self.peers, flow, entry, tcp_flags(&header), now);
                        true
                    }
                    _ => match flow.ids {
                        Ids::Ports { tunnel, .. } if self.is_public(tunnel) => {
                            self.begin(flow, true, tcp_flags(&header), now);
                            true
                        }
                        _ => false,
                    },
                },
            }
        };
        answers.then_some(()).ok_or(Counter::IpDroppedUnasked)
    }

    /// Whether `error`, an ICMP error, quotes the start of a packet this tunnel sent: from the address the error came
    /// to, of a flow that is alive. The error's own source is whichever router sent it.
    fn quotes_sent(&self, error: &Header, now: Instant) -> bool {
        let Some(Ok(quoted)) = error.upper.get(8..).map(|quoted| packet::read(quoted, false)) else { return false };
        if quoted.source != error.target {
            return false;
        }
        match names(&quoted, true) {
            Some(Names::Flow(flow)) => self.flows.get(&flow).is_some_and(|entry| entry.until(flow.protocol) > now),
            Some(Names::Peer(protocol, peer)) => self.peer_alive(protocol, peer, now),
            None => false,
        }
    }

    fn is_public(&self, port: u16) -> bool {
        u32::from(port).wrapping_sub(u32::from(self.first_port)) < u32::from(self.ports)
    }

    fn peer_alive(&self, protocol: u8, peer: IpAddr, now: Instant) -> bool {
        self.peers.get(&(protocol, peer)).is_some_and(|&until| until > now)
    }

    /// Removes the flows past their life and, if the table is still full, more until an eighth of it is free: first
    /// the flows only their peers sent on, since the next packet to a public port begins its flow again, then the ones
    /// nearest the end of their life, so that short flows go before an open TCP connection. A sweep costs a pass over
    /// the table, so freeing an eighth at once keeps a tunnel that opens a new flow with every packet at a few steps a
    /// packet on average.
    fn make_room(&mut self, now: Instant) {
        self.flows.retain(|flow, entry| entry.until(flow.protocol) > now);
        let keep = self.capacity - (self.capacity / 8).max(1);
        if self.flows.len() > keep {
            let pushed = self.flows.len() - keep;
            let mut by_rank: Vec<_> =
                self.flows.iter().map(|(flow, entry)| ((entry.sent, entry.until(flow.protocol)), *flow)).collect();
            by_rank.select_nth_unstable_by_key(pushed - 1, |&(rank, _)| rank);
            for (_, flow) in &by_rank[..pushed] {
                self.flows.remove(flow);
            }
        }
        self.peers.clear();
        for (flow, entry) in &self.flows {
            let until = entry.until(flow.protocol);
            let latest = self.peers.entry((flow.protocol, flow.peer)).or_insert(until);
            *latest = (*latest).max(until);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.flows.len()
    }
}

/// Notes a packet of `flow` either way at `now`.
fn touch(peers: &mut HashMap<(u8, IpAddr), Instant>, flow: Flow, entry: &mut Entry, flags: u8, now: Instant) {
    entry.seen = now;
    if flags & (TCP_FIN | TCP_RST) != 0 {
        entry.closing = true;
    }
    let until = entry.until(flow.protocol);
    let latest = peers.entry((flow.protocol, flow.peer)).or_insert(until);
    *latest = (*latest).max(until);
}

/// What a packet of `header` names, the tunnel's packet when `sent` and its peer's otherwise, or `None` when it is
/// cut short of its ports or echo identifier.
fn names(header: &Header, sent: bool) -> Option<Names> {
    let (protocol, upper) = (header.protocol, header.upper);
    let peer = if sent { header.target } else { header.source };
    if header.later_fragment {
        return Some(Names::Peer(protocol, peer));
    }
    let ids = match protocol {
        TCP | UDP => {
            let (source, target) = (u16_at(upper, 0)?, u16_at(upper, 2)?);
            let (tunnel, peer) = if sent { (source, target) } else { (target, source) };
            Ids::Ports { tunnel, peer }
        }
        ICMP | ICMPV6 if upper.first() == Some(&echo(protocol, sent)) => Ids::Echo(u16_at(upper, 4)?),
        _ => Ids::None,
    };
    Some(Names::Flow(Flow { protocol, peer, ids }))
}

/// The ICMP type of an echo request when `sent`, of an echo reply otherwise.
fn echo(protocol: u8, sent: bool) -> u8 {
    match (protocol == ICMP, sent) {
        (true, true) => 8,
        (true, false) => 0,
        (false, true) => 128,
        (false, false) => 129,
    }
}

/// Whether `header` is an ICMP error that quotes a packet: destination unreachable, time exceeded or parameter
/// problem, and for ICMPv6 packet too big too.
pub(crate) fn is_error(header: &Header) -> bool {
    matches!((header.protocol, header.upper.first()), (ICMP, Some(3 | 11 | 12)) | (ICMPV6, Some(1..=4)))
}

fn tcp_flags(header: &Header) -> u8 {
    match header.protocol {
        TCP if !header.later_fragment => header.upper.get(13).copied().unwrap_or(0),
        _ => 0,
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..at + 2).map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests::{v4, v6, CLIENT_V4, CLIENT_V6};

    const PEER_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
    const PEER_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9);
    const OTHER_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
    const ROUTER_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const ROUTER_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    const ANOTHER_TUNNEL_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 3);
    const GRE: u8 = 47;
    const MORE_FRAGMENTS: u16 = 0x2000;
    const MINUTE: Duration = Duration::from_secs(60);
    const MS: Duration = Duration::from_millis(1);

    /// A TCP or UDP header from `source` to `target`, with TCP's `flags`.
    fn ports(source: u16, target: u16, flags: u8) -> Vec<u8> {
        let mut header = [source.to_be_bytes(), target.to_be_bytes()].concat();
        header.resize(20, 0);
        header[13] = flags;
        header
    }

    /// An ICMP or ICMPv6 message of `kind` whose second word holds `identifier`, followed by `rest`.
    fn icmp(kind: u8, identifier: u16, rest: &[u8]) -> Vec<u8> {
        let mut message = vec![kind, 0, 0, 0];
        message.extend(identifier.to_be_bytes());
        message.extend([0, 1]);
        message.extend(rest);
        message
    }

    fn up(protocol: u8, payload: &[u8]) -> Vec<u8> {
        v4(CLIENT_V4, PEER_V4, protocol, 0, &[], payload)
    }

    fn down(protocol: u8, payload: &[u8]) -> Vec<u8> {
        v4(PEER_V4, CLIENT_V4, protocol, 0, &[], payload)
    }

    struct Table {
        flows: Flows,
        start: Instant,
    }

    impl Table {
        fn new(capacity: usize) -> Self {
            Self::public(capacity, 0, 0)
        }

        /// A table for a tunnel with `ports` public ports from `first_port` on.
        fn public(capacity: usize, first_port: u16, ports: u16) -> Self {
            Self { flows: Flows::new(capacity, first_port, ports), start: Instant::now() }
        }

        fn send_at(&mut self, at: Duration, packet: &[u8]) {
            let (_, header) = packet::check(packet, Some(CLIENT_V4), Some(CLIENT_V6)).expect("a packet that passes");
            self.flows.sent(&header, self.start + at);
        }

        fn send(&mut self, packet: &[u8]) {
            self.send_at(Duration::ZERO, packet);
        }

        fn admit_at(&mut self, at: Duration, packet: &[u8]) -> Result<(), Dropped> {
            self.flows.admit(packet, Some(CLIENT_V4), Some(CLIENT_V6), self.start + at)
        }

        fn admit(&mut self, packet: &[u8]) -> Result<(), Dropped> {
            self.admit_at(Duration::ZERO, packet)
        }
    }

    /// Opens a TCP connection from the tunnel's port 40000 to the peer's port 443 at the start, which the peer answers.
    fn open_tcp(table: &mut Table) {
        table.send(&up(TCP, &ports(40000, 443, TCP_SYN)));
        assert_eq!(table.admit(&down(TCP, &ports(443, 40000, TCP_SYN | TCP_ACK))), Ok(()));
        table.send(&up(TCP, &ports(40000, 443, TCP_ACK)));
    }

    const UNASKED: Result<(), Dropped> = Err(Counter::IpDroppedUnasked);

    #[test]
    fn a_tcp_or_udp_answer_passes_only_from_the_peer_s_port_to_the_tunnel_s_port() {
        for protocol in [TCP, UDP] {
            let mut table = Table::new(MAX_FLOWS);
            table.send(&up(protocol, &ports(40000, 443, TCP_SYN)));
            assert_eq!(table.admit(&down(protocol, &ports(443, 40000, TCP_SYN | TCP_ACK))), Ok(()));
            assert_eq!(table.admit(&down(protocol, &ports(444, 40000, TCP_ACK))), UNASKED, "another peer port");
            assert_eq!(table.admit(&down(protocol, &ports(443, 40001, TCP_ACK))), UNASKED, "another tunnel port");
            let elsewhere = v4(OTHER_V4, CLIENT_V4, protocol, 0, &[], &ports(443, 40000, TCP_ACK));
            assert_eq!(table.admit(&elsewhere), UNASKED, "another peer");
            let other = if protocol == TCP { UDP } else { TCP };
            assert_eq!(table.admit(&down(other, &ports(443, 40000, TCP_ACK))), UNASKED, "another protocol");
        }
    }

    #[test]
    fn an_echo_reply_passes_with_the_request_s_identifier_only() {
        let mut table = Table::new(MAX_FLOWS);
        table.send(&up(ICMP, &icmp(8, 7, &[])));
        assert_eq!(table.admit(&down(ICMP, &icmp(0, 7, &[]))), Ok(()));
        assert_eq!(table.admit(&down(ICMP, &icmp(0, 8, &[]))), UNASKED);
        // the peer's own echo request is not an answer
        assert_eq!(table.admit(&down(ICMP, &icmp(8, 7, &[]))), UNASKED);

        table.send(&v6(CLIENT_V6, PEER_V6, ICMPV6, &icmp(128, 9, &[])));
        assert_eq!(table.admit(&v6(PEER_V6, CLIENT_V6, ICMPV6, &icmp(129, 9, &[]))), Ok(()));
        assert_eq!(table.admit(&v6(PEER_V6, CLIENT_V6, ICMPV6, &icmp(129, 7, &[]))), UNASKED);
    }

    #[test]
    fn a_packet_of_another_protocol_passes_from_the_peer_the_tunnel_sent_it_to() {
        let mut table = Table::new(MAX_FLOWS);
        table.send(&up(GRE, &[0; 8]));
        assert_eq!(table.admit(&down(GRE, &[1; 8])), Ok(()));
        assert_eq!(table.admit(&v4(OTHER_V4, CLIENT_V4, GRE, 0, &[], &[1; 8])), UNASKED);
        assert_eq!(table.admit(&down(UDP, &ports(1, 2, 0))), UNASKED);
    }

    #[test]
    fn a_packet_that_is_not_whole_or_not_to_the_tunnel_s_address_is_dropped_first() {
        let mut table = Table::new(MAX_FLOWS);
        table.send(&up(UDP, &ports(40000, 53, 0)));
        let mut answer = down(UDP, &ports(53, 40000, 0));
        answer.push(0);
        assert_eq!(table.admit(&answer), Err(Counter::IpDroppedDownInvalid));
        assert_eq!(table.admit(&[0x45, 0]), Err(Counter::IpDroppedDownInvalid));
        // a UDP header cut short of its ports
        assert_eq!(table.admit(&down(UDP, &[0, 53])), Err(Counter::IpDroppedDownInvalid));
        let elsewhere = v4(PEER_V4, ANOTHER_TUNNEL_V4, UDP, 0, &[], &ports(53, 40000, 0));
        assert_eq!(table.admit(&elsewhere), Err(Counter::IpDroppedDownDestination));
        let v4_only = table.flows.admit(&down(UDP, &ports(53, 40000, 0)), None, Some(CLIENT_V6), table.start);
        assert_eq!(v4_only, Err(Counter::IpDroppedDownDestination));
    }

    #[test]
    fn an_icmpv4_error_passes_when_it_quotes_the_start_of_a_packet_the_tunnel_sent() {
        let mut table = Table::new(MAX_FLOWS);
        let sent = up(UDP, &ports(40000, 53, 0));
        table.send(&sent);
        let not_sent = up(UDP, &ports(40000, 54, 0));
        for kind in [3, 11, 12] {
            // an IPv4 error quotes the header and 8 bytes past it
            let error = |quoted: &[u8]| v4(ROUTER_V4, CLIENT_V4, ICMP, 0, &[], &icmp(kind, 0, quoted));
            assert_eq!(table.admit(&error(&sent[..28])), Ok(()), "type {kind}");
            assert_eq!(table.admit(&error(&not_sent[..28])), UNASKED, "type {kind}");
            assert_eq!(table.admit(&error(&sent[..23])), UNASKED, "type {kind} cut short");
        }
        // a type that is not an error is matched as a packet of its own
        assert_eq!(table.admit(&v4(ROUTER_V4, CLIENT_V4, ICMP, 0, &[], &icmp(5, 0, &sent[..28]))), UNASKED);
    }

    #[test]
    fn an_icmpv6_error_passes_when_it_quotes_the_start_of_a_packet_the_tunnel_sent() {
        let mut table = Table::new(MAX_FLOWS);
        let sent = v6(CLIENT_V6, PEER_V6, TCP, &ports(40000, 443, TCP_SYN));
        table.send(&sent);
        let not_sent = v6(CLIENT_V6, PEER_V6, TCP, &ports(40001, 443, TCP_SYN));
        for kind in 1..=4 {
            let error = |quoted: &[u8]| v6(ROUTER_V6, CLIENT_V6, ICMPV6, &icmp(kind, 0, quoted));
            assert_eq!(table.admit(&error(&sent)), Ok(()), "type {kind}");
            assert_eq!(table.admit(&error(&sent[..44])), Ok(()), "type {kind} quoting the ports only");
            assert_eq!(table.admit(&error(&not_sent)), UNASKED, "type {kind}");
            assert_eq!(table.admit(&error(&sent[..42])), UNASKED, "type {kind} cut short");
        }
    }

    #[test]
    fn an_error_passes_for_a_quoted_echo_request_or_packet_of_another_protocol() {
        let mut table = Table::new(MAX_FLOWS);
        let echo = up(ICMP, &icmp(8, 7, &[]));
        let gre = up(GRE, &[0; 8]);
        table.send(&echo);
        table.send(&gre);
        let error = |quoted: &[u8]| v4(ROUTER_V4, CLIENT_V4, ICMP, 0, &[], &icmp(11, 0, quoted));
        assert_eq!(table.admit(&error(&echo)), Ok(()));
        assert_eq!(table.admit(&error(&up(ICMP, &icmp(8, 6, &[])))), UNASKED);
        assert_eq!(table.admit(&error(&echo[..25])), UNASKED, "cut short of the identifier");
        assert_eq!(table.admit(&error(&gre[..28])), Ok(()));
        assert_eq!(table.admit(&error(&v4(CLIENT_V4, OTHER_V4, GRE, 0, &[], &[0; 8]))), UNASKED);
    }

    #[test]
    fn an_error_about_a_packet_from_another_address_does_not_pass() {
        let mut table = Table::new(MAX_FLOWS);
        table.send(&up(UDP, &ports(40000, 53, 0)));
        let from_another = v4(ANOTHER_TUNNEL_V4, PEER_V4, UDP, 0, &[], &ports(40000, 53, 0));
        let error = v4(ROUTER_V4, CLIENT_V4, ICMP, 0, &[], &icmp(3, 0, &from_another));
        assert_eq!(table.admit(&error), UNASKED);
    }

    #[test]
    fn a_later_fragment_passes_from_a_peer_with_a_flow_of_its_protocol_and_makes_no_flow() {
        let mut table = Table::new(MAX_FLOWS);
        table.send(&up(UDP, &ports(40000, 53, 0)));
        let later = |source, protocol| v4(source, CLIENT_V4, protocol, MORE_FRAGMENTS | 1, &[], &[0; 8]);
        assert_eq!(table.admit(&later(PEER_V4, UDP)), Ok(()));
        assert_eq!(table.admit(&later(PEER_V4, TCP)), UNASKED);
        assert_eq!(table.admit(&later(OTHER_V4, UDP)), UNASKED);
        let error = |target| {
            let quoted = v4(CLIENT_V4, target, UDP, MORE_FRAGMENTS | 1, &[], &[0; 8]);
            v4(ROUTER_V4, CLIENT_V4, ICMP, 0, &[], &icmp(3, 0, &quoted))
        };
        assert_eq!(table.admit(&error(PEER_V4)), Ok(()), "an error about a later fragment");
        assert_eq!(table.admit(&error(OTHER_V4)), UNASKED);

        table.send(&v4(CLIENT_V4, OTHER_V4, TCP, MORE_FRAGMENTS | 1, &[], &[0; 8]));
        assert_eq!(table.flows.len(), 1);
        assert_eq!(table.admit(&later(OTHER_V4, TCP)), UNASKED);
        // a later fragment of an error is matched as a fragment, not read for a quote
        let sent = up(UDP, &ports(40000, 53, 0));
        let error = v4(ROUTER_V4, CLIENT_V4, ICMP, MORE_FRAGMENTS | 1, &[], &icmp(3, 0, &sent));
        assert_eq!(table.admit(&error), UNASKED);
    }

    #[test]
    fn udp_and_other_flows_live_their_life_after_their_last_packet_either_way() {
        for (protocol, payload, life) in [(UDP, ports(40000, 53, 0), UDP_LIFE), (GRE, vec![0; 8], OTHER_LIFE)] {
            let mut table = Table::new(MAX_FLOWS);
            let answer = down(protocol, &[&payload[2..4], &payload[..2], &payload[4..]].concat());
            table.send(&up(protocol, &payload));
            assert_eq!(table.admit_at(life - MS, &answer), Ok(()), "{protocol}");
            // the answer refreshed it
            assert_eq!(table.admit_at(2 * life - 2 * MS, &answer), Ok(()), "{protocol}");
            table.send_at(3 * life - 3 * MS, &up(protocol, &payload));
            assert_eq!(table.admit_at(4 * life - 4 * MS, &answer), Ok(()), "{protocol}");
            assert_eq!(table.admit_at(5 * life - 4 * MS, &answer), UNASKED, "{protocol}");
            // sent again past its life, it is a new flow
            table.send_at(6 * life, &up(protocol, &payload));
            assert_eq!(table.admit_at(6 * life, &answer), Ok(()), "{protocol}");
        }
        assert_eq!((UDP_LIFE, OTHER_LIFE), (5 * MINUTE, 2 * MINUTE));
    }

    #[test]
    fn an_error_neither_refreshes_a_flow_nor_lives_past_it() {
        let mut table = Table::new(MAX_FLOWS);
        let sent = up(UDP, &ports(40000, 53, 0));
        table.send(&sent);
        let error = v4(ROUTER_V4, CLIENT_V4, ICMP, 0, &[], &icmp(11, 0, &sent));
        assert_eq!(table.admit_at(UDP_LIFE - MS, &error), Ok(()));
        assert_eq!(table.admit_at(UDP_LIFE, &error), UNASKED);
        assert_eq!(table.admit_at(UDP_LIFE, &down(UDP, &ports(53, 40000, 0))), UNASKED);
    }

    #[test]
    fn a_tcp_flow_lives_two_hours_once_answered_and_two_minutes_before_or_past_a_fin_or_a_rst() {
        let syn = up(TCP, &ports(40000, 443, TCP_SYN));
        let answer = |flags| down(TCP, &ports(443, 40000, flags));
        let ack = up(TCP, &ports(40000, 443, TCP_ACK));

        let mut unanswered = Table::new(MAX_FLOWS);
        unanswered.send(&syn);
        assert_eq!(unanswered.admit_at(2 * MINUTE, &answer(TCP_SYN | TCP_ACK)), UNASKED);

        let mut open = Table::new(MAX_FLOWS);
        open.send(&syn);
        assert_eq!(open.admit_at(2 * MINUTE - MS, &answer(TCP_SYN | TCP_ACK)), Ok(()));
        let quiet = 2 * MINUTE + TCP_OPEN_LIFE;
        assert_eq!(open.admit_at(quiet - 2 * MS, &answer(TCP_ACK)), Ok(()));
        let forgotten = quiet - 2 * MS + TCP_OPEN_LIFE;
        assert_eq!(open.admit_at(forgotten, &answer(TCP_ACK)), UNASKED);
        // sent on once forgotten, it is a new flow that no answer opened yet
        open.send_at(forgotten, &ack);
        assert_eq!(open.admit_at(forgotten + 2 * MINUTE, &answer(TCP_ACK)), UNASKED);
        assert_eq!(TCP_OPEN_LIFE, 124 * MINUTE);

        for (closing, from_tunnel) in [(TCP_FIN, true), (TCP_FIN, false), (TCP_RST, true), (TCP_RST, false)] {
            let mut table = Table::new(MAX_FLOWS);
            table.send(&syn);
            assert_eq!(table.admit(&answer(TCP_SYN | TCP_ACK)), Ok(()));
            if from_tunnel {
                table.send(&up(TCP, &ports(40000, 443, closing | TCP_ACK)));
            } else {
                assert_eq!(table.admit(&answer(closing | TCP_ACK)), Ok(()));
            }
            // an ACK past the close keeps the short life
            table.send(&ack);
            assert_eq!(table.admit_at(2 * MINUTE - MS, &answer(TCP_ACK)), Ok(()), "{closing} {from_tunnel}");
            assert_eq!(table.admit_at(4 * MINUTE, &answer(TCP_ACK)), UNASKED, "{closing} {from_tunnel}");
        }
    }

    #[test]
    fn a_new_syn_on_a_closed_tcp_flow_starts_it_over() {
        let mut table = Table::new(MAX_FLOWS);
        let answer = |flags| down(TCP, &ports(443, 40000, flags));
        table.send(&up(TCP, &ports(40000, 443, TCP_SYN)));
        assert_eq!(table.admit(&answer(TCP_RST | TCP_ACK)), Ok(()));
        table.send_at(MINUTE, &up(TCP, &ports(40000, 443, TCP_SYN)));
        assert_eq!(table.admit_at(MINUTE, &answer(TCP_SYN | TCP_ACK)), Ok(()));
        assert_eq!(table.admit_at(MINUTE + TCP_OPEN_LIFE - MS, &answer(TCP_ACK)), Ok(()));
    }

    #[test]
    fn a_full_table_first_removes_the_flows_past_their_life_then_the_one_silent_longest() {
        let mut table = Table::new(8);
        let udp = |port| up(UDP, &ports(40000, port, 0));
        let answer = |port| down(UDP, &ports(port, 40000, 0));
        table.send(&udp(1));
        for port in 2..=7 {
            table.send_at(MINUTE + u32::from(port) * MS, &udp(port));
        }
        // flow 8 is of another protocol: past its life at 3 minutes, while flow 1 lives until 5
        table.send_at(MINUTE, &up(GRE, &[0; 8]));
        // an answer keeps flow 2 from being the silent longest later
        assert_eq!(table.admit_at(2 * MINUTE, &answer(2)), Ok(()));
        assert_eq!(table.flows.len(), 8);

        table.send_at(4 * MINUTE, &udp(9));
        assert_eq!(table.flows.len(), 8);
        assert_eq!(table.admit_at(4 * MINUTE, &answer(1)), Ok(()), "flow 1 stays while one past its life goes");
        table.send_at(4 * MINUTE, &udp(10));
        assert_eq!(table.flows.len(), 8);
        for port in [1, 2, 4, 5, 6, 7, 9, 10] {
            assert_eq!(table.admit_at(4 * MINUTE, &answer(port)), Ok(()), "flow {port}");
        }
        assert_eq!(table.admit_at(4 * MINUTE, &answer(3)), UNASKED, "flow 3 was silent longest");
    }

    #[test]
    fn a_full_table_frees_an_eighth_of_itself_at_once_and_a_known_flow_takes_no_room() {
        let mut table = Table::new(64);
        let udp = |port| up(UDP, &ports(40000, port, 0));
        for port in 0..64 {
            table.send_at(u32::from(port) * MS, &udp(port));
        }
        table.send_at(MINUTE, &udp(0));
        assert_eq!(table.flows.len(), 64);
        table.send_at(MINUTE, &udp(64));
        assert_eq!(table.flows.len(), 64 - 8 + 1);
        // flow 0 was refreshed, so flows 1 to 8 went
        for port in 0..=64 {
            let expected = if (1..=8).contains(&port) { UNASKED } else { Ok(()) };
            assert_eq!(table.admit_at(MINUTE, &down(UDP, &ports(port, 40000, 0))), expected, "flow {port}");
        }
    }

    #[test]
    fn a_full_table_pushes_out_the_flows_nearest_the_end_of_their_life_not_an_open_tcp_connection() {
        let mut table = Table::new(8);
        open_tcp(&mut table);
        // the tunnel's own short flows, such as DNS queries, each newer than the connection's last packet
        for port in 1..=8 {
            table.send_at(MINUTE + u32::from(port) * MS, &up(UDP, &ports(40001, port, 0)));
        }
        assert_eq!(table.admit_at(2 * MINUTE, &down(TCP, &ports(443, 40000, TCP_ACK))), Ok(()));
        assert_eq!(table.admit_at(2 * MINUTE, &down(UDP, &ports(1, 40001, 0))), UNASKED, "flow 1 was nearest its end");
    }

    #[test]
    fn a_full_table_pushes_out_first_the_flows_only_their_peers_sent_on() {
        let mut table = Table::public(8, 30000, 8);
        open_tcp(&mut table);
        table.send(&up(UDP, &ports(40001, 53, 0)));
        // connections others begin on a public port, each made to live two hours by its peer's second SYN
        for source in 1..=8 {
            let syn = v4(OTHER_V4, CLIENT_V4, TCP, 0, &[], &ports(source, 30000, TCP_SYN));
            assert_eq!(table.admit_at(MINUTE, &syn), Ok(()));
            assert_eq!(table.admit_at(MINUTE, &syn), Ok(()));
        }
        assert_eq!(table.admit_at(2 * MINUTE, &down(TCP, &ports(443, 40000, TCP_ACK))), Ok(()));
        assert_eq!(table.admit_at(2 * MINUTE, &down(UDP, &ports(53, 40001, 0))), Ok(()));
    }

    #[test]
    fn a_full_table_pushes_out_the_connections_the_tunnel_reset_before_its_own_flows() {
        let mut table = Table::public(8, 30000, 8);
        open_tcp(&mut table);
        table.send(&up(UDP, &ports(40001, 53, 0)));
        // a stack resets a SYN to a port nothing listens on, so the tunnel sent on each of these flows too
        for source in 1..=8 {
            let at = MINUTE + u32::from(source) * MS;
            let syn = v4(OTHER_V4, CLIENT_V4, TCP, 0, &[], &ports(source, 30000, TCP_SYN));
            assert_eq!(table.admit_at(at, &syn), Ok(()));
            table.send_at(at, &v4(CLIENT_V4, OTHER_V4, TCP, 0, &[], &ports(30000, source, TCP_RST | TCP_ACK)));
        }
        assert_eq!(table.admit_at(2 * MINUTE, &down(TCP, &ports(443, 40000, TCP_ACK))), Ok(()));
        assert_eq!(table.admit_at(2 * MINUTE, &down(UDP, &ports(53, 40001, 0))), Ok(()));
    }

    #[test]
    fn a_sweep_rebuilds_the_peers_later_fragments_are_matched_against() {
        let mut table = Table::new(2);
        table.send(&up(UDP, &ports(40000, 53, 0)));
        table.send_at(MINUTE, &v4(CLIENT_V4, OTHER_V4, UDP, 0, &[], &ports(40000, 53, 0)));
        table.send_at(MINUTE, &v4(CLIENT_V4, OTHER_V4, UDP, 0, &[], &ports(40000, 54, 0)));
        let later = |source| v4(source, CLIENT_V4, UDP, MORE_FRAGMENTS | 1, &[], &[0; 8]);
        assert_eq!(table.admit_at(MINUTE, &later(PEER_V4)), UNASKED);
        assert_eq!(table.admit_at(MINUTE, &later(OTHER_V4)), Ok(()));
    }

    #[test]
    fn a_tcp_or_udp_packet_to_a_public_port_passes_and_begins_a_flow() {
        for protocol in [TCP, UDP] {
            let mut table = Table::public(MAX_FLOWS, 30000, 8);
            let syn = down(protocol, &ports(50000, 30007, TCP_SYN));
            assert_eq!(table.admit(&syn), Ok(()), "{protocol}");
            // the tunnel's answer and the peer's next packet belong to the flow it began
            table.send(&up(protocol, &ports(30007, 50000, TCP_SYN | TCP_ACK)));
            assert_eq!(table.admit(&down(protocol, &ports(50000, 30007, TCP_ACK))), Ok(()), "{protocol}");
            let error = v4(ROUTER_V4, CLIENT_V4, ICMP, 0, &[], &icmp(3, 0, &up(protocol, &ports(30007, 50000, 0))));
            assert_eq!(table.admit(&error), Ok(()), "{protocol}: an error about the tunnel's answer");
            assert_eq!(table.flows.len(), 1);
            for outside in [29999, 30008] {
                let unasked = down(protocol, &ports(50000, outside, TCP_SYN));
                assert_eq!(table.admit(&unasked), UNASKED, "{protocol} {outside}");
            }
        }
    }

    #[test]
    fn only_tcp_and_udp_begin_a_flow_on_a_public_port_and_a_tunnel_without_ports_takes_answers_only() {
        let mut table = Table::public(MAX_FLOWS, 30000, 8);
        assert_eq!(table.admit(&down(GRE, &ports(50000, 30000, 0))), UNASKED);
        let quoted = down(UDP, &ports(30000, 50000, 0));
        assert_eq!(table.admit(&v4(ROUTER_V4, CLIENT_V4, ICMP, 0, &[], &icmp(3, 0, &quoted))), UNASKED);
        assert_eq!(table.flows.len(), 0);

        let mut none = Table::new(MAX_FLOWS);
        for port in [0, 1, 30000, u16::MAX] {
            assert_eq!(none.admit(&down(UDP, &ports(50000, port, 0))), UNASKED, "port {port}");
        }
        // the last ports of the port space are public too
        let mut last = Table::public(MAX_FLOWS, u16::MAX - 7, 8);
        assert_eq!(last.admit(&down(UDP, &ports(50000, u16::MAX, 0))), Ok(()));
        assert_eq!(last.admit(&down(UDP, &ports(50000, 0, 0))), UNASKED);
    }

    #[test]
    fn a_datagram_in_fragments_to_a_public_port_passes_when_its_first_fragment_comes_first() {
        let mut table = Table::public(MAX_FLOWS, 30000, 8);
        let later = v4(PEER_V4, CLIENT_V4, UDP, 1, &[], &[0; 8]);
        assert_eq!(table.admit(&later), UNASKED, "a later fragment alone begins nothing");
        let first = v4(PEER_V4, CLIENT_V4, UDP, MORE_FRAGMENTS, &[], &ports(50000, 30001, 0));
        assert_eq!(table.admit(&first), Ok(()));
        assert_eq!(table.admit(&later), Ok(()));
    }

    #[test]
    fn a_flow_and_its_slot_take_the_bytes_the_bound_is_priced_at() {
        assert_eq!(std::mem::size_of::<(Flow, Entry)>(), 48);
        assert_eq!(std::mem::size_of::<((u8, IpAddr), Instant)>(), 40);
        assert_eq!(HashMap::<Flow, Entry>::with_capacity(MAX_FLOWS).capacity(), MAX_FLOWS);
    }
}
