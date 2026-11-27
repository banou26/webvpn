//! The checks an IP tunnel's packet from the client passes before the policy is asked about its destination.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::metrics::Counter;
use crate::policy::Proto;

const TCP: u8 = 6;
const UDP: u8 = 17;

const IPV4_HEADER_BYTES: usize = 20;
const IPV4_LOOSE_SOURCE_ROUTE: u8 = 131;
const IPV4_STRICT_SOURCE_ROUTE: u8 = 137;

const IPV6_HEADER_BYTES: usize = 40;
const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_AUTHENTICATION: u8 = 51;
const IPV6_DESTINATION_OPTIONS: u8 = 60;

/// The extension headers read before the upper-layer header. A packet with more is dropped: a real one carries a few
/// at most (RFC 8200 lists six kinds, each at most once), and the bound keeps the walk short.
const MAX_IPV6_EXTENSION_HEADERS: usize = 8;

/// Where a packet goes, as the policy is asked about it.
pub(crate) type Destination = (Proto, SocketAddr);

/// Why a packet was dropped, as the counter it is counted under.
pub(crate) type Dropped = Counter;

/// An IP packet's header, as far as the relay reads it.
#[derive(Debug)]
pub(crate) struct Header<'a> {
    pub source: IpAddr,
    pub target: IpAddr,
    /// The IP protocol number of the upper-layer header.
    pub protocol: u8,
    /// Whether the packet is a fragment after the first, which holds no upper-layer header.
    pub later_fragment: bool,
    /// The upper-layer header and what follows it.
    pub upper: &'a [u8],
}

/// The destination of `packet`, one whole IPv4 or IPv6 packet from a client, and its header, or why it is dropped:
/// not IP, a header cut short or that cannot be read, an own length that is not the packet's, an IPv4 source route or
/// IPv6 type 0 routing header, or a source that is not the tunnel's address of its family.
pub(crate) fn check(
    packet: &[u8],
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> Result<(Destination, Header<'_>), Dropped> {
    let header = read(packet, true)?;
    let own = match header.source {
        IpAddr::V4(source) => Some(source) == ipv4,
        IpAddr::V6(source) => Some(source) == ipv6,
    };
    if !own {
        return Err(Counter::IpDroppedSource);
    }
    Ok((destination(&header)?, header))
}

/// The header of `packet`, a whole IPv4 or IPv6 packet whose own length is its length, or with `whole` false the start
/// of one that an ICMP error quotes, cut anywhere past its IP header. Or why it cannot be read, as [`check`] gives it.
pub(crate) fn read(packet: &[u8], whole: bool) -> Result<Header<'_>, Dropped> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => read_v4(packet, whole),
        Some(6) => read_v6(packet, whole),
        _ => Err(Counter::IpDroppedNotIp),
    }
}

fn read_v4(packet: &[u8], whole: bool) -> Result<Header<'_>, Dropped> {
    let header = usize::from(packet[0] & 0x0f) * 4;
    if header < IPV4_HEADER_BYTES || header > packet.len() {
        return Err(Counter::IpDroppedHeader);
    }
    if whole && usize::from(u16_at(packet, 2)) != packet.len() {
        return Err(Counter::IpDroppedLength);
    }
    let mut options = &packet[IPV4_HEADER_BYTES..header];
    while let Some(&option) = options.first() {
        let length = match option {
            0 => break,
            1 => 1,
            _ => match options.get(1) {
                Some(&length) if length >= 2 && usize::from(length) <= options.len() => usize::from(length),
                _ => return Err(Counter::IpDroppedHeader),
            },
        };
        if option == IPV4_LOOSE_SOURCE_ROUTE || option == IPV4_STRICT_SOURCE_ROUTE {
            return Err(Counter::IpDroppedSourceRoute);
        }
        options = &options[length..];
    }
    Ok(Header {
        source: Ipv4Addr::from(array_at(packet, 12)).into(),
        target: Ipv4Addr::from(array_at(packet, 16)).into(),
        protocol: packet[9],
        later_fragment: u16_at(packet, 6) & 0x1fff != 0,
        upper: &packet[header..],
    })
}

fn read_v6(packet: &[u8], whole: bool) -> Result<Header<'_>, Dropped> {
    if packet.len() < IPV6_HEADER_BYTES {
        return Err(Counter::IpDroppedHeader);
    }
    if whole && usize::from(u16_at(packet, 4)) != packet.len() - IPV6_HEADER_BYTES {
        return Err(Counter::IpDroppedLength);
    }
    let source = Ipv6Addr::from(array_at(packet, 8)).into();
    let target = Ipv6Addr::from(array_at(packet, 24)).into();
    let header =
        |protocol, later_fragment, at| Header { source, target, protocol, later_fragment, upper: &packet[at..] };
    let (mut next, mut at) = (packet[6], IPV6_HEADER_BYTES);
    for _ in 0..=MAX_IPV6_EXTENSION_HEADERS {
        let length = match next {
            IPV6_HOP_BY_HOP | IPV6_ROUTING | IPV6_DESTINATION_OPTIONS => {
                packet.get(at + 1).map(|&units| (usize::from(units) + 1) * 8)
            }
            IPV6_AUTHENTICATION => packet.get(at + 1).map(|&units| (usize::from(units) + 2) * 4),
            IPV6_FRAGMENT => Some(8),
            _ => return Ok(header(next, false, at)),
        };
        let Some(extension) = length.and_then(|length| packet.get(at..at + length)) else {
            return Err(Counter::IpDroppedHeader);
        };
        if next == IPV6_ROUTING && extension[2] == 0 {
            return Err(Counter::IpDroppedSourceRoute);
        }
        if next == IPV6_FRAGMENT && u16_at(extension, 2) >> 3 != 0 {
            return Ok(header(extension[0], true, at + extension.len()));
        }
        next = extension[0];
        at += extension.len();
    }
    Err(Counter::IpDroppedHeader)
}

/// The destination of a packet. A TCP or UDP packet that holds its ports is asked about with its destination port; a
/// first fragment too short to hold them is dropped.
fn destination(header: &Header) -> Result<Destination, Dropped> {
    let proto = match header.protocol {
        TCP if !header.later_fragment => Proto::Tcp,
        UDP if !header.later_fragment => Proto::Udp,
        other => return Ok((Proto::Other(other), SocketAddr::new(header.target, 0))),
    };
    let port = header.upper.get(2..4).ok_or(Counter::IpDroppedHeader)?;
    Ok((proto, SocketAddr::new(header.target, u16::from_be_bytes([port[0], port[1]]))))
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn array_at<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    bytes[at..at + N].try_into().expect("the header holds the field")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
    pub(crate) const CLIENT_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    const SITE_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
    const SITE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9);
    const ICMP: u8 = 1;
    const MORE_FRAGMENTS: u16 = 0x2000;

    /// An IPv4 packet: its header with `options`, a multiple of 4 bytes, the fragment field, then `payload`.
    pub(crate) fn v4(
        source: Ipv4Addr,
        target: Ipv4Addr,
        protocol: u8,
        fragment: u16,
        options: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let header = IPV4_HEADER_BYTES + options.len();
        let mut packet = vec![0x40 | (header / 4) as u8, 0];
        packet.extend_from_slice(&((header + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(&fragment.to_be_bytes());
        packet.extend_from_slice(&[64, protocol, 0, 0]);
        packet.extend_from_slice(&source.octets());
        packet.extend_from_slice(&target.octets());
        packet.extend_from_slice(options);
        packet.extend_from_slice(payload);
        packet
    }

    /// An IPv6 packet whose first header names `next`, followed by `rest`: extension headers, then the payload.
    pub(crate) fn v6(source: Ipv6Addr, target: Ipv6Addr, next: u8, rest: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x60, 0, 0, 0];
        packet.extend_from_slice(&(rest.len() as u16).to_be_bytes());
        packet.extend_from_slice(&[next, 64]);
        packet.extend_from_slice(&source.octets());
        packet.extend_from_slice(&target.octets());
        packet.extend_from_slice(rest);
        packet
    }

    /// A UDP or TCP header's first bytes: from port 40000 to `port`.
    pub(crate) fn ports(port: u16) -> Vec<u8> {
        let mut ports = 40000u16.to_be_bytes().to_vec();
        ports.extend_from_slice(&port.to_be_bytes());
        ports.extend_from_slice(&[0; 4]);
        ports
    }

    /// An IPv6 extension header of 8 bytes naming `next`, with `third` as its third byte (a routing header's type).
    fn extension(next: u8, third: u8) -> [u8; 8] {
        [next, 0, third, 0, 0, 0, 0, 0]
    }

    fn checked(packet: &[u8]) -> Result<Destination, Dropped> {
        check(packet, Some(CLIENT_V4), Some(CLIENT_V6)).map(|(destination, _)| destination)
    }

    fn to(proto: Proto, target: impl Into<IpAddr>, port: u16) -> Result<Destination, Dropped> {
        Ok((proto, SocketAddr::new(target.into(), port)))
    }

    #[test]
    fn an_ipv4_packet_goes_to_its_destination_and_port_or_without_a_port_for_another_protocol() {
        assert_eq!(checked(&v4(CLIENT_V4, SITE_V4, UDP, 0, &[], &ports(53))), to(Proto::Udp, SITE_V4, 53));
        assert_eq!(checked(&v4(CLIENT_V4, SITE_V4, TCP, 0, &[], &ports(443))), to(Proto::Tcp, SITE_V4, 443));
        assert_eq!(checked(&v4(CLIENT_V4, SITE_V4, ICMP, 0, &[], &[8, 0, 0, 0])), to(Proto::Other(ICMP), SITE_V4, 0));
    }

    #[test]
    fn a_packet_that_is_not_ip_is_dropped() {
        assert_eq!(checked(&[]), Err(Counter::IpDroppedNotIp));
        let mut five = v4(CLIENT_V4, SITE_V4, UDP, 0, &[], &ports(53));
        five[0] = 0x55;
        assert_eq!(checked(&five), Err(Counter::IpDroppedNotIp));
    }

    #[test]
    fn an_ipv4_header_cut_short_is_dropped() {
        let whole = v4(CLIENT_V4, SITE_V4, UDP, 0, &[], &ports(53));
        assert_eq!(checked(&whole[..19]), Err(Counter::IpDroppedHeader));
        let mut too_short = whole.clone();
        too_short[0] = 0x44;
        assert_eq!(checked(&too_short), Err(Counter::IpDroppedHeader));
        let mut past_the_end = v4(CLIENT_V4, SITE_V4, ICMP, 0, &[], &[]);
        past_the_end[0] = 0x46;
        assert_eq!(checked(&past_the_end), Err(Counter::IpDroppedHeader));
        // an option whose length runs past the header
        assert_eq!(checked(&v4(CLIENT_V4, SITE_V4, UDP, 0, &[7, 9, 0, 0], &ports(53))), Err(Counter::IpDroppedHeader));
    }

    #[test]
    fn a_packet_whose_own_length_is_not_its_length_is_dropped() {
        let mut longer = v4(CLIENT_V4, SITE_V4, UDP, 0, &[], &ports(53));
        longer.push(0);
        assert_eq!(checked(&longer), Err(Counter::IpDroppedLength));
        let mut shorter = longer.clone();
        shorter.truncate(shorter.len() - 2);
        assert_eq!(checked(&shorter), Err(Counter::IpDroppedLength));
        for change in [-1, 1] {
            let mut v6 = v6(CLIENT_V6, SITE_V6, UDP, &ports(53));
            v6[5] = v6[5].wrapping_add_signed(change);
            assert_eq!(checked(&v6), Err(Counter::IpDroppedLength), "{change}");
        }
    }

    #[test]
    fn a_packet_from_another_source_or_of_a_family_the_tunnel_has_no_address_of_is_dropped() {
        let other_v4 = Ipv4Addr::new(198, 18, 0, 3);
        assert_eq!(checked(&v4(other_v4, SITE_V4, UDP, 0, &[], &ports(53))), Err(Counter::IpDroppedSource));
        let other_v6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);
        assert_eq!(checked(&v6(other_v6, SITE_V6, UDP, &ports(53))), Err(Counter::IpDroppedSource));

        let v6_only = check(&v4(CLIENT_V4, SITE_V4, UDP, 0, &[], &ports(53)), None, Some(CLIENT_V6)).err();
        assert_eq!(v6_only, Some(Counter::IpDroppedSource));
        let v4_only = check(&v6(CLIENT_V6, SITE_V6, UDP, &ports(53)), Some(CLIENT_V4), None).err();
        assert_eq!(v4_only, Some(Counter::IpDroppedSource));
    }

    #[test]
    fn an_ipv4_source_route_is_dropped_and_other_options_pass() {
        for route in [IPV4_LOOSE_SOURCE_ROUTE, IPV4_STRICT_SOURCE_ROUTE] {
            // a no-operation first, so the route is found behind another option
            let options = [1, route, 7, 4, 1, 2, 3, 4];
            let packet = v4(CLIENT_V4, SITE_V4, UDP, 0, &options, &ports(53));
            assert_eq!(checked(&packet), Err(Counter::IpDroppedSourceRoute), "option {route}");
        }
        // a record route, then the end of the options
        let options = [7, 7, 4, 0, 0, 0, 0, 0];
        assert_eq!(checked(&v4(CLIENT_V4, SITE_V4, UDP, 0, &options, &ports(53))), to(Proto::Udp, SITE_V4, 53));
    }

    #[test]
    fn an_ipv4_fragment_after_the_first_goes_without_a_port_and_a_first_one_needs_its_ports() {
        let first = v4(CLIENT_V4, SITE_V4, UDP, MORE_FRAGMENTS, &[], &ports(53));
        assert_eq!(checked(&first), to(Proto::Udp, SITE_V4, 53));
        let later = v4(CLIENT_V4, SITE_V4, UDP, MORE_FRAGMENTS | 1, &[], &[0; 8]);
        assert_eq!(checked(&later), to(Proto::Other(UDP), SITE_V4, 0));
        let last = v4(CLIENT_V4, SITE_V4, TCP, 185, &[], &[0; 8]);
        assert_eq!(checked(&last), to(Proto::Other(TCP), SITE_V4, 0));
        let short_first = v4(CLIENT_V4, SITE_V4, TCP, MORE_FRAGMENTS, &[], &[0x9c, 0x40, 1]);
        assert_eq!(checked(&short_first), Err(Counter::IpDroppedHeader));
    }

    #[test]
    fn an_ipv6_packet_goes_to_its_destination_past_its_extension_headers() {
        assert_eq!(checked(&v6(CLIENT_V6, SITE_V6, UDP, &ports(53))), to(Proto::Udp, SITE_V6, 53));
        assert_eq!(checked(&v6(CLIENT_V6, SITE_V6, 58, &[128, 0, 0, 0])), to(Proto::Other(58), SITE_V6, 0));

        let mut rest = extension(IPV6_DESTINATION_OPTIONS, 0).to_vec();
        rest.extend(extension(IPV6_ROUTING, 0));
        // a type 2 routing header (mobility), which names one address and passes
        rest.extend([IPV6_AUTHENTICATION, 2, 2, 1]);
        rest.extend([0; 20]);
        // an authentication header of 16 bytes
        rest.extend([TCP, 2, 0, 0]);
        rest.extend([0; 12]);
        rest.extend(ports(443));
        assert_eq!(checked(&v6(CLIENT_V6, SITE_V6, IPV6_HOP_BY_HOP, &rest)), to(Proto::Tcp, SITE_V6, 443));
    }

    #[test]
    fn an_ipv6_type_0_routing_header_is_dropped() {
        let mut rest = extension(IPV6_ROUTING, 0).to_vec();
        rest.extend([UDP, 2, 0, 1]);
        rest.extend([0; 20]);
        rest.extend(ports(53));
        assert_eq!(checked(&v6(CLIENT_V6, SITE_V6, IPV6_HOP_BY_HOP, &rest)), Err(Counter::IpDroppedSourceRoute));
    }

    #[test]
    fn an_ipv6_fragment_after_the_first_goes_without_a_port_and_a_first_one_is_read_on() {
        let mut first = [UDP, 0, 0, 1, 0, 0, 0, 7].to_vec();
        first.extend(ports(53));
        assert_eq!(checked(&v6(CLIENT_V6, SITE_V6, IPV6_FRAGMENT, &first)), to(Proto::Udp, SITE_V6, 53));

        let mut later = [UDP, 0, 0x05, 0x48, 0, 0, 0, 7].to_vec();
        later.extend([0; 8]);
        assert_eq!(checked(&v6(CLIENT_V6, SITE_V6, IPV6_FRAGMENT, &later)), to(Proto::Other(UDP), SITE_V6, 0));
    }

    #[test]
    fn an_ipv6_header_cut_short_or_with_too_many_extension_headers_is_dropped() {
        let whole = v6(CLIENT_V6, SITE_V6, UDP, &ports(53));
        assert_eq!(checked(&whole[..39]), Err(Counter::IpDroppedHeader));
        // an extension header longer than the packet, which names a protocol with no port to read after it
        let mut long = extension(58, 0);
        long[1] = 4;
        assert_eq!(checked(&v6(CLIENT_V6, SITE_V6, IPV6_DESTINATION_OPTIONS, &long)), Err(Counter::IpDroppedHeader));
        // a TCP header too short to hold its ports
        assert_eq!(checked(&v6(CLIENT_V6, SITE_V6, TCP, &[0x9c, 0x40, 1])), Err(Counter::IpDroppedHeader));

        let chain = |headers: usize| {
            let mut rest = Vec::new();
            for at in 0..headers {
                rest.extend(extension(if at + 1 == headers { UDP } else { IPV6_DESTINATION_OPTIONS }, 0));
            }
            rest.extend(ports(53));
            v6(CLIENT_V6, SITE_V6, IPV6_DESTINATION_OPTIONS, &rest)
        };
        assert_eq!(checked(&chain(MAX_IPV6_EXTENSION_HEADERS)), to(Proto::Udp, SITE_V6, 53));
        assert_eq!(checked(&chain(MAX_IPV6_EXTENSION_HEADERS + 1)), Err(Counter::IpDroppedHeader));
    }
}
