//! Which addresses are on the public internet, from IANA's special-purpose address registries for IPv4 and IPv6.
//! The default policy lets a session reach only those, so a relay cannot be pointed at the network it runs in.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const NOT_PUBLIC_V4: &[([u8; 4], u32)] = &[
    ([0, 0, 0, 0], 8),       // this network
    ([10, 0, 0, 0], 8),      // private
    ([100, 64, 0, 0], 10),   // shared address space, carrier NAT
    ([127, 0, 0, 0], 8),     // loopback
    ([169, 254, 0, 0], 16),  // link local, cloud metadata services included
    ([172, 16, 0, 0], 12),   // private
    ([192, 0, 0, 0], 24),    // IETF protocol assignments
    ([192, 0, 2, 0], 24),    // documentation
    ([192, 88, 99, 0], 24),  // 6to4 relay anycast, deprecated
    ([192, 168, 0, 0], 16),  // private
    ([198, 18, 0, 0], 15),   // benchmarking
    ([198, 51, 100, 0], 24), // documentation
    ([203, 0, 113, 0], 24),  // documentation
    ([224, 0, 0, 0], 4),     // multicast
    ([240, 0, 0, 0], 4),     // reserved, and the limited broadcast address
];

/// Inside 2000::/3, the only block global addresses come from.
const NOT_PUBLIC_V6: &[([u16; 2], u32)] = &[
    ([0x2001, 0x0000], 23), // IETF protocol assignments, Teredo included
    ([0x2001, 0x0db8], 32), // documentation
    ([0x3fff, 0x0000], 20), // documentation
    ([0x5f00, 0x0000], 16), // segment routing identifiers
];

/// Whether `ip` is an address on the public internet.
///
/// An IPv6 address that only spells an IPv4 one (see [`embedded_v4`]) is public when that IPv4 address is, so a
/// private address cannot be reached under another spelling.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match embedded_v4(v6) {
            Some(v4) => is_public_v4(v4),
            None => {
                let [a, b, ..] = v6.segments();
                let head = u32::from(a) << 16 | u32::from(b);
                a & 0xe000 == 0x2000
                    && !NOT_PUBLIC_V6.iter().any(|&([na, nb], length)| {
                        within(head, u32::from(na) << 16 | u32::from(nb), length)
                    })
            }
        },
    }
}

/// The IPv4 address an IPv6 address carries, for the spellings a socket or a translator turns back into IPv4:
/// IPv4-compatible (`::a.b.c.d`), IPv4-mapped (`::ffff:a.b.c.d`), IPv4-translated (`::ffff:0:a.b.c.d`), the NAT64
/// well-known prefix (`64:ff9b::a.b.c.d`) and 6to4 (`2002:aabb:ccdd::/48`).
pub fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let join = |high: u16, low: u16| Some(Ipv4Addr::from(u32::from(high) << 16 | u32::from(low)));
    match ip.segments() {
        [0, 0, 0, 0, 0, 0, high, low] => join(high, low),
        [0, 0, 0, 0, 0, 0xffff, high, low] => join(high, low),
        [0, 0, 0, 0, 0xffff, 0, high, low] => join(high, low),
        [0x64, 0xff9b, 0, 0, 0, 0, high, low] => join(high, low),
        [0x2002, high, low, ..] => join(high, low),
        _ => None,
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    !NOT_PUBLIC_V4.iter().any(|&(net, length)| within(u32::from(ip), u32::from_be_bytes(net), length))
}

/// Whether `address` and `net` share their first `length` bits, 1 to 32.
fn within(address: u32, net: u32, length: u32) -> bool {
    (address ^ net) >> (32 - length) == 0
}
