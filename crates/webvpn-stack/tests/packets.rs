// What comes in from the tunnel is whatever a peer sends, and a panic in the stack ends it for every socket of the
// tunnel, as a trap ends a WebAssembly instance.
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic::catch_unwind;

use webvpn_stack::{Buffers, Config, Stack};

const CLIENT4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SITE4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const CLIENT6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
const SITE6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const FIRST_PORT: u16 = 40000;
const SMALL: Buffers = Buffers { receive: 4096, send: 4096 };
const BIG: Buffers = Buffers { receive: 65536, send: 65536 };

const ICMP: u8 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMPV6: u8 = 58;
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// xorshift64, so that a seed always makes the same packets
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn chance(&mut self, permille: u64) -> bool {
        self.below(1000) < permille
    }

    fn byte(&mut self) -> u8 {
        self.next() as u8
    }

    fn pick<T: Copy>(&mut self, from: &[T]) -> T {
        from[self.below(from.len() as u64) as usize]
    }
}

fn sum(bytes: &[u8], mut acc: u32) -> u32 {
    for pair in bytes.chunks(2) {
        acc += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// The IP header, the protocol and what follows the header, of a packet the stacks made.
fn split(packet: &[u8]) -> Option<(Vec<u8>, u8, Vec<u8>)> {
    match packet.first()? >> 4 {
        4 => {
            let length = usize::from(packet[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
            if length < 20 || total < length || total > packet.len() {
                return None;
            }
            Some((packet[..length].to_vec(), packet[9], packet[length..total].to_vec()))
        }
        6 if packet.len() >= 40 => {
            let total = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            Some((packet[..40].to_vec(), packet[6], packet.get(40..total)?.to_vec()))
        }
        _ => None,
    }
}

/// A packet of these parts with its lengths and checksums right.
fn join(mut ip: Vec<u8>, protocol: u8, mut upper: Vec<u8>) -> Vec<u8> {
    let v4 = ip[0] >> 4 == 4;
    let addresses = if v4 { &ip[12..20] } else { &ip[8..40] };
    let at = match protocol {
        TCP => Some(16),
        UDP => Some(6),
        ICMP | ICMPV6 => Some(2),
        _ => None,
    };
    if let Some(at) = at.filter(|&at| upper.len() >= at + 2) {
        upper[at..at + 2].fill(0);
        let pseudo = if protocol == ICMP { 0 } else { sum(addresses, u32::from(protocol) + upper.len() as u32) };
        let checksum = fold(sum(&upper, pseudo));
        upper[at..at + 2].copy_from_slice(&checksum.to_be_bytes());
    }
    if v4 {
        let total = (ip.len() + upper.len()) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[10..12].fill(0);
        let checksum = fold(sum(&ip, 0));
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    } else {
        ip[4..6].copy_from_slice(&(upper.len() as u16).to_be_bytes());
    }
    ip.extend(upper);
    ip
}

/// How far to move a sequence number: mostly not or a little, sometimes across the window or half the space.
fn delta(rng: &mut Rng) -> u32 {
    match rng.below(10) {
        0..=3 => 0,
        4 => 1,
        5 => u32::MAX,
        6 => (rng.below(6000) as i64 - 3000) as u32,
        7 => (rng.below(140_000) as i64 - 70_000) as u32,
        8 => rng.pick(&[1 << 30, 1 << 31, 3 << 30]),
        _ => rng.next() as u32,
    }
}

fn tcp_options(rng: &mut Rng, ack: u32) -> Vec<u8> {
    let mut options = Vec::new();
    for _ in 0..rng.below(5) {
        match rng.below(7) {
            0 => options.push(rng.pick(&[0, 1])),
            1 => {
                options.extend([2, 4]);
                options.extend(rng.pick(&[0u16, 1, 536, 1460, 65535]).to_be_bytes());
            }
            2 => options.extend([3, 3, rng.pick(&[0, 7, 14, 15, 255])]),
            3 => options.extend([4, 2]),
            4 => {
                let blocks = 1 + rng.below(4) as u8;
                options.extend([5, 2 + 8 * blocks]);
                for _ in 0..2 * blocks {
                    options.extend(ack.wrapping_add(delta(rng)).to_be_bytes());
                }
            }
            5 => {
                options.extend([8, 10]);
                options.extend(rng.next().to_be_bytes());
            }
            _ => {
                // any kind, with a length that may not match what follows
                options.extend([rng.byte(), rng.below(12) as u8]);
                options.extend((0..rng.below(10)).map(|_| rng.byte()));
            }
        }
    }
    options.truncate(40);
    while options.len() % 4 != 0 {
        options.push(0);
    }
    options
}

fn change_tcp(rng: &mut Rng, segment: &[u8]) -> Vec<u8> {
    if segment.len() < 20 {
        return segment.to_vec();
    }
    let offset = (usize::from(segment[12] >> 4) * 4).clamp(20, segment.len());
    let mut header = segment[..20].to_vec();
    let mut options = segment[20..offset].to_vec();
    let mut payload = segment[offset..].to_vec();
    let ack = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    for at in [4, 8] {
        if rng.chance(400) {
            let number = u32::from_be_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]]);
            header[at..at + 4].copy_from_slice(&number.wrapping_add(delta(rng)).to_be_bytes());
        }
    }
    if rng.chance(300) {
        let flags = [SYN, SYN | ACK, ACK, FIN | ACK, RST | ACK, RST, PSH | ACK, FIN, SYN | FIN, 0, rng.byte()];
        header[13] = rng.pick(&flags);
    }
    if rng.chance(200) {
        let any = rng.next() as u16;
        let window = rng.pick(&[0, 1, 65535, any]);
        header[14..16].copy_from_slice(&window.to_be_bytes());
    }
    if rng.chance(300) {
        options = tcp_options(rng, ack);
    }
    if rng.chance(200) {
        match rng.below(3) {
            0 => payload.truncate(rng.below(payload.len() as u64 + 1) as usize),
            1 => payload.extend((0..rng.below(3000)).map(|_| rng.byte())),
            _ if !payload.is_empty() => {
                for _ in 0..rng.below(8) {
                    let at = rng.below(payload.len() as u64) as usize;
                    payload[at] = rng.byte();
                }
            }
            _ => {}
        }
    }
    // the data offset, sometimes not where the options end
    let words = if rng.chance(30) { rng.below(16) as u8 } else { ((20 + options.len()) / 4) as u8 };
    header[12] = words << 4 | header[12] & 0x0f;
    [header, options, payload].concat()
}

/// A packet of the site's, changed or cut.
fn change(rng: &mut Rng, packet: &[u8]) -> Vec<u8> {
    let Some((ip, protocol, mut upper)) = split(packet) else { return packet.to_vec() };
    match rng.below(10) {
        0 => {
            // bytes changed anywhere, mostly with the checksums made right again
            let mut packet = packet.to_vec();
            for _ in 0..1 + rng.below(4) {
                let at = rng.below(packet.len() as u64) as usize;
                packet[at] = rng.byte();
            }
            match split(&packet) {
                Some((ip, protocol, upper)) if rng.chance(800) => join(ip, protocol, upper),
                _ => packet,
            }
        }
        1 => {
            // cut anywhere, so that the IP header says more than there is
            let mut packet = join(ip, protocol, upper);
            packet.truncate(rng.below(packet.len() as u64 + 1) as usize);
            packet
        }
        _ => {
            if protocol == TCP {
                upper = change_tcp(rng, &upper);
            } else if protocol == UDP && upper.len() >= 8 && rng.chance(300) {
                let any = rng.next() as u16;
                let length = rng.pick(&[0, 1, 7, 8, 9, upper.len() as u16 + 1, any]);
                upper[4..6].copy_from_slice(&length.to_be_bytes());
            }
            join(ip, protocol, upper)
        }
    }
}

/// An ICMP error from a router about a packet the client sent, quoting all of it or a cut of it.
fn icmp_error(rng: &mut Rng, quoted: &[u8]) -> Vec<u8> {
    let any = rng.below(quoted.len() as u64 + 1) as usize;
    let cut = rng.pick(&[28, 48, quoted.len(), any]).min(quoted.len());
    let v4 = quoted[0] >> 4 == 4;
    let any = rng.byte();
    let kind = if v4 { rng.pick(&[3, 3, 3, 11, 12, 4, 5, any]) } else { rng.pick(&[1, 1, 2, 3, 4, any]) };
    let mut icmp = vec![kind, rng.below(16) as u8, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&quoted[..cut]);
    if v4 {
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, ICMP, 0, 0, 198, 51, 100, 1];
        ip.extend_from_slice(&quoted[12..16]);
        join(ip, ICMP, icmp)
    } else {
        let mut ip = vec![0x60, 0, 0, 0, 0, 0, ICMPV6, 64];
        ip.extend(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff).octets());
        ip.extend_from_slice(&quoted[8..24]);
        join(ip, ICMPV6, icmp)
    }
}

/// Bytes of any value to the client's address, mostly with a right checksum.
fn noise(rng: &mut Rng) -> Vec<u8> {
    let mut packet: Vec<u8> = (0..rng.below(120)).map(|_| rng.byte()).collect();
    let any = rng.byte();
    if let Some(first) = packet.first_mut() {
        *first = rng.pick(&[0x45, 0x46, 0x4f, 0x60, 0x40, 0x00, any]);
    }
    match packet.first().map(|first| first >> 4) {
        Some(6) if packet.len() >= 40 => packet[24..40].copy_from_slice(&CLIENT6.octets()),
        Some(4) if packet.len() >= 20 => packet[16..20].copy_from_slice(&CLIENT4.octets()),
        _ => {}
    }
    match split(&packet) {
        Some((ip, protocol, upper)) if rng.chance(700) => join(ip, protocol, upper),
        _ => packet,
    }
}

fn config(ipv4: Ipv4Addr, ipv6: Ipv6Addr, first_port: u16, ports: u16, seed: u64) -> Config {
    Config { ipv4: Some(ipv4), ipv6: Some(ipv6), mtu: 1500, first_port, ports, seed, connect_timeout_ms: 10_000 }
}

fn either(rng: &mut Rng, v4: Ipv4Addr, v6: Ipv6Addr, port: u16) -> SocketAddr {
    if rng.chance(500) {
        SocketAddr::new(v4.into(), port)
    } else {
        SocketAddr::new(v6.into(), port)
    }
}

/// The client and a site that talk over a link that loses, repeats and reorders packets, and changes and cuts the
/// site's. The packets due at a step all go in before the next poll, as a page that polls late hands them in.
fn run(seed: u64, steps: usize) {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut client = Stack::new(config(CLIENT4, CLIENT6, FIRST_PORT, 8, seed), 0);
    let mut site = Stack::new(config(SITE4, SITE6, 1, 30000, seed ^ 7), 0);
    let listener = client.tcp_listen(FIRST_PORT, 4, SMALL).unwrap();
    let site_listener = site.tcp_listen(80, 16, BIG).unwrap();
    let udp = client.udp_bind(FIRST_PORT + 1, SMALL).unwrap();
    let site_udp = site.udp_bind(53, BIG).unwrap();
    let (mut ids, mut site_ids) = (Vec::new(), Vec::new());
    let mut sent = Vec::new();
    let mut flying: Vec<(i64, bool, Vec<u8>)> = Vec::new();
    let mut buffer = vec![0; 65536];
    let mut now = 0;
    for _ in 0..steps {
        if rng.chance(30) {
            let buffers = if rng.chance(500) { SMALL } else { BIG };
            ids.extend(client.tcp_connect(either(&mut rng, SITE4, SITE6, 80), buffers));
        }
        ids.extend(std::iter::from_fn(|| client.tcp_accept(listener)));
        for &id in &ids {
            match rng.below(40) {
                0..=9 => _ = client.tcp_send(id, &buffer[..rng.below(5000) as usize]),
                10..=25 => _ = client.tcp_recv(id, &mut buffer[..1 + rng.below(65535) as usize]),
                26 => client.tcp_close(id),
                27 if rng.chance(200) => client.tcp_abort(id),
                28 if rng.chance(100) => client.release(id),
                29 => _ = client.tcp_set_keep_alive(id, Some(rng.below(3) as u32)),
                30 => _ = client.tcp_set_no_delay(id, rng.chance(500)),
                _ => {}
            }
        }
        if rng.chance(50) {
            let length = rng.below(1500) as usize;
            let _ = client.udp_send(udp, either(&mut rng, SITE4, SITE6, 53), &buffer[..length]);
        }
        while client.udp_recv(udp, &mut buffer).is_some() {}
        if rng.chance(20) {
            site_ids.extend(site.tcp_connect(either(&mut rng, CLIENT4, CLIENT6, FIRST_PORT), BIG));
        }
        site_ids.extend(std::iter::from_fn(|| site.tcp_accept(site_listener)));
        for &id in &site_ids {
            match rng.below(40) {
                0..=14 => _ = site.tcp_send(id, &buffer[..rng.below(20000) as usize]),
                15..=30 => _ = site.tcp_recv(id, &mut buffer),
                31 => site.tcp_close(id),
                32 if rng.chance(200) => site.tcp_abort(id),
                _ => {}
            }
        }
        while let Some((length, from)) = site.udp_recv(site_udp, &mut buffer) {
            let answer = buffer[..length.min(1400)].to_vec();
            let _ = site.udp_send(site_udp, from, &answer);
        }
        if rng.chance(20) {
            let length = rng.below(1400) as usize;
            let _ = site.udp_send(site_udp, either(&mut rng, CLIENT4, CLIENT6, FIRST_PORT + 1), &buffer[..length]);
        }

        now += match rng.below(100) {
            0 => 61_000,
            1..=3 => 2000,
            _ => rng.below(30) as i64,
        };
        client.poll(now);
        site.poll(now);
        client.events(usize::MAX);
        site.events(usize::MAX);
        while let Some(packet) = client.output() {
            if sent.len() == 64 {
                sent.remove(0);
            }
            sent.push(packet.clone());
            if !rng.chance(20) {
                flying.push((now + rng.below(20) as i64, true, packet));
            }
        }
        while let Some(mut packet) = site.output() {
            if rng.chance(20) {
                continue;
            }
            if rng.chance(250) {
                packet = change(&mut rng, &packet);
            }
            if rng.chance(30) {
                flying.push((now + rng.below(50) as i64, false, packet.clone()));
            }
            flying.push((now + rng.below(20) as i64, false, packet));
        }
        if rng.chance(30) && !sent.is_empty() {
            let quoted = sent[rng.below(sent.len() as u64) as usize].clone();
            flying.push((now, false, icmp_error(&mut rng, &quoted)));
        }
        if rng.chance(30) {
            flying.push((now, false, noise(&mut rng)));
        }
        let (due, later): (Vec<_>, Vec<_>) = flying.drain(..).partition(|(at, ..)| *at <= now);
        flying = later;
        for (_, to_site, packet) in due {
            if to_site {
                site.input(&packet);
            } else {
                client.input(&packet);
            }
        }
        ids.retain(|&id| client.tcp_state(id).is_some());
        site_ids.retain(|&id| site.tcp_state(id).is_some());
    }
}

#[test]
fn the_stack_takes_packets_of_any_content() {
    for seed in 1..=20 {
        assert!(catch_unwind(|| run(seed, 2000)).is_ok(), "seed {seed}");
    }
}
