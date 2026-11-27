//! The relay's own addresses. A client that dials one of them means a socket another session bound on this relay,
//! so the connection is turned to that socket's loopback address, and an address a socket reports is spelled as the
//! public one its peer knows.

use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use webvpn_proto::ErrorCode;

use crate::egress::{embedded_v4, is_public};
use crate::policy::{Proto, Refusal, Session};

const KERNEL_IPV6: &str = "/proc/net/if_inet6";
const REREAD: Duration = Duration::from_secs(1);

/// The relay's own addresses and the ports sessions hold on them.
pub(crate) struct Hairpin {
    given: Vec<IpAddr>,
    own: Arc<RwLock<Own>>,
    ports: Arc<Mutex<Ports>>,
}

/// A port a session bound, on record until this is dropped.
pub(crate) struct BoundPort {
    ports: Arc<Mutex<Ports>>,
    lease: Lease,
}

/// The socket a route onto the relay's own address leads to. A route held across an await is checked with
/// [`Hairpin::is_live`] right before it is used, since that socket may have closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lease {
    proto: Proto,
    port: u16,
    owner: u64,
}

/// Where the bytes for a destination go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Route {
    /// The destination itself, or the loopback address of a socket bound on this relay.
    pub dial: SocketAddr,
    /// Set when `dial` is a socket bound on this relay.
    pub lease: Option<Lease>,
}

// Public, so the policy would let a dial to one through, yet it reaches this host: only a port a session bound is
// routed there, onto that socket.
struct Own {
    addresses: Vec<IpAddr>,
    // each kernel address's on-link prefix, widened to its /64 when longer: the relay may hold or gain any address in it
    links: Vec<(Ipv6Addr, u8)>,
}

// The bound address only picks where a dial onto an own address goes; a peer outside reaches the socket directly.
// Owner ids rise and are never reused, so an id also tells a lease from a later binding of the same port.
#[derive(Default)]
struct Ports {
    held: HashMap<(Proto, u16), Vec<(IpAddr, u64)>>,
    next_owner: u64,
}

impl Hairpin {
    /// A relay whose own addresses are `own_addresses`, plus those [`Hairpin::watch_kernel_ipv6`] reads.
    pub fn new(own_addresses: Vec<IpAddr>) -> Self {
        Self { own: Arc::new(RwLock::new(Own::new(&own_addresses, &[]))), given: own_addresses, ports: Arc::default() }
    }

    /// Adds the node's public IPv6 addresses, as the kernel lists them, to the own addresses: now, then again every
    /// second on a thread of its own, so an address a router advertisement adds later is the relay's own within a
    /// second. Call it once, before the relay takes sessions. The thread ends within a second of `self` being dropped.
    ///
    /// An error means the kernel's list exists but could not be read or parsed; it names no address. A kernel with
    /// IPv6 off has no list, which reads as no IPv6. A failed later read keeps the addresses read before. Linux only:
    /// on another system it reads nothing, starts no thread and adds no address.
    pub fn watch_kernel_ipv6(&self) -> std::io::Result<()> {
        if cfg!(target_os = "linux") {
            self.watch(KERNEL_IPV6.into())?;
        }
        Ok(())
    }

    /// The relay's own addresses now: the ones it was made with, then the public IPv6 addresses last read.
    pub fn own_addresses(&self) -> Vec<IpAddr> {
        self.own.read().unwrap().addresses.clone()
    }

    fn watch(&self, path: PathBuf) -> std::io::Result<JoinHandle<()>> {
        let kernel = read_if_inet6(&path)?;
        *self.own.write().unwrap() = Own::new(&self.given, &kernel);
        let (own, given) = (Arc::downgrade(&self.own), self.given.clone());
        thread::Builder::new().name("own-ipv6".into()).spawn(move || loop {
            thread::sleep(REREAD);
            let Some(own) = own.upgrade() else { return };
            if let Ok(kernel) = read_if_inet6(&path) {
                *own.write().unwrap() = Own::new(&given, &kernel);
            }
        })
    }

    /// `None` when `target` is not one of the relay's own addresses, which leaves it to the policy. Otherwise the
    /// route to the socket bound on that port, or a refusal when no session holds it. An address on one of the
    /// relay's own IPv6 links that is not its own is refused too: another host there, the router included, or an
    /// address the relay may take next.
    pub fn own_route(&self, proto: Proto, target: SocketAddr) -> Option<Result<Route, Refusal>> {
        let own = self.own.read().unwrap();
        if is_own(target.ip(), &own.addresses) {
            let route = self.hairpin_target(proto, target);
            return Some(
                route.ok_or_else(|| Refusal::new(ErrorCode::REFUSED, "no session on the relay holds that port")),
            );
        }
        let IpAddr::V6(target) = target.ip() else { return None };
        own.links
            .iter()
            .any(|&(net, length)| on_link(target, net, length))
            .then(|| Err(Refusal::new(ErrorCode::REFUSED, "the relay does not reach its own network")))
    }

    fn hairpin_target(&self, proto: Proto, original: SocketAddr) -> Option<Route> {
        let ports = self.ports.lock().unwrap();
        let (ip, owner) = hairpin_route(ports.held.get(&(proto, original.port()))?, original)?;
        let lease = Lease { proto, port: original.port(), owner };
        Some(Route { dial: SocketAddr::new(ip, original.port()), lease: Some(lease) })
    }

    /// Puts the address a session's socket is bound to on record, so a dial onto an own address at that port reaches
    /// the socket.
    pub fn register(&self, proto: Proto, bound: SocketAddr) -> BoundPort {
        let mut ports = self.ports.lock().unwrap();
        let owner = ports.next_owner;
        ports.next_owner += 1;
        ports.held.entry((proto, bound.port())).or_default().push((bound.ip(), owner));
        BoundPort { ports: self.ports.clone(), lease: Lease { proto, port: bound.port(), owner } }
    }

    /// Whether the socket `lease` leads to is still on record.
    pub fn is_live(&self, lease: &Lease) -> bool {
        let ports = self.ports.lock().unwrap();
        let owners = ports.held.get(&(lease.proto, lease.port));
        owners.is_some_and(|owners| owners.iter().any(|&(_, owner)| owner == lease.owner))
    }

    /// `address` as a peer outside the relay knows it: a loopback address of a relay socket becomes the relay's
    /// public address of that family.
    pub fn public_spelling(&self, address: SocketAddr) -> SocketAddr {
        let own = self.own.read().unwrap();
        let v4 = own.addresses.iter().find(|ip| ip.is_ipv4()).copied();
        let v6 = own.addresses.iter().find(|ip| ip.is_ipv6()).copied();
        let v4_mapped = match v4 {
            Some(IpAddr::V4(v4)) => Some(IpAddr::V6(v4.to_ipv6_mapped())),
            _ => None,
        };
        let public = match address.ip() {
            IpAddr::V4(ip) if ip.is_loopback() => v4,
            IpAddr::V6(ip) if ip.is_loopback() => v6.or(v4_mapped),
            IpAddr::V6(ip) if embedded_v4(ip).is_some_and(|ip| ip.is_loopback()) => v4_mapped,
            _ => None,
        };
        public.map_or(address, |ip| SocketAddr::new(ip, address.port()))
    }
}

impl Drop for BoundPort {
    fn drop(&mut self) {
        let key = (self.lease.proto, self.lease.port);
        let mut ports = self.ports.lock().unwrap();
        if let Some(owners) = ports.held.get_mut(&key) {
            owners.retain(|&(_, owner)| owner != self.lease.owner);
            if owners.is_empty() {
                ports.held.remove(&key);
            }
        }
    }
}

impl Own {
    fn new(given: &[IpAddr], kernel: &[(Ipv6Addr, u8)]) -> Self {
        let mut own = Self { addresses: given.to_vec(), links: Vec::new() };
        for &(address, length) in kernel {
            if !is_public(IpAddr::V6(address)) {
                continue;
            }
            if !own.addresses.contains(&IpAddr::V6(address)) {
                own.addresses.push(IpAddr::V6(address));
            }
            own.links.push((address, length.min(64)));
        }
        own
    }
}

fn read_if_inet6(path: &Path) -> std::io::Result<Vec<(Ipv6Addr, u8)>> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_if_inet6(&text),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

// One line per address: 32 hex digits, then the interface index, prefix length, scope, flags and name, the numbers
// in hex. Scope 00 is global, which Linux also gives a unique local address (Own::new leaves it out, as it is not
// public), and an address still in duplicate address detection is listed too, so it is the relay's own before it can
// receive. The error names no address, since callers log it.
fn parse_if_inet6(text: &str) -> std::io::Result<Vec<(Ipv6Addr, u8)>> {
    let malformed = || Error::new(ErrorKind::InvalidData, "malformed line in /proc/net/if_inet6");
    let mut global = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [address, _, length, scope, _, _] = fields[..] else {
            return Err(malformed());
        };
        let address = Some(address)
            .filter(|a| a.len() == 32)
            .and_then(|a| u128::from_str_radix(a, 16).ok())
            .ok_or_else(malformed)?;
        let length = u8::from_str_radix(length, 16).ok().filter(|l| *l <= 128).ok_or_else(malformed)?;
        if u8::from_str_radix(scope, 16).map_err(|_| malformed())? == 0 {
            global.push((Ipv6Addr::from_bits(address), length));
        }
    }
    Ok(global)
}

/// Whether `ip` and `net` share their first `length` bits, 0 to 128.
fn on_link(ip: Ipv6Addr, net: Ipv6Addr, length: u8) -> bool {
    (ip.to_bits() ^ net.to_bits()).checked_shr(128 - u32::from(length)).unwrap_or(0) == 0
}

fn is_own(ip: IpAddr, own: &[IpAddr]) -> bool {
    let unembed = |ip: IpAddr| match ip {
        IpAddr::V6(v6) => embedded_v4(v6).map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    own.iter().any(|&own| unembed(own) == unembed(ip))
}

// Exact-family bindings outrank cross-family ones, the newest binding wins within a tier, and a tier holding routes
// to different addresses is refused rather than picked at random.
fn hairpin_route(owners: &[(IpAddr, u64)], original: SocketAddr) -> Option<(IpAddr, u64)> {
    let exact_exists = owners.iter().any(|(ip, _)| ip.is_ipv4() == original.is_ipv4());
    let mut route: Option<(IpAddr, u64)> = None;
    for &(bound_ip, owner) in owners {
        if exact_exists && bound_ip.is_ipv4() != original.is_ipv4() {
            continue;
        }
        let dial = hairpin_dial_ip(bound_ip, original);
        match route {
            Some((previous, _)) if previous != dial => return None,
            // entries are in registration order, so a later one is newer
            _ => route = Some((dial, owner)),
        }
    }
    route
}

fn hairpin_dial_ip(bound_ip: IpAddr, original: SocketAddr) -> IpAddr {
    match (bound_ip, original.is_ipv4()) {
        (IpAddr::V4(v4), true) => IpAddr::V4(if v4.is_unspecified() { Ipv4Addr::LOCALHOST } else { v4 }),
        // A concrete IPv6 bind is dialed at its own address even from an IPv4 spelling: TCP opens a fresh socket in
        // the dial's family, and a UDP sender that cannot carry IPv6 fails per packet with the system's error.
        (IpAddr::V6(v6), true) => {
            if v6.is_unspecified() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(v6)
            }
        }
        (IpAddr::V4(v4), false) => {
            IpAddr::V6(if v4.is_unspecified() { Ipv4Addr::LOCALHOST } else { v4 }.to_ipv6_mapped())
        }
        (IpAddr::V6(v6), false) => {
            if !v6.is_unspecified() {
                IpAddr::V6(v6)
            } else if matches!(original.ip(), IpAddr::V6(o) if embedded_v4(o).is_some()) {
                // The receiver sees the loopback address dialed as the source, and public_spelling turns ::1 into the
                // relay's own IPv6, so an IPv4 spelling must come back as IPv4 or the reply reads as another address.
                IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped())
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            }
        }
    }
}

/// Where `session` may send for `target`: the relay's own addresses are decided here, every other by the policy.
pub(crate) fn route<S: Session>(
    hairpin: &Hairpin,
    session: &S,
    proto: Proto,
    target: SocketAddr,
) -> Result<Route, Refusal> {
    match hairpin.own_route(proto, target) {
        Some(own) => own,
        None => session.check_egress(proto, target).map(|()| Route { dial: target, lease: None }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFUSED: Option<Result<SocketAddr, ErrorCode>> = Some(Err(ErrorCode::REFUSED));

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn relay(given: &[&str], kernel: &str) -> Hairpin {
        let hairpin = Hairpin::new(given.iter().map(|s| ip(s)).collect());
        *hairpin.own.write().unwrap() = Own::new(&hairpin.given, &parse_if_inet6(kernel).unwrap());
        hairpin
    }

    fn dial(hairpin: &Hairpin, proto: Proto, target: &str) -> Option<Result<SocketAddr, ErrorCode>> {
        hairpin.own_route(proto, sa(target)).map(|route| route.map(|r| r.dial).map_err(|r| r.code))
    }

    fn soon(done: impl Fn() -> bool) -> bool {
        (0..30).any(|_| {
            thread::sleep(Duration::from_millis(100));
            done()
        })
    }

    // Kernel addresses must be public to count, so they come from unassigned global space (3000::/16) rather than
    // the documentation prefix, which is not public. An operator's own addresses are taken as given.
    // A global /64, a /128 held alone, an on-link /48, link local, loopback, a unique local, and a global still in
    // duplicate address detection.
    const IF_INET6: &str = "\
30000001000200000000000000000005 06 40 00 80    eth0
300000010003000000000000000000aa 06 80 00 80    eth0
30000004000000000000000000000001 06 30 00 80    eth0
fe800000000000000000000000000001 06 40 20 80    eth0
00000000000000000000000000000001 01 80 10 80       lo
fd000000000000000000000000000001 06 40 00 80    eth0
30000005000000000000000000000007 06 40 00 40    eth0
";

    #[test]
    fn own_addresses_match_in_every_spelling() {
        let own = [ip("203.0.113.7"), ip("2001:db8::1")];
        for s in ["203.0.113.7", "::ffff:203.0.113.7", "::ffff:0:cb00:7107", "2002:cb00:7107::1", "2001:db8::1"] {
            assert!(is_own(ip(s), &own), "{s} should be an own address");
        }
        for s in ["198.51.100.1", "2001:db8::2"] {
            assert!(!is_own(ip(s), &own), "{s} should not be an own address");
        }
        assert!(!is_own(ip("203.0.113.7"), &[]));
        for s in ["203.0.113.7", "::ffff:203.0.113.7", "2002:cb00:7107::1"] {
            assert!(is_own(ip(s), &[ip("::ffff:203.0.113.7")]), "{s} should match an own address given mapped");
        }
    }

    #[test]
    fn only_a_port_a_session_holds_is_routed() {
        let hairpin = relay(&["203.0.113.7"], "");
        let tcp = hairpin.register(Proto::Tcp, sa("0.0.0.0:41001"));
        let udp = hairpin.register(Proto::Udp, sa("0.0.0.0:41002"));

        assert_eq!(dial(&hairpin, Proto::Tcp, "203.0.113.7:41001"), Some(Ok(sa("127.0.0.1:41001"))));
        assert_eq!(dial(&hairpin, Proto::Udp, "203.0.113.7:41002"), Some(Ok(sa("127.0.0.1:41002"))));
        assert_eq!(dial(&hairpin, Proto::Tcp, "[::ffff:203.0.113.7]:41001"), Some(Ok(sa("[::ffff:127.0.0.1]:41001"))));
        assert_eq!(dial(&hairpin, Proto::Udp, "203.0.113.7:41001"), REFUSED);
        assert_eq!(dial(&hairpin, Proto::Tcp, "203.0.113.7:41002"), REFUSED);
        assert_eq!(dial(&hairpin, Proto::Tcp, "203.0.113.7:22"), REFUSED);
        assert_eq!(dial(&hairpin, Proto::Tcp, "198.51.100.1:443"), None);
        assert_eq!(dial(&hairpin, Proto::Tcp, "10.0.0.1:80"), None);

        drop(tcp);
        assert_eq!(dial(&hairpin, Proto::Tcp, "203.0.113.7:41001"), REFUSED);
        drop(udp);
    }

    #[test]
    fn the_route_follows_the_bound_address() {
        let hairpin = relay(&["203.0.113.7"], "");
        let _any_v6 = hairpin.register(Proto::Tcp, sa("[::]:41003"));
        let _pinned = hairpin.register(Proto::Tcp, sa("127.0.0.1:41004"));

        assert_eq!(dial(&hairpin, Proto::Tcp, "203.0.113.7:41003"), Some(Ok(sa("127.0.0.1:41003"))));
        assert_eq!(dial(&hairpin, Proto::Tcp, "[::ffff:203.0.113.7]:41003"), Some(Ok(sa("[::ffff:127.0.0.1]:41003"))));
        assert_eq!(dial(&hairpin, Proto::Tcp, "203.0.113.7:41004"), Some(Ok(sa("127.0.0.1:41004"))));
        assert_eq!(dial(&hairpin, Proto::Tcp, "[::ffff:203.0.113.7]:41004"), Some(Ok(sa("[::ffff:127.0.0.1]:41004"))));
    }

    #[test]
    fn bindings_to_different_addresses_on_one_port_are_refused_as_ambiguous() {
        let hairpin = relay(&["203.0.113.7"], "");
        let first = hairpin.register(Proto::Tcp, sa("127.0.0.1:41010"));
        let second = hairpin.register(Proto::Tcp, sa("10.42.0.5:41010"));
        assert_eq!(dial(&hairpin, Proto::Tcp, "203.0.113.7:41010"), REFUSED);
        drop(first);
        assert_eq!(dial(&hairpin, Proto::Tcp, "203.0.113.7:41010"), Some(Ok(sa("10.42.0.5:41010"))));
        drop(second);
        assert_eq!(dial(&hairpin, Proto::Tcp, "203.0.113.7:41010"), REFUSED);
    }

    #[test]
    fn dropping_the_newer_binding_restores_the_older_route() {
        let hairpin = relay(&["203.0.113.7"], "");
        let first = hairpin.register(Proto::Tcp, sa("127.0.0.1:41011"));
        let second = hairpin.register(Proto::Tcp, sa("10.42.0.5:41011"));
        drop(second);
        assert_eq!(dial(&hairpin, Proto::Tcp, "203.0.113.7:41011"), Some(Ok(sa("127.0.0.1:41011"))));
        drop(first);
        assert_eq!(dial(&hairpin, Proto::Tcp, "203.0.113.7:41011"), REFUSED);
    }

    #[test]
    fn the_newest_of_equal_routes_wins() {
        let hairpin = relay(&["203.0.113.7"], "");
        let _older = hairpin.register(Proto::Udp, sa("0.0.0.0:41018"));
        let newer = hairpin.register(Proto::Udp, sa("127.0.0.1:41018"));
        let route = hairpin.own_route(Proto::Udp, sa("203.0.113.7:41018")).unwrap().unwrap();
        assert_eq!(route.dial, sa("127.0.0.1:41018"));
        assert_eq!(route.lease, Some(newer.lease));
    }

    #[test]
    fn bindings_of_both_families_route_by_the_dialer_family() {
        let hairpin = relay(&["203.0.113.7", "2001:db8::1"], "");
        let v4 = hairpin.register(Proto::Udp, sa("0.0.0.0:41012"));
        let v6 = hairpin.register(Proto::Udp, sa("[::]:41012"));
        assert_eq!(dial(&hairpin, Proto::Udp, "203.0.113.7:41012"), Some(Ok(sa("127.0.0.1:41012"))));
        assert_eq!(dial(&hairpin, Proto::Udp, "[2001:db8::1]:41012"), Some(Ok(sa("[::1]:41012"))));
        drop(v6);
        assert_eq!(dial(&hairpin, Proto::Udp, "[::ffff:203.0.113.7]:41012"), Some(Ok(sa("[::ffff:127.0.0.1]:41012"))));
        drop(v4);
        assert_eq!(dial(&hairpin, Proto::Udp, "203.0.113.7:41012"), REFUSED);
        assert_eq!(dial(&hairpin, Proto::Udp, "[::ffff:203.0.113.7]:41012"), REFUSED);
    }

    #[test]
    fn a_concrete_ipv6_bind_is_dialed_directly_from_an_ipv4_spelling() {
        let hairpin = relay(&["203.0.113.7"], "");
        for proto in [Proto::Tcp, Proto::Udp] {
            let pinned_v6 = hairpin.register(proto, sa("[::1]:41013"));
            assert_eq!(dial(&hairpin, proto, "203.0.113.7:41013"), Some(Ok(sa("[::1]:41013"))));
            assert_eq!(dial(&hairpin, proto, "[::ffff:203.0.113.7]:41013"), Some(Ok(sa("[::1]:41013"))));
            drop(pinned_v6);
            assert_eq!(dial(&hairpin, proto, "203.0.113.7:41013"), REFUSED);
        }
    }

    #[test]
    fn an_ipv4_spelling_over_two_distinct_ipv6_routes_is_refused_as_ambiguous() {
        let hairpin = relay(&["203.0.113.7"], "");
        let _any_v6 = hairpin.register(Proto::Udp, sa("[::]:41016"));
        let pinned_v6 = hairpin.register(Proto::Udp, sa("[::1]:41016"));
        assert_eq!(dial(&hairpin, Proto::Udp, "203.0.113.7:41016"), REFUSED);
        drop(pinned_v6);
        assert_eq!(dial(&hairpin, Proto::Udp, "203.0.113.7:41016"), Some(Ok(sa("127.0.0.1:41016"))));
    }

    #[test]
    fn a_route_carries_a_lease_that_ends_with_its_binding() {
        let hairpin = relay(&["203.0.113.7"], "");
        let bound = hairpin.register(Proto::Udp, sa("0.0.0.0:41014"));
        let route = hairpin.own_route(Proto::Udp, sa("203.0.113.7:41014")).unwrap().unwrap();
        let lease = route.lease.expect("a route onto a relay socket carries a lease");
        assert_eq!(route.dial, sa("127.0.0.1:41014"));
        assert!(hairpin.is_live(&lease));
        assert_eq!(hairpin.own_route(Proto::Udp, sa("198.51.100.1:53")), None);
        drop(bound);
        assert!(!hairpin.is_live(&lease));

        let rebound = hairpin.register(Proto::Udp, sa("0.0.0.0:41014"));
        assert!(!hairpin.is_live(&lease), "a later binding of the same port is another socket");
        let fresh = hairpin.own_route(Proto::Udp, sa("203.0.113.7:41014")).unwrap().unwrap().lease.unwrap();
        assert!(hairpin.is_live(&fresh));
        assert_ne!(fresh, lease);
        drop(rebound);
        assert!(!hairpin.is_live(&fresh));
    }

    #[test]
    fn the_registry_frees_a_port_when_its_last_binding_drops() {
        let hairpin = relay(&["203.0.113.7"], "");
        let bound: Vec<BoundPort> =
            (0..4).map(|i| hairpin.register(Proto::Udp, sa(&format!("0.0.0.0:{}", 41020 + i % 2)))).collect();
        assert_eq!(hairpin.ports.lock().unwrap().held.len(), 2);
        drop(bound);
        assert!(hairpin.ports.lock().unwrap().held.is_empty());
    }

    #[test]
    fn without_own_addresses_everything_is_left_to_the_policy() {
        let hairpin = Hairpin::new(Vec::new());
        let _bound = hairpin.register(Proto::Tcp, sa("0.0.0.0:41030"));
        for t in ["127.0.0.1:41030", "[::1]:41030", "198.51.100.1:41030", "[3000:1::1]:41030", "[fe80::1]:41030"] {
            assert_eq!(dial(&hairpin, Proto::Tcp, t), None, "{t}");
        }
        for a in ["127.0.0.1:41030", "[::1]:41030", "[::ffff:127.0.0.1]:41030"] {
            assert_eq!(hairpin.public_spelling(sa(a)), sa(a));
        }
    }

    #[test]
    fn a_loopback_source_is_spelled_as_the_relay_public_address() {
        let hairpin = relay(&["203.0.113.7"], "");
        assert_eq!(hairpin.public_spelling(sa("127.0.0.1:41005")), sa("203.0.113.7:41005"));
        assert_eq!(hairpin.public_spelling(sa("[::ffff:127.0.0.1]:41005")), sa("[::ffff:203.0.113.7]:41005"));
        assert_eq!(hairpin.public_spelling(sa("[::1]:41005")), sa("[::ffff:203.0.113.7]:41005"));
        assert_eq!(hairpin.public_spelling(sa("198.51.100.1:53")), sa("198.51.100.1:53"));

        let with_ipv6 = relay(&["203.0.113.7", "2001:db8::1"], "");
        assert_eq!(with_ipv6.public_spelling(sa("[::ffff:127.0.0.1]:41005")), sa("[::ffff:203.0.113.7]:41005"));
        assert_eq!(with_ipv6.public_spelling(sa("[::1]:41005")), sa("[2001:db8::1]:41005"));
    }

    // Two sessions whose UDP sockets are bound to [::], on a relay holding IPv6: an app that matches replies by
    // address (STUN, uTP, a DHT) needs the reply to come from the address it dialed.
    #[test]
    fn a_reply_comes_from_the_address_the_sender_dialed() {
        let hairpin = relay(&["203.0.113.7"], "30000001000200000000000000000001 01 40 00 80 lo");
        let a = std::net::UdpSocket::bind("[::]:0").unwrap();
        let b = std::net::UdpSocket::bind("[::]:0").unwrap();
        let _a_bound = hairpin.register(Proto::Udp, a.local_addr().unwrap());
        let _b_bound = hairpin.register(Proto::Udp, b.local_addr().unwrap());
        // the relay's route, then the source the receiving app is told
        let pass = |from: &std::net::UdpSocket, to: &std::net::UdpSocket, target: SocketAddr| {
            // an IPv6 socket takes an IPv4 destination in its IPv4-mapped spelling on every system, and macOS only so
            let dial = match hairpin.own_route(Proto::Udp, target).unwrap().unwrap().dial {
                SocketAddr::V4(v4) => SocketAddr::from((v4.ip().to_ipv6_mapped(), v4.port())),
                v6 => v6,
            };
            from.send_to(b"x", dial).unwrap();
            to.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let (_, source) = to.recv_from(&mut [0; 8]).unwrap();
            hairpin.public_spelling(source)
        };
        let b_port = b.local_addr().unwrap().port();
        for (dialed, reply_from) in [
            ("203.0.113.7", "[::ffff:203.0.113.7]"),
            ("[::ffff:203.0.113.7]", "[::ffff:203.0.113.7]"),
            ("[3000:1:2::1]", "[3000:1:2::1]"),
        ] {
            let a_as_b_sees_it = pass(&a, &b, sa(&format!("{dialed}:{b_port}")));
            let reply = pass(&b, &a, a_as_b_sees_it);
            assert_eq!(reply, sa(&format!("{reply_from}:{b_port}")), "a reply to {dialed}");
        }
    }

    #[test]
    fn the_own_addresses_are_the_given_ones_then_the_public_ones_the_kernel_lists() {
        assert_eq!(Hairpin::new(vec![ip("203.0.113.7")]).own_addresses(), [ip("203.0.113.7")]);
        let read = relay(&["203.0.113.7", "3000:4::1"], IF_INET6).own_addresses();
        assert_eq!(read, ["203.0.113.7", "3000:4::1", "3000:1:2::5", "3000:1:3::aa", "3000:5::7"].map(ip));
    }

    #[test]
    fn kernel_lines() {
        let kernel = parse_if_inet6(IF_INET6).unwrap();
        let six = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        assert_eq!(
            kernel,
            [("3000:1:2::5", 64), ("3000:1:3::aa", 128), ("3000:4::1", 48), ("fd00::1", 64), ("3000:5::7", 64)]
                .map(|(a, l)| (six(a), l))
        );
        let own = Own::new(&[], &kernel);
        assert_eq!(own.addresses, ["3000:1:2::5", "3000:1:3::aa", "3000:4::1", "3000:5::7"].map(ip));
        assert_eq!(
            own.links,
            [("3000:1:2::5", 64), ("3000:1:3::aa", 64), ("3000:4::1", 48), ("3000:5::7", 64)].map(|(a, l)| (six(a), l))
        );
    }

    #[test]
    fn a_missing_kernel_list_is_no_ipv6_and_a_garbled_one_an_error() {
        assert!(read_if_inet6(Path::new("/nonexistent/if_inet6")).unwrap().is_empty());
        assert!(parse_if_inet6("").unwrap().is_empty());
        assert!(read_if_inet6(&std::env::temp_dir()).is_err(), "a path that cannot be read is an error");
        assert!(Hairpin::new(Vec::new()).watch(std::env::temp_dir()).is_err(), "so is a first read that fails");
        for garbled in [
            "3000 06 40 00 80 eth0",
            "30000001000200000000000000000005 06 zz 00 80 eth0",
            "30000001000200000000000000000005 06 81 00 80 eth0",
            "30000001000200000000000000000005 06 40 00 80",
        ] {
            assert!(parse_if_inet6(garbled).is_err(), "{garbled:?} should be an error");
        }
    }

    #[test]
    fn an_own_ipv6_link_is_refused_but_for_a_held_port_on_an_own_address() {
        let hairpin = relay(&["203.0.113.7"], IF_INET6);
        assert_eq!(dial(&hairpin, Proto::Tcp, "[3000:1:2::5]:22"), REFUSED, "an own address");
        assert_eq!(dial(&hairpin, Proto::Tcp, "[3000:1:2::9]:443"), REFUSED, "a neighbour on the own /64");
        assert_eq!(dial(&hairpin, Proto::Tcp, "[3000:1:3::bb]:443"), REFUSED, "a /128 counts as its /64");
        assert_eq!(dial(&hairpin, Proto::Tcp, "[3000:4:0:ffff::1]:443"), REFUSED, "the on-link /48");
        assert_eq!(dial(&hairpin, Proto::Tcp, "[3000:5::9]:443"), REFUSED, "an address still being checked");

        let _v6 = hairpin.register(Proto::Tcp, sa("[::]:41020"));
        let _v4 = hairpin.register(Proto::Tcp, sa("0.0.0.0:41021"));
        assert_eq!(dial(&hairpin, Proto::Tcp, "[3000:1:2::5]:41020"), Some(Ok(sa("[::1]:41020"))));
        assert_eq!(dial(&hairpin, Proto::Tcp, "[3000:1:2::9]:41020"), REFUSED);
        assert_eq!(dial(&hairpin, Proto::Tcp, "203.0.113.7:41021"), Some(Ok(sa("127.0.0.1:41021"))));
        for t in ["[3000:1:4::9]:443", "[3000:9::1]:443", "[fd00::2]:443"] {
            assert_eq!(dial(&hairpin, Proto::Tcp, t), None, "{t} is the policy's to decide");
        }
    }

    #[test]
    fn the_kernel_reader_follows_the_list_and_ends_with_the_relay() {
        let path = std::env::temp_dir().join(format!("webvpn-hairpin-if_inet6-{}", std::process::id()));
        // a rename replaces the list at once, so a reread never sees it half written
        let put = |text: &str| {
            let next = path.with_extension("next");
            std::fs::write(&next, text).unwrap();
            std::fs::rename(&next, &path).unwrap();
        };
        put("30000001000200000000000000000005 06 40 00 80 eth0\n");
        let hairpin = Hairpin::new(Vec::new());
        let reader = hairpin.watch(path.clone()).unwrap();
        assert_eq!(dial(&hairpin, Proto::Tcp, "[3000:1:2::5]:22"), REFUSED, "read at once");

        put("30000009000000000000000000000001 06 40 00 80 eth0\n");
        assert!(soon(|| dial(&hairpin, Proto::Tcp, "[3000:9::1]:22").is_some()), "a new address is read");
        assert_eq!(dial(&hairpin, Proto::Tcp, "[3000:1:2::5]:22"), None, "a removed one is gone");

        put("garbled\n");
        thread::sleep(REREAD * 3 / 2);
        assert_eq!(dial(&hairpin, Proto::Tcp, "[3000:9::1]:22"), REFUSED, "a failed reread keeps the last list");

        drop(hairpin);
        let ended = soon(|| reader.is_finished());
        std::fs::remove_file(&path).unwrap();
        assert!(ended, "the reader ends once the relay is dropped");
    }
}
