//! A [`Forwarder`] over a Linux TUN device, for a relay whose tunnels' packets go through the system's own routing.

use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::str::FromStr;
use std::sync::{Arc, Mutex, Weak};
use std::thread;

use tokio::sync::mpsc;
use webvpn_proto::ErrorCode;

use crate::policy::Refusal;
use crate::tunnel::{Forwarder, TunnelEnd};

/// How long the device's reader waits on it before it checks whether the forwarder was dropped.
const POLL_MS: libc::c_int = 1000;

/// The packets each tunnel's channel holds before the forwarder drops one.
const CHANNEL: usize = 256;

/// The largest packet read from the device. A packet over the `mtu` reaches the relay, which drops and counts it.
const READ_BYTES: usize = 65535;

/// An IPv4 network a TUN device holds, written `198.18.0.0/16`: the address with its host bits clear, and the
/// prefix length, from 8 to 30.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Pool {
    network: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Pool {
    /// The network `network/prefix`, or `None` when `prefix` is outside 8 to 30 or `network` has a host bit set.
    pub fn new(network: Ipv4Addr, prefix: u8) -> Option<Self> {
        let pool = Self { network, prefix };
        ((8..=30).contains(&prefix) && u32::from(network) & !pool.mask() == 0).then_some(pool)
    }

    /// The network's address.
    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    /// The network's prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// The device's own address: by convention, the network's first host address.
    pub fn device_address(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network) + 1)
    }

    fn mask(&self) -> u32 {
        u32::MAX << (32 - self.prefix)
    }

    fn size(&self) -> u32 {
        1 << (32 - self.prefix)
    }
}

/// The public ports a [`TunForwarder`] gives its tunnels: the ports from `first` to `last`, in blocks of `per_tunnel`.
///
/// The k-th tunnel address of the network, counting from 0 at the network's second host address (the device holds
/// the first), holds the k-th block: the ports from `first + k * per_tunnel` to `first + (k + 1) * per_tunnel - 1`.
/// [`TunForwarder::open`] refuses a network with more tunnel addresses than blocks, so every address holds one. The
/// setup step maps the same blocks on the node, so a TCP or UDP packet to one of the node's own addresses on a port of
/// a block reaches the address that holds it, on the same port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortBlocks {
    pub first: u16,
    pub last: u16,
    pub per_tunnel: u16,
}

impl PortBlocks {
    /// The block of the k-th tunnel address, as its first port and how many, or `(0, 0)` when it holds none.
    fn block(&self, k: u32) -> (u16, u16) {
        let first = u64::from(self.first) + u64::from(k) * u64::from(self.per_tunnel);
        let last = first + u64::from(self.per_tunnel);
        if self.per_tunnel == 0 || last > u64::from(self.last) + 1 {
            return (0, 0);
        }
        (first as u16, self.per_tunnel)
    }
}

/// Why an [`Ipv4Pool`] does not parse. It never repeats the text it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolError(&'static str);

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for PoolError {}

impl FromStr for Ipv4Pool {
    type Err = PoolError;

    fn from_str(text: &str) -> Result<Self, PoolError> {
        let (network, prefix) =
            text.split_once('/').ok_or(PoolError("not an IPv4 network written with its prefix length"))?;
        let network = network.parse().map_err(|_| PoolError("the network is not an IPv4 address"))?;
        let prefix = prefix.parse().map_err(|_| PoolError("the prefix length is not a number"))?;
        Self::new(network, prefix)
            .ok_or(PoolError("the prefix length is not 8 to 30, or the address has a host bit set"))
    }
}

/// A [`Forwarder`] over a TUN device that exists already and belongs to the relay's user, so the relay needs no
/// privilege: a setup step made the device, gave it its address, routes and rules.
///
/// Each tunnel is given one address of the device's IPv4 network. The device holds the first host address, and a
/// tunnel the next one after the address given last, skipping the ones in use, the network's and the broadcast
/// address, and starting over at the end of the network. So an address freed is given again only once the whole
/// network was gone through. A tunnel's address is free again once the relay dropped its end. No free address
/// refuses the tunnel with `CAPACITY`.
///
/// A packet the device holds for an address goes to the tunnel given it, and is dropped when that tunnel's channel is
/// full or no tunnel holds the address. A packet a tunnel sends is written to the device without waiting, and dropped
/// when the device takes none now. The device is read on a thread of its own, which ends within a second of the
/// forwarder being dropped, or once the device fails, which ends every tunnel. Nothing it logs or returns names an
/// address or holds a packet.
///
/// Linux only, with the `tun` feature.
pub struct TunForwarder {
    shared: Arc<Shared>,
}

struct Shared {
    device: OwnedFd,
    mtu: u16,
    ports: Option<PortBlocks>,
    tunnels: Mutex<Tunnels>,
}

struct Tunnels {
    walk: Walk,
    ends: HashMap<Ipv4Addr, mpsc::Sender<Vec<u8>>>,
    /// Set once the device failed, removed while the relay ran for example: every tunnel was ended, and new ones
    /// are refused.
    failed: bool,
}

impl TunForwarder {
    /// Opens the TUN device named `device`, whose network is `ipv4`, and starts reading it. With `ports`, each tunnel
    /// is given the public ports of its address's block.
    ///
    /// An error says what to check: `ipv4` has more tunnel addresses than `ports` has blocks, the device does not
    /// exist, belongs to another user or is not a TUN device, `/dev/net/tun` is missing or cannot be opened, or the
    /// device's MTU is under 1280. It names the device and never an address.
    pub fn open(device: &str, ipv4: Ipv4Pool, ports: Option<PortBlocks>) -> io::Result<Self> {
        if let Some(PortBlocks { first, last, per_tunnel }) = ports {
            // the walk gives every address in turn, so an address past the last block would get none on an idle relay
            let addresses = ipv4.size() - 3;
            let span = (u32::from(last) + 1).saturating_sub(u32::from(first));
            let blocks = span.checked_div(u32::from(per_tunnel)).unwrap_or(0);
            if blocks < addresses {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "the pool holds {addresses} tunnel addresses and the public ports only {blocks} blocks: make \
                         the pool smaller or the range larger, so that every address holds a block"
                    ),
                ));
            }
        }
        let name =
            CString::new(device).ok().filter(|name| name.as_bytes().len() < libc::IFNAMSIZ).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("{device:?} is not a network device's name"))
            })?;
        // Checked first: with CAP_NET_ADMIN, attaching to a missing device makes a new one with no address.
        // SAFETY: `name` is a valid C string.
        if unsafe { libc::if_nametoindex(name.as_ptr()) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("the TUN device {device} does not exist: make it in the setup step before the relay starts"),
            ));
        }
        let fd = open_tun().map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => io::Error::new(
                error.kind(),
                "/dev/net/tun is missing: give the relay the device node (in a container, --device /dev/net/tun)",
            ),
            _ => io::Error::new(error.kind(), format!("/dev/net/tun could not be opened: {error}")),
        })?;
        attach(&fd, &name).map_err(|error| match error.raw_os_error() {
            Some(libc::EPERM) => io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "the TUN device {device} belongs to another user: make it with `ip tuntap add dev {device} mode \
                     tun user <the relay's user>`"
                ),
            ),
            Some(libc::EINVAL) | Some(libc::EBUSY) => io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{device} is not a free TUN device: make it with `ip tuntap add dev {device} mode tun`"),
            ),
            _ => io::Error::new(error.kind(), format!("the TUN device {device} could not be opened: {error}")),
        })?;
        let mtu = read_mtu(&name)
            .map_err(|error| io::Error::new(error.kind(), format!("the MTU of {device} could not be read: {error}")))?;
        let mtu = u16::try_from(mtu).unwrap_or(u16::MAX);
        if mtu < webvpn_proto::ip::MIN_MTU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the MTU of {device} is {mtu}, under the 1280 a tunnel carries: raise it"),
            ));
        }
        let tunnels = Mutex::new(Tunnels { walk: Walk::new(ipv4), ends: HashMap::new(), failed: false });
        let shared = Arc::new(Shared { device: fd, mtu, ports, tunnels });
        let weak = Arc::downgrade(&shared);
        thread::Builder::new().name("tun-reader".into()).spawn(move || read(weak))?;
        Ok(Self { shared })
    }
}

impl Forwarder for TunForwarder {
    fn mtu(&self) -> u16 {
        self.shared.mtu
    }

    fn attach(&self) -> Result<TunnelEnd, Refusal> {
        let mut tunnels = self.shared.tunnels.lock().unwrap();
        let Tunnels { walk, ends, failed } = &mut *tunnels;
        if *failed {
            return Err(Refusal::new(ErrorCode::OTHER, "the relay's TUN device failed"));
        }
        ends.retain(|_, end| !end.is_closed());
        let ipv4 = walk
            .take(|address| ends.contains_key(&address))
            .ok_or_else(|| Refusal::new(ErrorCode::CAPACITY, "the relay has no tunnel address left"))?;
        // the walk gives only the network's host addresses from the second on
        let k = u32::from(ipv4) - u32::from(walk.pool.network) - 2;
        let (first_port, ports) = self.shared.ports.map_or((0, 0), |blocks| blocks.block(k));
        let (sender, packets) = mpsc::channel(CHANNEL);
        ends.insert(ipv4, sender);
        Ok(TunnelEnd { ipv4: Some(ipv4), ipv6: None, first_port, ports, packets })
    }

    fn public_ports(&self) -> Option<RangeInclusive<u16>> {
        self.shared.ports.map(|blocks| blocks.first..=blocks.last)
    }

    fn send(&self, packet: &[u8]) {
        // SAFETY: the device is open and non-blocking, and `packet` is valid for its length.
        unsafe { libc::write(self.shared.device.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
    }
}

/// Reads the device until the forwarder is dropped, handing each packet to the tunnel that holds its destination.
fn read(shared: Weak<Shared>) {
    let mut buf = vec![0; READ_BYTES];
    loop {
        let Some(shared) = shared.upgrade() else { return };
        let fd = shared.device.as_raw_fd();
        let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: `poll` is one valid pollfd.
        if unsafe { libc::poll(&mut poll, 1, POLL_MS) } <= 0 {
            continue;
        }
        if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            let mut tunnels = shared.tunnels.lock().unwrap();
            tunnels.failed = true;
            tunnels.ends.clear();
            return;
        }
        loop {
            // SAFETY: the device is open and non-blocking, and `buf` is valid for its length.
            let read = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            let Ok(length @ 1..) = usize::try_from(read) else { break };
            let packet = &buf[..length];
            if packet.len() < 20 || packet[0] >> 4 != 4 {
                continue;
            }
            let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            if let Some(end) = shared.tunnels.lock().unwrap().ends.get(&destination) {
                let _ = end.try_send(packet.to_vec());
            }
        }
    }
}

fn open_tun() -> io::Result<OwnedFd> {
    // SAFETY: the path is a valid C string.
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn request(name: &CString) -> libc::ifreq {
    // SAFETY: an all-zero ifreq is valid.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (to, &from) in request.ifr_name.iter_mut().zip(name.as_bytes()) {
        *to = from as libc::c_char;
    }
    request
}

fn attach(fd: &OwnedFd, name: &CString) -> io::Result<()> {
    let mut request = request(name);
    request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    // SAFETY: `request` is a valid ifreq that outlives the call.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_mtu(name: &CString) -> io::Result<libc::c_int> {
    // SAFETY: plain socket creation.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if socket < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `socket` was just made and nothing else owns it.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    let mut request = request(name);
    // SAFETY: `request` is a valid ifreq that outlives the call.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFMTU, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: SIOCGIFMTU filled the MTU.
    Ok(unsafe { request.ifr_ifru.ifru_mtu })
}

/// The walk through a network's host addresses that gives each tunnel its address.
#[derive(Debug)]
struct Walk {
    pool: Ipv4Pool,
    /// The offset in the network of the address to try next.
    next: u32,
}

impl Walk {
    fn new(pool: Ipv4Pool) -> Self {
        Self { pool, next: 2 }
    }

    /// The first address from the one after the last given that `in_use` says is free, or `None` when none is.
    fn take(&mut self, in_use: impl Fn(Ipv4Addr) -> bool) -> Option<Ipv4Addr> {
        // offsets 0, 1 and size - 1 are the network's, the device's and the broadcast address
        let (first, last) = (2, self.pool.size() - 2);
        for _ in first..=last {
            let offset = self.next;
            self.next = if offset >= last { first } else { offset + 1 };
            let address = Ipv4Addr::from(u32::from(self.pool.network) + offset);
            if !in_use(address) {
                return Some(address);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn pool(text: &str) -> Ipv4Pool {
        text.parse().unwrap()
    }

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    #[test]
    fn a_pool_parses_from_its_network_and_prefix() {
        let parsed = pool("198.18.0.0/16");
        assert_eq!((parsed.network(), parsed.prefix()), (ip("198.18.0.0"), 16));
        assert_eq!(parsed.device_address(), ip("198.18.0.1"));
        for refused in ["198.51.0.0", "198.18.0.1/16", "198.18.0.0/31", "198.18.0.0/7", "::/64", "a/16", "1.2.3.0/x"] {
            let error = refused.parse::<Ipv4Pool>().unwrap_err().to_string();
            assert!(!error.contains(refused), "{error:?} repeats {refused:?}");
        }
    }

    #[test]
    fn the_walk_gives_the_next_address_skipping_the_device_and_the_broadcast_and_wraps() {
        let mut walk = Walk::new(pool("10.0.0.0/29"));
        let given: Vec<_> = (0..7).map(|_| walk.take(|_| false).unwrap()).collect();
        let expected = ["10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.2", "10.0.0.3"];
        assert_eq!(given, expected.map(ip));
    }

    #[test]
    fn the_walk_skips_the_addresses_in_use_and_gives_one_back_only_after_a_whole_round() {
        let mut walk = Walk::new(pool("10.0.0.0/29"));
        let mut held = HashSet::new();
        for _ in 0..5 {
            held.insert(walk.take(|address| held.contains(&address)).unwrap());
        }
        assert_eq!(walk.take(|address| held.contains(&address)), None, "a full pool gives nothing");

        held.remove(&ip("10.0.0.4"));
        assert_eq!(walk.take(|address| held.contains(&address)), Some(ip("10.0.0.4")), "a freed one comes back");

        held.remove(&ip("10.0.0.3"));
        held.remove(&ip("10.0.0.6"));
        assert_eq!(
            walk.take(|address| held.contains(&address)),
            Some(ip("10.0.0.6")),
            "the walk goes on from 10.0.0.5"
        );
        held.insert(ip("10.0.0.6"));
        assert_eq!(walk.take(|address| held.contains(&address)), Some(ip("10.0.0.3")), "then wraps around");
    }

    #[test]
    fn a_freed_address_waits_for_the_rest_of_the_pool() {
        let mut walk = Walk::new(pool("10.0.0.0/24"));
        let freed = walk.take(|_| false).unwrap();
        let others: Vec<_> = (0..252).map(|_| walk.take(|_| false).unwrap()).collect();
        assert!(!others.contains(&freed), "given again before the rest of the pool");
        assert_eq!(walk.take(|_| false), Some(freed));
    }

    #[test]
    fn a_slash_30_holds_one_tunnel() {
        let mut walk = Walk::new(pool("10.0.0.0/30"));
        assert_eq!(walk.take(|_| false), Some(ip("10.0.0.2")));
        assert_eq!(walk.take(|address| address == ip("10.0.0.2")), None);
    }

    #[test]
    fn each_address_holds_its_block_of_ports_and_one_past_the_range_holds_none() {
        let blocks = PortBlocks { first: 30000, last: 30031, per_tunnel: 8 };
        let given: Vec<_> = (0..6).map(|k| blocks.block(k)).collect();
        assert_eq!(given, [(30000, 8), (30008, 8), (30016, 8), (30024, 8), (0, 0), (0, 0)]);
        assert_eq!(PortBlocks { last: 30030, ..blocks }.block(3), (0, 0), "a block cut short is none");
        assert_eq!(PortBlocks { per_tunnel: 0, ..blocks }.block(0), (0, 0));
        let top = PortBlocks { first: 65528, last: 65535, per_tunnel: 8 };
        assert_eq!((top.block(0), top.block(1)), ((65528, 8), (0, 0)));
        assert_eq!(PortBlocks { first: 1024, last: 65535, per_tunnel: 64 }.block(1 << 24), (0, 0));
    }

    #[test]
    fn a_missing_device_is_named_and_no_address_is() {
        let error = TunForwarder::open("webvpn-none0", pool("198.18.0.0/16"), None).err().unwrap().to_string();
        assert!(error.contains("webvpn-none0 does not exist"), "{error}");
        assert!(!error.contains("198.18"), "{error}");
    }

    #[test]
    fn a_pool_with_more_tunnel_addresses_than_blocks_of_ports_is_refused() {
        let blocks = Some(PortBlocks { first: 20000, last: 29999, per_tunnel: 8 });
        let error = TunForwarder::open("webvpn-none0", pool("198.18.0.0/16"), blocks).err().unwrap().to_string();
        assert!(error.contains("65533") && error.contains("1250"), "{error}");
        assert!(!error.contains("198.18"), "{error}");
        let error = TunForwarder::open("webvpn-none0", pool("198.18.0.0/22"), blocks).err().unwrap().to_string();
        assert!(error.contains("does not exist"), "a pool the blocks cover is taken: {error}");
    }
}
