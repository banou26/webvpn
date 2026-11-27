use std::borrow::Cow;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use webvpn_proto::ErrorCode;

use crate::egress::is_public;

/// A "no" from a policy: the code a client's library acts on, and a message for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: ErrorCode,
    pub message: Cow<'static, str>,
}

impl Refusal {
    pub fn new(code: ErrorCode, message: impl Into<Cow<'static, str>>) -> Self {
        Self { code, message: message.into() }
    }

    /// What a failed system call becomes for the client: the code its kind maps to and the system's own text, which
    /// names no address.
    pub(crate) fn from_io(error: &std::io::Error) -> Self {
        use std::io::ErrorKind;
        let code = match error.kind() {
            ErrorKind::ConnectionRefused => ErrorCode::CONNECTION_REFUSED,
            ErrorKind::TimedOut => ErrorCode::TIMED_OUT,
            ErrorKind::HostUnreachable => ErrorCode::HOST_UNREACHABLE,
            ErrorKind::NetworkUnreachable => ErrorCode::NETWORK_UNREACHABLE,
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => ErrorCode::CONNECTION_RESET,
            ErrorKind::AddrInUse => ErrorCode::ADDRESS_IN_USE,
            ErrorKind::AddrNotAvailable => ErrorCode::ADDRESS_NOT_AVAILABLE,
            _ => ErrorCode::OTHER,
        };
        // an error made in this crate may hold any text, the system's own holds its message and number only
        let message = if error.raw_os_error().is_some() { error.to_string() } else { error.kind().to_string() };
        Self::new(code, message)
    }
}

/// The protocol bytes go out with, as [`Session::check_egress`] and [`Session::check_bind`] are asked about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
    /// A packet of an IP tunnel that carries no port the relay reads: one of another protocol, by its IP protocol
    /// number (1 for ICMP, 58 for ICMPv6), or a fragment after the first, of any protocol. The target's port is 0.
    ///
    /// A later fragment holds no port, so it is asked about without one. That keeps a port's refusal whole: a policy
    /// that refuses a port refuses the first fragment, which holds the ports, and the destination cannot put the
    /// datagram together without it.
    Other(u8),
}

/// What a socket permit is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketKind {
    /// One TCP connection, dialed by the client or accepted by one of its listeners.
    Tcp,
    TcpListener,
    Udp,
    /// An IP tunnel, which carries whole packets.
    IpTunnel,
}

/// Which way relayed bytes move.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// From the client to its peer.
    Up,
    /// From the peer to the client.
    Down,
}

/// Whether a relay takes credentials, which its hello tells every client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// `Auth` is answered `UNSUPPORTED`.
    None,
    /// A session works without a credential and may present one.
    Optional,
    /// The server answers socket requests `AUTH_REQUIRED` until [`Session::authenticate`] returned `Ok`.
    Required,
}

/// The rules of one relay. The server asks it once per session, and asks the [`Session`] it returns for everything
/// that session does.
pub trait Policy: Send + Sync + 'static {
    type Session: Session;

    fn auth(&self) -> Auth {
        Auth::None
    }

    /// A client at `peer` opened a transport session; nothing was read from it yet. `Err` closes it with
    /// `SESSION_LIMIT` and the refusal's message.
    ///
    /// An IPv4 client is given as IPv4 on every carrier, also where a listener on every address reported it as an
    /// IPv4-mapped IPv6 address, so a policy that counts by address finds one client under one key.
    ///
    /// The returned value lives exactly as long as the session and is dropped when it ends, which is where a policy
    /// gives back what it counted here.
    fn admit(&self, peer: IpAddr) -> Result<Self::Session, Refusal>;
}

/// The rules of one admitted session. Methods take `&self` and may be called from several sockets' tasks at once.
pub trait Session: Send + Sync + 'static {
    /// Held by the server while a socket is open and dropped when it closes.
    type Permit: Send + 'static;

    /// The client presented `credential`. `Ok` gives the session that identity from now on: what it may open and how
    /// its bytes are counted and paced follow from it. `Err` must leave the session exactly as it was.
    ///
    /// A client may present a credential again at any time, for example a renewed one.
    fn authenticate(&self, credential: &[u8]) -> Result<(), Refusal> {
        let _ = credential;
        Err(Refusal::new(ErrorCode::UNSUPPORTED, "this relay takes no credentials"))
    }

    /// The client gave its identity up: the session is as [`Policy::admit`] made it.
    fn clear_auth(&self) {}

    /// The client asks for a socket, or one of its listeners accepted a connection. Called before the socket is
    /// counted as open; a refusal reaches the client under the request's id and leaves the session untouched.
    fn open_socket(&self, kind: SocketKind) -> Result<Self::Permit, Refusal>;

    /// Whether the session may send to `target`. Called with the literal address the bytes will go to: for a TCP
    /// connect (after its name was resolved), for the destination of every UDP datagram, for a multicast group, and
    /// for the destination of every packet of an IP tunnel, as [`Proto::Tcp`] or [`Proto::Udp`] with its port when the
    /// packet holds one, and as [`Proto::Other`] otherwise.
    ///
    /// Never called for the relay's own addresses: the server routes those to sockets other sessions bound on it,
    /// or refuses them itself.
    fn check_egress(&self, proto: Proto, target: SocketAddr) -> Result<(), Refusal>;

    /// Whether the session may bind `local`, for a UDP socket or a listener. Port 0 asks for any free port. It has no
    /// default, so a policy that wraps another one forwards it or decides itself.
    fn check_bind(&self, proto: Proto, local: SocketAddr) -> Result<(), Refusal>;

    /// `bytes` are about to be relayed. The future resolves when they may move, so a policy that paces waits here
    /// and a policy that meters counts here. Called for both directions of every socket, for each packet of an IP
    /// tunnel with its whole length, and for a DNS answer as `Down`.
    fn relayed(&self, direction: Direction, bytes: usize) -> impl Future<Output = ()> + Send {
        let _ = (direction, bytes);
        std::future::ready(())
    }
}

/// One unit taken from a shared ceiling and given back on drop.
#[derive(Debug)]
pub struct Slot(Arc<AtomicUsize>);

impl Slot {
    /// One more of `held`, unless `max` are taken.
    pub fn take(held: &Arc<AtomicUsize>, max: usize) -> Option<Self> {
        let mut taken = held.load(Ordering::Acquire);
        while taken < max {
            match held.compare_exchange_weak(taken, taken + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(Self(held.clone())),
                Err(now) => taken = now,
            }
        }
        None
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Whether two credentials hold the same bytes. Every byte is compared, so the time taken does not depend on where
/// they differ or how much of them matched. Their lengths may be learned from it: credentials of different lengths
/// are told apart at once.
pub fn same_credential(a: &[u8], b: &[u8]) -> bool {
    // `black_box` keeps the compiler from ending the loop at the first difference
    a.len() == b.len() && a.iter().zip(b).fold(0, |differs, (x, y)| std::hint::black_box(differs | (x ^ y))) == 0
}

/// The policy of a relay with no accounts: a ceiling on sessions and on sockets, public destinations only, and no
/// low ports. It neither paces nor meters. Start from `Basic::default()` and set the fields that differ, as in
/// `Basic { max_sessions: 64, ..Basic::default() }`.
#[derive(Debug, Clone)]
pub struct Basic {
    /// Sessions the relay holds at once.
    pub max_sessions: usize,
    /// Sockets the relay holds at once, across every session.
    pub max_sockets: usize,
    /// Lets sessions reach private, local and reserved addresses. For a relay on a network its operator trusts.
    pub allow_private_targets: bool,
    /// The lowest port a session may bind. Port 0, any free port, always passes.
    pub min_bind_port: u16,
    /// The sessions and sockets held now, which every clone shares, and so does a value made from this one with
    /// struct update syntax. Leave it at its default.
    pub held: BasicHeld,
}

/// The sessions and sockets a [`Basic`] holds now. Opaque: `BasicHeld::default()` holds none.
#[derive(Debug, Clone, Default)]
pub struct BasicHeld {
    sessions: Arc<AtomicUsize>,
    sockets: Arc<AtomicUsize>,
}

impl Default for Basic {
    fn default() -> Self {
        Self {
            max_sessions: 1024,
            max_sockets: 65536,
            allow_private_targets: false,
            min_bind_port: 1024,
            held: BasicHeld::default(),
        }
    }
}

impl Policy for Basic {
    type Session = BasicSession;

    fn admit(&self, _peer: IpAddr) -> Result<BasicSession, Refusal> {
        let slot = Slot::take(&self.held.sessions, self.max_sessions)
            .ok_or(Refusal::new(ErrorCode::CAPACITY, "the relay holds as many sessions as it allows"))?;
        Ok(BasicSession { rules: self.clone(), _slot: slot })
    }
}

/// A session [`Basic`] admitted.
#[derive(Debug)]
pub struct BasicSession {
    rules: Basic,
    _slot: Slot,
}

impl Session for BasicSession {
    type Permit = Slot;

    fn open_socket(&self, _kind: SocketKind) -> Result<Slot, Refusal> {
        Slot::take(&self.rules.held.sockets, self.rules.max_sockets)
            .ok_or(Refusal::new(ErrorCode::CAPACITY, "the relay holds as many sockets as it allows"))
    }

    fn check_egress(&self, _proto: Proto, target: SocketAddr) -> Result<(), Refusal> {
        if self.rules.allow_private_targets || is_public(target.ip()) {
            Ok(())
        } else {
            Err(Refusal::new(ErrorCode::REFUSED, "the relay reaches public addresses only"))
        }
    }

    fn check_bind(&self, _proto: Proto, local: SocketAddr) -> Result<(), Refusal> {
        if local.port() == 0 || local.port() >= self.rules.min_bind_port {
            Ok(())
        } else {
            Err(Refusal::new(ErrorCode::REFUSED, "the relay does not bind a port this low"))
        }
    }
}
