use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::{DecodeError, ErrorCode};
use crate::options::{TcpOption, UdpOption};
use crate::wire::{put_address, put_u16, put_u32, Reader};

/// The first four bytes of every `Hello` body.
pub const MAGIC: [u8; 4] = *b"WVPN";
/// The version this crate speaks, major then minor. While the major is 0, peers need the same minor.
pub const VERSION: (u8, u8) = (0, 1);
/// The longest frame body a relay reads from a client.
pub const MAX_CLIENT_FRAME_BYTES: usize = 4096;
/// The longest frame body a client reads from a relay; a whole DNS answer fits.
pub const MAX_RELAY_FRAME_BYTES: usize = 128 * 1024;
/// The longest agent a `Hello` carries; a longer one is cut when it is written.
pub const MAX_AGENT_BYTES: usize = 255;

const HEADER_BYTES: usize = 5;

/// What a relay offers, as the bits of [`Hello::features`]. A client sends a request only when its bit is set.
pub mod features {
    /// `TcpListen` and `TcpUnlisten`.
    pub const LISTEN: u32 = 1 << 0;
    /// `DnsQuery` and `TcpConnectName`.
    pub const DNS: u32 = 1 << 1;
    /// `Auth` and `AuthClear`.
    pub const AUTH: u32 = 1 << 2;
    /// Socket requests are answered `AUTH_REQUIRED` until an `Auth` succeeded.
    pub const AUTH_REQUIRED: u32 = 1 << 3;
    /// `IpOpen` and `IpClose`.
    pub const IP: u32 = 1 << 4;
}

/// The first frame each side writes: the relay first, then the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub major: u8,
    pub minor: u8,
    /// Bits of [`features`]. A client sends 0.
    pub features: u32,
    /// Names the implementation for a person reading a log. Nothing may branch on it.
    pub agent: String,
}

impl Hello {
    /// A hello at this crate's version.
    pub fn new(features: u32, agent: impl Into<String>) -> Self {
        Self { major: VERSION.0, minor: VERSION.1, features, agent: agent.into() }
    }

    /// Whether this crate can speak to the peer that sent this hello.
    pub fn compatible(&self) -> bool {
        self.major == VERSION.0 && (self.major != 0 || self.minor == VERSION.1)
    }

    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&MAGIC);
        out.push(self.major);
        out.push(self.minor);
        put_u32(out, self.features);
        let mut end = self.agent.len().min(MAX_AGENT_BYTES);
        while !self.agent.is_char_boundary(end) {
            end -= 1;
        }
        out.extend_from_slice(&self.agent.as_bytes()[..end]);
    }

    fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        if r.array::<4>()? != MAGIC {
            return Err(DecodeError::Invalid("not a WebVPN hello"));
        }
        let (major, minor, features) = (r.u8()?, r.u8()?, r.u32()?);
        let agent = r.rest();
        let agent = String::from_utf8_lossy(&agent[..agent.len().min(MAX_AGENT_BYTES)]).into_owned();
        Ok(Self { major, minor, features, agent })
    }
}

mod client {
    pub const HELLO: u8 = 0x00;
    pub const AUTH: u8 = 0x01;
    pub const AUTH_CLEAR: u8 = 0x02;
    pub const TCP_CONNECT: u8 = 0x10;
    pub const TCP_CONNECT_NAME: u8 = 0x11;
    pub const TCP_CLOSE: u8 = 0x12;
    pub const TCP_RESET: u8 = 0x13;
    pub const TCP_SET_OPTION: u8 = 0x14;
    pub const TCP_LISTEN: u8 = 0x20;
    pub const TCP_UNLISTEN: u8 = 0x21;
    pub const UDP_BIND: u8 = 0x30;
    pub const UDP_CLOSE: u8 = 0x31;
    pub const UDP_CONNECT: u8 = 0x32;
    pub const UDP_DISCONNECT: u8 = 0x33;
    pub const UDP_SET_OPTION: u8 = 0x34;
    pub const DNS_QUERY: u8 = 0x40;
    pub const IP_OPEN: u8 = 0x50;
    pub const IP_CLOSE: u8 = 0x51;
}

mod relay {
    pub const HELLO: u8 = 0x00;
    pub const OK: u8 = 0x01;
    pub const ERROR: u8 = 0x02;
    pub const SOCKET: u8 = 0x03;
    pub const DNS_ANSWER: u8 = 0x04;
    pub const IP_TUNNEL: u8 = 0x05;
    pub const ACCEPTED: u8 = 0x10;
    pub const ACCEPT_REFUSED: u8 = 0x11;
    pub const CLOSED: u8 = 0x12;
    pub const DRAINING: u8 = 0x20;
    pub const BYE: u8 = 0x21;
}

/// A control frame a client sends. `id` names the request in its reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientPacket {
    Hello(Hello),
    /// Presents a credential, whose bytes the relay's operator defines. Answered `Ok`.
    Auth { id: u32, credential: Vec<u8> },
    /// Returns the session to no identity. Answered `Ok`.
    AuthClear { id: u32 },
    /// Answered `Socket`.
    TcpConnect { id: u32, remote: SocketAddr },
    /// Connects to the first A record the relay's resolver answers for `query`, a whole DNS message. Answered `Socket`.
    TcpConnectName { id: u32, port: u16, query: Vec<u8> },
    /// Ends the socket in order. Answered `Ok`, also for a socket that is gone.
    TcpClose { id: u32, socket: u32 },
    /// Ends the socket with a reset toward its peer. Answered `Ok`, also for a socket that is gone.
    TcpReset { id: u32, socket: u32 },
    TcpSetOption { id: u32, socket: u32, option: TcpOption },
    /// Port 0 takes a free port. Answered `Socket` with the bound address and no remote.
    TcpListen { id: u32, local: SocketAddr },
    TcpUnlisten { id: u32, socket: u32 },
    /// Port 0 takes a free port. Answered `Socket` with the bound address and no remote.
    UdpBind { id: u32, local: SocketAddr },
    UdpClose { id: u32, socket: u32 },
    UdpConnect { id: u32, socket: u32, remote: SocketAddr },
    UdpDisconnect { id: u32, socket: u32 },
    UdpSetOption { id: u32, socket: u32, option: UdpOption },
    /// `query` is a whole DNS message. Answered `DnsAnswer`.
    DnsQuery { id: u32, query: Vec<u8> },
    /// Answered `IpTunnel`.
    IpOpen { id: u32 },
    /// Ends the tunnel. Answered `Ok`, also for a tunnel that is gone.
    IpClose { id: u32, socket: u32 },
    /// A type this crate does not name. A relay answers `id`, when the body held one, with `UNSUPPORTED`.
    Unknown { kind: u8, id: Option<u32> },
}

impl ClientPacket {
    /// Appends the packet as one frame.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let at = open(out);
        let kind = match self {
            Self::Hello(hello) => {
                hello.put(out);
                client::HELLO
            }
            Self::Auth { id, credential } => {
                put_u32(out, *id);
                out.extend_from_slice(credential);
                client::AUTH
            }
            Self::AuthClear { id } => {
                put_u32(out, *id);
                client::AUTH_CLEAR
            }
            Self::TcpConnect { id, remote } => {
                put_u32(out, *id);
                put_address(out, Some(*remote));
                client::TCP_CONNECT
            }
            Self::TcpConnectName { id, port, query } => {
                put_u32(out, *id);
                put_u16(out, *port);
                out.extend_from_slice(query);
                client::TCP_CONNECT_NAME
            }
            Self::TcpClose { id, socket } => on_socket(out, *id, *socket, client::TCP_CLOSE),
            Self::TcpReset { id, socket } => on_socket(out, *id, *socket, client::TCP_RESET),
            Self::TcpSetOption { id, socket, option } => {
                on_socket(out, *id, *socket, 0);
                option.put(out);
                client::TCP_SET_OPTION
            }
            Self::TcpListen { id, local } => {
                put_u32(out, *id);
                put_address(out, Some(*local));
                client::TCP_LISTEN
            }
            Self::TcpUnlisten { id, socket } => on_socket(out, *id, *socket, client::TCP_UNLISTEN),
            Self::UdpBind { id, local } => {
                put_u32(out, *id);
                put_address(out, Some(*local));
                client::UDP_BIND
            }
            Self::UdpClose { id, socket } => on_socket(out, *id, *socket, client::UDP_CLOSE),
            Self::UdpConnect { id, socket, remote } => {
                on_socket(out, *id, *socket, 0);
                put_address(out, Some(*remote));
                client::UDP_CONNECT
            }
            Self::UdpDisconnect { id, socket } => on_socket(out, *id, *socket, client::UDP_DISCONNECT),
            Self::UdpSetOption { id, socket, option } => {
                on_socket(out, *id, *socket, 0);
                option.put(out);
                client::UDP_SET_OPTION
            }
            Self::DnsQuery { id, query } => {
                put_u32(out, *id);
                out.extend_from_slice(query);
                client::DNS_QUERY
            }
            Self::IpOpen { id } => {
                put_u32(out, *id);
                client::IP_OPEN
            }
            Self::IpClose { id, socket } => on_socket(out, *id, *socket, client::IP_CLOSE),
            Self::Unknown { kind, id } => {
                if let Some(id) = id {
                    put_u32(out, *id);
                }
                *kind
            }
        };
        seal(out, at, kind);
    }

    /// Reads one packet off the front of `buf`: the packet and how many bytes it took, or `None` until a whole frame
    /// is there.
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>, DecodeError> {
        let Some((kind, body, taken)) = split(buf, MAX_CLIENT_FRAME_BYTES)? else {
            return Ok(None);
        };
        let mut r = Reader(body);
        let packet = match kind {
            client::HELLO => Self::Hello(Hello::read(&mut r)?),
            client::AUTH => Self::Auth { id: r.u32()?, credential: r.rest().to_vec() },
            client::AUTH_CLEAR => Self::AuthClear { id: r.u32()? },
            client::TCP_CONNECT => Self::TcpConnect { id: r.u32()?, remote: r.address()? },
            client::TCP_CONNECT_NAME => {
                Self::TcpConnectName { id: r.u32()?, port: r.u16()?, query: r.rest().to_vec() }
            }
            client::TCP_CLOSE => Self::TcpClose { id: r.u32()?, socket: r.u32()? },
            client::TCP_RESET => Self::TcpReset { id: r.u32()?, socket: r.u32()? },
            client::TCP_SET_OPTION => {
                Self::TcpSetOption { id: r.u32()?, socket: r.u32()?, option: TcpOption::read(&mut r)? }
            }
            client::TCP_LISTEN => Self::TcpListen { id: r.u32()?, local: r.address()? },
            client::TCP_UNLISTEN => Self::TcpUnlisten { id: r.u32()?, socket: r.u32()? },
            client::UDP_BIND => Self::UdpBind { id: r.u32()?, local: r.address()? },
            client::UDP_CLOSE => Self::UdpClose { id: r.u32()?, socket: r.u32()? },
            client::UDP_CONNECT => Self::UdpConnect { id: r.u32()?, socket: r.u32()?, remote: r.address()? },
            client::UDP_DISCONNECT => Self::UdpDisconnect { id: r.u32()?, socket: r.u32()? },
            client::UDP_SET_OPTION => {
                Self::UdpSetOption { id: r.u32()?, socket: r.u32()?, option: UdpOption::read(&mut r)? }
            }
            client::DNS_QUERY => Self::DnsQuery { id: r.u32()?, query: r.rest().to_vec() },
            client::IP_OPEN => Self::IpOpen { id: r.u32()? },
            client::IP_CLOSE => Self::IpClose { id: r.u32()?, socket: r.u32()? },
            kind => Self::Unknown { kind, id: r.u32().ok() },
        };
        Ok(Some((packet, taken)))
    }
}

/// A control frame a relay sends: a reply, which starts with the request's `id`, or a notice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayPacket {
    Hello(Hello),
    /// The request was done and has nothing to return.
    Ok { id: u32 },
    /// The request was not done. `message` is for a person.
    Error { id: u32, code: ErrorCode, message: String },
    /// The socket a connect, a listen or a bind opened. `remote` is the peer of a connect and `None` otherwise.
    Socket { id: u32, socket: u32, local: SocketAddr, remote: Option<SocketAddr> },
    /// The resolver's whole DNS message.
    DnsAnswer { id: u32, answer: Vec<u8> },
    /// The tunnel an `IpOpen` opened: the largest packet it carries, and the addresses the relay gave the client's
    /// end, at least one of them. Then its public ports, if any: the relay's public address as others dial it, and
    /// `ports` ports from `first_port` on, each reaching the client's address on the same port; `ports` 0 is none.
    /// A family with no address, private or public, is all zero bytes on the wire.
    IpTunnel {
        id: u32,
        socket: u32,
        mtu: u16,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        public_ipv4: Option<Ipv4Addr>,
        public_ipv6: Option<Ipv6Addr>,
        first_port: u16,
        ports: u16,
    },
    /// A listener accepted a connection, which is socket `socket` from now on.
    Accepted { listener: u32, socket: u32, local: SocketAddr, remote: SocketAddr },
    /// A listener had a connection the relay turned away.
    AcceptRefused { listener: u32, code: ErrorCode, remote: SocketAddr },
    /// The relay ended a listener, a UDP socket or an IP tunnel on its own, and `code` says why. The socket is gone.
    Closed { socket: u32, code: ErrorCode },
    /// The relay is about to stop: this session keeps its sockets, and new ones belong on a new session.
    Draining,
    /// The relay closes the session on its own right after this frame, the last on the control stream. `code` is the
    /// session close code it closes with, from `webvpn_proto::close`, and `reason` is for a person. A client takes the
    /// session's code from it, since a carrier may not show its own close to the client.
    Bye { code: u32, reason: String },
    /// A type this crate does not name, which a client skips.
    Unknown { kind: u8 },
}

impl RelayPacket {
    /// Appends the packet as one frame.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let at = open(out);
        let kind = match self {
            Self::Hello(hello) => {
                hello.put(out);
                relay::HELLO
            }
            Self::Ok { id } => {
                put_u32(out, *id);
                relay::OK
            }
            Self::Error { id, code, message } => {
                put_u32(out, *id);
                put_u16(out, code.0);
                out.extend_from_slice(message.as_bytes());
                relay::ERROR
            }
            Self::Socket { id, socket, local, remote } => {
                put_u32(out, *id);
                put_u32(out, *socket);
                put_address(out, Some(*local));
                put_address(out, *remote);
                relay::SOCKET
            }
            Self::DnsAnswer { id, answer } => {
                put_u32(out, *id);
                out.extend_from_slice(answer);
                relay::DNS_ANSWER
            }
            Self::IpTunnel { id, socket, mtu, ipv4, ipv6, public_ipv4, public_ipv6, first_port, ports } => {
                on_socket(out, *id, *socket, 0);
                put_u16(out, *mtu);
                for (v4, v6) in [(ipv4, ipv6), (public_ipv4, public_ipv6)] {
                    out.extend_from_slice(&v4.unwrap_or(Ipv4Addr::UNSPECIFIED).octets());
                    out.extend_from_slice(&v6.unwrap_or(Ipv6Addr::UNSPECIFIED).octets());
                }
                put_u16(out, *first_port);
                put_u16(out, *ports);
                relay::IP_TUNNEL
            }
            Self::Accepted { listener, socket, local, remote } => {
                put_u32(out, *listener);
                put_u32(out, *socket);
                put_address(out, Some(*local));
                put_address(out, Some(*remote));
                relay::ACCEPTED
            }
            Self::AcceptRefused { listener, code, remote } => {
                put_u32(out, *listener);
                put_u16(out, code.0);
                put_address(out, Some(*remote));
                relay::ACCEPT_REFUSED
            }
            Self::Closed { socket, code } => {
                put_u32(out, *socket);
                put_u16(out, code.0);
                relay::CLOSED
            }
            Self::Draining => relay::DRAINING,
            Self::Bye { code, reason } => {
                put_u32(out, *code);
                out.extend_from_slice(reason.as_bytes());
                relay::BYE
            }
            Self::Unknown { kind } => *kind,
        };
        seal(out, at, kind);
    }

    /// Reads one packet off the front of `buf`: the packet and how many bytes it took, or `None` until a whole frame
    /// is there.
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>, DecodeError> {
        let Some((kind, body, taken)) = split(buf, MAX_RELAY_FRAME_BYTES)? else {
            return Ok(None);
        };
        let mut r = Reader(body);
        let packet = match kind {
            relay::HELLO => Self::Hello(Hello::read(&mut r)?),
            relay::OK => Self::Ok { id: r.u32()? },
            relay::ERROR => Self::Error {
                id: r.u32()?,
                code: ErrorCode(r.u16()?),
                message: String::from_utf8_lossy(r.rest()).into_owned(),
            },
            relay::SOCKET => Self::Socket {
                id: r.u32()?,
                socket: r.u32()?,
                local: r.address()?,
                remote: r.optional_address()?,
            },
            relay::DNS_ANSWER => Self::DnsAnswer { id: r.u32()?, answer: r.rest().to_vec() },
            relay::IP_TUNNEL => Self::IpTunnel {
                id: r.u32()?,
                socket: r.u32()?,
                mtu: r.u16()?,
                ipv4: Some(Ipv4Addr::from(r.array::<4>()?)).filter(|ip| !ip.is_unspecified()),
                ipv6: Some(Ipv6Addr::from(r.array::<16>()?)).filter(|ip| !ip.is_unspecified()),
                public_ipv4: Some(Ipv4Addr::from(r.array::<4>()?)).filter(|ip| !ip.is_unspecified()),
                public_ipv6: Some(Ipv6Addr::from(r.array::<16>()?)).filter(|ip| !ip.is_unspecified()),
                first_port: r.u16()?,
                ports: r.u16()?,
            },
            relay::ACCEPTED => Self::Accepted {
                listener: r.u32()?,
                socket: r.u32()?,
                local: r.address()?,
                remote: r.address()?,
            },
            relay::ACCEPT_REFUSED => {
                Self::AcceptRefused { listener: r.u32()?, code: ErrorCode(r.u16()?), remote: r.address()? }
            }
            relay::CLOSED => Self::Closed { socket: r.u32()?, code: ErrorCode(r.u16()?) },
            relay::DRAINING => Self::Draining,
            relay::BYE => Self::Bye { code: r.u32()?, reason: String::from_utf8_lossy(r.rest()).into_owned() },
            kind => Self::Unknown { kind },
        };
        Ok(Some((packet, taken)))
    }
}

fn open(out: &mut Vec<u8>) -> usize {
    let at = out.len();
    out.extend_from_slice(&[0; HEADER_BYTES]);
    at
}

fn seal(out: &mut [u8], at: usize, kind: u8) {
    let length = (out.len() - at - HEADER_BYTES) as u32;
    out[at] = kind;
    out[at + 1..at + HEADER_BYTES].copy_from_slice(&length.to_be_bytes());
}

fn on_socket(out: &mut Vec<u8>, id: u32, socket: u32, kind: u8) -> u8 {
    put_u32(out, id);
    put_u32(out, socket);
    kind
}

/// A frame's type, its body, and the bytes the whole frame took.
type Frame<'a> = (u8, &'a [u8], usize);

fn split(buf: &[u8], limit: usize) -> Result<Option<Frame<'_>>, DecodeError> {
    if buf.len() < HEADER_BYTES {
        return Ok(None);
    }
    let length = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if length > limit {
        return Err(DecodeError::TooLong);
    }
    let end = HEADER_BYTES + length;
    Ok((buf.len() >= end).then(|| (buf[0], &buf[HEADER_BYTES..end], end)))
}
