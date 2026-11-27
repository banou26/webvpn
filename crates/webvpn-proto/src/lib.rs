//! The WebVPN wire protocol as `spec/protocol.md` lays it out: control frames, the UDP data packet, the frame of an
//! IP tunnel's stream and the WebSocket mux frame. No I/O and no dependencies: the caller owns the streams and hands
//! bytes in.

mod control;
mod error;
pub mod ip;
pub mod mux;
mod options;
mod udp;
mod wire;

pub use control::{
    features, ClientPacket, Hello, RelayPacket, MAGIC, MAX_AGENT_BYTES, MAX_CLIENT_FRAME_BYTES,
    MAX_RELAY_FRAME_BYTES, VERSION,
};
pub use error::{close, reset, DecodeError, ErrorCode};
pub use options::{TcpOption, UdpOption};
pub use udp::{UdpPacket, MAX_UDP_PAYLOAD_BYTES};
