//! The client's end of a WebVPN IP tunnel: a TCP/IP stack, smoltcp on the IP medium, that `@webvpn/client` runs in
//! a page as WebAssembly so that TCP and UDP work over a tunnel that carries nothing but IP packets.
//!
//! [`Stack`] is the stack as a Rust type, which the tests drive. The WebAssembly module wraps one `Stack` per
//! instance, so a page makes one instance per tunnel, and exports plain functions over integers and one shared
//! buffer, with no binding generator:
//!
//! - `stack_buffer() -> ptr`: the shared buffer, 65600 bytes in the instance's memory. Every call that takes bytes
//!   reads them from its start, and every call that gives bytes writes them there. An address in it is laid out as
//!   the protocol's `Address`: a family byte (0 IPv4, 1 IPv6), the 4 or 16 address bytes, a big-endian `u16` port.
//! - `stack_open(mtu, first_port, ports, connect_timeout_ms, now)`: makes the stack. The buffer holds the tunnel's
//!   IPv4 address (4 bytes) and IPv6 address (16 bytes), all zero for a family it has not, then an 8-byte seed.
//! - `stack_input(length)`: one packet from the tunnel, in the buffer.
//! - `stack_poll(now) -> f64`: runs the stack at `now` milliseconds, on the page's clock, and returns how many
//!   milliseconds may pass before the next poll, or -1 for none until a packet or a call.
//! - `stack_output() -> length`: the next packet for the tunnel, in the buffer, or 0 when there is none.
//! - `stack_events() -> count`: the ids of the sockets that changed, as big-endian `u32`s in the buffer.
//! - `stack_public_port(protocol) -> port`: a free public port, 0 for none; protocol 0 is TCP and 1 is UDP.
//! - `stack_release(id)`: lets go of a socket or a listener, as [`Stack::release`] does.
//! - `tcp_connect(receive, send) -> id`, to the address in the buffer, with buffers of those sizes in bytes.
//! - `tcp_listen(port, backlog, receive, send) -> id` and `tcp_accept(listener) -> id`, 0 for none.
//! - `tcp_state(id)`, as [`state_number`] numbers it, and `tcp_error(id)`, an `ErrorCode` or 0.
//! - `tcp_endpoints(id) -> length`: the local address, then the remote one, in the buffer.
//! - `tcp_send(id, length) -> taken`, from the buffer; `tcp_recv(id, max) -> length`, into the buffer, -1 for the end.
//! - `tcp_close(id)`, `tcp_abort(id)` and `tcp_option(id, option, value)`: option 0 is no delay (0 or 1), 1 the TTL,
//!   2 keep-alive on, probing after that many idle seconds (0 for two hours), 3 keep-alive off.
//! - `udp_bind(port, receive, send) -> id` and `udp_port(id) -> port`.
//! - `udp_send(id, length) -> 1 sent, 0 dropped`: the buffer holds the peer's address, then `length` payload bytes.
//! - `udp_recv(id) -> length`, -1 for none: the buffer then holds where it came from, then the payload.
//! - `udp_ttl(id, ttl)`.
//!
//! A call that opens or sets something returns a negative `ErrorCode` when it fails. A call on an id the stack does
//! not know does nothing and answers as for a socket with nothing to give.

mod ffi;
mod stack;

pub use smoltcp::socket::tcp::State as TcpState;
pub use stack::{state_number, Buffers, Config, Protocol, Result, Sent, Stack};
