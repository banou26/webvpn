use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use webvpn_proto::ErrorCode;

use crate::{state_number, Buffers, Config, Protocol, Result, Sent, Stack};

const BUFFER_BYTES: usize = 65536 + 64;

thread_local! {
    static STACK: RefCell<Option<Stack>> = const { RefCell::new(None) };
    static BUFFER: RefCell<Vec<u8>> = RefCell::new(vec![0; BUFFER_BYTES]);
}

fn with<R>(none: R, f: impl FnOnce(&mut Stack, &mut [u8]) -> R) -> R {
    STACK.with_borrow_mut(|stack| match stack {
        Some(stack) => BUFFER.with_borrow_mut(|buffer| f(stack, buffer)),
        None => none,
    })
}

fn code(error: ErrorCode) -> i32 {
    -i32::from(error.0)
}

fn opened(result: Result<u32>) -> i32 {
    result.map_or_else(code, |id| id as i32)
}

fn done(result: Result<()>) -> i32 {
    result.map_or_else(code, |()| 0)
}

fn buffers(receive: u32, send: u32) -> Buffers {
    Buffers { receive: receive as usize, send: send as usize }
}

fn read_address(bytes: &[u8]) -> Option<(SocketAddr, usize)> {
    let (ip, length): (IpAddr, usize) = match bytes.first()? {
        0 => (Ipv4Addr::from(<[u8; 4]>::try_from(bytes.get(1..5)?).ok()?).into(), 5),
        1 => (Ipv6Addr::from(<[u8; 16]>::try_from(bytes.get(1..17)?).ok()?).into(), 17),
        _ => return None,
    };
    let port = bytes.get(length..length + 2)?;
    Some((SocketAddr::new(ip, u16::from_be_bytes([port[0], port[1]])), length + 2))
}

fn write_address(out: &mut [u8], address: SocketAddr) -> usize {
    let length = match address.ip() {
        IpAddr::V4(ip) => {
            out[0] = 0;
            out[1..5].copy_from_slice(&ip.octets());
            5
        }
        IpAddr::V6(ip) => {
            out[0] = 1;
            out[1..17].copy_from_slice(&ip.octets());
            17
        }
    };
    out[length..length + 2].copy_from_slice(&address.port().to_be_bytes());
    length + 2
}

#[no_mangle]
pub extern "C" fn stack_buffer() -> *mut u8 {
    BUFFER.with_borrow_mut(|buffer| buffer.as_mut_ptr())
}

#[no_mangle]
pub extern "C" fn stack_open(mtu: u32, first_port: u32, ports: u32, connect_timeout_ms: u32, now: f64) {
    let config = BUFFER.with_borrow(|buffer| {
        let ipv4 = Ipv4Addr::from(<[u8; 4]>::try_from(&buffer[..4]).unwrap());
        let ipv6 = Ipv6Addr::from(<[u8; 16]>::try_from(&buffer[4..20]).unwrap());
        Config {
            ipv4: Some(ipv4).filter(|ip| !ip.is_unspecified()),
            ipv6: Some(ipv6).filter(|ip| !ip.is_unspecified()),
            mtu: mtu as usize,
            first_port: first_port as u16,
            ports: ports as u16,
            seed: u64::from_be_bytes(buffer[20..28].try_into().unwrap()),
            connect_timeout_ms,
        }
    });
    STACK.set(Some(Stack::new(config, now as i64)));
}

#[no_mangle]
pub extern "C" fn stack_input(length: u32) {
    with((), |stack, buffer| stack.input(&buffer[..(length as usize).min(BUFFER_BYTES)]));
}

#[no_mangle]
pub extern "C" fn stack_poll(now: f64) -> f64 {
    with(-1.0, |stack, _| stack.poll(now as i64).map_or(-1.0, |delay| delay as f64))
}

#[no_mangle]
pub extern "C" fn stack_output() -> u32 {
    with(0, |stack, buffer| match stack.output() {
        Some(packet) if packet.len() <= buffer.len() => {
            buffer[..packet.len()].copy_from_slice(&packet);
            packet.len() as u32
        }
        _ => 0,
    })
}

#[no_mangle]
pub extern "C" fn stack_events() -> u32 {
    with(0, |stack, buffer| {
        let events = stack.events(buffer.len() / 4);
        for (at, id) in events.iter().enumerate() {
            buffer[at * 4..at * 4 + 4].copy_from_slice(&id.to_be_bytes());
        }
        events.len() as u32
    })
}

#[no_mangle]
pub extern "C" fn stack_public_port(protocol: u32) -> u32 {
    let protocol = if protocol == 0 { Protocol::Tcp } else { Protocol::Udp };
    with(0, |stack, _| stack.public_port(protocol).map_or(0, u32::from))
}

#[no_mangle]
pub extern "C" fn stack_release(id: u32) {
    with((), |stack, _| stack.release(id));
}

#[no_mangle]
pub extern "C" fn tcp_connect(receive: u32, send: u32) -> i32 {
    with(code(ErrorCode::OTHER), |stack, buffer| {
        let Some((remote, _)) = read_address(buffer) else { return code(ErrorCode::OTHER) };
        opened(stack.tcp_connect(remote, buffers(receive, send)))
    })
}

#[no_mangle]
pub extern "C" fn tcp_listen(port: u32, backlog: u32, receive: u32, send: u32) -> i32 {
    with(code(ErrorCode::OTHER), |stack, _| {
        opened(stack.tcp_listen(port as u16, backlog as usize, buffers(receive, send)))
    })
}

#[no_mangle]
pub extern "C" fn tcp_accept(listener: u32) -> u32 {
    with(0, |stack, _| stack.tcp_accept(listener).unwrap_or(0))
}

#[no_mangle]
pub extern "C" fn tcp_state(id: u32) -> i32 {
    with(-1, |stack, _| stack.tcp_state(id).map_or(-1, |state| i32::from(state_number(state))))
}

#[no_mangle]
pub extern "C" fn tcp_error(id: u32) -> u32 {
    with(0, |stack, _| stack.tcp_error(id).map_or(0, |error| u32::from(error.0)))
}

#[no_mangle]
pub extern "C" fn tcp_endpoints(id: u32) -> u32 {
    with(0, |stack, buffer| {
        let Some((local, remote)) = stack.tcp_endpoints(id) else { return 0 };
        let length = write_address(buffer, local);
        (length + write_address(&mut buffer[length..], remote)) as u32
    })
}

#[no_mangle]
pub extern "C" fn tcp_send(id: u32, length: u32) -> i32 {
    with(code(ErrorCode::OTHER), |stack, buffer| {
        let data = &buffer[..(length as usize).min(BUFFER_BYTES)];
        stack.tcp_send(id, data).map_or_else(code, |taken| taken as i32)
    })
}

#[no_mangle]
pub extern "C" fn tcp_recv(id: u32, max: u32) -> i32 {
    with(-1, |stack, buffer| {
        let out = &mut buffer[..(max as usize).min(BUFFER_BYTES)];
        stack.tcp_recv(id, out).map_or(-1, |length| length as i32)
    })
}

#[no_mangle]
pub extern "C" fn tcp_close(id: u32) {
    with((), |stack, _| stack.tcp_close(id));
}

#[no_mangle]
pub extern "C" fn tcp_abort(id: u32) {
    with((), |stack, _| stack.tcp_abort(id));
}

#[no_mangle]
pub extern "C" fn tcp_option(id: u32, option: u32, value: u32) -> i32 {
    with(code(ErrorCode::OTHER), |stack, _| {
        done(match option {
            0 => stack.tcp_set_no_delay(id, value != 0),
            1 => stack.tcp_set_ttl(id, value),
            2 => stack.tcp_set_keep_alive(id, Some(value)),
            3 => stack.tcp_set_keep_alive(id, None),
            _ => Err(ErrorCode::UNSUPPORTED),
        })
    })
}

#[no_mangle]
pub extern "C" fn udp_bind(port: u32, receive: u32, send: u32) -> i32 {
    with(code(ErrorCode::OTHER), |stack, _| opened(stack.udp_bind(port as u16, buffers(receive, send))))
}

#[no_mangle]
pub extern "C" fn udp_port(id: u32) -> u32 {
    with(0, |stack, _| stack.udp_port(id).map_or(0, u32::from))
}

#[no_mangle]
pub extern "C" fn udp_send(id: u32, length: u32) -> i32 {
    with(code(ErrorCode::OTHER), |stack, buffer| {
        let Some((remote, at)) = read_address(buffer) else { return code(ErrorCode::OTHER) };
        let Some(data) = buffer.get(at..at + length as usize) else { return code(ErrorCode::OTHER) };
        match stack.udp_send(id, remote, data) {
            Ok(Sent::Queued) => 1,
            Ok(Sent::Dropped) => 0,
            Err(error) => code(error),
        }
    })
}

#[no_mangle]
pub extern "C" fn udp_recv(id: u32) -> i32 {
    with(-1, |stack, buffer| {
        let (head, payload) = buffer.split_at_mut(19);
        let Some((length, remote)) = stack.udp_recv(id, payload) else { return -1 };
        let at = write_address(head, remote);
        buffer.copy_within(19..19 + length, at);
        length as i32
    })
}

#[no_mangle]
pub extern "C" fn udp_ttl(id: u32, ttl: u32) -> i32 {
    with(code(ErrorCode::OTHER), |stack, _| done(stack.udp_set_ttl(id, ttl)))
}
