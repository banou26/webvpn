use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::DecodeError;
use crate::wire::{put_u32, Reader};

/// A TCP socket option a client may set. `Unknown` holds the tag of an option this crate does not name, which a
/// relay answers with `UNSUPPORTED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOption {
    NoDelay(bool),
    Ttl(u32),
    /// `initial_delay_seconds` is the idle time before the first probe; 0 leaves the system's default.
    KeepAlive { enabled: bool, initial_delay_seconds: u32 },
    SendBufferSize(u32),
    RecvBufferSize(u32),
    Unknown(u8),
}

impl TcpOption {
    pub(crate) fn put(&self, out: &mut Vec<u8>) {
        match *self {
            Self::NoDelay(on) => out.extend_from_slice(&[0, on as u8]),
            Self::Ttl(ttl) => tagged_u32(out, 1, ttl),
            Self::KeepAlive { enabled, initial_delay_seconds } => {
                out.push(2);
                out.push(enabled as u8);
                put_u32(out, initial_delay_seconds);
            }
            Self::SendBufferSize(bytes) => tagged_u32(out, 3, bytes),
            Self::RecvBufferSize(bytes) => tagged_u32(out, 4, bytes),
            Self::Unknown(tag) => out.push(tag),
        }
    }

    pub(crate) fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(match r.u8()? {
            0 => Self::NoDelay(r.bool()?),
            1 => Self::Ttl(r.u32()?),
            2 => Self::KeepAlive { enabled: r.bool()?, initial_delay_seconds: r.u32()? },
            3 => Self::SendBufferSize(r.u32()?),
            4 => Self::RecvBufferSize(r.u32()?),
            tag => Self::Unknown(tag),
        })
    }
}

/// A UDP socket option a client may set. `Unknown` is as for [`TcpOption`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpOption {
    Broadcast(bool),
    Ttl(u32),
    MulticastTtlV4(u32),
    MulticastLoopV4(bool),
    MulticastLoopV6(bool),
    /// `interface` 0.0.0.0 lets the system pick.
    AddMembershipV4 { group: Ipv4Addr, interface: Ipv4Addr },
    DropMembershipV4 { group: Ipv4Addr, interface: Ipv4Addr },
    /// `interface` is an index; 0 is the default interface.
    AddMembershipV6 { group: Ipv6Addr, interface: u32 },
    DropMembershipV6 { group: Ipv6Addr, interface: u32 },
    SendBufferSize(u32),
    RecvBufferSize(u32),
    Unknown(u8),
}

impl UdpOption {
    pub(crate) fn put(&self, out: &mut Vec<u8>) {
        match *self {
            Self::Broadcast(on) => out.extend_from_slice(&[0, on as u8]),
            Self::Ttl(ttl) => tagged_u32(out, 1, ttl),
            Self::MulticastTtlV4(ttl) => tagged_u32(out, 2, ttl),
            Self::MulticastLoopV4(on) => out.extend_from_slice(&[3, on as u8]),
            Self::MulticastLoopV6(on) => out.extend_from_slice(&[4, on as u8]),
            Self::AddMembershipV4 { group, interface } => membership_v4(out, 5, group, interface),
            Self::DropMembershipV4 { group, interface } => membership_v4(out, 6, group, interface),
            Self::AddMembershipV6 { group, interface } => membership_v6(out, 7, group, interface),
            Self::DropMembershipV6 { group, interface } => membership_v6(out, 8, group, interface),
            Self::SendBufferSize(bytes) => tagged_u32(out, 9, bytes),
            Self::RecvBufferSize(bytes) => tagged_u32(out, 10, bytes),
            Self::Unknown(tag) => out.push(tag),
        }
    }

    pub(crate) fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(match r.u8()? {
            0 => Self::Broadcast(r.bool()?),
            1 => Self::Ttl(r.u32()?),
            2 => Self::MulticastTtlV4(r.u32()?),
            3 => Self::MulticastLoopV4(r.bool()?),
            4 => Self::MulticastLoopV6(r.bool()?),
            5 => Self::AddMembershipV4 { group: r.array::<4>()?.into(), interface: r.array::<4>()?.into() },
            6 => Self::DropMembershipV4 { group: r.array::<4>()?.into(), interface: r.array::<4>()?.into() },
            7 => Self::AddMembershipV6 { group: r.array::<16>()?.into(), interface: r.u32()? },
            8 => Self::DropMembershipV6 { group: r.array::<16>()?.into(), interface: r.u32()? },
            9 => Self::SendBufferSize(r.u32()?),
            10 => Self::RecvBufferSize(r.u32()?),
            tag => Self::Unknown(tag),
        })
    }
}

fn tagged_u32(out: &mut Vec<u8>, tag: u8, value: u32) {
    out.push(tag);
    put_u32(out, value);
}

fn membership_v4(out: &mut Vec<u8>, tag: u8, group: Ipv4Addr, interface: Ipv4Addr) {
    out.push(tag);
    out.extend_from_slice(&group.octets());
    out.extend_from_slice(&interface.octets());
}

fn membership_v6(out: &mut Vec<u8>, tag: u8, group: Ipv6Addr, interface: u32) {
    out.push(tag);
    out.extend_from_slice(&group.octets());
    put_u32(out, interface);
}
