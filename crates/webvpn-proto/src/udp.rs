use std::net::SocketAddr;

use crate::error::DecodeError;
use crate::wire::{put_address, put_u32, Reader};

/// The longest payload a [`UdpPacket`] carries.
pub const MAX_UDP_PAYLOAD_BYTES: usize = 64 * 1024;

/// One datagram of a UDP socket, the same on a stream, in a WebTransport datagram and in a mux `DATAGRAM` frame.
///
/// Toward the relay `remote` is where to send it, `None` on a connected socket. Toward the client it is where the
/// datagram came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPacket<'a> {
    pub socket: u32,
    pub remote: Option<SocketAddr>,
    pub data: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_u32(out, self.socket);
        put_address(out, self.remote);
        put_u32(out, self.data.len() as u32);
        out.extend_from_slice(self.data);
    }

    /// The packet behind the `u32` length a stream carries it with.
    pub fn encode_framed(&self, out: &mut Vec<u8>) {
        let at = out.len();
        out.extend_from_slice(&[0; 4]);
        self.encode(out);
        let length = (out.len() - at - 4) as u32;
        out[at..at + 4].copy_from_slice(&length.to_be_bytes());
    }

    /// Reads `buf` as one whole packet. The payload borrows from `buf`.
    pub fn decode(buf: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader(buf);
        let socket = r.u32()?;
        let remote = r.optional_address()?;
        let length = r.u32()? as usize;
        if length > MAX_UDP_PAYLOAD_BYTES {
            return Err(DecodeError::TooLong);
        }
        Ok(Self { socket, remote, data: r.take(length)? })
    }
}
