//! The frame that carries a session's streams over one WebSocket: `[u8 kind][u32 stream][payload]`.

/// The control stream. It is never opened and never credited.
pub const CONTROL_STREAM: u32 = 0;

const HEADER_BYTES: usize = 5;

/// Frame kinds.
pub mod kind {
    /// Relay only: a new stream, with one [`stream_type`](super::stream_type) byte.
    pub const OPEN: u8 = 0;
    pub const DATA: u8 = 1;
    /// This side of the stream is finished.
    pub const FIN: u8 = 2;
    /// Empty, or the `u32` code a stream reset carries.
    pub const RESET: u8 = 3;
    /// Client only: one `UdpPacket`.
    pub const DATAGRAM: u8 = 4;
    /// Client only: a `u32` of further bytes the relay may send on the stream.
    pub const CREDIT: u8 = 5;
}

/// What an `OPEN` frame says the stream carries.
pub mod stream_type {
    pub const TCP: u8 = 0;
    /// A UDP socket's datagrams toward the client.
    pub const UDP_DOWNLOAD: u8 = 1;
}

pub fn encode(kind: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len());
    frame.push(kind);
    frame.extend_from_slice(&stream.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// The kind, stream and payload of one WebSocket message, or `None` for a message too short to be a frame, which a
/// receiver ignores.
pub fn decode(message: &[u8]) -> Option<(u8, u32, &[u8])> {
    if message.len() < HEADER_BYTES {
        return None;
    }
    let stream = u32::from_be_bytes([message[1], message[2], message[3], message[4]]);
    Some((message[0], stream, &message[HEADER_BYTES..]))
}
