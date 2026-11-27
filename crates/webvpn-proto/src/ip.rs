//! The frame that carries one packet on an IP tunnel's stream: `[u16 length][packet]`.

/// The least `mtu` a tunnel carries: the 1280 bytes every IPv6 link carries.
pub const MIN_MTU: u16 = 1280;

const HEADER_BYTES: usize = 2;

/// Appends `packet` behind its length. A packet holds at most the tunnel's `mtu`, so its length fits the `u16`.
pub fn encode(packet: &[u8], out: &mut Vec<u8>) {
    let length = u16::try_from(packet.len()).expect("a packet fits a tunnel frame");
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(packet);
}

/// Reads one frame off the front of `buf`: the packet and how many bytes the frame took, or `None` until a whole
/// frame is there.
pub fn decode(buf: &[u8]) -> Option<(&[u8], usize)> {
    let length = usize::from(u16::from_be_bytes([*buf.first()?, *buf.get(1)?]));
    let end = HEADER_BYTES + length;
    Some((buf.get(HEADER_BYTES..end)?, end))
}
