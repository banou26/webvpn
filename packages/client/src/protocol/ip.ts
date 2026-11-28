const HEADER_BYTES = 2

/** The least `mtu` a tunnel carries, the 1280 bytes every IPv6 link carries, as `webvpn_proto::ip::MIN_MTU`. */
export const MIN_MTU = 1280

/** One packet behind the `u16` length an IP tunnel's stream carries it with. */
export const encodeIpFrame = (packet: Uint8Array) => {
  if (packet.byteLength > 0xffff) throw new TypeError(`a tunnel frame holds at most 65535 bytes, not ${packet.byteLength}`)
  const frame = new Uint8Array(HEADER_BYTES + packet.byteLength)
  new DataView(frame.buffer).setUint16(0, packet.byteLength)
  frame.set(packet, HEADER_BYTES)
  return frame
}

/**
 * Reads one frame off the front of `bytes`: the packet and how many bytes the frame took, or `undefined` until a whole
 * frame is there. `packet` is a view into `bytes`, not a copy.
 */
export const decodeIpFrame = (bytes: Uint8Array) => {
  if (bytes.byteLength < HEADER_BYTES) return undefined
  const taken = HEADER_BYTES + new DataView(bytes.buffer, bytes.byteOffset, HEADER_BYTES).getUint16(0)
  if (bytes.byteLength < taken) return undefined
  return { packet: bytes.subarray(HEADER_BYTES, taken), taken }
}
