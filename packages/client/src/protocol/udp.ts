import type { Address } from './wire'

import { addressFamily, ProtocolError, reader } from './wire'

/** The longest payload a `UdpPacket` carries. */
export const MAX_UDP_PAYLOAD_BYTES = 64 * 1024

/**
 * One datagram of a UDP socket, the same on a stream, in a WebTransport datagram and in a mux `DATAGRAM` frame.
 *
 * Toward the relay `remote` is where to send it, absent on a connected socket. Toward the client it is where the
 * datagram came from.
 */
export type UdpPacket = { socket: number, remote?: Address, data: Uint8Array }

const size = (packet: UdpPacket) =>
  4 + (packet.remote ? 1 + packet.remote.ip.byteLength + 2 : 1) + 4 + packet.data.byteLength

const put = (packet: UdpPacket, out: Uint8Array, from: number) => {
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength)
  let at = from
  view.setUint32(at, packet.socket)
  at += 4
  if (packet.remote) {
    const { ip, port } = packet.remote
    out[at] = addressFamily(ip)
    out.set(ip, at + 1)
    view.setUint16(at + 1 + ip.byteLength, port)
    at += 1 + ip.byteLength + 2
  } else {
    out[at] = 2
    at += 1
  }
  view.setUint32(at, packet.data.byteLength)
  out.set(packet.data, at + 4)
  return out
}

export const encodeUdpPacket = (packet: UdpPacket) => put(packet, new Uint8Array(size(packet)), 0)

/** The packet behind the `u32` length a stream carries it with. */
export const encodeFramedUdpPacket = (packet: UdpPacket) => {
  const length = size(packet)
  const out = new Uint8Array(4 + length)
  new DataView(out.buffer).setUint32(0, length)
  return put(packet, out, 4)
}

/** Reads `bytes` as one whole packet. `data` is a view into `bytes`, not a copy. */
export const decodeUdpPacket = (bytes: Uint8Array): UdpPacket => {
  const r = reader(bytes)
  const socket = r.u32()
  const remote = r.optionalAddress()
  const length = r.u32()
  if (length > MAX_UDP_PAYLOAD_BYTES) throw new ProtocolError('a length is over the limit')
  return { socket, remote, data: r.take(length) }
}
