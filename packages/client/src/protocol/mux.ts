/** The control stream of the WebSocket mux. It is never opened and never credited. */
export const CONTROL_STREAM = 0

const HEADER_BYTES = 5
const EMPTY = new Uint8Array(0)

/** The kinds of the frame that carries a session's streams over one WebSocket: `[u8 kind][u32 stream][payload]`. */
export const MuxKind = {
  /** Relay only: a new stream, with one `MuxStreamType` byte. */
  OPEN: 0,
  DATA: 1,
  /** This side of the stream is finished. */
  FIN: 2,
  /** Empty, or the `u32` code a stream reset carries. */
  RESET: 3,
  /** Client only: one `UdpPacket`. */
  DATAGRAM: 4,
  /** Client only: a `u32` of further bytes the relay may send on the stream. */
  CREDIT: 5,
} as const

/** What an `OPEN` frame says the stream carries. */
export const MuxStreamType = {
  TCP: 0,
  /** A UDP socket's datagrams toward the client. */
  UDP_DOWNLOAD: 1,
} as const

export const encodeMuxFrame = (kind: number, stream: number, payload: Uint8Array = EMPTY) => {
  const frame = new Uint8Array(HEADER_BYTES + payload.byteLength)
  frame[0] = kind
  new DataView(frame.buffer).setUint32(1, stream)
  frame.set(payload, HEADER_BYTES)
  return frame
}

/**
 * The kind, stream and payload of one WebSocket message, or `undefined` for a message too short to be a frame, which
 * a receiver ignores. `payload` is a view into `message`, not a copy.
 */
export const decodeMuxFrame = (message: Uint8Array) => {
  if (message.byteLength < HEADER_BYTES) return undefined
  const stream = new DataView(message.buffer, message.byteOffset, message.byteLength).getUint32(1)
  return { kind: message[0]!, stream, payload: message.subarray(HEADER_BYTES) }
}
