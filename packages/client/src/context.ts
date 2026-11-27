import type { Address, ClientPacket, RelayPacket, UdpPacket } from './protocol'

import { CloseCode, ErrorCode } from './protocol'

/**
 * A request the relay refused, or one the client refused on its own: a feature the relay has off, no answer in
 * time, a session that is closed. `code` is an `ErrorCode`; a code this package does not name is kept as the relay
 * sent it and means `OTHER`. `message` is the relay's text for a person, or the client's. `closeCode` is the
 * session's `CloseCode` when the session's end is why it failed, as for a `connect` that a full relay refused with
 * `SESSION_LIMIT`, and absent otherwise.
 */
export class WebVpnError extends Error {
  readonly code: number
  readonly closeCode?: number

  constructor(code: number, message: string, closeCode?: number) {
    super(message)
    this.name = 'WebVpnError'
    this.code = code
    this.closeCode = closeCode
  }
}

/** A stream both ways, as a carrier hands it over. */
export type Duplex = { readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array> }

/** How a session ended: a `CloseCode` and a reason for a person. */
export type CloseInfo = { code: number, reason: string }

/** The error of whatever a session's end made fail, with the session's `CloseCode` as its `closeCode`. */
export const closeError = ({ code, reason }: CloseInfo) => new WebVpnError(
  code === CloseCode.SESSION_LIMIT ? ErrorCode.CAPACITY
  : code === CloseCode.VERSION_MISMATCH ? ErrorCode.UNSUPPORTED
  : ErrorCode.OTHER,
  `the session closed: ${reason}`,
  code,
)

/**
 * Who closed a listener, a UDP socket or an IP tunnel: the client with its `close()`, the relay with a `Closed` notice
 * and its `ErrorCode`, or the end of the session.
 */
export type ClosedBy = { by: 'client' } | { by: 'relay', code: number } | { by: 'session' }

/**
 * What a session needs of its carrier, WebTransport or the WebSocket mux. The relay opens every stream, and the
 * client opens only what `openUni` gives.
 */
export type Carrier = {
  kind: 'webtransport' | 'websocket',
  /** The streams the relay opens both ways, in order. The first is the control stream. */
  incoming: ReadableStream<Duplex>,
  /** The streams the relay opens toward the client only. */
  incomingUni: ReadableStream<ReadableStream<Uint8Array>>,
  /** One `UdpPacket` in each datagram from the relay, on a carrier that has datagrams. */
  datagrams?: ReadableStream<Uint8Array>,
  /** Sends one `UdpPacket` outside any stream, or drops it when the carrier holds too much unsent. */
  sendDatagram: (packet: Uint8Array) => void,
  /** Opens a stream toward the relay only, on a carrier that has such streams. */
  openUni?: () => Promise<WritableStream<Uint8Array>>,
  /**
   * Resolves once, with the first of the close this side asked for and the end the relay or the network caused. An
   * end that carried no session close code reads as `LOST`. Never rejects.
   */
  closed: Promise<CloseInfo>,
  /** Closes the carrier with a `CloseCode`, and does nothing once it ended. */
  close: (code: number, reason: string) => void,
}

/**
 * A socket's stream once its id was read: the bytes that came after the id in the same read, the reader of the
 * rest, and the client's side, which a stream toward the client only has not.
 */
export type SocketStream = {
  head: Uint8Array,
  reader: ReadableStreamDefaultReader<Uint8Array>,
  writable?: WritableStream<Uint8Array>,
}

/** A request as a socket hands it to its session, which gives it its id. */
export type Request = ClientPacket extends infer Packet
  ? Packet extends { id: number } ? Omit<Packet, 'id'> : never
  : never

/** The kind of socket a request opens, so that the socket a late reply names can be closed. */
export type Opens = 'tcp' | 'listener' | 'udp' | 'ip'

/** A socket the relay opened, as a `socket` or an `accepted` packet names it. */
export type Opened = { socket: number, local: Address, remote?: Address }

/** What a listener, a UDP socket or an IP tunnel hears from its session. */
export type Owner = {
  /** A notice that names the socket: `closed`, and for a listener `accepted` and `acceptRefused`. */
  notice: (packet: RelayPacket) => void,
  /** A UDP packet the relay sent outside the socket's stream. */
  packet?: (packet: UdpPacket) => void,
  /** The session ended. */
  end: () => void,
}

/** What a socket asks of its session. */
export type Context = {
  carrier: Carrier,
  /**
   * Sends `packet` under a fresh id. Its reply goes to `take` as it is read, ahead of the next frame, and the promise
   * resolves with what `take` returns. An `error` reply rejects with a `WebVpnError`.
   */
  request: <T>(packet: Request, take: (reply: RelayPacket) => T, options?: { timeoutMs?: number, opens?: Opens }) => Promise<T>,
  /** The stream of `socket`, held since it arrived or awaited, for at most `timeoutMs` when it is given. */
  claim: (socket: number, timeoutMs?: number) => Promise<SocketStream>,
  /** Forgets a socket that ended, so that a stream that arrives for it later is dropped. */
  retire: (socket: number) => void,
  /** Retires a socket nobody will use, and closes it at the relay. */
  release: (opens: Opens, socket: number) => void,
  /** Hands the notices and UDP packets of `socket` to `owner`, until the call it returns. */
  own: (socket: number, owner: Owner) => () => void,
  /** Why the session ended, once it did. */
  ended: () => WebVpnError | undefined,
  /** The bytes of UDP packets the session holds unread, across its sockets. */
  unread: { bytes: number },
}

export const EMPTY: Uint8Array = new Uint8Array(0)

export const noop = () => {}

export const concat = (first: Uint8Array, second: Uint8Array) => {
  if (!first.byteLength) return second
  const both = new Uint8Array(first.byteLength + second.byteLength)
  both.set(first)
  both.set(second, first.byteLength)
  return both
}

export const u32 = (value: number) => {
  const bytes = new Uint8Array(4)
  new DataView(bytes.buffer).setUint32(0, value)
  return bytes
}

export const readU32 = (bytes: Uint8Array) => new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0)

/** The code a stream's reset carried, as WebTransport and the mux both report it. */
export const streamErrorCode = (error: unknown) => (error as { streamErrorCode?: unknown } | undefined)?.streamErrorCode

/** Rejects with a `WebVpnError` of `code` when `promise` takes longer than `ms`. */
export const within = <T>(promise: Promise<T>, ms: number, code: number, message: string) => {
  let timer: ReturnType<typeof setTimeout> | undefined
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new WebVpnError(code, message)), ms)
  })
  return Promise.race([promise, late]).finally(() => clearTimeout(timer))
}

export const unexpected = (reply: RelayPacket) => new WebVpnError(ErrorCode.OTHER, `the relay answered with ${reply.type}`)

export const ok = (reply: RelayPacket) => {
  if (reply.type !== 'ok') throw unexpected(reply)
}

/**
 * Cuts a byte stream into frames. Each call takes the next chunk and returns the frames it completed, in order;
 * `decode` returns `undefined` until the bytes hold a whole frame, so a frame split at any byte, in any number of
 * chunks, comes out exactly once.
 */
export const framed = <T extends { taken: number }>(decode: (bytes: Uint8Array) => T | undefined) => {
  let held = EMPTY
  return (chunk: Uint8Array) => {
    let bytes = concat(held, chunk)
    const frames: T[] = []
    for (let frame = decode(bytes); frame; frame = decode(bytes)) {
      frames.push(frame)
      bytes = bytes.subarray(frame.taken)
    }
    // copied when it is still a view of the chunk, which a reader may fill again with the next one
    held = bytes.byteLength && bytes.buffer === chunk.buffer ? bytes.slice() : bytes
    return frames
  }
}
