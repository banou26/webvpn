import type { Context, Opened, SocketStream } from './context'
import type { Address, UdpOption, UdpPacket } from './protocol'

import { framed, noop, ok, readU32, u32, WebVpnError } from './context'
import {
  decodeUdpPacket,
  encodeFramedUdpPacket,
  encodeUdpPacket,
  ErrorCode,
  MAX_UDP_PAYLOAD_BYTES,
  ProtocolError,
} from './protocol'

// what a socket and the whole session may hold of packets nobody read yet; a packet past either is dropped, so a
// slow reader of one socket holds back nothing else. Each packet counts at least this many bytes.
const SOCKET_UNREAD_BYTES = 4 * 1024 * 1024
const SESSION_UNREAD_BYTES = 32 * 1024 * 1024
const PACKET_COST_BYTES = 256

// a WebTransport stream's writable counts its queue in chunks, not bytes, so the bytes written and not yet taken are
// counted here, and a packet past them is dropped as a busy network would
const UPLINK_QUEUED_BYTES = 256 * 1024

// the relay gives up opening the socket's stream after 5 seconds, so past 8 the stream is not coming
const UNI_FALLBACK_MS = 8000

// a socket id, an IPv6 address with its port, the length, and the payload
const MAX_FRAME_BYTES = 4 + 19 + 4 + MAX_UDP_PAYLOAD_BYTES

/** A datagram the socket received, and where from. */
export type UdpDatagram = { remote: Address, data: Uint8Array }

/**
 * A UDP socket on the relay, from `Session.udpBind`.
 *
 * `readable` gives each datagram the relay received for the socket. Datagrams wait for the reader up to 4 MiB for
 * the socket and 32 MiB for the session, and past that are dropped. `writable` sends a datagram to `remote`, or to
 * the connected peer when `remote` is absent; it never waits, and drops a datagram the carrier cannot take now or one
 * over 65536 bytes, as a network would. `closed` resolves with the code of the relay's `Closed` notice when the relay
 * ended the socket on its own, and `undefined` when the client closed it or the session ended; `readable` ends then.
 * Cancelling `readable` closes the socket.
 */
export type UdpSocket = {
  /** The socket's id in its session. */
  id: number,
  /** The bound address, with the port the relay took for port 0. */
  local: Address,
  readable: ReadableStream<UdpDatagram>,
  writable: WritableStream<{ remote?: Address, data: Uint8Array }>,
  /** Fixes the peer: datagrams then go to it, and only its datagrams arrive. */
  connect: (remote: Address) => Promise<void>,
  disconnect: () => Promise<void>,
  setOption: (option: UdpOption) => Promise<void>,
  closed: Promise<number | undefined>,
  close: () => Promise<void>,
}

const decodeFramed = (bytes: Uint8Array) => {
  if (bytes.byteLength < 4) return undefined
  const length = readU32(bytes)
  if (length > MAX_FRAME_BYTES) throw new ProtocolError('a length is over the limit')
  if (bytes.byteLength < 4 + length) return undefined
  let packet: UdpPacket | undefined
  try {
    packet = decodeUdpPacket(bytes.subarray(4, 4 + length))
  } catch {
    // a packet that cannot be read is dropped alone
  }
  return { packet, taken: 4 + length }
}

export const udpSocket = (context: Context, { socket, local }: Opened): UdpSocket => {
  let done = false
  let closing: Promise<void> | undefined
  let finish!: (code?: number) => void
  const closed = new Promise<number | undefined>((resolve) => { finish = resolve })
  const queue: UdpDatagram[] = []
  let unread = 0
  let wake: (() => void) | undefined
  let uplink: WritableStreamDefaultWriter<Uint8Array> | undefined
  let uplinkBytes = 0

  const deliver = ({ remote, data }: UdpPacket) => {
    const cost = PACKET_COST_BYTES + data.byteLength
    if (done || !remote || unread + cost > SOCKET_UNREAD_BYTES) return
    if (context.unread.bytes + cost > SESSION_UNREAD_BYTES) return
    queue.push({ remote, data: data.slice() })
    unread += cost
    context.unread.bytes += cost
    wake?.()
  }

  const drop = () => {
    context.unread.bytes -= unread
    unread = 0
    queue.length = 0
  }

  const close = () => closing ??= (async () => {
    if (done) return
    try {
      await context.request({ type: 'udpClose', socket }, ok)
    } catch (error) {
      if (!context.ended()) throw error
    } finally {
      stop()
    }
  })()

  const readable = new ReadableStream<UdpDatagram>({
    pull: async (controller) => {
      while (!queue.length) {
        if (done) return controller.close()
        await new Promise<void>((resolve) => { wake = resolve })
      }
      const datagram = queue.shift()!
      const cost = PACKET_COST_BYTES + datagram.data.byteLength
      unread -= cost
      context.unread.bytes -= cost
      controller.enqueue(datagram)
    },
    cancel: () => close().catch(noop),
  }, { highWaterMark: 0 })

  // read at once and whole, never paced by the reader, so the relay's stream never waits on it
  const readStream = async ({ head, reader }: SocketStream) => {
    const take = framed(decodeFramed)
    try {
      for (let chunk = head; ;) {
        for (const { packet } of take(chunk)) if (packet) deliver(packet)
        const { value, done: ended } = await reader.read()
        if (ended) return
        chunk = value
      }
    } catch {
      reader.cancel().catch(noop)
    }
  }

  const useUplink = (writable: WritableStream<Uint8Array>) => {
    const writer = writable.getWriter()
    if (done || uplink) return writer.close().catch(noop)
    uplink = writer
    writer.write(u32(socket)).catch(noop)
  }

  // over WebTransport the relay opens one stream both ways for the socket after its reply; over the mux one toward
  // the client only, before the reply
  context.claim(socket).then((stream) => {
    readStream(stream)
    if (stream.writable) useUplink(stream.writable)
  }, noop)
  const { openUni } = context.carrier
  const fallback = openUni && setTimeout(() => {
    if (!done && !uplink) openUni().then(useUplink, noop)
  }, UNI_FALLBACK_MS)

  const send = ({ remote, data }: { remote?: Address, data: Uint8Array }) => {
    if (data.byteLength > MAX_UDP_PAYLOAD_BYTES) return
    const packet = { socket, remote, data }
    const writer = uplink
    if (!writer) return context.carrier.sendDatagram(encodeUdpPacket(packet))
    const frame = encodeFramedUdpPacket(packet)
    if (uplinkBytes + frame.byteLength > UPLINK_QUEUED_BYTES) return
    uplinkBytes += frame.byteLength
    writer.write(frame)
      .catch(() => {
        if (uplink === writer) uplink = undefined
      })
      .finally(() => { uplinkBytes -= frame.byteLength })
  }

  const writable = new WritableStream<{ remote?: Address, data: Uint8Array }>({
    write: (datagram) => {
      if (done) throw context.ended() ?? new WebVpnError(ErrorCode.OTHER, 'the socket is closed')
      send(datagram)
    },
  })

  const stop = (code?: number) => {
    if (done) return
    done = true
    unown()
    clearTimeout(fallback)
    context.retire(socket)
    drop()
    wake?.()
    uplink?.close().catch(noop)
    finish(code)
  }

  const unown = context.own(socket, {
    notice: (packet) => {
      if (packet.type === 'closed') stop(packet.code)
    },
    packet: deliver,
    end: () => stop(),
  })

  return {
    id: socket,
    local,
    readable,
    writable,
    connect: (remote) => context.request({ type: 'udpConnect', socket, remote }, ok),
    disconnect: () => context.request({ type: 'udpDisconnect', socket }, ok),
    setOption: (option) => context.request({ type: 'udpSetOption', socket, option }, ok),
    closed,
    close,
  }
}
