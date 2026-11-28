import type { ClosedBy, Context, SocketStream } from './context'
import type { RelayPacket } from './protocol'

import { formatIp } from './address'
import { framed, noop, ok, unexpected, WebVpnError } from './context'
import { decodeIpFrame, encodeIpFrame, ErrorCode, MIN_MTU } from './protocol'

// the relay holds as much toward the client (QUEUE_BYTES in its tunnel.rs): a link's short queue, about 44 packets of
// 1500 bytes, so that what flows through the tunnel learns of a slow path from loss within a few dozen milliseconds
const QUEUE_BYTES = 64 * 1024

const STREAM_MS = 30_000

/**
 * An IP tunnel through the relay, from `Session.ipOpen`: a link that carries whole IPv4 and IPv6 packets, with no
 * link header, for a program that brings its own network stack. The relay forwards what the client sends as a
 * router does and drops, saying nothing, a packet its checks refuse; the client does not look into a packet. A tunnel
 * has two ends and nothing between them, so there is no gateway address: a stack that wants one makes one up.
 *
 * `readable` gives the packets the relay sent, one whole packet per chunk, each a `Uint8Array` that owns its buffer,
 * so it can be transferred to a worker. The tunnel's stream is read only as `readable` is, so a reader that stops
 * makes the relay drop the newest packets, as a link would. Cancelling `readable` closes the tunnel. The tunnel stops
 * at its own `close()`, at the relay's `Closed` notice, or when the session ends: `readable` ends then, and `closed`
 * resolves with which of the three it was.
 */
export type IpTunnel = {
  /** The tunnel's id in its session. */
  id: number,
  /** The address the relay gave this end, as text, for a tunnel that carries IPv4. */
  ipv4?: string,
  /** The address the relay gave this end, as text, for a tunnel that carries IPv6. At least one of the two is set. */
  ipv6?: string,
  /** The largest packet the tunnel carries, at least 1280 bytes. */
  mtu: number,
  /**
   * The relay's public IPv4 address, as text, as others dial it to reach the tunnel's public ports. Absent when the
   * relay gave no public ports or none of this family.
   */
  publicIpv4?: string,
  /** The relay's public IPv6 address, as `publicIpv4` is the IPv4 one. */
  publicIpv6?: string,
  /** The first of the tunnel's public ports. Meaningless when `ports` is 0. */
  firstPort: number,
  /**
   * How many public ports the tunnel holds, from `firstPort` on: a TCP or UDP packet anyone sends to the public
   * address on one of them reaches this end's address on the same port. 0 when the relay gave none, and the tunnel
   * is then reached only by answers to what it sent.
   */
  ports: number,
  readable: ReadableStream<Uint8Array>,
  /**
   * Sends one packet and never waits. `false` when the packet was dropped: it is empty or longer than `mtu`, the
   * tunnel stopped, or the short queue toward the relay is full, as a busy link's would be. Over the WebSocket, that
   * queue also counts the bytes the session's other sockets have not sent yet, so a tunnel drops every packet while
   * one of them uploads.
   */
  send: (packet: Uint8Array) => boolean,
  /** Resolves once the tunnel stopped, with who stopped it. Never rejects. */
  closed: Promise<ClosedBy>,
  /** Stops the tunnel at once and closes it at the relay. Rejects with the relay's refusal while the session lasts. */
  close: () => Promise<void>,
}

/** The tunnel an `ipTunnel` reply names, once its stream arrived. */
export const ipTunnel = async (context: Context, reply: RelayPacket): Promise<IpTunnel> => {
  if (reply.type !== 'ipTunnel') throw unexpected(reply)
  const { socket, mtu } = reply
  if (mtu < MIN_MTU) {
    context.release('ip', socket)
    throw new WebVpnError(ErrorCode.OTHER, `the relay gave the tunnel an mtu of ${mtu}, under ${MIN_MTU}`)
  }
  let done = false
  let closing: Promise<void> | undefined
  let finish!: (by: ClosedBy) => void
  const closed = new Promise<ClosedBy>((resolve) => { finish = resolve })
  let shut: (() => void) | undefined
  let queued = 0

  const stop = (by: ClosedBy) => {
    if (done) return
    done = true
    unown()
    context.retire(socket)
    finish(by)
    shut?.()
  }

  // owned before the stream is awaited, so a `Closed` that comes first is not missed
  const unown = context.own(socket, {
    notice: (packet) => {
      if (packet.type === 'closed') stop({ by: 'relay', code: packet.code })
    },
    end: () => stop({ by: 'session' }),
  })

  let stream: SocketStream
  try {
    stream = await context.claim(socket, STREAM_MS)
  } catch (error) {
    if (!done) {
      done = true
      unown()
      context.release('ip', socket)
    }
    throw error
  }
  const { head, reader } = stream
  const writer = stream.writable!.getWriter()
  let controller!: ReadableStreamDefaultController<Uint8Array>

  const close = () => closing ??= (async () => {
    if (done) return
    const asked = context.request({ type: 'ipClose', socket }, ok)
    stop({ by: 'client' })
    try {
      await asked
    } catch (error) {
      if (!context.ended()) throw error
    }
  })()

  const take = framed(decodeIpFrame)
  const packets = take(head).map(({ packet }) => packet.slice())
  // pulled only as the reader reads, so the relay's queue fills and drops while nobody reads
  const readable = new ReadableStream<Uint8Array>({
    start: (started) => { controller = started },
    pull: async () => {
      while (!packets.length) {
        if (done) return
        let read: ReadableStreamReadResult<Uint8Array>
        try {
          read = await reader.read()
        } catch {
          read = { done: true, value: undefined }
        }
        if (done) return
        if (read.done) return controller.close()
        for (const { packet } of take(read.value)) packets.push(packet.slice())
      }
      controller.enqueue(packets.shift()!)
    },
    cancel: () => close().catch(noop),
  }, { highWaterMark: 0 })

  // the stream is read to its end once nobody will read it, as a TCP socket's is (see `stopReading` in tcp.ts)
  shut = () => {
    try {
      controller.close()
    } catch {}
    writer.close().catch(noop)
    void (async () => {
      try {
        while (!(await reader.read()).done) {}
      } catch {}
    })()
  }
  if (done) shut()

  const send = (packet: Uint8Array) => {
    if (done || !packet.byteLength || packet.byteLength > mtu) return false
    const frame = encodeIpFrame(packet)
    // a frame leaves `queued` once the carrier took it, and the WebSocket mux takes up to 1 MiB it did not send yet,
    // so that counts too. It holds what the session's other sockets send as well: while their uploads keep it past
    // 64 KiB, the tunnel drops every packet. Counting only the tunnel's own bytes there would take much more code,
    // and a page that sends only through the tunnel has no such uploads.
    if (queued + (context.carrier.buffered?.() ?? 0) + frame.byteLength > QUEUE_BYTES) return false
    queued += frame.byteLength
    writer.write(frame).catch(noop).finally(() => { queued -= frame.byteLength })
    return true
  }

  return {
    id: socket,
    ipv4: reply.ipv4 && formatIp(reply.ipv4),
    ipv6: reply.ipv6 && formatIp(reply.ipv6),
    mtu,
    publicIpv4: reply.publicIpv4 && formatIp(reply.publicIpv4),
    publicIpv6: reply.publicIpv6 && formatIp(reply.publicIpv6),
    firstPort: reply.firstPort,
    ports: reply.ports,
    readable,
    send,
    closed,
    close,
  }
}
