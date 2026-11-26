import type { Carrier, CloseInfo, Duplex } from '../src/context'
import type { Address, ClientPacket, Hello, RelayPacket, UdpPacket } from '../src/protocol'

import { concat, framed, u32 } from '../src/context'
import { decodeClientPacket, decodeUdpPacket, encodeRelayPacket, encodeUdpPacket, hello } from '../src/protocol'
import { openSession } from '../src/session'

/** Lets every callback already due run, timers at 0 included. */
export const settle = async () => {
  for (let turn = 0; turn < 20; turn++) await Promise.resolve()
}

export const v4 = (text: string, port: number): Address => ({ ip: Uint8Array.from(text.split('.'), Number), port })

/** The relay's end of one stream: what it writes, and what the client did with its own side. */
export type RelayStream = ReturnType<typeof relayStream>

const relayStream = () => {
  let down!: ReadableStreamDefaultController<Uint8Array>
  const seen = { cancelled: false, aborted: false, finished: false, received: [] as Uint8Array[] }
  let broken: unknown
  const readable = new ReadableStream<Uint8Array>({
    start: (controller) => { down = controller },
    cancel: () => { seen.cancelled = true },
  })
  const writable = new WritableStream<Uint8Array>({
    write: (chunk) => {
      if (broken) throw broken
      seen.received.push(chunk.slice())
    },
    close: () => { seen.finished = true },
    abort: () => { seen.aborted = true },
  })
  return {
    readable,
    writable,
    seen,
    write: (bytes: Uint8Array) => down.enqueue(bytes),
    finish: () => down.close(),
    reset: (code: number) => down.error(Object.assign(new Error('reset'), { streamErrorCode: code })),
    fail: (error: unknown) => down.error(error),
    /** Fails the client's writes from now on. */
    breakWrites: (error: unknown) => { broken = error },
    /** 1 once the client read all the relay wrote, 0 or less while it holds some unread. */
    desiredSize: () => down.desiredSize,
    received: () => seen.received.reduce(concat, new Uint8Array(0)),
  }
}

/**
 * A relay played over in-memory streams: it hands the session a `Carrier`, writes relay frames on the control stream
 * and reads the client's.
 */
export const fakeRelay = (kind: Carrier['kind'] = 'webtransport') => {
  let incoming!: ReadableStreamDefaultController<Duplex>
  let incomingUni!: ReadableStreamDefaultController<ReadableStream<Uint8Array>>
  let datagrams!: ReadableStreamDefaultController<Uint8Array>
  let settleClosed!: (info: CloseInfo) => void
  const closed = new Promise<CloseInfo>((resolve) => { settleClosed = resolve })
  const streams: RelayStream[] = []
  const sentDatagrams: UdpPacket[] = []
  const uplinks: RelayStream[] = []
  const packets: ClientPacket[] = []
  let waiting: (() => void) | undefined

  const control = relayStream()
  const take = framed(decodeClientPacket)
  const controlUp = new WritableStream<Uint8Array>({
    write: (chunk) => {
      packets.push(...take(chunk).map(({ packet }) => packet))
      waiting?.()
    },
  })

  const end = () => {
    for (const stream of [control, ...streams]) {
      try {
        stream.fail(new Error('the session closed'))
      } catch {}
    }
    for (const controller of [incoming, incomingUni, datagrams]) {
      try {
        controller.close()
      } catch {}
    }
  }

  const carrier: Carrier = {
    kind,
    incoming: new ReadableStream({ start: (controller) => { incoming = controller } }),
    incomingUni: new ReadableStream({ start: (controller) => { incomingUni = controller } }),
    datagrams: kind === 'webtransport' ? new ReadableStream({ start: (controller) => { datagrams = controller } }) : undefined,
    sendDatagram: (packet) => { sentDatagrams.push(decodeUdpPacket(packet.slice())) },
    openUni: kind === 'webtransport'
      ? async () => {
        const uplink = relayStream()
        uplinks.push(uplink)
        return uplink.writable
      }
      : undefined,
    closed,
    close: (code, reason) => {
      settleClosed({ code, reason })
      end()
    },
  }

  let read = 0
  const relay = {
    carrier,
    /** What the client wrote on the control stream, every frame so far. */
    packets,
    sentDatagrams,
    uplinks,
    streams,
    /** Opens the control stream, as the relay's first stream. */
    start: () => incoming.enqueue({ readable: control.readable, writable: controlUp }),
    send: (packet: RelayPacket) => control.write(encodeRelayPacket(packet)),
    write: (bytes: Uint8Array) => control.write(bytes),
    endControl: () => control.finish(),
    /** The client's next control frame. */
    next: async () => {
      while (read >= packets.length) await new Promise<void>((resolve) => { waiting = resolve })
      return packets[read++]!
    },
    /** Opens a stream for `socket`, both ways or toward the client only, and writes `first`, its id by default. */
    open: (socket: number, both = true, first = u32(socket)) => {
      const stream = relayStream()
      streams.push(stream)
      if (both) incoming.enqueue({ readable: stream.readable, writable: stream.writable })
      else incomingUni.enqueue(stream.readable)
      stream.write(first)
      return stream
    },
    datagram: (packet: UdpPacket) => datagrams.enqueue(encodeUdpPacket(packet)),
    /** Ends the session from the relay's side. */
    close: (code: number, reason: string) => {
      settleClosed({ code, reason })
      end()
    },
  }
  return relay
}

export type FakeRelay = ReturnType<typeof fakeRelay>

/** A session through a fake relay that offered `features`, past the hello exchange. */
export const opened = async (features = 0, kind: Carrier['kind'] = 'webtransport', relayHello: Partial<Hello> = {}) => {
  const relay = fakeRelay(kind)
  relay.start()
  const session = openSession(relay.carrier, { agent: 'test client' })
  relay.send({ ...hello(features, 'test relay'), ...relayHello })
  const clientHello = await relay.next()
  return { relay, session: await session, clientHello }
}
