import type { Carrier, CloseInfo, Context, Opened, Opens, Owner, Request, SocketStream } from './context'
import type { TcpListener } from './listener'
import type { Address, ClientPacket, RelayPacket } from './protocol'
import type { TcpSocket } from './tcp'
import type { UdpSocket } from './udp'

import { closeError, concat, EMPTY, framed, noop, ok, readU32, unexpected, WebVpnError, within } from './context'
import { dnsQuery } from './dns'
import { tcpListener } from './listener'
import {
  CloseCode,
  compatible,
  decodeRelayPacket,
  decodeUdpPacket,
  encodeClientPacket,
  ErrorCode,
  Feature,
  hello,
  MAX_CLIENT_FRAME_BYTES,
  ProtocolError,
} from './protocol'
import { tcpSocket } from './tcp'
import { udpSocket } from './udp'

const AGENT = '@webvpn/client'

// the relay answers a lookup within 5 seconds and every other request but a connect at once (spec/protocol.md,
// Limits), so the client waits longer and reads the relay's own answer rather than giving up first
const REQUEST_TIMEOUT_MS = 10_000
// the relay answers a connect within 10 seconds (spec/protocol.md, Limits), the same way
const CONNECT_TIMEOUT_MS = 12_000
// a WebTransport session can be ready and then never deliver its control stream (seen on Firefox)
const SETUP_TIMEOUT_MS = 4000

const UNCLAIMED_STREAM_MS = 30_000
const RETIRED_SOCKET_MS = 30_000
const RETIRED_SOCKET_MAX = 4096
const LATE_REPLY_MS = 60_000
const LATE_REPLY_MAX = 512

const FRAME_HEADER_BYTES = 5

const CLOSES = { tcp: 'tcpClose', listener: 'tcpUnlisten', udp: 'udpClose' } as const

/**
 * One session with a relay, over WebTransport or the WebSocket mux, from `connect`. Every request rejects with a
 * `WebVpnError`: the relay's own refusal, `UNSUPPORTED` for a feature the relay's hello did not offer (the request
 * is then never sent), `TIMED_OUT` when the relay gave no answer in 10 seconds (12 for a connect), and `OTHER` once
 * the session is closed. Closing the session ends every socket it holds.
 */
export type Session = {
  carrier: 'webtransport' | 'websocket',
  /** The `Feature` bits of the relay's hello. */
  features: number,
  /**
   * Resolves when the session ended, with a `CloseCode` and a reason: the relay's `bye` when it said one, else the
   * carrier's close, else `LOST` for a carrier that ended with no code. Never rejects.
   */
  closed: Promise<CloseInfo>,
  /** Resolves when the relay says it is about to stop. The sockets keep working; new ones belong on a new session. */
  draining: Promise<void>,
  /** Presents a credential; a refusal leaves the session as it was. Needs the `AUTH` feature. */
  authenticate: (credential: Uint8Array) => Promise<void>,
  /** Returns the session to no identity. Needs the `AUTH` feature. */
  clearAuth: () => Promise<void>,
  /** Connects to an address, or to the first A record of a name, which the relay looks up (the `DNS` feature). */
  tcpConnect: (target: Address | { name: string, port: number }) => Promise<TcpSocket>,
  /** Listens for connections on the relay. Port 0 takes a free port. Needs the `LISTEN` feature. */
  tcpListen: (local: Address) => Promise<TcpListener>,
  /** Binds a UDP socket on the relay. Port 0 takes a free port. */
  udpBind: (local: Address) => Promise<UdpSocket>,
  /** Puts a whole DNS message to the relay's resolver and returns its whole answer. Needs the `DNS` feature. */
  lookup: (query: Uint8Array) => Promise<Uint8Array>,
  /** Closes the session with `NORMAL`. */
  close: () => void,
}

// keeps the map in stamping order, so the oldest entries go first once they outlive `ms` or outnumber `max`
const remember = <V extends { at: number }>(map: Map<number, V>, key: number, value: V, ms: number, max: number) => {
  map.delete(key)
  map.set(key, value)
  for (const [old, { at }] of map) {
    if (value.at - at <= ms && map.size <= max) break
    map.delete(old)
  }
}

const opened = (reply: RelayPacket): Opened => {
  if (reply.type !== 'socket') throw unexpected(reply)
  return reply
}

const connected = (reply: RelayPacket) => {
  const socket = opened(reply)
  if (!socket.remote) throw unexpected(reply)
  return { ...socket, remote: socket.remote }
}

const dispose = ({ reader, writable }: Omit<SocketStream, 'head'>) => {
  reader.cancel().catch(noop)
  writable?.abort().catch(noop)
}

/**
 * Runs a session on `carrier`: reads the relay's hello from the first stream the relay opens, answers with the
 * client's, and serves requests from then on. Rejects, with the carrier closed, when the relay's version does not
 * suit (`VERSION_MISMATCH`), when the relay closes the session in its setup (the error's `closeCode` says why, as
 * `SESSION_LIMIT` for a full relay), when the setup breaks the protocol, ends, or does not finish within 4 seconds.
 */
export const openSession = async (carrier: Carrier, options: { agent?: string } = {}): Promise<Session> => {
  let ended: WebVpnError | undefined
  // set by the first frame after the hello: a request with no answer on a session that read nothing since is a
  // session that is stuck, not one slow target
  let heard = false
  const pending = new Map<number, { settle: (reply: RelayPacket) => void, fail: (error: WebVpnError) => void }>()
  const late = new Map<number, { at: number, opens?: Opens }>()
  const retired = new Map<number, { at: number }>()
  const parked = new Map<number, { stream: SocketStream, timer: ReturnType<typeof setTimeout> }>()
  const claims = new Map<number, { resolve: (stream: SocketStream) => void, reject: (error: WebVpnError) => void }>()
  const owners = new Map<number, Owner>()
  let announceDraining!: () => void
  const draining = new Promise<void>((resolve) => { announceDraining = resolve })
  let lastId = 0

  const end = (info: CloseInfo) => {
    if (ended) return
    ended = closeError(info)
    for (const { fail } of pending.values()) fail(ended)
    for (const { reject } of claims.values()) reject(ended)
    for (const { stream, timer } of parked.values()) {
      clearTimeout(timer)
      dispose(stream)
    }
    for (const owner of [...owners.values()]) owner.end()
    for (const map of [pending, claims, parked, owners, late, retired]) map.clear()
  }
  carrier.closed.then(end)
  const fail = (code: number, reason: string) => carrier.close(code, reason)

  const incoming = carrier.incoming.getReader()
  const setup = async () => {
    const { value: control } = await incoming.read()
    if (!control) throw new WebVpnError(ErrorCode.OTHER, 'the relay opened no control stream')
    const reader = control.readable.getReader()
    const take = framed(decodeRelayPacket)
    const backlog: RelayPacket[] = []
    const next = async () => {
      while (!backlog.length) {
        const { value, done } = await reader.read()
        if (done) return undefined
        backlog.push(...take(value).map(({ packet }) => packet))
      }
      return backlog.shift()
    }
    const relayHello = await next()
    if (relayHello?.type === 'bye') {
      fail(relayHello.code, relayHello.reason)
      throw closeError(relayHello)
    }
    if (relayHello?.type !== 'hello') throw new ProtocolError('the relay did not start with its hello')
    if (!compatible(relayHello)) {
      const reason = `the relay speaks WebVPN ${relayHello.major}.${relayHello.minor}`
      fail(CloseCode.VERSION_MISMATCH, reason)
      throw closeError({ code: CloseCode.VERSION_MISMATCH, reason })
    }
    const writer = control.writable.getWriter()
    await writer.write(encodeClientPacket(hello(0, options.agent ?? AGENT)))
    return { next, writer, features: relayHello.features }
  }
  const { next, writer, features } = await within(
    Promise.race([setup(), carrier.closed.then((info) => { throw closeError(info) })]),
    SETUP_TIMEOUT_MS,
    ErrorCode.TIMED_OUT,
    'the relay did not finish the session setup in time',
  ).catch((error: unknown) => {
    fail(CloseCode.PROTOCOL_ERROR, error instanceof Error ? error.message : 'the session setup failed')
    throw error
  })

  const nextId = () => {
    do lastId = (lastId + 1) >>> 0
    while (pending.has(lastId) || late.has(lastId))
    return lastId
  }

  // the deadline is armed and the id registered before the bytes are written, so no reply can slip past its waiter
  const request: Context['request'] = (packet, take, { timeoutMs = REQUEST_TIMEOUT_MS, opens } = {}) =>
    new Promise((resolve, reject) => {
      if (ended) return reject(ended)
      const id = nextId()
      const frame = encodeClientPacket({ ...packet, id } as ClientPacket)
      if (frame.byteLength - FRAME_HEADER_BYTES > MAX_CLIENT_FRAME_BYTES) {
        return reject(new WebVpnError(ErrorCode.OTHER, `a request holds at most ${MAX_CLIENT_FRAME_BYTES} bytes`))
      }
      const timer = setTimeout(() => {
        pending.delete(id)
        remember(late, id, { at: Date.now(), opens }, LATE_REPLY_MS, LATE_REPLY_MAX)
        if (!heard) fail(CloseCode.PROTOCOL_ERROR, 'the relay answers nothing')
        reject(new WebVpnError(ErrorCode.TIMED_OUT, `the relay did not answer in ${timeoutMs} ms`))
      }, timeoutMs)
      pending.set(id, {
        settle: (reply) => {
          clearTimeout(timer)
          if (reply.type === 'error') return reject(new WebVpnError(reply.code, reply.message))
          try {
            resolve(take(reply))
          } catch (error) {
            reject(error)
          }
        },
        fail: (error) => {
          clearTimeout(timer)
          reject(error)
        },
      })
      writer.write(frame).catch(() => fail(CloseCode.PROTOCOL_ERROR, 'the control stream failed'))
    })

  const isRetired = (socket: number) => Date.now() - (retired.get(socket)?.at ?? -Infinity) <= RETIRED_SOCKET_MS

  const retire = (socket: number) => {
    if (ended) return
    const held = parked.get(socket)
    if (held) {
      clearTimeout(held.timer)
      dispose(held.stream)
    }
    claims.get(socket)?.reject(new WebVpnError(ErrorCode.OTHER, 'the socket closed'))
    parked.delete(socket)
    claims.delete(socket)
    remember(retired, socket, { at: Date.now() }, RETIRED_SOCKET_MS, RETIRED_SOCKET_MAX)
  }

  const release = (opens: Opens, socket: number) => {
    retire(socket)
    request({ type: CLOSES[opens], socket }, ok).catch(noop)
  }

  const claim = (socket: number, timeoutMs?: number) => {
    if (ended) return Promise.reject(ended)
    const held = parked.get(socket)
    if (held) {
      clearTimeout(held.timer)
      parked.delete(socket)
      return Promise.resolve(held.stream)
    }
    const arrival = new Promise<SocketStream>((resolve, reject) => claims.set(socket, { resolve, reject }))
    if (timeoutMs === undefined) return arrival
    const message = 'the relay did not open the socket\'s stream in time'
    return within(arrival, timeoutMs, ErrorCode.NO_STREAM, message).catch((error: unknown) => {
      claims.delete(socket)
      throw error
    })
  }

  // a stream may come before or after the reply that names its socket: one whose socket nobody claimed yet waits here
  const arrive = (socket: number, stream: SocketStream) => {
    if (ended || isRetired(socket)) return dispose(stream)
    const claimed = claims.get(socket)
    if (claimed) {
      claims.delete(socket)
      return claimed.resolve(stream)
    }
    const previous = parked.get(socket)
    if (previous) {
      clearTimeout(previous.timer)
      dispose(previous.stream)
    }
    const timer = setTimeout(() => {
      parked.delete(socket)
      dispose(stream)
    }, UNCLAIMED_STREAM_MS)
    parked.set(socket, { stream, timer })
  }

  // the 4 bytes of the id can come split across reads
  const readId = async (readable: ReadableStream<Uint8Array>, writable?: WritableStream<Uint8Array>) => {
    const reader = readable.getReader()
    let head = EMPTY
    try {
      while (head.byteLength < 4) {
        const { value, done } = await reader.read()
        if (done) return dispose({ reader, writable })
        head = concat(head, value)
      }
    } catch {
      return dispose({ reader, writable })
    }
    arrive(readU32(head), { head: head.subarray(4), reader, writable })
  }

  const acceptStreams = async <T>(reader: ReadableStreamDefaultReader<T>, accept: (stream: T) => void) => {
    try {
      for (let read = await reader.read(); !read.done; read = await reader.read()) accept(read.value)
    } catch {}
  }
  acceptStreams(incoming, ({ readable, writable }) => readId(readable, writable))
  acceptStreams(carrier.incomingUni.getReader(), (readable) => readId(readable))
  if (carrier.datagrams) {
    acceptStreams(carrier.datagrams.getReader(), (datagram) => {
      try {
        const packet = decodeUdpPacket(datagram)
        owners.get(packet.socket)?.packet?.(packet)
      } catch {}
    })
  }

  const reply = (packet: RelayPacket & { id: number }) => {
    const waiting = pending.get(packet.id)
    if (waiting) {
      pending.delete(packet.id)
      return waiting.settle(packet)
    }
    const given = late.get(packet.id)
    if (!given) return
    late.delete(packet.id)
    // a socket opened for a request that already gave up is closed, since nobody holds it
    if (packet.type === 'socket' && given.opens) release(given.opens, packet.socket)
  }

  const notify = (socket: number, packet: RelayPacket) => {
    const owner = owners.get(socket)
    if (owner) return owner.notice(packet)
    // a connection a listener accepted as it closed
    if (packet.type === 'accepted') release('tcp', packet.socket)
  }

  const readControl = async () => {
    try {
      for (let packet = await next(); packet; packet = await next()) {
        heard = true
        switch (packet.type) {
          case 'ok':
          case 'error':
          case 'socket':
          case 'dnsAnswer':
            reply(packet)
            break
          case 'accepted':
          case 'acceptRefused':
            notify(packet.listener, packet)
            break
          case 'closed':
            notify(packet.socket, packet)
            break
          case 'draining':
            announceDraining()
            break
          // the last frame: closing the carrier with its code and reason makes them the session's
          case 'bye':
            return fail(packet.code, packet.reason)
        }
      }
      fail(CloseCode.PROTOCOL_ERROR, 'the relay ended the control stream')
    } catch (error) {
      fail(CloseCode.PROTOCOL_ERROR, error instanceof ProtocolError ? error.message : 'the control stream failed')
    }
  }
  readControl()

  const context: Context = {
    carrier,
    request,
    claim,
    retire,
    release,
    own: (socket, owner) => {
      owners.set(socket, owner)
      return () => {
        if (owners.get(socket) === owner) owners.delete(socket)
      }
    },
    ended: () => ended,
    unread: { bytes: 0 },
  }

  const offered = (bit: number, what: string) => {
    if (!(features & bit)) throw new WebVpnError(ErrorCode.UNSUPPORTED, `the relay does not take ${what}`)
  }

  return {
    carrier: carrier.kind,
    features,
    closed: carrier.closed,
    draining,
    authenticate: async (credential) => {
      offered(Feature.AUTH, 'credentials')
      await request({ type: 'auth', credential }, ok)
    },
    clearAuth: async () => {
      offered(Feature.AUTH, 'credentials')
      await request({ type: 'authClear' }, ok)
    },
    tcpConnect: async (target) => {
      let packet: Request = { type: 'tcpConnect', remote: target as Address }
      if ('name' in target) {
        offered(Feature.DNS, 'names')
        packet = { type: 'tcpConnectName', port: target.port, query: dnsQuery(target.name, 'A') }
      }
      const socket = await request(packet, connected, { timeoutMs: CONNECT_TIMEOUT_MS, opens: 'tcp' })
      const stream = await claim(socket.socket, UNCLAIMED_STREAM_MS).catch((error: unknown) => {
        release('tcp', socket.socket)
        throw error
      })
      return tcpSocket(context, socket, stream)
    },
    tcpListen: async (local) => {
      offered(Feature.LISTEN, 'listeners')
      return request({ type: 'tcpListen', local }, (reply) => tcpListener(context, opened(reply)), { opens: 'listener' })
    },
    udpBind: (local) => request({ type: 'udpBind', local }, (reply) => udpSocket(context, opened(reply)), { opens: 'udp' }),
    lookup: async (query) => {
      offered(Feature.DNS, 'names')
      return request({ type: 'dnsQuery', query }, (reply) => {
        if (reply.type !== 'dnsAnswer') throw unexpected(reply)
        return reply.answer
      })
    },
    close: () => fail(CloseCode.NORMAL, 'the client closed the session'),
  }
}
