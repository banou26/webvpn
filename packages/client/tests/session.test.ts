import type { IpTunnel, Session, UdpSocket } from '../src'
import type { ClientPacket, RelayPacket } from '../src/protocol'
import type { FakeRelay } from './relay'

import { afterEach, describe, expect, it, vi } from 'vite-plus/test'

import { WebVpnError } from '../src'
import { concat, u32 } from '../src/context'
import { dnsQuery } from '../src/dns'
import {
  CloseCode,
  encodeFramedUdpPacket,
  encodeIpFrame,
  encodeRelayPacket,
  ErrorCode,
  Feature,
  hello,
  MAX_RELAY_FRAME_BYTES,
  ResetCode,
  VERSION,
} from '../src/protocol'
import { openSession } from '../src/session'
import { fakeRelay, opened, settle, v4 } from './relay'

const SITE = v4('192.0.2.7', 443)
const RELAY_END = v4('198.51.100.4', 50000)
const ANY = v4('0.0.0.0', 0)
const QUERY = Uint8Array.of(1, 2, 3)

const idOf = (packet: ClientPacket) => (packet as { id: number }).id

/** What a promise settled with, a value or an error, so a rejection is never left unhandled. */
const outcome = <T>(promise: Promise<T>) => promise.then((value) => value, (error: unknown) => error)

const isPending = async (promise: Promise<unknown>) => {
  let pending = true
  promise.then(() => { pending = false }, () => { pending = false })
  await settle()
  return pending
}

const answer = async (relay: FakeRelay, reply: (id: number, packet: ClientPacket) => RelayPacket) => {
  const packet = await relay.next()
  relay.send(reply(idOf(packet), packet))
  return packet
}

const connected = async (relay: FakeRelay, session: Session, socket = 5) => {
  const connecting = session.tcpConnect(SITE)
  const stream = relay.open(socket)
  await answer(relay, (id) => ({ type: 'socket', id, socket, local: RELAY_END, remote: SITE }))
  return { socket: await connecting, stream }
}

const bound = async (relay: FakeRelay, session: Session, socket = 7) => {
  const binding = session.udpBind(ANY)
  await answer(relay, (id) => ({ type: 'socket', id, socket, local: v4('0.0.0.0', 5000) }))
  return binding
}

afterEach(() => {
  vi.useRealTimers()
})

describe('the hello exchange', () => {
  it('answers the relay\'s hello with the client\'s, as its first frame, and keeps the relay\'s features', async () => {
    const { relay, session, clientHello } = await opened(Feature.LISTEN | Feature.DNS)
    expect(clientHello).toEqual(hello(0, 'test client'))
    expect(relay.packets).toHaveLength(1)
    expect(session.features).toBe(Feature.LISTEN | Feature.DNS)
    expect(session.carrier).toBe('webtransport')
  })

  it('closes the session with VERSION_MISMATCH for a relay of another minor version', async () => {
    const relay = fakeRelay()
    relay.start()
    const session = outcome(openSession(relay.carrier))
    relay.send({ ...hello(0, 'relay'), minor: VERSION.minor + 1 })
    expect(await session).toMatchObject({ code: ErrorCode.UNSUPPORTED })
    expect((await relay.carrier.closed).code).toBe(CloseCode.VERSION_MISMATCH)
    expect(relay.packets).toEqual([])
  })

  it('closes the session with PROTOCOL_ERROR when the relay does not start with its hello', async () => {
    const relay = fakeRelay()
    relay.start()
    const session = outcome(openSession(relay.carrier))
    relay.send({ type: 'draining' })
    expect(await session).toBeInstanceOf(Error)
    expect((await relay.carrier.closed).code).toBe(CloseCode.PROTOCOL_ERROR)
  })

  it('gives up after 4 seconds without a hello', async () => {
    vi.useFakeTimers()
    const relay = fakeRelay()
    relay.start()
    const session = outcome(openSession(relay.carrier))
    await vi.advanceTimersByTimeAsync(3999)
    expect(await isPending(session)).toBe(true)
    await vi.advanceTimersByTimeAsync(1)
    expect(await session).toMatchObject({ code: ErrorCode.TIMED_OUT })
    expect((await relay.carrier.closed).code).toBe(CloseCode.PROTOCOL_ERROR)
  })

  it('reads a hello split at every byte', async () => {
    const frame = encodeRelayPacket(hello(Feature.DNS, 'a relay with a longer agent'))
    for (let cut = 1; cut < frame.byteLength; cut++) {
      const relay = fakeRelay()
      relay.start()
      const session = openSession(relay.carrier)
      relay.write(frame.subarray(0, cut))
      await settle()
      relay.write(frame.subarray(cut))
      expect((await session).features, `cut at ${cut}`).toBe(Feature.DNS)
    }
  })
})

describe('the session\'s end', () => {
  const BYE = { code: CloseCode.RESTARTING, reason: 'the relay is stopping' }

  it('takes the code and reason of the relay\'s bye over the carrier\'s close that follows it', async () => {
    const { relay, session } = await opened(Feature.DNS)
    const waiting = outcome(session.lookup(QUERY))
    await relay.next()
    relay.send({ type: 'bye', ...BYE })
    await settle()
    // as a browser reports the relay's QUIC close over WebTransport
    relay.close(CloseCode.LOST, 'Connection lost.')
    expect(await session.closed).toEqual(BYE)
    expect(await waiting).toMatchObject({ code: ErrorCode.OTHER, closeCode: CloseCode.RESTARTING })
    expect(await relay.carrier.closed).toEqual(BYE)
  })

  it('takes the carrier\'s code and reason when no bye came', async () => {
    const { relay, session } = await opened()
    relay.close(CloseCode.SESSION_LIMIT, 'full')
    expect(await session.closed).toEqual({ code: CloseCode.SESSION_LIMIT, reason: 'full' })
    expect(await outcome(session.udpBind(ANY))).toMatchObject({ closeCode: CloseCode.SESSION_LIMIT })
  })

  it('reads as LOST when the carrier ended with no code and no bye came', async () => {
    const { relay, session } = await opened(Feature.DNS)
    const waiting = outcome(session.lookup(QUERY))
    await relay.next()
    relay.close(CloseCode.LOST, '')
    expect(await session.closed).toEqual({ code: CloseCode.LOST, reason: '' })
    expect(await waiting).toMatchObject({ code: ErrorCode.OTHER, closeCode: CloseCode.LOST })
  })

  it('rejects a session the relay refuses in its setup with the bye\'s close code, and sends no hello', async () => {
    const relay = fakeRelay()
    relay.start()
    const session = outcome(openSession(relay.carrier))
    relay.send({ type: 'bye', code: CloseCode.SESSION_LIMIT, reason: 'the relay holds as many sessions as it allows' })
    const error = await session
    expect(error).toBeInstanceOf(WebVpnError)
    expect(error).toMatchObject({ code: ErrorCode.CAPACITY, closeCode: CloseCode.SESSION_LIMIT })
    expect((await relay.carrier.closed).code).toBe(CloseCode.SESSION_LIMIT)
    expect(relay.packets).toEqual([])
  })
})

describe('requests', () => {
  it('match their replies by id, in whatever order the replies come', async () => {
    const { relay, session } = await opened(Feature.DNS)
    const first = session.lookup(Uint8Array.of(1))
    const second = session.lookup(Uint8Array.of(2))
    const [a, b] = [await relay.next(), await relay.next()]
    expect(a).toMatchObject({ type: 'dnsQuery', query: Uint8Array.of(1) })
    expect(idOf(a)).not.toBe(idOf(b))
    relay.send({ type: 'dnsAnswer', id: idOf(b), answer: Uint8Array.of(20) })
    relay.send({ type: 'dnsAnswer', id: idOf(a), answer: Uint8Array.of(10) })
    expect(await first).toEqual(Uint8Array.of(10))
    expect(await second).toEqual(Uint8Array.of(20))
  })

  it('reject with the relay\'s code and message when it refuses them', async () => {
    const { relay, session } = await opened()
    const connecting = outcome(session.tcpConnect(SITE))
    const request = await answer(relay, (id) => ({
      type: 'error',
      id,
      code: ErrorCode.CONNECTION_REFUSED,
      message: 'connection refused',
    }))
    expect(request).toEqual({ type: 'tcpConnect', id: idOf(request), remote: SITE })
    const error = await connecting
    expect(error).toBeInstanceOf(WebVpnError)
    expect(error).toMatchObject({ code: ErrorCode.CONNECTION_REFUSED, message: 'connection refused' })
  })

  it('reject after 10 seconds without an answer, and a late answer that opened a socket closes it', async () => {
    vi.useFakeTimers()
    const { relay, session } = await opened()
    await bound(relay, session, 1)
    const late = outcome(session.udpBind(ANY))
    const request = await relay.next()
    await vi.advanceTimersByTimeAsync(9999)
    expect(await isPending(late)).toBe(true)
    await vi.advanceTimersByTimeAsync(1)
    expect(await late).toMatchObject({ code: ErrorCode.TIMED_OUT })

    relay.send({ type: 'socket', id: idOf(request), socket: 2, local: ANY })
    expect(await relay.next()).toMatchObject({ type: 'udpClose', socket: 2 })
    // the session carries on, and a stream for the late socket is dropped
    const stream = relay.open(2)
    await vi.waitFor(() => expect(stream.seen.cancelled).toBe(true))
    const next = bound(relay, session, 3)
    expect((await next).id).toBe(3)
  })

  it('close a session that answered nothing since its hello when one times out', async () => {
    vi.useFakeTimers()
    const { relay, session } = await opened()
    const binding = outcome(session.udpBind(ANY))
    await relay.next()
    await vi.advanceTimersByTimeAsync(10_000)
    expect(await binding).toMatchObject({ code: ErrorCode.TIMED_OUT })
    expect(await session.closed).toMatchObject({ code: CloseCode.PROTOCOL_ERROR })
  })

  it('wait 12 seconds for a connect, which the relay bounds at 10', async () => {
    vi.useFakeTimers()
    const { relay, session } = await opened()
    await bound(relay, session, 1)
    const connecting = outcome(session.tcpConnect(SITE))
    await relay.next()
    await vi.advanceTimersByTimeAsync(11_999)
    expect(await isPending(connecting)).toBe(true)
    await vi.advanceTimersByTimeAsync(1)
    expect(await connecting).toMatchObject({ code: ErrorCode.TIMED_OUT })
  })

  it('are refused without being sent when they are longer than a relay reads', async () => {
    const { relay, session } = await opened(Feature.AUTH)
    expect(await outcome(session.authenticate(new Uint8Array(5000)))).toMatchObject({ code: ErrorCode.OTHER })
    await settle()
    expect(relay.packets).toHaveLength(1)
  })
})

describe('the control stream', () => {
  it('skips frames of a type the client does not know', async () => {
    const { relay, session } = await opened(Feature.AUTH)
    const cleared = session.clearAuth()
    const request = await relay.next()
    relay.write(Uint8Array.of(0x7f, 0, 0, 0, 3, 1, 2, 3))
    relay.send({ type: 'ok', id: idOf(request) })
    await cleared
  })

  it('resolves draining on the relay\'s notice and keeps serving', async () => {
    const { relay, session } = await opened(Feature.AUTH)
    let drained = false
    session.draining.then(() => { drained = true })
    await settle()
    expect(drained).toBe(false)
    relay.send({ type: 'draining' })
    await vi.waitFor(() => expect(drained).toBe(true))
    const cleared = session.clearAuth()
    await answer(relay, (id) => ({ type: 'ok', id }))
    await cleared
  })

  it('closes the session and rejects every waiting request when it ends', async () => {
    const { relay, session } = await opened(Feature.DNS)
    const waiting = outcome(session.lookup(QUERY))
    await relay.next()
    relay.endControl()
    expect(await waiting).toMatchObject({ code: ErrorCode.OTHER })
    expect(await session.closed).toMatchObject({ code: CloseCode.PROTOCOL_ERROR })
    expect(await outcome(session.lookup(QUERY))).toBeInstanceOf(WebVpnError)
    expect(await outcome(session.udpBind(ANY))).toBeInstanceOf(WebVpnError)
  })

  it('closes the session with PROTOCOL_ERROR on a frame over the limit', async () => {
    const { relay, session } = await opened()
    const header = Uint8Array.of(0x01, 0, 0, 0, 0)
    new DataView(header.buffer).setUint32(1, MAX_RELAY_FRAME_BYTES + 1)
    relay.write(header)
    expect(await session.closed).toMatchObject({ code: CloseCode.PROTOCOL_ERROR })
  })

  // the old wire's desync came from a packet cut inside its last field, read as whole: every cut of a recorded
  // sequence must give the same frames, each exactly once
  it('reads a recorded sequence split at every byte exactly as whole, each frame once', async () => {
    vi.useFakeTimers()
    const LISTENER = v4('0.0.0.0', 4000)
    const sequence = [
      Uint8Array.of(0x7f, 0, 0, 0, 3, 9, 9, 9),
      encodeRelayPacket({ type: 'ok', id: 1 }),
      encodeRelayPacket({ type: 'error', id: 2, code: ErrorCode.LOOKUP_FAILED, message: 'the resolver did not answer' }),
      encodeRelayPacket({ type: 'dnsAnswer', id: 3, answer: Uint8Array.from({ length: 40 }, (_, at) => at) }),
      encodeRelayPacket({ type: 'socket', id: 4, socket: 20, local: LISTENER }),
      encodeRelayPacket({ type: 'accepted', listener: 20, socket: 21, local: LISTENER, remote: SITE }),
      encodeRelayPacket({ type: 'accepted', listener: 20, socket: 22, local: LISTENER, remote: RELAY_END }),
      encodeRelayPacket({ type: 'socket', id: 5, socket: 23, local: ANY }),
      encodeRelayPacket({ type: 'closed', socket: 23, code: ErrorCode.CAPACITY }),
      encodeRelayPacket({ type: 'draining' }),
    ].reduce(concat)
    const pieces = (cut: number) => cut < 0
      ? Array.from(sequence, (byte) => Uint8Array.of(byte))
      : [sequence.subarray(0, cut), sequence.subarray(cut)]

    for (let cut = -1; cut < sequence.byteLength; cut++) {
      const { relay, session } = await opened(Feature.AUTH | Feature.DNS | Feature.LISTEN, 'websocket')
      const auth = session.authenticate(Uint8Array.of(1))
      const failed = outcome(session.lookup(QUERY))
      const looked = session.lookup(QUERY)
      const listening = session.tcpListen(LISTENER)
      const binding = session.udpBind(ANY)
      for (let request = 0; request < 5; request++) await relay.next()
      relay.open(21)
      relay.open(22)
      for (const piece of pieces(cut)) {
        relay.write(piece)
        await settle()
      }

      const at = `cut at ${cut}`
      await auth
      expect(await failed, at).toMatchObject({ code: ErrorCode.LOOKUP_FAILED, message: 'the resolver did not answer' })
      expect(await looked, at).toEqual(Uint8Array.from({ length: 40 }, (_, at) => at))
      const connections = (await listening).connections.getReader()
      expect((await connections.read()).value, at).toMatchObject({ id: 21, remote: SITE })
      expect((await connections.read()).value, at).toMatchObject({ id: 22, remote: RELAY_END })
      expect(await (await binding).closed, at).toEqual({ by: 'relay', code: ErrorCode.CAPACITY })
      await session.draining
      // a frame read twice would claim its socket again, give up after 30 seconds and close it
      await vi.advanceTimersByTimeAsync(30_000)
      expect(relay.packets, at).toHaveLength(6)
      session.close()
    }
  })
})

describe('socket streams', () => {
  it('wait for the reply that names their socket when they come first', async () => {
    const { relay, session } = await opened()
    const connecting = session.tcpConnect(SITE)
    const request = await relay.next()
    relay.open(5).write(Uint8Array.of(1, 2))
    await settle()
    relay.send({ type: 'socket', id: idOf(request), socket: 5, local: RELAY_END, remote: SITE })
    const socket = await connecting
    expect(socket).toMatchObject({ id: 5, local: RELAY_END, remote: SITE })
    expect((await socket.readable.getReader().read()).value).toEqual(Uint8Array.of(1, 2))
  })

  it('are taken by a socket whose reply came first, with an id split across reads', async () => {
    const { relay, session } = await opened()
    const connecting = session.tcpConnect(SITE)
    await answer(relay, (id) => ({ type: 'socket', id, socket: 5, local: RELAY_END, remote: SITE }))
    await settle()
    const stream = relay.open(5, true, Uint8Array.of(0, 0))
    stream.write(Uint8Array.of(0, 5, 7))
    const socket = await connecting
    expect((await socket.readable.getReader().read()).value).toEqual(Uint8Array.of(7))
  })

  it('are dropped after 30 seconds when no socket claims them', async () => {
    vi.useFakeTimers()
    const { relay } = await opened()
    const stray = relay.open(9)
    await vi.advanceTimersByTimeAsync(29_999)
    expect(stray.seen.cancelled).toBe(false)
    await vi.advanceTimersByTimeAsync(1)
    expect(stray.seen).toMatchObject({ cancelled: true, aborted: true })
  })

  it('give up a connect whose stream does not come in 30 seconds, and close its socket', async () => {
    vi.useFakeTimers()
    const { relay, session } = await opened()
    const connecting = outcome(session.tcpConnect(SITE))
    await answer(relay, (id) => ({ type: 'socket', id, socket: 5, local: RELAY_END, remote: SITE }))
    await vi.advanceTimersByTimeAsync(30_000)
    expect(await connecting).toMatchObject({ code: ErrorCode.NO_STREAM })
    expect(await relay.next()).toMatchObject({ type: 'tcpClose', socket: 5 })
  })

  it('are dropped at once for a socket that ended', async () => {
    const { relay, session } = await opened()
    const udp = await bound(relay, session, 7)
    const closing = udp.close()
    await answer(relay, (id) => ({ type: 'ok', id }))
    await closing
    const late = relay.open(7)
    await vi.waitFor(() => expect(late.seen.cancelled).toBe(true))
  })
})

describe('a TCP socket', () => {
  it('errors its readable with CONNECTION_RESET when the peer reset the connection', async () => {
    const { relay, session } = await opened()
    const { socket, stream } = await connected(relay, session)
    stream.reset(ResetCode.PEER_RESET)
    const error = await outcome(socket.readable.getReader().read())
    expect(error).toBeInstanceOf(WebVpnError)
    expect(error).toMatchObject({ code: ErrorCode.CONNECTION_RESET })
  })

  it('fails a write with CONNECTION_RESET when the upload fails just ahead of the peer\'s reset', async () => {
    const { relay, session } = await opened()
    const { socket, stream } = await connected(relay, session)
    socket.readable.getReader().read().catch(() => {})
    stream.breakWrites(new Error('error writing data'))
    const written = outcome(socket.writable.getWriter().write(Uint8Array.of(1)))
    await new Promise((resolve) => setTimeout(resolve, 20))
    stream.reset(ResetCode.PEER_RESET)
    expect(await written).toMatchObject({ code: ErrorCode.CONNECTION_RESET })
  })

  it('fails a write with CONNECTION_RESET at once when the peer reset a socket nobody reads', async () => {
    const { relay, session } = await opened()
    const { socket, stream } = await connected(relay, session)
    stream.reset(ResetCode.PEER_RESET)
    stream.breakWrites(new Error('error writing data'))
    const started = Date.now()
    const written = outcome(socket.writable.getWriter().write(Uint8Array.of(1)))
    expect(await written).toMatchObject({ code: ErrorCode.CONNECTION_RESET })
    expect(Date.now() - started).toBeLessThan(500)
  })

  it('half closes when its writable closes, and keeps reading', async () => {
    const { relay, session } = await opened()
    const { socket, stream } = await connected(relay, session)
    await socket.writable.close()
    expect(stream.seen.finished).toBe(true)
    stream.write(Uint8Array.of(4))
    stream.finish()
    const reader = socket.readable.getReader()
    expect(await reader.read()).toEqual({ done: false, value: Uint8Array.of(4) })
    expect(await reader.read()).toEqual({ done: true, value: undefined })
  })

  it('closes with TcpClose, resolves on its Ok, ends its readable cleanly and drops the rest', async () => {
    const { relay, session } = await opened()
    const { socket, stream } = await connected(relay, session)
    const reader = socket.readable.getReader()
    const closing = socket.close()
    const request = await relay.next()
    expect(request).toEqual({ type: 'tcpClose', id: idOf(request), socket: 5 })
    expect(await isPending(closing)).toBe(true)
    // the relay's reset of code 0 can come ahead of its answer
    stream.write(new Uint8Array(100))
    relay.send({ type: 'ok', id: idOf(request) })
    await closing
    expect(await reader.read()).toEqual({ done: true, value: undefined })
    await vi.waitFor(() => expect(stream.desiredSize()).toBe(1))
    stream.reset(ResetCode.CLOSED)
    expect(await isPending(socket.reset())).toBe(false)
    // the hello, the connect and the one close
    expect(relay.packets).toHaveLength(3)
  })

  it('reads the relay\'s reset of code 0 as a clean end', async () => {
    const { relay, session } = await opened()
    const { socket, stream } = await connected(relay, session)
    const reader = socket.readable.getReader()
    stream.reset(ResetCode.CLOSED)
    expect(await reader.read()).toEqual({ done: true, value: undefined })
  })

  it('resets with TcpReset', async () => {
    const { relay, session } = await opened()
    const { socket } = await connected(relay, session)
    const resetting = socket.reset()
    expect(await answer(relay, (id) => ({ type: 'ok', id }))).toMatchObject({ type: 'tcpReset', socket: 5 })
    await resetting
  })

  it('holds back only its own stream when nobody reads it', async () => {
    const { relay, session } = await opened(Feature.AUTH)
    const { stream } = await connected(relay, session)
    for (let chunk = 0; chunk < 16; chunk++) stream.write(new Uint8Array(64 * 1024))
    const other = await connected(relay, session, 6)
    other.stream.write(Uint8Array.of(9))
    expect((await other.socket.readable.getReader().read()).value).toEqual(Uint8Array.of(9))
    const cleared = session.clearAuth()
    await answer(relay, (id) => ({ type: 'ok', id }))
    await cleared
    // what nobody read stays on the relay's side of the stream
    expect(stream.desiredSize()).toBeLessThan(-14)
  })

  it('errors its readable with the session\'s error when the session ends', async () => {
    const { relay, session } = await opened()
    const { socket } = await connected(relay, session)
    relay.close(CloseCode.RESTARTING, 'the relay is stopping')
    expect(await outcome(socket.readable.getReader().read())).toMatchObject({ code: ErrorCode.OTHER })
    expect(await session.closed).toEqual({ code: CloseCode.RESTARTING, reason: 'the relay is stopping' })
  })
})

describe('a TCP listener', () => {
  const listening = async (relay: FakeRelay, session: Session) => {
    const listen = session.tcpListen(ANY)
    await answer(relay, (id) => ({ type: 'socket', id, socket: 4, local: v4('0.0.0.0', 4000) }))
    return listen
  }

  it('gives each accepted connection with its stream', async () => {
    const { relay, session } = await opened(Feature.LISTEN)
    const listener = await listening(relay, session)
    expect(listener).toMatchObject({ id: 4, local: v4('0.0.0.0', 4000) })
    relay.send({ type: 'accepted', listener: 4, socket: 9, local: v4('192.0.2.1', 4000), remote: SITE })
    await settle()
    relay.open(9).write(Uint8Array.of(3))
    const { value: connection } = await listener.connections.getReader().read()
    expect(connection).toMatchObject({ id: 9, remote: SITE })
    expect((await connection!.readable.getReader().read()).value).toEqual(Uint8Array.of(3))
  })

  it('resolves closed with the code of the relay\'s Closed notice, and ends its connections', async () => {
    const { relay, session } = await opened(Feature.LISTEN)
    const listener = await listening(relay, session)
    relay.send({ type: 'closed', socket: 4, code: ErrorCode.OTHER })
    expect(await listener.closed).toEqual({ by: 'relay', code: ErrorCode.OTHER })
    expect((await listener.connections.getReader().read()).done).toBe(true)
  })

  it('closes with TcpUnlisten, and closes a connection accepted after that', async () => {
    const { relay, session } = await opened(Feature.LISTEN)
    const listener = await listening(relay, session)
    const closing = listener.close()
    expect(await answer(relay, (id) => ({ type: 'ok', id }))).toMatchObject({ type: 'tcpUnlisten', socket: 4 })
    await closing
    expect(await listener.closed).toEqual({ by: 'client' })
    const late = relay.open(10)
    relay.send({ type: 'accepted', listener: 4, socket: 10, local: v4('192.0.2.1', 4000), remote: SITE })
    expect(await relay.next()).toMatchObject({ type: 'tcpClose', socket: 10 })
    await vi.waitFor(() => expect(late.seen.cancelled).toBe(true))
  })

  it('resolves closed as the session\'s when the session ends', async () => {
    const { relay, session } = await opened(Feature.LISTEN)
    const listener = await listening(relay, session)
    session.close()
    expect(await listener.closed).toEqual({ by: 'session' })
  })

  it('closes the connections it did not hand out, whichever way it stops', async () => {
    for (const way of ['close', 'notice', 'session'] as const) {
      const { relay, session } = await opened(Feature.LISTEN)
      const listener = await listening(relay, session)
      for (const socket of [9, 10]) {
        relay.open(socket)
        relay.send({ type: 'accepted', listener: 4, socket, local: v4('192.0.2.1', 4000), remote: SITE })
      }
      await settle()
      if (way === 'close') {
        const closing = listener.close()
        await answer(relay, (id) => ({ type: 'ok', id }))
        await closing
      }
      if (way === 'notice') relay.send({ type: 'closed', socket: 4, code: ErrorCode.OTHER })
      if (way === 'session') session.close()
      await listener.closed
      expect((await listener.connections.getReader().read()).done, way).toBe(true)
      const closes = () => relay.packets.flatMap((packet) => packet.type === 'tcpClose' ? [packet.socket] : [])
      // a session that ended has no relay left to tell
      if (way === 'session') expect(closes()).toEqual([])
      else await vi.waitFor(() => expect(closes(), way).toEqual([9, 10]))
    }
  })

  it('closes a connection that came after its connections were cancelled during a read, once it stops', async () => {
    const { relay, session } = await opened(Feature.LISTEN)
    const listener = await listening(relay, session)
    const reader = listener.connections.getReader()
    const read = reader.read()
    await reader.cancel()
    expect(await read).toEqual({ done: true, value: undefined })
    relay.open(9)
    relay.send({ type: 'accepted', listener: 4, socket: 9, local: v4('192.0.2.1', 4000), remote: SITE })
    await settle()
    const closing = listener.close()
    await answer(relay, (id) => ({ type: 'ok', id }))
    await closing
    const closes = () => relay.packets.flatMap((packet) => packet.type === 'tcpClose' ? [packet.socket] : [])
    await vi.waitFor(() => expect(closes()).toEqual([9]))
  })
})

describe('a UDP socket over WebTransport', () => {
  it('sends datagrams until its stream comes, then sends and reads on the stream', async () => {
    const { relay, session } = await opened()
    const udp = await bound(relay, session)
    const writer = udp.writable.getWriter()
    await writer.write({ remote: SITE, data: Uint8Array.of(1) })
    expect(relay.sentDatagrams).toEqual([{ socket: 7, remote: SITE, data: Uint8Array.of(1) }])

    const stream = relay.open(7)
    await settle()
    await writer.write({ remote: SITE, data: Uint8Array.of(2) })
    await writer.write({ data: Uint8Array.of(3) })
    const sent = concat(
      encodeFramedUdpPacket({ socket: 7, remote: SITE, data: Uint8Array.of(2) }),
      encodeFramedUdpPacket({ socket: 7, data: Uint8Array.of(3) }),
    )
    await vi.waitFor(() => expect(stream.received()).toEqual(concat(u32(7), sent)))
    expect(relay.sentDatagrams).toHaveLength(1)

    // a frame split across reads, then one in a datagram
    const framed = encodeFramedUdpPacket({ socket: 7, remote: RELAY_END, data: Uint8Array.of(4, 4) })
    stream.write(framed.subarray(0, 6))
    stream.write(framed.subarray(6))
    const reader = udp.readable.getReader()
    expect((await reader.read()).value).toEqual({ remote: RELAY_END, data: Uint8Array.of(4, 4) })
    relay.datagram({ socket: 7, remote: SITE, data: Uint8Array.of(5) })
    expect((await reader.read()).value).toEqual({ remote: SITE, data: Uint8Array.of(5) })
  })

  it('opens a stream of its own when none came in 8 seconds', async () => {
    vi.useFakeTimers()
    const { relay, session } = await opened()
    const udp = await bound(relay, session)
    await vi.advanceTimersByTimeAsync(7999)
    expect(relay.uplinks).toHaveLength(0)
    await vi.advanceTimersByTimeAsync(1)
    expect(relay.uplinks).toHaveLength(1)
    await udp.writable.getWriter().write({ remote: SITE, data: Uint8Array.of(6) })
    const sent = encodeFramedUdpPacket({ socket: 7, remote: SITE, data: Uint8Array.of(6) })
    await vi.waitFor(() => expect(relay.uplinks[0]!.received()).toEqual(concat(u32(7), sent)))
    expect(relay.sentDatagrams).toEqual([])
  })

  it('resolves closed with the code of the relay\'s Closed notice, and ends its readable', async () => {
    const { relay, session } = await opened()
    const udp = await bound(relay, session)
    relay.send({ type: 'closed', socket: 7, code: ErrorCode.CAPACITY })
    expect(await udp.closed).toEqual({ by: 'relay', code: ErrorCode.CAPACITY })
    expect((await udp.readable.getReader().read()).done).toBe(true)
  })

  it('closes with UdpClose, and resolves closed as the client\'s', async () => {
    const { relay, session } = await opened()
    const udp = await bound(relay, session)
    const closing = udp.close()
    expect(await answer(relay, (id) => ({ type: 'ok', id }))).toMatchObject({ type: 'udpClose', socket: 7 })
    await closing
    expect(await udp.closed).toEqual({ by: 'client' })
  })

  it('resolves closed as the session\'s when the session ends', async () => {
    const { relay, session } = await opened()
    const udp = await bound(relay, session)
    session.close()
    expect(await udp.closed).toEqual({ by: 'session' })
  })

  it('fails a write over 65536 bytes with a WebVpnError, which errors its writable and leaves the socket open', async () => {
    const { relay, session } = await opened()
    const udp = await bound(relay, session)
    const writer = udp.writable.getWriter()
    await writer.write({ remote: SITE, data: new Uint8Array(65_536) })
    const error = await outcome(writer.write({ remote: SITE, data: new Uint8Array(65_537) }))
    expect(error).toBeInstanceOf(WebVpnError)
    expect(error).toMatchObject({ code: ErrorCode.OTHER, message: expect.stringContaining('the datagram is too large') })
    expect(await outcome(writer.write({ remote: SITE, data: Uint8Array.of(1) }))).toBe(error)
    expect(relay.sentDatagrams.map(({ data }) => data.byteLength)).toEqual([65_536])
    relay.datagram({ socket: 7, remote: SITE, data: Uint8Array.of(2) })
    expect((await udp.readable.getReader().read()).value).toEqual({ remote: SITE, data: Uint8Array.of(2) })
  })

  it('holds at most 4 MiB unread for one socket and 32 MiB for the session, and drops the rest', async () => {
    const { relay, session } = await opened()
    const data = new Uint8Array(65_536)
    const sockets: UdpSocket[] = []
    for (let socket = 10; socket < 19; socket++) sockets.push(await bound(relay, session, socket))
    for (const { id } of sockets) {
      for (let packet = 0; packet < 70; packet++) relay.datagram({ socket: id, remote: SITE, data })
    }
    // datagrams are taken in order, so once this one is read every one before it was taken or dropped
    const last = await bound(relay, session, 19)
    relay.datagram({ socket: 19, remote: SITE, data: Uint8Array.of(0) })
    expect((await last.readable.getReader().read()).value?.data).toEqual(Uint8Array.of(0))
    // each packet counts its payload and 256 bytes: 63 fit in 4 MiB, 8 sockets of them leave room for 6 more
    const reads = async (socket: UdpSocket, expected: number) => {
      const reader = socket.readable.getReader()
      for (let packet = 0; packet < expected; packet++) expect((await reader.read()).value?.data.byteLength).toBe(65_536)
      relay.datagram({ socket: socket.id, remote: SITE, data: Uint8Array.of(1) })
      expect((await reader.read()).value?.data).toEqual(Uint8Array.of(1))
      reader.releaseLock()
    }
    await reads(sockets[8]!, 6)
    await reads(sockets[0]!, 63)
  })
})

describe('a UDP socket over the WebSocket mux', () => {
  it('reads the stream the relay opens toward it before the reply, and sends datagrams', async () => {
    vi.useFakeTimers()
    const { relay, session } = await opened(0, 'websocket')
    const binding = session.udpBind(ANY)
    const request = await relay.next()
    const stream = relay.open(7, false)
    relay.send({ type: 'socket', id: idOf(request), socket: 7, local: v4('0.0.0.0', 5000) })
    const udp = await binding
    stream.write(encodeFramedUdpPacket({ socket: 7, remote: SITE, data: Uint8Array.of(1) }))
    expect((await udp.readable.getReader().read()).value).toEqual({ remote: SITE, data: Uint8Array.of(1) })
    await vi.advanceTimersByTimeAsync(8000)
    await udp.writable.getWriter().write({ remote: SITE, data: Uint8Array.of(2) })
    expect(relay.sentDatagrams).toEqual([{ socket: 7, remote: SITE, data: Uint8Array.of(2) }])
  })
})

describe('an IP tunnel', () => {
  const MTU = 1500
  const TUNNEL_V4 = Uint8Array.of(198, 18, 0, 2)
  const TUNNEL_V6 = Uint8Array.of(0xfd, ...new Uint8Array(14), 2)
  const BOTH = { ipv4: TUNNEL_V4, ipv6: TUNNEL_V6, firstPort: 0, ports: 0 }

  const packet = (length: number, fill = length & 0xff) => new Uint8Array(length).fill(fill)

  const framed = (packets: Uint8Array[]) => packets.map(encodeIpFrame).reduce<Uint8Array>(concat, new Uint8Array(0))

  // the reply first, then the stream
  type Given = { ipv4?: Uint8Array, ipv6?: Uint8Array, publicIpv4?: Uint8Array, firstPort?: number, ports?: number }
  const tunnelled = async (relay: FakeRelay, session: Session, given: Given = BOTH) => {
    const opening = session.ipOpen()
    const request = await answer(relay, (id) => ({ type: 'ipTunnel', id, socket: 12, mtu: MTU, firstPort: 0, ports: 0, ...given }))
    await settle()
    const stream = relay.open(12)
    return { tunnel: await opening, stream, request }
  }

  const reads = async (tunnel: IpTunnel, count: number) => {
    const reader = tunnel.readable.getReader()
    const read: Uint8Array[] = []
    for (let at = 0; at < count; at++) read.push((await reader.read()).value!)
    reader.releaseLock()
    return read
  }

  it('is refused with UNSUPPORTED, and not asked for, when the relay does not offer it', async () => {
    const { relay, session } = await opened(Feature.DNS)
    expect(await outcome(session.ipOpen())).toMatchObject({ code: ErrorCode.UNSUPPORTED })
    await settle()
    expect(relay.packets).toHaveLength(1)
  })

  it('opens with IpOpen and gives the relay\'s addresses and mtu', async () => {
    const { relay, session } = await opened(Feature.IP)
    const { tunnel, request } = await tunnelled(relay, session)
    expect(request).toEqual({ type: 'ipOpen', id: idOf(request) })
    expect(tunnel).toMatchObject({ id: 12, ipv4: '198.18.0.2', ipv6: 'fd00::2', mtu: MTU, ports: 0 })
    expect(tunnel.carrier).toBe(session.carrier)
    expect(tunnel.publicIpv4).toBeUndefined()
    expect(tunnel.publicIpv6).toBeUndefined()
  })

  it('gives the public address and ports the relay gave', async () => {
    const { relay, session } = await opened(Feature.IP)
    const publicIpv4 = Uint8Array.of(203, 0, 113, 9)
    const { tunnel } = await tunnelled(relay, session, { ...BOTH, publicIpv4, firstPort: 40000, ports: 8 })
    expect(tunnel).toMatchObject({ publicIpv4: '203.0.113.9', firstPort: 40000, ports: 8 })
    expect(tunnel.publicIpv6).toBeUndefined()
  })

  it('gives no IPv6 address when the relay gave only an IPv4 one', async () => {
    const { relay, session } = await opened(Feature.IP)
    const { tunnel } = await tunnelled(relay, session, { ipv4: TUNNEL_V4 })
    expect(tunnel.ipv4).toBe('198.18.0.2')
    expect(tunnel.ipv6).toBeUndefined()
  })

  it('rejects with the relay\'s refusal', async () => {
    const { relay, session } = await opened(Feature.IP)
    const opening = outcome(session.ipOpen())
    await answer(relay, (id) => ({ type: 'error', id, code: ErrorCode.CAPACITY, message: 'no address is free' }))
    expect(await opening).toMatchObject({ code: ErrorCode.CAPACITY, message: 'no address is free' })
  })

  it('refuses a tunnel under 1280 bytes and closes it at the relay', async () => {
    const { relay, session } = await opened(Feature.IP)
    const opening = outcome(session.ipOpen())
    await answer(relay, (id) => ({ type: 'ipTunnel', id, socket: 12, mtu: 1279, ...BOTH }))
    await settle()
    relay.open(12)
    expect(await opening).toMatchObject({ code: ErrorCode.OTHER })
    expect(await relay.next()).toMatchObject({ type: 'ipClose', socket: 12 })

    const next = session.ipOpen()
    await answer(relay, (id) => ({ type: 'ipTunnel', id, socket: 13, mtu: 1280, ...BOTH }))
    await settle()
    relay.open(13)
    expect((await next).mtu).toBe(1280)
  })

  it('waits for the reply when its stream comes first', async () => {
    const { relay, session } = await opened(Feature.IP)
    const opening = session.ipOpen()
    const request = await relay.next()
    relay.open(12, true, concat(u32(12), encodeIpFrame(packet(40))))
    await settle()
    relay.send({ type: 'ipTunnel', id: idOf(request), socket: 12, mtu: MTU, ...BOTH })
    const tunnel = await opening
    expect(await reads(tunnel, 1)).toEqual([packet(40)])
  })

  it('gives up when its stream does not come in 30 seconds, and closes the tunnel', async () => {
    vi.useFakeTimers()
    const { relay, session } = await opened(Feature.IP)
    const opening = outcome(session.ipOpen())
    await answer(relay, (id) => ({ type: 'ipTunnel', id, socket: 12, mtu: MTU, ...BOTH }))
    await vi.advanceTimersByTimeAsync(29_999)
    expect(await isPending(opening)).toBe(true)
    await vi.advanceTimersByTimeAsync(1)
    expect(await opening).toMatchObject({ code: ErrorCode.NO_STREAM })
    expect(await relay.next()).toMatchObject({ type: 'ipClose', socket: 12 })
  })

  it('opens the next tunnel only once the relay answered the close of one whose stream did not come', async () => {
    vi.useFakeTimers()
    const { relay, session } = await opened(Feature.IP)
    const opening = outcome(session.ipOpen())
    await answer(relay, (id) => ({ type: 'ipTunnel', id, socket: 12, mtu: MTU, ...BOTH }))
    await vi.advanceTimersByTimeAsync(30_000)
    await opening
    const reopening = outcome(session.ipOpen())
    const close = await relay.next()
    expect(close).toMatchObject({ type: 'ipClose', socket: 12 })
    await settle()
    expect(relay.packets.map(({ type }) => type)).toEqual(['hello', 'ipOpen', 'ipClose'])
    relay.send({ type: 'ok', id: idOf(close) })
    const reopen = await relay.next()
    expect(reopen).toEqual({ type: 'ipOpen', id: idOf(reopen) })
    relay.send({ type: 'error', id: idOf(reopen), code: ErrorCode.CAPACITY, message: 'no address is free' })
    expect(await reopening).toMatchObject({ code: ErrorCode.CAPACITY })
  })

  it('closes a tunnel the relay gave after the request gave up', async () => {
    vi.useFakeTimers()
    const { relay, session } = await opened(Feature.IP)
    await bound(relay, session, 1)
    const opening = outcome(session.ipOpen())
    const request = await relay.next()
    await vi.advanceTimersByTimeAsync(10_000)
    expect(await opening).toMatchObject({ code: ErrorCode.TIMED_OUT })
    relay.send({ type: 'ipTunnel', id: idOf(request), socket: 12, mtu: MTU, ...BOTH })
    expect(await relay.next()).toMatchObject({ type: 'ipClose', socket: 12 })
  })

  it('gives each packet whole, however its frames are cut across the stream\'s chunks', async () => {
    const { relay, session } = await opened(Feature.IP)
    const { tunnel, stream } = await tunnelled(relay, session)
    const sent = [packet(20), packet(1500), packet(1), packet(300), packet(60)]
    const bytes = framed(sent)
    // one byte, then a cut inside the second frame's length, then the rest with several frames in one chunk
    stream.write(bytes.subarray(0, 1))
    stream.write(bytes.subarray(1, 23))
    stream.write(bytes.subarray(23))
    expect(await reads(tunnel, sent.length)).toEqual(sent)
  })

  it('gives each packet in a buffer of its own', async () => {
    const { relay, session } = await opened(Feature.IP)
    const { tunnel, stream } = await tunnelled(relay, session)
    stream.write(concat(encodeIpFrame(packet(20)), encodeIpFrame(packet(30))))
    for (const read of await reads(tunnel, 2)) {
      expect(read.byteOffset).toBe(0)
      expect(read.buffer.byteLength).toBe(read.byteLength)
    }
  })

  it('reads its stream only as its readable is read', async () => {
    const { relay, session } = await opened(Feature.IP)
    const { tunnel, stream } = await tunnelled(relay, session)
    for (let at = 0; at < 10; at++) stream.write(encodeIpFrame(packet(100)))
    await settle()
    // the relay's side holds what nobody read, so its own queue fills and drops
    expect(stream.desiredSize()).toBe(-9)
    await reads(tunnel, 1)
    await settle()
    expect(stream.desiredSize()).toBe(-8)
  })

  it('sends a packet behind its length on the stream', async () => {
    const { relay, session } = await opened(Feature.IP)
    const { tunnel, stream } = await tunnelled(relay, session)
    expect(tunnel.send(packet(20))).toBe(true)
    expect(tunnel.send(packet(MTU))).toBe(true)
    await vi.waitFor(() => expect(stream.received()).toEqual(concat(encodeIpFrame(packet(20)), encodeIpFrame(packet(MTU)))))
  })

  it('drops a packet that is empty or longer than its mtu', async () => {
    const { relay, session } = await opened(Feature.IP)
    const { tunnel, stream } = await tunnelled(relay, session)
    expect(tunnel.send(new Uint8Array(0))).toBe(false)
    expect(tunnel.send(packet(MTU + 1))).toBe(false)
    tunnel.send(packet(7))
    await vi.waitFor(() => expect(stream.received()).toEqual(encodeIpFrame(packet(7))))
  })

  it('drops the newest packets once 1 MiB waits for the stream, and sends the earlier ones in order', async () => {
    const { relay, session } = await opened(Feature.IP)
    const { tunnel, stream } = await tunnelled(relay, session)
    const resume = stream.holdWrites()
    const taken: Uint8Array[] = []
    for (let at = 0; at < 800; at++) {
      const sent = packet(1400, at)
      if (tunnel.send(sent)) taken.push(sent)
    }
    // 1402 bytes a frame, 747 of them in 1 MiB
    expect(taken).toHaveLength(747)
    expect(taken.at(-1)![0]).toBe(746 & 0xff)
    resume()
    await vi.waitFor(() => expect(stream.received()).toEqual(framed(taken)))
    expect(tunnel.send(packet(1400, 99))).toBe(true)
  })

  it('closes with IpClose, resolves on its Ok, and stops', async () => {
    const { relay, session } = await opened(Feature.IP)
    const { tunnel, stream } = await tunnelled(relay, session)
    const reader = tunnel.readable.getReader()
    const reading = reader.read()
    const closing = tunnel.close()
    const request = await relay.next()
    expect(request).toEqual({ type: 'ipClose', id: idOf(request), socket: 12 })
    expect(await isPending(closing)).toBe(true)
    expect(await tunnel.closed).toEqual({ by: 'client' })
    expect(await reading).toEqual({ done: true, value: undefined })
    expect(tunnel.send(packet(20))).toBe(false)
    relay.send({ type: 'ok', id: idOf(request) })
    await closing
    await vi.waitFor(() => expect(stream.seen.finished).toBe(true))
  })

  it('opens the next tunnel only once the relay answered the close before it', async () => {
    const { relay, session } = await opened(Feature.IP)
    const { tunnel } = await tunnelled(relay, session)
    const closing = tunnel.close()
    const reopening = outcome(session.ipOpen())
    const close = await relay.next()
    expect(close).toEqual({ type: 'ipClose', id: idOf(close), socket: 12 })
    // the relay counts the tunnel until it answers, so an IpOpen sent now would be refused with CAPACITY
    await settle()
    expect(relay.packets.map(({ type }) => type)).toEqual(['hello', 'ipOpen', 'ipClose'])
    relay.send({ type: 'ok', id: idOf(close) })
    await closing
    const reopen = await relay.next()
    expect(reopen).toEqual({ type: 'ipOpen', id: idOf(reopen) })
    relay.send({ type: 'error', id: idOf(reopen), code: ErrorCode.CAPACITY, message: 'no address is free' })
    expect(await reopening).toMatchObject({ code: ErrorCode.CAPACITY })
  })

  it('stops at the relay\'s Closed notice', async () => {
    const { relay, session } = await opened(Feature.IP)
    const { tunnel } = await tunnelled(relay, session)
    relay.send({ type: 'closed', socket: 12, code: ErrorCode.OTHER })
    expect(await tunnel.closed).toEqual({ by: 'relay', code: ErrorCode.OTHER })
    expect((await tunnel.readable.getReader().read()).done).toBe(true)
    expect(tunnel.send(packet(20))).toBe(false)
    await settle()
    expect(relay.packets).toHaveLength(2)
  })

  it('stops when the session ends', async () => {
    const { relay, session } = await opened(Feature.IP)
    const { tunnel } = await tunnelled(relay, session)
    session.close()
    expect(await tunnel.closed).toEqual({ by: 'session' })
    expect(tunnel.send(packet(20))).toBe(false)
  })
})

describe('the relay\'s features', () => {
  it('are checked before a request is sent', async () => {
    const { relay, session } = await opened(0)
    const attempts: Promise<unknown>[] = [
      session.lookup(QUERY),
      session.tcpConnect({ name: 'example.com', port: 443 }),
      session.tcpListen(ANY),
      session.authenticate(Uint8Array.of(1)),
      session.clearAuth(),
    ]
    for (const attempt of attempts) expect(await outcome(attempt)).toMatchObject({ code: ErrorCode.UNSUPPORTED })
    await settle()
    expect(relay.packets).toHaveLength(1)
  })

  it('let a connect by name ask for the name\'s A records', async () => {
    const { relay, session } = await opened(Feature.DNS)
    session.tcpConnect({ name: 'example.com', port: 443 }).catch(() => {})
    expect(await relay.next()).toMatchObject({ type: 'tcpConnectName', port: 443, query: dnsQuery('example.com', 'A') })
  })
})

describe('two sessions', () => {
  it('share nothing', async () => {
    const one = await opened(Feature.AUTH)
    const two = await opened(Feature.AUTH)
    const cleared = [one.session.clearAuth(), two.session.clearAuth()]
    const [first, second] = [await one.relay.next(), await two.relay.next()]
    expect(idOf(first)).toBe(idOf(second))
    one.relay.send({ type: 'ok', id: idOf(first) })
    two.relay.send({ type: 'ok', id: idOf(second) })
    await Promise.all(cleared)

    let drained = 0
    one.session.draining.then(() => { drained++ })
    two.session.draining.then(() => { drained += 10 })
    one.relay.send({ type: 'draining' })
    await vi.waitFor(() => expect(drained).toBe(1))

    // a socket id retired in one is a new socket in the other
    const udp = await bound(one.relay, one.session, 7)
    const closing = udp.close()
    await answer(one.relay, (id) => ({ type: 'ok', id }))
    await closing
    await connected(two.relay, two.session, 7)

    one.session.close()
    expect(await one.session.closed).toMatchObject({ code: CloseCode.NORMAL })
    const again = two.session.clearAuth()
    await answer(two.relay, (id) => ({ type: 'ok', id }))
    await again
  })
})
