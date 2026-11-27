import type { ConnectOptions, Session } from '../src'
import type { RelayInfo } from './browser/rig'

import { commands } from 'vite-plus/test/browser'
import { afterEach, describe, expect, inject, it } from 'vite-plus/test'

import { CloseCode, connect, dnsAddresses, dnsQuery, ErrorCode, Feature, formatIp, WebVpnError } from '../src'

const { open, locked } = inject('relays')
const echo = inject('echo')
const LOOPBACK = Uint8Array.of(127, 0, 0, 1)
const encoder = new TextEncoder()
const decoder = new TextDecoder()

const outcome = <T>(promise: Promise<T>) => promise.then((value) => value, (error: unknown) => error)

const limited = <T>(promise: Promise<T>, ms = 5000) => {
  let timer: ReturnType<typeof setTimeout> | undefined
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`no result in ${ms} ms`)), ms) }),
  ]).finally(() => clearTimeout(timer))
}

/** Reads text off `readable` until `expected` came, or until its end when `expected` is not given. */
const readText = async (readable: ReadableStream<Uint8Array>, expected?: string) => {
  const reader = readable.getReader()
  let text = ''
  try {
    while (expected === undefined || text.length < expected.length) {
      const { value, done } = await limited(reader.read())
      if (done) break
      text += decoder.decode(value)
    }
    return text
  } finally {
    reader.releaseLock()
  }
}

const sessions: Session[] = []
afterEach(() => {
  for (const session of sessions.splice(0)) session.close()
})

describe.for(['webtransport', 'websocket'] as const)('over %s', (transport) => {
  const options = (relay: RelayInfo): ConnectOptions => ({
    url: relay.url,
    webSocketUrl: relay.webSocketUrl,
    transport,
    serverCertificateHashes: [{ algorithm: 'sha-256', value: Uint8Array.from(relay.certHash) }],
  })

  const opened = async (relay = open, credential?: Uint8Array) => {
    const session = await connect({ ...options(relay), credential })
    sessions.push(session)
    return session
  }

  it('connects and reads the relay\'s features', async () => {
    const session = await opened()
    expect(session.carrier).toBe(transport)
    expect(session.features & (Feature.LISTEN | Feature.DNS)).toBe(Feature.LISTEN | Feature.DNS)
  })

  it('echoes over TCP, half closes and reads the peer\'s end', async () => {
    const session = await opened()
    const socket = await session.tcpConnect({ ip: LOOPBACK, port: echo.tcp })
    expect(socket.remote).toEqual({ ip: LOOPBACK, port: echo.tcp })
    const writer = socket.writable.getWriter()
    await writer.write(encoder.encode('hello'))
    expect(await readText(socket.readable, 'hello')).toBe('hello')
    await writer.write(encoder.encode('bye'))
    await writer.close()
    expect(await readText(socket.readable)).toBe('bye')
    await socket.close()
  })

  it('closes a socket with its readable ended cleanly, and resets another', async () => {
    const session = await opened()
    const closing = await session.tcpConnect({ ip: LOOPBACK, port: echo.tcp })
    const reading = readText(closing.readable)
    await closing.close()
    expect(await reading).toBe('')

    const resetting = await session.tcpConnect({ ip: LOOPBACK, port: echo.tcp })
    await resetting.reset()
    expect(await readText(resetting.readable)).toBe('')
  })

  it('errors the readable with CONNECTION_RESET when the peer resets', async () => {
    const session = await opened()
    const socket = await session.tcpConnect({ ip: LOOPBACK, port: echo.tcp })
    await socket.writable.getWriter().write(encoder.encode('reset'))
    const error = await outcome(readText(socket.readable))
    expect(error).toBeInstanceOf(WebVpnError)
    expect(error).toMatchObject({ code: ErrorCode.CONNECTION_RESET })
  })

  it('accepts a connection on a listener', async () => {
    const session = await opened()
    const listener = await session.tcpListen({ ip: LOOPBACK, port: 0 })
    expect(listener.local.port).toBeGreaterThan(0)
    const dialed = commands.dialTcp(listener.local.port, 'from node')
    const { value: connection } = await limited(listener.connections.getReader().read())
    expect(await readText(connection!.readable)).toBe('from node')
    const writer = connection!.writable.getWriter()
    await writer.write(encoder.encode('from the page'))
    await writer.close()
    expect(await limited(dialed)).toBe('from the page')
    await listener.close()
    expect(await listener.closed).toEqual({ by: 'client' })
  })

  it('reaches the peer as a half close when the page aborts its side of a socket', async () => {
    const session = await opened()
    const listener = await session.tcpListen({ ip: LOOPBACK, port: 0 })
    const dialed = commands.dialTcp(listener.local.port, 'from node')
    const { value: connection } = await limited(listener.connections.getReader().read())
    expect(await readText(connection!.readable)).toBe('from node')
    await connection!.writable.abort()
    // a reset toward Node would reject this with ECONNRESET
    expect(await limited(dialed)).toBe('')
    await listener.close()
  })

  it('echoes over UDP', async () => {
    const session = await opened()
    const udp = await session.udpBind({ ip: LOOPBACK, port: 0 })
    const writer = udp.writable.getWriter()
    const reader = udp.readable.getReader()
    // WebTransport sends datagrams until the socket's stream comes, and a browser may drop those, so a few go out
    for (let attempt = 0; attempt < 5; attempt++) await writer.write({ remote: { ip: LOOPBACK, port: echo.udp }, data: encoder.encode('ping') })
    const { value } = await limited(reader.read())
    expect(value).toEqual({ remote: { ip: LOOPBACK, port: echo.udp }, data: encoder.encode('ping') })
    await udp.close()
    expect(await udp.closed).toEqual({ by: 'client' })
  })

  it('connects by name and looks a name up through the relay\'s resolver', async () => {
    const session = await opened()
    const socket = await session.tcpConnect({ name: 'echo.test', port: echo.tcp })
    expect(socket.remote).toEqual({ ip: LOOPBACK, port: echo.tcp })
    await socket.writable.getWriter().write(encoder.encode('named'))
    expect(await readText(socket.readable, 'named')).toBe('named')
    expect(dnsAddresses(await session.lookup(dnsQuery('echo.test'))).map(formatIp)).toEqual(['127.0.0.1'])
    expect(dnsAddresses(await session.lookup(dnsQuery('other.test')))).toEqual([])
    const missing = await outcome(session.tcpConnect({ name: 'other.test', port: echo.tcp }))
    expect(missing).toMatchObject({ code: ErrorCode.NAME_NOT_FOUND })
  })

  it('opens sockets on a relay that requires a credential only with the right one', async () => {
    const anonymous = await opened(locked)
    expect(anonymous.features & Feature.AUTH_REQUIRED).toBe(Feature.AUTH_REQUIRED)
    expect(await outcome(anonymous.tcpConnect({ ip: LOOPBACK, port: echo.tcp }))).toMatchObject({ code: ErrorCode.AUTH_REQUIRED })
    expect(await outcome(anonymous.lookup(dnsQuery('echo.test')))).toMatchObject({ code: ErrorCode.UNSUPPORTED })
    expect(await outcome(anonymous.tcpListen({ ip: LOOPBACK, port: 0 }))).toMatchObject({ code: ErrorCode.UNSUPPORTED })

    expect(await outcome(opened(locked, encoder.encode('wrong')))).toMatchObject({ code: ErrorCode.AUTH_FAILED })

    const session = await opened(locked, encoder.encode('right'))
    const socket = await session.tcpConnect({ ip: LOOPBACK, port: echo.tcp })
    await socket.close()
  })

  it('resolves draining, then closed with RESTARTING, when the relay stops', async () => {
    const relay = await commands.startRelay()
    const session = await opened(relay)
    let drained = false
    session.draining.then(() => { drained = true })
    const stopped = commands.stopRelay(relay.id)
    await limited(session.draining)
    const closed = await limited(session.closed)
    expect(drained).toBe(true)
    await stopped
    expect(closed).toEqual({ code: CloseCode.RESTARTING, reason: 'the relay is stopping' })
  })

  it('reads a full relay\'s refusal as SESSION_LIMIT', async () => {
    const full = await commands.startRelay({ WEBVPN_MAX_SESSIONS: '1' })
    try {
      await opened(full)
      const refused = await outcome(limited(connect(options(full))))
      expect(refused).toBeInstanceOf(WebVpnError)
      expect(refused).toMatchObject({ code: ErrorCode.CAPACITY, closeCode: CloseCode.SESSION_LIMIT })
    } finally {
      await commands.stopRelay(full.id)
    }
  })
})
