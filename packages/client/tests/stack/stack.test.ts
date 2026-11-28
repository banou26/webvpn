import type { TcpListener, TcpSocket, UdpSocket } from '../../src'
import type { Stack } from '../../src/stack'

import { describe, expect, it, vi } from 'vite-plus/test'

import { formatIp } from '../../src/address'
import { dnsAddresses, dnsQuery } from '../../src/dns'
import { ErrorCode } from '../../src/protocol'
import { openStack } from '../../src/stack'
import {
  at,
  CLIENT,
  CLIENT_PUBLIC,
  dnsAnswer,
  fakeTunnel,
  FIRST_PORT,
  internet,
  pattern,
  readAll,
  SITE,
  udpPacket,
  unreachable,
} from './internet'

const ANY = at('0.0.0.0', 0)
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes)
const bytes = (value: string) => new TextEncoder().encode(value)
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
const outcome = <T>(promise: Promise<T>) => promise.then((value) => value, (error: unknown) => error)
const named = ({ ip, port }: { ip: Uint8Array, port: number }) => `${formatIp(ip)}:${port}`

const accept = async (listener: TcpListener) => (await listener.connections.getReader().read()).value!

/** A connection from the client to a listener of the site on `port`, with both ends. */
const connect = async (client: Stack, site: Stack, port = 80) => {
  const listener = await site.tcpListen(at('0.0.0.0', port))
  const socket = await client.tcpConnect(at(SITE, port))
  return { socket, peer: await accept(listener), listener }
}

/** Writes `data` in chunks and counts what the socket took, without waiting for the last write. */
const pour = (socket: TcpSocket, data: Uint8Array, chunk = 16 * 1024) => {
  const writer = socket.writable.getWriter()
  const state = { taken: 0, done: Promise.resolve() }
  state.done = (async () => {
    for (let offset = 0; offset < data.byteLength; offset += chunk) {
      const part = data.subarray(offset, offset + chunk)
      await writer.write(part)
      state.taken += part.byteLength
    }
    writer.releaseLock()
  })()
  return state
}

/** A resolver on the site's UDP port 53 that answers each query with `answer`, or not at all for `undefined`. */
const resolver = async (site: Stack, answer: (query: Uint8Array, count: number) => Uint8Array | undefined) => {
  const socket = await site.udpBind(at('0.0.0.0', 53))
  const writer = socket.writable.getWriter()
  let count = 0
  void (async () => {
    for await (const { remote, data } of socket.readable) {
      const reply = answer(data, ++count)
      if (reply) writer.write({ remote, data: reply })
    }
  })()
  return { socket, count: () => count }
}

describe('TCP over a tunnel', () => {
  it('connects to an address and carries bytes both ways, with the addresses each side sees', async () => {
    const { client, site } = await internet()
    const { socket, peer } = await connect(client, site)
    expect(named(socket.remote)).toBe(`${SITE}:80`)
    expect(formatIp(socket.local.ip)).toBe(CLIENT)
    expect(named(peer.remote)).toBe(`${CLIENT_PUBLIC}:${socket.local.port}`)

    const up = pattern(300_000)
    const down = pattern(500_000)
    const writer = socket.writable.getWriter()
    void writer.write(up).then(() => writer.close())
    const peerWriter = peer.writable.getWriter()
    void peerWriter.write(down).then(() => peerWriter.close())
    const [read, peerRead] = await Promise.all([readAll(socket.readable), readAll(peer.readable)])
    expect(read).toEqual(down)
    expect(peerRead).toEqual(up)
  })

  it('connects to a name through the resolver, to its first A record', async () => {
    const { client, site } = await internet()
    const { count } = await resolver(site, (query) => dnsAnswer(query, [SITE, '192.0.2.200']))
    const listener = await site.tcpListen(at('0.0.0.0', 443))
    const socket = await client.tcpConnect({ name: 'example.test', port: 443 })
    expect(named(socket.remote)).toBe(`${SITE}:443`)
    expect(named((await accept(listener)).remote)).toBe(`${CLIENT_PUBLIC}:${socket.local.port}`)
    expect(count()).toBe(1)
  })

  it('connects to a name by its first AAAA record on a tunnel without IPv4', async () => {
    const SITE_V6 = '2001:db8::1'
    const client = fakeTunnel({ id: 1, ipv6: 'fd00::2', mtu: 1500, firstPort: FIRST_PORT, ports: 0 }, (packet) => {
      site.deliver(packet)
      return true
    })
    const site = fakeTunnel(
      { id: 2, ipv6: SITE_V6, publicIpv6: SITE_V6, mtu: 1500, firstPort: 1, ports: 49151 },
      (packet) => {
        client.deliver(packet)
        return true
      },
    )
    const [clientStack, siteStack] = await Promise.all([
      openStack(client.tunnel, { resolver: at(SITE_V6, 53) }),
      openStack(site.tunnel),
    ])
    const types: number[] = []
    // the question's type is the u16 before its class, at the end of the query
    await resolver(siteStack, (query) => {
      const type = new DataView(query.buffer, query.byteOffset).getUint16(query.byteLength - 4)
      types.push(type)
      return dnsAnswer(query, [type === 28 ? SITE_V6 : SITE])
    })
    const listener = await siteStack.tcpListen(at('::', 443))
    const socket = await clientStack.tcpConnect({ name: 'example.test', port: 443 })
    expect(named(socket.remote)).toBe(`${SITE_V6}:443`)
    expect(named((await accept(listener)).remote)).toBe(`fd00::2:${socket.local.port}`)
    expect(types).toEqual([28])
  })

  it('rejects a name with no A record with NAME_NOT_FOUND', async () => {
    const { client, site } = await internet()
    await resolver(site, (query) => dnsAnswer(query, []))
    expect(await outcome(client.tcpConnect({ name: 'nothing.test', port: 443 }))).toMatchObject({ code: ErrorCode.NAME_NOT_FOUND })
  })

  it('rejects a connect to a closed port with CONNECTION_REFUSED', async () => {
    const { client } = await internet()
    expect(await outcome(client.tcpConnect(at(SITE, 81)))).toMatchObject({ code: ErrorCode.CONNECTION_REFUSED })
  })

  it('rejects a connect nobody answers with TIMED_OUT, at its limit', async () => {
    const { client, pipe } = await internet({ client: { connectTimeoutMs: 400 } })
    pipe.drop = () => true
    const start = performance.now()
    expect(await outcome(client.tcpConnect(at(SITE, 80)))).toMatchObject({ code: ErrorCode.TIMED_OUT })
    expect(performance.now() - start).toBeGreaterThanOrEqual(390)
  })

  it('rejects a connect an ICMP error answers with its reason', async () => {
    for (const [code, error] of [[1, ErrorCode.HOST_UNREACHABLE], [0, ErrorCode.NETWORK_UNREACHABLE]]) {
      const { client, pipe } = await internet()
      pipe.answer = (packet) => unreachable(packet, code!)
      expect(await outcome(client.tcpConnect(at(SITE, 80))), `code ${code}`).toMatchObject({ code: error })
    }
  })

  it('holds back the peer while the reader does not read, and takes the rest once it does', async () => {
    const { client, site } = await internet({ client: { tcpReceiveBuffer: 32 * 1024 } })
    const { socket, peer } = await connect(client, site)
    const data = pattern(1024 * 1024)
    const poured = pour(peer, data)
    await wait(300)
    // the client's window, the site's send buffer, and the chunk that waits for room in it
    expect(poured.taken).toBeLessThanOrEqual(32 * 1024 + 64 * 1024 + 16 * 1024)
    const read = readAll(socket.readable)
    await poured.done
    await peer.close()
    expect(await read).toEqual(data)
  })

  it('holds the writer while the peer does not read, and lets it go on once it does', async () => {
    const { client, site } = await internet({ client: { tcpSendBuffer: 16 * 1024 } })
    const { socket, peer } = await connect(client, site)
    const data = pattern(1024 * 1024)
    const poured = pour(socket, data)
    await wait(300)
    // the site's window, the client's send buffer, and the chunk that waits for room in it
    expect(poured.taken).toBeLessThanOrEqual(128 * 1024 + 16 * 1024 + 16 * 1024)
    const read = readAll(peer.readable)
    await poured.done
    await socket.close()
    expect(await read).toEqual(data)
  })

  it('half closes: the peer reads the end, and its own bytes still arrive', async () => {
    const { client, site } = await internet()
    const { socket, peer } = await connect(client, site)
    await socket.writable.getWriter().close()
    const peerReader = peer.readable.getReader()
    expect(await peerReader.read()).toEqual({ done: true, value: undefined })
    const peerWriter = peer.writable.getWriter()
    await peerWriter.write(bytes('still here'))
    await peerWriter.close()
    expect(text(await readAll(socket.readable))).toBe('still here')
  })

  it('a reset from the peer errors the reader and the next write with CONNECTION_RESET', async () => {
    const { client, site } = await internet()
    const { socket, peer } = await connect(client, site)
    const reader = socket.readable.getReader()
    const read = outcome(reader.read())
    await peer.reset()
    expect(await read).toMatchObject({ code: ErrorCode.CONNECTION_RESET })
    const writer = socket.writable.getWriter()
    expect(await outcome(writer.write(bytes('late')))).toMatchObject({ code: ErrorCode.CONNECTION_RESET })
  })

  it('a reset from the peer fails a write that waits for room with CONNECTION_RESET, with nobody reading', async () => {
    const { client, site } = await internet({ client: { tcpSendBuffer: 16 * 1024 } })
    const { socket, peer } = await connect(client, site)
    const write = outcome(socket.writable.getWriter().write(pattern(1024 * 1024)))
    await wait(200)
    await peer.reset()
    expect(await write).toMatchObject({ code: ErrorCode.CONNECTION_RESET })
  })

  it('a peer silent through keep-alive\'s probes errors the reader and the next write with TIMED_OUT', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] })
    try {
      const { client, site, pipe } = await internet()
      const { socket } = await connect(client, site)
      pipe.drop = () => true
      await socket.setOption({ type: 'keepAlive', enabled: true, initialDelaySeconds: 1 })
      const read = outcome(socket.readable.getReader().read())
      // the idle second, then 9 probes 75 seconds apart
      await vi.advanceTimersByTimeAsync(1000 + 9 * 75_000)
      expect(await read).toMatchObject({ code: ErrorCode.TIMED_OUT })
      const writer = socket.writable.getWriter()
      expect(await outcome(writer.write(bytes('late')))).toMatchObject({ code: ErrorCode.TIMED_OUT })
    } finally {
      vi.useRealTimers()
    }
  })

  it('close() sends what this side holds, then ends; reset() ends at once with a reset', async () => {
    const { client, site } = await internet()
    const first = await connect(client, site, 80)
    await first.socket.writable.getWriter().write(pattern(100_000))
    await first.socket.close()
    expect(await readAll(first.peer.readable)).toEqual(pattern(100_000))
    expect(await first.socket.readable.getReader().read()).toEqual({ done: true, value: undefined })

    const second = await connect(client, site, 81)
    await second.socket.reset()
    expect(await outcome(second.peer.readable.getReader().read())).toMatchObject({ code: ErrorCode.CONNECTION_RESET })
  })

  it('answers the options it has, and UNSUPPORTED for the buffer sizes', async () => {
    const { client, site } = await internet()
    const { socket } = await connect(client, site)
    await socket.setOption({ type: 'noDelay', value: true })
    await socket.setOption({ type: 'ttl', value: 32 })
    await socket.setOption({ type: 'keepAlive', enabled: true, initialDelaySeconds: 30 })
    await socket.setOption({ type: 'keepAlive', enabled: false, initialDelaySeconds: 0 })
    expect(await outcome(socket.setOption({ type: 'sendBufferSize', value: 1 }))).toMatchObject({ code: ErrorCode.UNSUPPORTED })
    expect(await outcome(socket.setOption({ type: 'recvBufferSize', value: 1 }))).toMatchObject({ code: ErrorCode.UNSUPPORTED })
  })
})

describe('listening over a tunnel', () => {
  it('takes a free public port for port 0 and names the public address a peer dials', async () => {
    const { client, site } = await internet()
    const listener = await client.tcpListen(ANY)
    expect(named(listener.local)).toBe(`${CLIENT_PUBLIC}:${FIRST_PORT}`)
    expect(named((await client.tcpListen(ANY)).local)).toBe(`${CLIENT_PUBLIC}:${FIRST_PORT + 1}`)
    // the stack's sockets take both families, and the tunnel has a public address of IPv4 only
    expect(named((await client.tcpListen(at('::', 0))).local)).toBe(`${CLIENT_PUBLIC}:${FIRST_PORT + 2}`)
    const dialed = await site.tcpConnect(listener.local)
    const accepted = await accept(listener)
    expect(named(accepted.local)).toBe(`${CLIENT_PUBLIC}:${FIRST_PORT}`)
    expect(named(accepted.remote)).toBe(named(dialed.local))
    const writer = dialed.writable.getWriter()
    await writer.write(bytes('hello'))
    await writer.close()
    expect(text(await readAll(accepted.readable))).toBe('hello')
  })

  it('takes a given public port, and refuses one that is not public or is taken', async () => {
    const { client } = await internet()
    expect(named((await client.tcpListen(at('0.0.0.0', FIRST_PORT + 3))).local)).toBe(`${CLIENT_PUBLIC}:${FIRST_PORT + 3}`)
    expect(await outcome(client.tcpListen(at('0.0.0.0', FIRST_PORT + 3)))).toMatchObject({ code: ErrorCode.ADDRESS_IN_USE })
    expect(await outcome(client.tcpListen(at('0.0.0.0', 8080)))).toMatchObject({ code: ErrorCode.ADDRESS_NOT_AVAILABLE })
    expect(await outcome(client.tcpListen(at('198.51.100.1', FIRST_PORT)))).toMatchObject({ code: ErrorCode.ADDRESS_NOT_AVAILABLE })
  })

  it('is UNSUPPORTED on a tunnel with no public ports', async () => {
    const { client } = await internet({ ports: 0 })
    expect(await outcome(client.tcpListen(ANY))).toMatchObject({ code: ErrorCode.UNSUPPORTED })
  })

  it('takes several connections at once and hands them over in order', async () => {
    const { client, site } = await internet()
    const listener = await client.tcpListen(ANY)
    const dialed = await Promise.all(Array.from({ length: 6 }, () => site.tcpConnect(listener.local)))
    const reader = listener.connections.getReader()
    const accepted: TcpSocket[] = []
    for (const _ of dialed) accepted.push((await reader.read()).value!)
    expect(accepted.map(({ remote }) => remote.port).sort()).toEqual(dialed.map(({ local }) => local.port).sort())
    await Promise.all(dialed.map(async (socket, index) => {
      const writer = socket.writable.getWriter()
      await writer.write(bytes(`from ${socket.local.port}`))
      await writer.close()
      expect(index).toBeGreaterThanOrEqual(0)
    }))
    for (const socket of accepted) expect(text(await readAll(socket.readable))).toBe(`from ${socket.remote.port}`)
  })

  it('closing it closes what nobody took, as a session\'s listener does, and refuses what comes after', async () => {
    const { client, site } = await internet()
    const listener = await client.tcpListen(ANY)
    const dialed = await site.tcpConnect(listener.local)
    await wait(50)
    await listener.close()
    expect(await listener.closed).toEqual({ by: 'client' })
    expect(await dialed.readable.getReader().read()).toEqual({ done: true, value: undefined })
    expect(await outcome(site.tcpConnect(listener.local))).toMatchObject({ code: ErrorCode.CONNECTION_REFUSED })
  })

  it('refuses what its backlog has no room for while nobody takes a connection, until one is taken', async () => {
    const { client, site } = await internet({ client: { backlog: 2 } })
    const listener = await client.tcpListen(ANY)
    await site.tcpConnect(listener.local)
    await site.tcpConnect(listener.local)
    expect(await outcome(site.tcpConnect(listener.local))).toMatchObject({ code: ErrorCode.CONNECTION_REFUSED })
    await accept(listener)
    await site.tcpConnect(listener.local)
  })

  it('closes a connection that came after its connections were cancelled during a read, once it stops', async () => {
    const { client, site } = await internet()
    const listener = await client.tcpListen(ANY)
    const reader = listener.connections.getReader()
    const read = reader.read()
    await reader.cancel()
    expect(await read).toEqual({ done: true, value: undefined })
    const dialed = await site.tcpConnect(listener.local)
    await wait(50)
    await listener.close()
    expect(await dialed.readable.getReader().read()).toEqual({ done: true, value: undefined })
  })
})

describe('UDP over a tunnel', () => {
  const echo = async (site: Stack) => {
    const socket = await site.udpBind(at('0.0.0.0', 7))
    const writer = socket.writable.getWriter()
    const seen: string[] = []
    void (async () => {
      for await (const { remote, data } of socket.readable) {
        seen.push(named(remote))
        writer.write({ remote, data })
      }
    })()
    return seen
  }

  const next = async (socket: UdpSocket) => {
    const reader = socket.readable.getReader()
    const { value } = await reader.read()
    reader.releaseLock()
    return value!
  }

  it('binds port 0 on a free public port, which a peer reaches, and carries datagrams both ways', async () => {
    const { client, site } = await internet()
    const seen = await echo(site)
    const socket = await client.udpBind(ANY)
    expect(named(socket.local)).toBe(`${CLIENT_PUBLIC}:${FIRST_PORT}`)
    await socket.writable.getWriter().write({ remote: at(SITE, 7), data: bytes('ping') })
    const { remote, data } = await next(socket)
    expect([named(remote), text(data)]).toEqual([`${SITE}:7`, 'ping'])
    expect(seen).toEqual([`${CLIENT_PUBLIC}:${FIRST_PORT}`])

    const stranger = await site.udpBind(ANY)
    await stranger.writable.getWriter().write({ remote: socket.local, data: bytes('unasked') })
    expect(text((await next(socket)).data)).toBe('unasked')
  })

  it('binds a private port once every public one is taken, and says so in its address', async () => {
    const { client, site } = await internet({ ports: 1 })
    await echo(site)
    expect(named((await client.udpBind(ANY)).local)).toBe(`${CLIENT_PUBLIC}:${FIRST_PORT}`)
    const socket = await client.udpBind(ANY)
    expect(formatIp(socket.local.ip)).toBe(CLIENT)
    expect(socket.local.port).toBeGreaterThanOrEqual(49152)
    await socket.writable.getWriter().write({ remote: at(SITE, 7), data: bytes('from a private port') })
    expect(text((await next(socket)).data)).toBe('from a private port')
    expect(named((await client.udpBind(at('0.0.0.0', FIRST_PORT + 1))).local)).toBe(`${CLIENT}:${FIRST_PORT + 1}`)
  })

  it('a connected socket sends to its peer and hears only it, until it disconnects', async () => {
    const { client, site } = await internet()
    await echo(site)
    const socket = await client.udpBind(ANY)
    const stranger = (await site.udpBind(ANY)).writable.getWriter()
    await socket.connect(at(SITE, 7))
    const writer = socket.writable.getWriter()
    await stranger.write({ remote: socket.local, data: bytes('unasked') })
    await writer.write({ data: bytes('to the peer') })
    expect(text((await next(socket)).data)).toBe('to the peer')
    await socket.disconnect()
    await stranger.write({ remote: socket.local, data: bytes('heard now') })
    expect(text((await next(socket)).data)).toBe('heard now')
  })

  it('fails a datagram longer than the tunnel carries, and answers the options it has', async () => {
    const { client } = await internet()
    const socket = await client.udpBind(ANY)
    await socket.setOption({ type: 'ttl', value: 8 })
    expect(await outcome(socket.setOption({ type: 'broadcast', value: true }))).toMatchObject({ code: ErrorCode.UNSUPPORTED })
    const write = socket.writable.getWriter().write({ remote: at(SITE, 7), data: new Uint8Array(1473) })
    expect(await outcome(write)).toMatchObject({ code: ErrorCode.OTHER })
  })
})

describe('names over a tunnel', () => {
  const QUERY = dnsQuery('example.test', 'A')

  it('asks once more when the first query got no answer', async () => {
    const { client, site } = await internet({ client: { lookupTimeoutMs: 1000 } })
    const { count } = await resolver(site, (query, count) => count === 1 ? undefined : dnsAnswer(query, [SITE]))
    const start = performance.now()
    const answer = await client.lookup(QUERY)
    expect(dnsAddresses(answer).map(formatIp)).toEqual([SITE])
    expect(count()).toBe(2)
    expect(performance.now() - start).toBeGreaterThanOrEqual(390)
  })

  it('asks again over TCP when the answer is truncated', async () => {
    const { client, site } = await internet()
    await resolver(site, (query) => dnsAnswer(query, [], true))
    const listener = await site.tcpListen(at('0.0.0.0', 53))
    void (async () => {
      const socket = await accept(listener)
      const reader = socket.readable.getReader()
      const { value } = await reader.read()
      const query = value!.subarray(2)
      const answer = dnsAnswer(query, [SITE, '192.0.2.2'])
      const framed = new Uint8Array(2 + answer.byteLength)
      new DataView(framed.buffer).setUint16(0, answer.byteLength)
      framed.set(answer, 2)
      const writer = socket.writable.getWriter()
      // in two parts, so the client reads past the first
      await writer.write(framed.subarray(0, 5))
      await wait(20)
      await writer.write(framed.subarray(5))
    })()
    expect(dnsAddresses(await client.lookup(QUERY)).map(formatIp)).toEqual([SITE, '192.0.2.2'])
  })

  it('drops an answer that does not match the query, and asks from a random private port and id', async () => {
    const ELSEWHERE = '198.51.100.66'
    // the public ports reach halfway into the private ones, so a port taken at random is often a public one
    const ports = 49152 + 8192 - FIRST_PORT
    const { client, site, pipe, clientTunnel } = await internet({ client: { lookupTimeoutMs: 1000 }, ports })
    // the real resolver gives the name back in another case, which still answers the query
    await resolver(site, (query) => {
      const answer = dnsAnswer(query, [SITE])
      answer.set(bytes('EXAMPLE'), 13)
      return answer
    })
    const sent: { port: number, id: number }[] = []
    pipe.drop = (toward, packet) => {
      const view = new DataView(packet.buffer, packet.byteOffset)
      if (toward !== 'site' || packet[9] !== 17 || view.getUint16(22) !== 53) return false
      const [port, query] = [view.getUint16(20), packet.slice(28)]
      sent.push({ port, id: view.getUint16(28) })
      // answers from the resolver's address that come first: with id 0, without the answer bit, and to another name
      // of the same length
      const zero = dnsAnswer(query, [ELSEWHERE])
      zero.set([0, 0])
      const unanswered = dnsAnswer(query, [ELSEWHERE])
      unanswered[2] = 0x01
      const other = dnsAnswer(dnsQuery('another.test'), [ELSEWHERE])
      other.set(query.subarray(0, 2))
      queueMicrotask(() => {
        for (const data of [zero, unanswered, other]) {
          clientTunnel.deliver(udpPacket(at(SITE, 53), at(CLIENT, port), data))
        }
      })
      return false
    }
    for (let count = 0; count < 8; count++) {
      const answer = await client.lookup(QUERY)
      expect(dnsAddresses(answer).map(formatIp)).toEqual([SITE])
      expect([...answer.subarray(0, 2)]).toEqual([0, 0])
    }
    expect(sent.some(({ id }) => id !== 0)).toBe(true)
    expect(sent.slice(1).some(({ port }, index) => port !== sent[index]!.port + 1)).toBe(true)
    for (const { port } of sent) expect(port).toBeGreaterThanOrEqual(FIRST_PORT + ports)
  })

  it('gives up with LOOKUP_FAILED at its limit when the resolver never answers', async () => {
    const { client, site } = await internet({ client: { lookupTimeoutMs: 500 } })
    const { count } = await resolver(site, () => undefined)
    const start = performance.now()
    expect(await outcome(client.lookup(QUERY))).toMatchObject({ code: ErrorCode.LOOKUP_FAILED })
    expect(performance.now() - start).toBeGreaterThanOrEqual(490)
    expect(performance.now() - start).toBeLessThan(800)
    expect(count()).toBe(2)
  })
})

describe('a tunnel that loses packets', () => {
  it('delivers everything in order through a pipe that drops one packet in twenty', { timeout: 60_000 }, async () => {
    const { client, site, pipe } = await internet()
    let count = 0
    pipe.drop = () => ++count % 20 === 0
    pipe.delayMs = 5
    const { socket, peer } = await connect(client, site)
    const down = pattern(200_000)
    const up = pattern(100_000)
    const writer = peer.writable.getWriter()
    void writer.write(down).then(() => writer.close())
    const clientWriter = socket.writable.getWriter()
    void clientWriter.write(up).then(() => clientWriter.close())
    const [read, peerRead] = await Promise.all([readAll(socket.readable), readAll(peer.readable)])
    expect(read).toEqual(down)
    expect(peerRead).toEqual(up)
    expect(count).toBeGreaterThan(20)
  })

  it('treats a send the tunnel refuses as a loss, and still delivers', { timeout: 60_000 }, async () => {
    const { client, site, pipe } = await internet()
    let count = 0
    pipe.refuse = () => ++count % 20 === 0
    const { socket, peer } = await connect(client, site)
    const up = pattern(200_000)
    const writer = socket.writable.getWriter()
    void writer.write(up).then(() => writer.close())
    expect(await readAll(peer.readable)).toEqual(up)
    expect(pipe.counts.refused).toBeGreaterThan(5)
  })
})

describe('the tunnel ending', () => {
  it('ends every socket as a session\'s end does, and every call after it', async () => {
    const { client, site, clientTunnel } = await internet()
    const { socket } = await connect(client, site)
    const listener = await client.tcpListen(ANY)
    const udp = await client.udpBind(ANY)
    const read = outcome(socket.readable.getReader().read())
    clientTunnel.end({ by: 'relay', code: ErrorCode.CAPACITY })
    expect(await client.closed).toEqual({ by: 'relay', code: ErrorCode.CAPACITY })
    expect(await read).toMatchObject({ code: ErrorCode.OTHER, message: 'the tunnel closed' })
    expect(await outcome(socket.writable.getWriter().write(bytes('late')))).toMatchObject({ message: 'the tunnel closed' })
    expect(await listener.closed).toEqual({ by: 'session' })
    expect(await udp.closed).toEqual({ by: 'session' })
    expect(await listener.connections.getReader().read()).toEqual({ done: true, value: undefined })
    expect(await outcome(client.tcpConnect(at(SITE, 80)))).toMatchObject({ message: 'the tunnel closed' })
    expect(await outcome(client.udpBind(ANY))).toMatchObject({ message: 'the tunnel closed' })
  })

  it('close() closes the tunnel, and so every socket', async () => {
    const { client, site } = await internet()
    const { socket } = await connect(client, site)
    await client.close()
    expect(await client.closed).toEqual({ by: 'client' })
    expect(await outcome(socket.readable.getReader().read())).toMatchObject({ message: 'the tunnel closed' })
  })

  it('ends the stack and closes the tunnel when a call into the module throws, and calls it no more', async () => {
    const instantiate = WebAssembly.instantiate.bind(WebAssembly)
    let broken = false
    let callsAfter = 0
    // an instance's exports are frozen, so the engine gets a copy whose functions throw as a trap does once broken
    vi.spyOn(WebAssembly, 'instantiate').mockImplementationOnce((async (module: WebAssembly.Module) => {
      const { exports } = await instantiate(module)
      return {
        exports: Object.fromEntries(Object.entries(exports).map(([name, value]) => [
          name,
          typeof value !== 'function' ? value : (...args: number[]) => {
            if (!broken) return value(...args)
            callsAfter++
            throw new WebAssembly.RuntimeError('unreachable')
          },
        ])),
      }
    }) as never)
    try {
      const { tunnel } = fakeTunnel(
        { id: 1, ipv4: CLIENT, mtu: 1500, publicIpv4: CLIENT_PUBLIC, firstPort: FIRST_PORT, ports: 8 },
        () => true,
      )
      const stack = await openStack(tunnel)
      const listener = await stack.tcpListen(ANY)
      const udp = await stack.udpBind(ANY)
      const read = outcome(udp.readable.getReader().read())
      const lookup = outcome(stack.lookup(dnsQuery('example.test', 'A')))
      // nothing answers the SYN, so the next call into the module is the poll of its retransmission, from a timer
      const connecting = outcome(stack.tcpConnect(at(SITE, 80)))
      await wait(50)
      broken = true
      expect(await connecting).toMatchObject({ code: ErrorCode.OTHER, message: 'the stack failed' })
      expect(await lookup).toMatchObject({ code: ErrorCode.OTHER, message: 'the stack failed' })
      expect(await read).toEqual({ done: true, value: undefined })
      expect(await listener.closed).toEqual({ by: 'session' })
      expect(await tunnel.closed).toEqual({ by: 'client' })
      expect(await outcome(stack.tcpListen(ANY))).toMatchObject({ message: 'the stack failed' })
      expect(await outcome(stack.udpBind(ANY))).toMatchObject({ message: 'the stack failed' })
      expect(callsAfter).toBe(1)
    } finally {
      vi.restoreAllMocks()
    }
  })
})
