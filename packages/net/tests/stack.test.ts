import type { Server, Socket } from 'node:net'

import { describe, expect, it, vi } from 'vite-plus/test'

import { at, CLIENT_PUBLIC, dnsAnswer, FIRST_PORT, internet, SITE } from '../../client/tests/stack/internet'
import { createNet } from '../src'

/**
 * The module on a stack over a tunnel instead of a session: `createNet` takes the stack as its provider unchanged, and
 * a second stack plays the internet (see the client's `tests/stack/internet.ts`).
 */
const once = <T = unknown>(emitter: Socket | Server, event: string) =>
  new Promise<T>((resolve) => emitter.once(event, (value: T) => resolve(value)))

const readAll = (socket: Socket) => {
  let text = ''
  socket.setEncoding('utf8')
  socket.on('data', (chunk: string) => { text += chunk })
  return once(socket, 'end').then(() => text)
}

/** A TCP echo server on the site's `port`, which ends its side once it read the peer's end. */
const echo = async (site: Awaited<ReturnType<typeof internet>>['site'], port: number) => {
  const listener = await site.tcpListen(at('0.0.0.0', port))
  void (async () => {
    for await (const socket of listener.connections) void socket.readable.pipeTo(socket.writable)
  })()
}

describe('net on a stack over a tunnel', () => {
  it('connects, carries data both ways and half closes, with Node\'s events', async () => {
    const { client, site } = await internet()
    await echo(site, 7)
    const net = createNet(client)
    const socket = net.connect(7, SITE)
    await once(socket, 'connect')
    expect([socket.remoteAddress, socket.remotePort, socket.remoteFamily]).toEqual([SITE, 7, 'IPv4'])
    const rest = readAll(socket)
    socket.end('hello over a tunnel')
    expect(await rest).toBe('hello over a tunnel')
    expect(await once(socket, 'close')).toBe(false)
    expect([socket.bytesRead, socket.bytesWritten]).toEqual([19, 19])
  })

  it('fails a connect to a closed port with Node\'s ECONNREFUSED', async () => {
    const { client } = await internet()
    const socket = createNet(client).connect(81, SITE)
    const error = await once<Error>(socket, 'error')
    expect(error).toMatchObject({ code: 'ECONNREFUSED', syscall: 'connect', address: SITE, port: 81 })
  })

  it('a peer silent through keep-alive destroys the socket with Node\'s ECONNRESET', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] })
    try {
      const { client, site, pipe } = await internet()
      await echo(site, 7)
      const socket = createNet(client).connect(7, SITE)
      await once(socket, 'connect')
      const error = once<Error>(socket, 'error')
      socket.setKeepAlive(true, 1000)
      await vi.advanceTimersByTimeAsync(50)
      pipe.drop = () => true
      // the idle second, then 9 probes 75 seconds apart
      await vi.advanceTimersByTimeAsync(1000 + 9 * 75_000 + 1000)
      expect(await error).toMatchObject({
        message: 'read ECONNRESET',
        errno: -104,
        code: 'ECONNRESET',
        syscall: 'read',
      })
    } finally {
      vi.useRealTimers()
    }
  })

  it('connects to a name the stack looks up through the tunnel', async () => {
    const { client, site } = await internet()
    const resolver = await site.udpBind(at('0.0.0.0', 53))
    const answers = resolver.writable.getWriter()
    void (async () => {
      for await (const { remote, data } of resolver.readable) answers.write({ remote, data: dnsAnswer(data, [SITE, '192.0.2.200']) })
    })()
    await echo(site, 80)
    const socket = createNet(client).connect(80, 'example.test')
    await once(socket, 'connect')
    expect(socket.remoteAddress).toBe(SITE)
    socket.destroy()
  })

  it('listens on a public port of the tunnel and takes the connection a peer dials there', async () => {
    const { client, site } = await internet()
    const server = createNet(client).createServer((socket) => socket.end('welcome'))
    server.listen(0)
    await once(server, 'listening')
    expect(server.address()).toMatchObject({ address: CLIENT_PUBLIC, port: FIRST_PORT, family: 'IPv4' })
    const dialed = await site.tcpConnect(at(CLIENT_PUBLIC, FIRST_PORT))
    const chunks: Uint8Array[] = []
    for await (const chunk of dialed.readable) chunks.push(chunk)
    expect(new TextDecoder().decode(Buffer.concat(chunks))).toBe('welcome')
    await new Promise((resolve) => server.close(resolve))
  })

  it('fails a listen on a port that is not public with Node\'s EADDRNOTAVAIL', async () => {
    const { client } = await internet()
    const server = createNet(client).createServer()
    server.listen(8080)
    expect(await once<Error>(server, 'error')).toMatchObject({ code: 'EADDRNOTAVAIL', syscall: 'listen', port: 8080 })
  })
})
