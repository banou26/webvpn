import type { Session } from '@webvpn/client'
import type { Server, Socket } from 'node:net'
import type { RelayInfo } from '../../client/tests/browser/rig'

import { connect as openSession } from '@webvpn/client'
import { commands } from 'vite-plus/test/browser'
import { afterAll, describe, expect, inject, it } from 'vite-plus/test'

import net, { setProvider } from '../src'

const relay: RelayInfo = inject('relays').open
const echo = inject('echo')

const limited = <T>(promise: Promise<T>, ms = 5000) => {
  let timer: ReturnType<typeof setTimeout> | undefined
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`no result in ${ms} ms`)), ms) }),
  ]).finally(() => clearTimeout(timer))
}

const once = <T = unknown>(emitter: Socket | Server, event: string) =>
  limited(new Promise<T>((resolve) => emitter.once(event, (value: T) => resolve(value))))

/** Everything the socket reads until the peer's end. */
const readAll = (socket: Socket) => {
  let text = ''
  socket.setEncoding('utf8')
  socket.on('data', (chunk: string) => { text += chunk })
  return once(socket, 'end').then(() => text)
}

// as an app does: the session opens at the first socket, over the WebSocket carrier (the client's own tests cover both)
let session: Session | undefined
setProvider(async () => session = await openSession({ webSocketUrl: relay.webSocketUrl, transport: 'websocket' }))
afterAll(() => session?.close())

describe('net over a real relay', () => {
  it('connects to the echo server, carries data both ways, and half closes', async () => {
    const socket = net.connect(echo.tcp, '127.0.0.1')
    await once(socket, 'connect')
    expect([socket.remoteAddress, socket.remotePort, socket.remoteFamily]).toEqual(['127.0.0.1', echo.tcp, 'IPv4'])
    const echoed = new Promise<string>((resolve) => socket.once('data', (chunk: Uint8Array) => resolve(new TextDecoder().decode(chunk))))
    socket.write('hello')
    expect(await limited(echoed)).toBe('hello')
    const rest = readAll(socket)
    // the echo server ends its side once it read this side's end
    socket.end('bye')
    expect(await rest).toBe('bye')
    expect(await once(socket, 'close')).toBe(false)
    expect([socket.bytesRead, socket.bytesWritten]).toEqual([8, 8])
  })

  it('fails a connect to a closed port with Node\'s ECONNREFUSED', async () => {
    const server = net.createServer().listen(0, '127.0.0.1')
    await once(server, 'listening')
    const { port } = server.address() as { port: number }
    await limited(new Promise((resolve) => server.close(resolve)))
    const socket = net.connect(port, '127.0.0.1')
    const error = await once<Error>(socket, 'error')
    expect(error).toMatchObject({
      message: `connect ECONNREFUSED 127.0.0.1:${port}`,
      errno: -111,
      code: 'ECONNREFUSED',
      syscall: 'connect',
      address: '127.0.0.1',
      port,
    })
    expect(socket.destroyed).toBe(true)
  })

  it('accepts a connection the rig dials from Node on a server', async () => {
    const server = net.createServer({ allowHalfOpen: true }).listen(0, '127.0.0.1')
    await once(server, 'listening')
    const { address, port } = server.address() as { address: string, port: number }
    expect(address).toBe('127.0.0.1')
    const accepted = once<Socket>(server, 'connection')
    const dialed = commands.dialTcp(port, 'from node')
    const socket = await accepted
    expect(socket.remoteAddress).toBe('127.0.0.1')
    expect(await readAll(socket)).toBe('from node')
    socket.end('from the page')
    expect(await limited(dialed)).toBe('from the page')
    await limited(new Promise((resolve) => server.close(resolve)))
  })

  it('connects to a name the relay looks up', async () => {
    const socket = net.connect(echo.tcp, 'echo.test')
    await once(socket, 'connect')
    expect(socket.remoteAddress).toBe('127.0.0.1')
    const echoed = new Promise<string>((resolve) => socket.once('data', (chunk: Uint8Array) => resolve(new TextDecoder().decode(chunk))))
    socket.write('named')
    expect(await limited(echoed)).toBe('named')
    socket.destroy()
    await once(socket, 'close')
  })
})
