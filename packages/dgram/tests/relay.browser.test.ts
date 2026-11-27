import type { Session } from '@webvpn/client'
import type { RemoteInfo } from 'node:dgram'
import type { RelayInfo } from '../../client/tests/browser/rig'

import { connect as openSession } from '@webvpn/client'
import { afterAll, describe, expect, inject, it } from 'vite-plus/test'

import dgram, { setProvider } from '../src'

const relay: RelayInfo = inject('relays').open
const echo = inject('echo')

const limited = <T>(promise: Promise<T>, ms = 5000) => {
  let timer: ReturnType<typeof setTimeout> | undefined
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`no result in ${ms} ms`)), ms) }),
  ]).finally(() => clearTimeout(timer))
}

// as an app does: the session opens at the first socket, over the WebSocket carrier (the client's own tests cover both)
let session: Session | undefined
setProvider(async () => session = await openSession({ webSocketUrl: relay.webSocketUrl, transport: 'websocket' }))
afterAll(() => session?.close())

describe('dgram over a real relay', () => {
  it('echoes a datagram, with the implicit bind of a first send', async () => {
    const socket = dgram.createSocket('udp4')
    const reply = limited(new Promise<[string, RemoteInfo]>((resolve) => socket.once('message', (message: Uint8Array, remote: RemoteInfo) => {
      resolve([new TextDecoder().decode(message), remote])
    })))
    const sent = await limited(new Promise<number | undefined>((resolve, reject) => {
      socket.send('ping', echo.udp, '127.0.0.1', (error, bytes) => error ? reject(error) : resolve(bytes))
    }))
    expect(sent).toBe(4)
    expect(socket.address().port).toBeGreaterThan(0)
    expect(await reply).toEqual(['ping', { address: '127.0.0.1', family: 'IPv4', port: echo.udp, size: 4 }])
    await limited(new Promise<void>((resolve) => socket.close(resolve)))
  })

  it('echoes on a connected socket, to the peer it connected to', async () => {
    const socket = dgram.createSocket('udp4')
    await limited(new Promise<void>((resolve) => socket.connect(echo.udp, '127.0.0.1', resolve)))
    expect(socket.remoteAddress()).toEqual({ address: '127.0.0.1', family: 'IPv4', port: echo.udp })
    const reply = limited(new Promise<string>((resolve) => socket.once('message', (message: Uint8Array) => resolve(new TextDecoder().decode(message)))))
    socket.send('connected')
    expect(await reply).toBe('connected')
    await limited(new Promise<void>((resolve) => socket.close(resolve)))
  })

  it('sends to an address again after a disconnect, from the port it had', async () => {
    const socket = dgram.createSocket('udp4')
    await limited(new Promise<void>((resolve) => socket.connect(echo.udp, '127.0.0.1', resolve)))
    const { port } = socket.address()
    socket.disconnect()
    const reply = limited(new Promise<string>((resolve) => socket.once('message', (message: Uint8Array) => resolve(new TextDecoder().decode(message)))))
    socket.send('after', echo.udp, '127.0.0.1')
    expect(await reply).toBe('after')
    expect(socket.address().port).toBe(port)
    await limited(new Promise<void>((resolve) => socket.close(resolve)))
  })
})
