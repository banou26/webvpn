import type { Socket } from 'node:dgram'

import { describe, expect, it } from 'vite-plus/test'

import { at, CLIENT, CLIENT_PUBLIC, FIRST_PORT, internet, SITE } from '../../client/tests/stack/internet'
import { createDgram } from '../src'

/**
 * The module on a stack over a tunnel instead of a session: `createDgram` takes the stack as its provider unchanged,
 * and a second stack plays the internet (see the client's `tests/stack/internet.ts`).
 */
const message = (socket: Socket) =>
  new Promise<[Buffer, { address: string, port: number }]>((resolve) => socket.once('message', (data, info) => resolve([data, info])))

/** A UDP echo server on the site's port 7, which notes where each datagram came from. */
const echo = async (site: Awaited<ReturnType<typeof internet>>['site']) => {
  const socket = await site.udpBind(at('0.0.0.0', 7))
  const writer = socket.writable.getWriter()
  const from: string[] = []
  void (async () => {
    for await (const { remote, data } of socket.readable) {
      from.push(`${remote.ip.join('.')}:${remote.port}`)
      writer.write({ remote, data })
    }
  })()
  return from
}

describe('dgram on a stack over a tunnel', () => {
  it('echoes a datagram from the implicit bind of a first send, on a public port', async () => {
    const { client, site } = await internet()
    const from = await echo(site)
    const socket = createDgram(client).createSocket('udp4')
    const echoed = message(socket)
    socket.send('ping', 7, SITE)
    const [data, info] = await echoed
    expect([data.toString(), info.address, info.port]).toEqual(['ping', SITE, 7])
    expect(socket.address()).toMatchObject({ address: CLIENT_PUBLIC, port: FIRST_PORT, family: 'IPv4' })
    expect(from).toEqual([`${CLIENT_PUBLIC}:${FIRST_PORT}`])
    socket.close()
  })

  it('echoes on a connected socket, from a private port once the public ones are taken', async () => {
    const { client, site } = await internet({ ports: 1 })
    await echo(site)
    const dgram = createDgram(client)
    const first = dgram.createSocket('udp4')
    await new Promise<void>((resolve) => first.bind(0, resolve))
    const socket = dgram.createSocket('udp4')
    await new Promise<void>((resolve) => socket.connect(7, SITE, resolve))
    expect(socket.address().address).toBe(CLIENT)
    expect(socket.remoteAddress()).toMatchObject({ address: SITE, port: 7 })
    const echoed = message(socket)
    socket.send('connected')
    expect((await echoed)[0].toString()).toBe('connected')
    first.close()
    socket.close()
  })
})
