import { describe, expect, it } from 'vite-plus/test'

import { ErrorCode } from '../../src/protocol'
import { at, CLIENT_PUBLIC, FIRST_PORT, internet, pattern, readAll, SITE } from './internet'

// the stack in a page, its WebAssembly loaded as a bundler loads it; the unit project covers the behaviour in depth
describe('the stack in a browser', () => {
  it('connects and carries bytes both ways', async () => {
    const { client, site } = await internet()
    const listener = await site.tcpListen(at('0.0.0.0', 80))
    const socket = await client.tcpConnect(at(SITE, 80))
    const peer = (await listener.connections.getReader().read()).value!
    const writer = peer.writable.getWriter()
    void writer.write(pattern(200_000)).then(() => writer.close())
    const up = socket.writable.getWriter()
    void up.write(pattern(100_000)).then(() => up.close())
    const [down, back] = await Promise.all([readAll(socket.readable), readAll(peer.readable)])
    expect(down).toEqual(pattern(200_000))
    expect(back).toEqual(pattern(100_000))
    expect(await client.tcpConnect(at(SITE, 81)).catch((error: unknown) => error)).toMatchObject({ code: ErrorCode.CONNECTION_REFUSED })
  })

  it('listens on a public port and binds UDP on one', async () => {
    const { client, site } = await internet()
    const listener = await client.tcpListen(at('0.0.0.0', 0))
    expect(listener.local.port).toBe(FIRST_PORT)
    const dialed = site.tcpConnect(at(CLIENT_PUBLIC, FIRST_PORT))
    await listener.connections.getReader().read()
    await dialed
    const udp = await client.udpBind(at('0.0.0.0', 0))
    expect(udp.local.port).toBe(FIRST_PORT)
  })
})
