import { at, internet, SITE } from './internet'

/**
 * Megabits per second of one TCP download of `megabytes` through the whole glue: the site's stack writes, the fake
 * tunnels and their pipe carry the packets, and the client's stack and streams read. Both stacks run in this thread,
 * so the figure is what one page's thread gets for both ends together.
 */
export const measure = async (megabytes: number) => {
  const { client, site } = await internet()
  const listener = await site.tcpListen(at('0.0.0.0', 80))
  const socket = await client.tcpConnect(at(SITE, 80))
  const peer = (await listener.connections.getReader().read()).value!
  const chunk = new Uint8Array(64 * 1024)
  const total = megabytes * 1024 * 1024
  const start = performance.now()
  void (async () => {
    const writer = peer.writable.getWriter()
    for (let sent = 0; sent < total; sent += chunk.byteLength) await writer.write(chunk)
    await writer.close()
  })()
  let read = 0
  for await (const bytes of socket.readable) read += bytes.byteLength
  const seconds = (performance.now() - start) / 1000
  await client.close()
  await site.close()
  return { megabytes: read / 1024 / 1024, seconds, mbps: (read * 8) / seconds / 1e6 }
}

Object.assign(globalThis, { measure })
