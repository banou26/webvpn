import type { ChildProcess } from 'node:child_process'

import { execFileSync, spawn } from 'node:child_process'
import { createSocket } from 'node:dgram'
import { createServer as createHttpServer } from 'node:http'
import { connect as dial, createServer } from 'node:net'
import { join } from 'node:path'

/** A relay the tests reach, as the page sees it. */
export type RelayInfo = { id: number, url: string, webSocketUrl: string, certHash: number[] }

declare module 'vitest' {
  export interface ProvidedContext {
    relays: { open: RelayInfo, locked: RelayInfo },
    echo: { tcp: number, udp: number },
  }
}

declare module 'vitest/browser' {
  interface BrowserCommands {
    startRelay: () => Promise<RelayInfo>,
    stopRelay: (id: number) => Promise<void>,
    dialTcp: (port: number, text: string) => Promise<string>,
  }
}

const ROOT = join(import.meta.dirname, '../../../..')
const WAIT_MS = 30_000

const children = new Map<number, ChildProcess>()
process.once('exit', () => {
  for (const child of children.values()) child.kill('SIGKILL')
})

const limited = <T>(promise: Promise<T>, what: string) => {
  let timer: ReturnType<typeof setTimeout> | undefined
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`${what} took over ${WAIT_MS} ms`)), WAIT_MS) }),
  ]).finally(() => clearTimeout(timer))
}

/** Starts `webvpnd` on loopback ports the system picks, reads them from its log and its certificate's hash. */
const startRelay = async (env: Record<string, string> = {}): Promise<RelayInfo> => {
  const child = spawn(join(ROOT, 'target/debug/webvpnd'), [], {
    env: {
      PATH: process.env.PATH,
      RUST_LOG: 'info',
      WEBVPN_ADDRESS: '127.0.0.1',
      WEBVPN_WEBTRANSPORT_PORT: '0',
      WEBVPN_WEBSOCKET_PORT: '0',
      WEBVPN_HTTP_PORT: '0',
      WEBVPN_ALLOW_PRIVATE_TARGETS: 'true',
      WEBVPN_DRAIN_SECONDS: '1',
      ...env,
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  children.set(child.pid!, child)
  const ports = await limited(new Promise<Record<string, number>>((resolve, reject) => {
    const found: Record<string, number> = {}
    let log = ''
    child.stdout!.on('data', (chunk: Buffer) => {
      log += chunk
      for (const [, carrier, port] of log.matchAll(/(WebTransport|WebSocket|HTTP) listening on \w+\/(\d+)/g)) {
        found[carrier!] = Number(port)
      }
      if (Object.keys(found).length === 3) resolve(found)
    })
    child.once('exit', (code) => reject(new Error(`webvpnd exited with ${code} before it listened`)))
  }), 'the relay\'s start')
  child.stdout!.resume()
  const certHash = await (await fetch(`http://127.0.0.1:${ports.HTTP}/cert-hash`)).json() as number[]
  return {
    id: child.pid!,
    url: `https://127.0.0.1:${ports.WebTransport}`,
    webSocketUrl: `wss://127.0.0.1:${ports.WebSocket}`,
    certHash,
  }
}

/** Stops a relay as a deploy does, with SIGTERM: it sends `Draining`, waits its drain and closes what is left. */
const stopRelay = async (id: number) => {
  const child = children.get(id)
  if (!child) return
  children.delete(id)
  if (child.exitCode !== null) return
  const exited = new Promise((resolve) => child.once('exit', resolve))
  child.kill('SIGTERM')
  await limited(exited, 'the relay\'s stop')
}

/** Commands a test in the page runs in Node. */
export const commands = {
  startRelay: () => startRelay(),
  stopRelay: (_: unknown, id: number) => stopRelay(id),
  /** Connects to a port on loopback, sends `text`, finishes, and answers with all it read before the peer's end. */
  dialTcp: (_: unknown, port: number, text: string) => limited(new Promise<string>((resolve, reject) => {
    const socket = dial(port, '127.0.0.1', () => socket.end(text))
    let read = ''
    socket.setEncoding('utf8')
    socket.on('data', (chunk: string) => { read += chunk })
    socket.on('end', () => resolve(read))
    socket.on('error', reject)
  }), 'a dial from Node'),
}

// answers `echo.test`'s A records with 127.0.0.1, and any other question with no record
const dnsAnswer = (query: Buffer) => {
  let end = 12
  const labels: string[] = []
  while (query[end]) {
    labels.push(query.subarray(end + 1, end + 1 + query[end]!).toString())
    end += 1 + query[end]!
  }
  const question = query.subarray(12, end + 5)
  const known = labels.join('.') === 'echo.test' && query.readUInt16BE(end + 1) === 1
  const header = Buffer.from([query[0]!, query[1]!, 0x81, 0x80, 0, 1, 0, known ? 1 : 0, 0, 0, 0, 0])
  const record = Buffer.from([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1])
  return Buffer.concat(known ? [header, question, record] : [header, question])
}

const listening = (server: { once: (event: 'listening', listener: () => void) => unknown }) =>
  new Promise<void>((resolve) => server.once('listening', resolve))

/**
 * Builds and starts two relays, a TCP and a UDP echo on loopback and a DNS over HTTPS resolver for the open relay,
 * and stops them all after the run. A TCP peer that sends `reset` is reset.
 */
export default async ({ provide }: { provide: (key: string, value: unknown) => void }) => {
  execFileSync('cargo', ['build', '-p', 'webvpnd'], { cwd: ROOT, stdio: 'inherit' })

  const tcp = createServer((socket) => {
    socket.on('data', (data) => {
      if (data.toString() === 'reset') socket.resetAndDestroy()
      else socket.write(data)
    })
    socket.on('end', () => socket.end())
    socket.on('error', () => {})
  }).listen(0, '127.0.0.1')
  const udp = createSocket('udp4')
  udp.on('message', (data, from) => udp.send(data, from.port, from.address))
  udp.bind(0, '127.0.0.1')
  const doh = createHttpServer((request, response) => {
    const chunks: Buffer[] = []
    request.on('data', (chunk: Buffer) => chunks.push(chunk))
    request.on('end', () => {
      response.writeHead(200, { 'content-type': 'application/dns-message' })
      response.end(dnsAnswer(Buffer.concat(chunks)))
    })
  }).listen(0, '127.0.0.1')
  await Promise.all([listening(tcp), listening(udp), listening(doh)])
  const port = (server: { address: () => unknown }) => (server.address() as { port: number }).port

  const open = await startRelay({ WEBVPN_DNS_UPSTREAM: `http://127.0.0.1:${port(doh)}/dns-query` })
  const locked = await startRelay({ WEBVPN_CREDENTIALS: 'right', WEBVPN_LISTEN: 'false' })
  provide('relays', { open, locked })
  provide('echo', { tcp: port(tcp), udp: port(udp) })

  return async () => {
    await Promise.all([...children.keys()].map(stopRelay))
    tcp.close()
    udp.close()
    doh.close()
  }
}
