import type { RelayPacket } from '../src/protocol'

import { expect, inject, it } from 'vite-plus/test'

import { framed } from '../src/context'
import { CloseCode, decodeRelayPacket, encodeClientPacket, VERSION } from '../src/protocol'

const { open } = inject('relays')
const SESSIONS = 20
const WAIT_MS = 5000

const limited = <T>(promise: Promise<T>, what: string) => {
  let timer: ReturnType<typeof setTimeout> | undefined
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${what}: no result in ${WAIT_MS} ms`)), WAIT_MS)
    }),
  ]).finally(() => clearTimeout(timer))
}

type Duplex = { readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array> }

/**
 * Opens a raw WebTransport session, answers the relay's hello with one of another minor version and reads the control
 * stream to its end: the frames read, and how the stream ended.
 */
const mismatch = async () => {
  const transport = new WebTransport(open.url, {
    serverCertificateHashes: [{ algorithm: 'sha-256', value: Uint8Array.from(open.certHash) }],
  })
  // read before `ready`, as the client does (Firefox bug 2046262)
  const first = transport.incomingBidirectionalStreams.getReader().read()
  first.catch(() => {})
  transport.closed.catch(() => {})
  try {
    await limited(transport.ready, 'ready')
    const { value } = await limited(first, 'the control stream')
    const control = value as Duplex
    const reader = control.readable.getReader()
    const take = framed(decodeRelayPacket)
    const packets: RelayPacket[] = []
    let end = 'finished'
    let answered = false
    while (true) {
      const read = await limited(reader.read(), 'a read').catch((error: unknown) => error)
      if (read instanceof Error || !('done' in (read as object))) {
        const { source, streamErrorCode } = read as { source?: string, streamErrorCode?: number }
        end = `failed: ${String(read)} (source ${source}, streamErrorCode ${streamErrorCode})`
        break
      }
      const { value: chunk, done } = read as ReadableStreamReadResult<Uint8Array>
      if (done) break
      packets.push(...take(chunk).map(({ packet }) => packet))
      if (packets.at(-1)?.type === 'bye') break
      if (!answered && packets.some((packet) => packet.type === 'hello')) {
        answered = true
        const writer = control.writable.getWriter()
        const minor = VERSION.minor + 1
        const hello = encodeClientPacket({ type: 'hello', major: VERSION.major, minor, features: 0, agent: 'mismatch' })
        writer.write(hello).catch(() => {})
        writer.releaseLock()
      }
    }
    return { types: packets.map((packet) => packet.type), last: packets.at(-1), end }
  } finally {
    try {
      transport.close()
    } catch {}
  }
}

// pins the relay's order on a failed setup: it writes `Bye` while it still holds its receive half of the control
// stream. Firefox 157 errors the stream's readable on the STOP_SENDING that dropping that half sends (bug 1986138):
// with the half dropped first, 0 of 20 sessions read the `Bye` there (2026-11-28)
it(`reads the relay's Bye after a hello of another minor version, ${SESSIONS} times`, async () => {
  const results = []
  for (let session = 0; session < SESSIONS; session++) results.push(await mismatch())
  const missed = results.filter(({ last }) => last?.type !== 'bye')
  expect(missed, JSON.stringify(missed)).toEqual([])
  for (const { last } of results) expect(last).toMatchObject({ type: 'bye', code: CloseCode.VERSION_MISMATCH })
}, 60_000)
