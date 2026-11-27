import type { Address } from '../protocol'
import type { Engine } from './engine'
import type { Buffers } from './tcp'

import { concat, EMPTY, noop, WebVpnError } from '../context'
import { ErrorCode } from '../protocol'
import { stackConnect } from './tcp'
import { stackUdpBind } from './udp'

// the share of the whole time the first query waits for its answer before it is asked again
const RETRY_SHARE = 0.4
const TRUNCATED = 0x02

const LATE = Symbol('late')

const by = <T>(promise: Promise<T>, at: number) => {
  let timer: ReturnType<typeof setTimeout> | undefined
  const late = new Promise<typeof LATE>((resolve) => {
    timer = setTimeout(() => resolve(LATE), Math.max(0, at - performance.now()))
  })
  return Promise.race([promise, late]).finally(() => clearTimeout(timer))
}

const overTcp = async (engine: Engine, resolver: Address, query: Uint8Array, deadline: number, buffers: Buffers) => {
  const connecting = stackConnect(engine, resolver, buffers)
  const socket = await by(connecting, deadline)
  if (socket === LATE) {
    connecting.then((late) => late.reset(), noop)
    return undefined
  }
  try {
    const writer = socket.writable.getWriter()
    const framed = new Uint8Array(2 + query.byteLength)
    new DataView(framed.buffer).setUint16(0, query.byteLength)
    framed.set(query, 2)
    writer.write(framed).catch(noop)
    const reader = socket.readable.getReader()
    let bytes = EMPTY
    const length = () => new DataView(bytes.buffer, bytes.byteOffset).getUint16(0)
    while (bytes.byteLength < 2 || bytes.byteLength < 2 + length()) {
      const read = await by(reader.read(), deadline)
      if (read === LATE || read.done) return undefined
      bytes = concat(bytes, read.value)
    }
    return bytes.slice(2, 2 + length())
  } finally {
    socket.close().catch(noop)
  }
}

/**
 * Puts a whole DNS message to `resolver` over UDP through the stack, asks once more when no answer came in the first
 * part of `timeoutMs`, and asks again over TCP when the answer is truncated. Rejects with `LOOKUP_FAILED` when no
 * answer came within `timeoutMs`, as a relay whose resolver does not answer.
 */
export const stackLookup = async (engine: Engine, resolver: Address, query: Uint8Array, timeoutMs: number, buffers: Buffers) => {
  const start = performance.now()
  const deadline = start + timeoutMs
  const socket = stackUdpBind(engine, 0, new Uint8Array(resolver.ip.byteLength), buffers)
  const reader = socket.readable.getReader()
  const writer = socket.writable.getWriter()
  let read = reader.read()
  try {
    await socket.connect(resolver)
    for (const until of [start + timeoutMs * RETRY_SHARE, deadline]) {
      await writer.write({ data: query })
      for (;;) {
        const result = await by(read, until)
        if (result === LATE) break
        if (result.done) throw engine.ended() ?? new WebVpnError(ErrorCode.LOOKUP_FAILED, 'the lookup\'s socket closed')
        read = reader.read()
        const answer = result.value.data
        if (answer.byteLength < 12 || answer[0] !== query[0] || answer[1] !== query[1]) continue
        if (!(answer[2]! & TRUNCATED)) return answer
        const whole = await overTcp(engine, resolver, query, deadline, buffers).catch(() => undefined)
        if (whole) return whole
        throw engine.ended() ?? new WebVpnError(ErrorCode.LOOKUP_FAILED, 'the resolver did not answer over TCP')
      }
    }
    throw new WebVpnError(ErrorCode.LOOKUP_FAILED, 'the resolver did not answer')
  } finally {
    socket.close().catch(noop)
  }
}
