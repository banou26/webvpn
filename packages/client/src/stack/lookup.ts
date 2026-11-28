import type { Address } from '../protocol'
import type { Engine } from './engine'
import type { Buffers } from './tcp'

import { concat, EMPTY, noop, WebVpnError } from '../context'
import { pastName } from '../dns'
import { ErrorCode } from '../protocol'
import { stackConnect } from './tcp'
import { stackUdpBind } from './udp'

// the share of the whole time the first query waits for its answer before it is asked again
const RETRY_SHARE = 0.4
const ANSWER = 0x80
const TRUNCATED = 0x02
// the stack's private ports, 49152 to 65535, and how many random ones a lookup tries before it takes the stack's own
const FIRST_PRIVATE_PORT = 49152
const PRIVATE_PORTS = 16384
const PORT_TRIES = 8

const LATE = Symbol('late')

const by = <T>(promise: Promise<T>, at: number) => {
  let timer: ReturnType<typeof setTimeout> | undefined
  const late = new Promise<typeof LATE>((resolve) => {
    timer = setTimeout(() => resolve(LATE), Math.max(0, at - performance.now()))
  })
  return Promise.race([promise, late]).finally(() => clearTimeout(timer))
}

const fold = (byte: number) => byte >= 0x41 && byte <= 0x5a ? byte | 0x20 : byte

// whether `answer` answers `sent`: its id, the answer bit and the same question, whose name may differ in case, as
// a resolver may give it back; a label's length is at most 63, so folding never changes one
const answers = (sent: Uint8Array, answer: Uint8Array) => {
  const name = pastName(sent, 12)
  if (name === undefined || answer.byteLength < name + 4) return false
  if (answer[0] !== sent[0] || answer[1] !== sent[1] || !(answer[2]! & ANSWER)) return false
  if (answer[4] !== sent[4] || answer[5] !== sent[5]) return false
  for (let at = 12; at < name; at++) if (fold(answer[at]!) !== fold(sent[at]!)) return false
  for (let at = name; at < name + 4; at++) if (answer[at] !== sent[at]) return false
  return true
}

// a random private port, so that a sender off the path must guess it with the id; the stack's own choice for port 0
// goes up by one each time. Never a public port, which takes datagrams from anyone.
const bindRandom = (engine: Engine, isPublic: (port: number) => boolean, ip: Uint8Array, buffers: Buffers) => {
  for (let tries = 0; tries < PORT_TRIES; tries++) {
    const port = FIRST_PRIVATE_PORT + crypto.getRandomValues(new Uint16Array(1))[0]! % PRIVATE_PORTS
    if (isPublic(port)) continue
    try {
      return stackUdpBind(engine, port, ip, buffers)
    } catch (error) {
      if (!(error instanceof WebVpnError) || error.code !== ErrorCode.ADDRESS_IN_USE) throw error
    }
  }
  return stackUdpBind(engine, 0, ip, buffers)
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
 * Puts a whole DNS message to `resolver` over UDP through the stack, from a random private port that is not one of
 * `isPublic`, asks once more when no answer came in the first part of `timeoutMs`, and asks again over TCP when the
 * answer is truncated. The message goes with a random id, and only an answer with that id, the answer bit and the
 * same question is taken; the caller gets it back with its own id. Rejects with `LOOKUP_FAILED` when no answer came
 * within `timeoutMs`, as a relay whose resolver does not answer.
 */
export const stackLookup = async (
  engine: Engine,
  resolver: Address,
  query: Uint8Array,
  timeoutMs: number,
  buffers: Buffers,
  isPublic: (port: number) => boolean,
) => {
  const start = performance.now()
  const deadline = start + timeoutMs
  const sent = query.slice()
  crypto.getRandomValues(sent.subarray(0, 2))
  // the caller's own id, in the answer that is a fresh copy
  const back = (answer: Uint8Array) => {
    answer.set(query.subarray(0, 2))
    return answer
  }
  const socket = bindRandom(engine, isPublic, new Uint8Array(resolver.ip.byteLength), buffers)
  const reader = socket.readable.getReader()
  const writer = socket.writable.getWriter()
  let read = reader.read()
  try {
    await socket.connect(resolver)
    for (const until of [start + timeoutMs * RETRY_SHARE, deadline]) {
      await writer.write({ data: sent })
      for (;;) {
        const result = await by(read, until)
        if (result === LATE) break
        if (result.done) throw engine.ended() ?? new WebVpnError(ErrorCode.LOOKUP_FAILED, 'the lookup\'s socket closed')
        read = reader.read()
        const answer = result.value.data
        if (!answers(sent, answer)) continue
        if (!(answer[2]! & TRUNCATED)) return back(answer)
        const whole = await overTcp(engine, resolver, sent, deadline, buffers).catch(() => undefined)
        if (whole && answers(sent, whole)) return back(whole)
        throw engine.ended() ?? new WebVpnError(ErrorCode.LOOKUP_FAILED, 'the resolver did not answer over TCP')
      }
    }
    throw new WebVpnError(ErrorCode.LOOKUP_FAILED, 'the resolver did not answer')
  } finally {
    socket.close().catch(noop)
  }
}
