import type { IpTunnel } from '../ip'
import type { Address } from '../protocol'

import { parseIp } from '../address'
import { WebVpnError } from '../context'
import { ErrorCode } from '../protocol'
import wasm from './wasm.js'

// the crate's shared buffer: a packet of up to 65535 bytes, or a UDP payload of 65536 behind its address
const BUFFER_BYTES = 65536 + 64

const MESSAGES: Record<number, string> = {
  [ErrorCode.UNSUPPORTED]: 'the stack does not have this option',
  [ErrorCode.CONNECTION_REFUSED]: 'the peer refused the connection',
  [ErrorCode.TIMED_OUT]: 'the peer did not answer in time',
  [ErrorCode.HOST_UNREACHABLE]: 'no route to the host',
  [ErrorCode.NETWORK_UNREACHABLE]: 'no route to the network',
  [ErrorCode.CONNECTION_RESET]: 'the peer reset the connection',
  [ErrorCode.ADDRESS_IN_USE]: 'the local address is taken',
  [ErrorCode.ADDRESS_NOT_AVAILABLE]: 'the tunnel has no such local address',
  [ErrorCode.UNKNOWN_SOCKET]: 'the socket is closed',
}

/** The `WebVpnError` a session would give for `code`. */
export const stackError = (code: number, message = MESSAGES[code] ?? 'the stack refused') => new WebVpnError(code, message)

/** The TCP states as the crate numbers them, the ones the glue tells apart. */
export const TcpState = { CLOSED: 0, ESTABLISHED: 4 } as const

/** The crate's exports, as its documentation lists them. */
type Calls = {
  memory: WebAssembly.Memory,
  stack_buffer: () => number,
  stack_open: (mtu: number, firstPort: number, ports: number, connectTimeoutMs: number, now: number) => void,
  stack_input: (length: number) => void,
  stack_poll: (now: number) => number,
  stack_output: () => number,
  stack_events: () => number,
  stack_public_port: (protocol: number) => number,
  stack_release: (id: number) => void,
  tcp_connect: (receive: number, send: number) => number,
  tcp_listen: (port: number, backlog: number, receive: number, send: number) => number,
  tcp_accept: (listener: number) => number,
  tcp_state: (id: number) => number,
  tcp_error: (id: number) => number,
  tcp_endpoints: (id: number) => number,
  tcp_send: (id: number, length: number) => number,
  tcp_recv: (id: number, max: number) => number,
  tcp_close: (id: number) => void,
  tcp_abort: (id: number) => void,
  tcp_option: (id: number, option: number, value: number) => number,
  udp_bind: (port: number, receive: number, send: number) => number,
  udp_port: (id: number) => number,
  udp_send: (id: number, length: number) => number,
  udp_recv: (id: number) => number,
  udp_ttl: (id: number, ttl: number) => number,
}

/** One stack, in a WebAssembly instance of its own, driven over one tunnel. */
export type Engine = {
  calls: Calls,
  /** The shared buffer. A fresh view each time, since the instance's memory may grow under an older one. */
  buffer: () => Uint8Array,
  /** Writes `address` into the buffer at `at` and returns where it ends. */
  putAddress: (address: Address, at?: number) => number,
  /** Reads the address at `at` in the buffer, and where it ends. */
  readAddress: (at: number) => { address: Address, end: number },
  /** A poll once the current task is done. Every socket call is followed by one, so the stack sends what it made. */
  kick: () => void,
  /** Calls `wake` when the socket or listener `id` changed, and once when the tunnel ended, until the call it returns. */
  watch: (id: number, wake: () => void) => () => void,
  /** The error of whatever the tunnel's end made fail, once it ended. */
  ended: () => WebVpnError | undefined,
}

/** Promises the next change of a socket, to every waiter at once. */
export const changes = () => {
  const waiting: (() => void)[] = []
  return {
    next: () => new Promise<void>((resolve) => waiting.push(resolve)),
    wake: () => {
      for (const resolve of waiting.splice(0)) resolve()
    },
  }
}

const decode = (base64: string) => Uint8Array.from(atob(base64), (char) => char.charCodeAt(0))

let compiled: Promise<WebAssembly.Module> | undefined

/**
 * Starts a stack on `tunnel`: reads every packet the tunnel gives into it, sends every packet it makes with
 * `tunnel.send`, and polls it on a timer at the time it asks for, and after each packet in and each socket call.
 * It stops when the tunnel ends.
 */
export const startEngine = async (tunnel: IpTunnel, connectTimeoutMs: number): Promise<Engine> => {
  compiled ??= WebAssembly.compile(decode(wasm))
  const instance = await WebAssembly.instantiate(await compiled)
  const calls = instance.exports as unknown as Calls
  const at = calls.stack_buffer()
  const buffer = () => new Uint8Array(calls.memory.buffer, at, BUFFER_BYTES)
  const watchers = new Map<number, () => void>()
  let ended: WebVpnError | undefined
  let timer: ReturnType<typeof setTimeout> | undefined
  let kicked = false

  const setup = buffer()
  setup.fill(0, 0, 20)
  if (tunnel.ipv4) setup.set(parseIp(tunnel.ipv4)!, 0)
  if (tunnel.ipv6) setup.set(parseIp(tunnel.ipv6)!, 4)
  crypto.getRandomValues(setup.subarray(20, 28))
  calls.stack_open(tunnel.mtu, tunnel.firstPort, tunnel.ports, connectTimeoutMs, performance.now())

  const poll = () => {
    kicked = false
    if (ended) return
    const delay = calls.stack_poll(performance.now())
    for (let length = calls.stack_output(); length; length = calls.stack_output()) tunnel.send(buffer().slice(0, length))
    const view = new DataView(calls.memory.buffer, at, calls.stack_events() * 4)
    const changed = Array.from({ length: view.byteLength / 4 }, (_, index) => view.getUint32(index * 4))
    clearTimeout(timer)
    timer = delay >= 0 ? setTimeout(poll, delay) : undefined
    for (const id of changed) watchers.get(id)?.()
  }

  const kick = () => {
    if (kicked || ended) return
    kicked = true
    queueMicrotask(poll)
  }

  const end = () => {
    if (ended) return
    ended = new WebVpnError(ErrorCode.OTHER, 'the tunnel closed')
    clearTimeout(timer)
    for (const wake of [...watchers.values()]) wake()
    watchers.clear()
  }
  tunnel.closed.then(end)

  void (async () => {
    const reader = tunnel.readable.getReader()
    try {
      for (let read = await reader.read(); !read.done && !ended; read = await reader.read()) {
        buffer().set(read.value)
        calls.stack_input(read.value.byteLength)
        kick()
      }
    } catch {}
    end()
  })()

  return {
    calls,
    buffer,
    putAddress: ({ ip, port }, offset = 0) => {
      const bytes = buffer()
      bytes[offset] = ip.byteLength === 4 ? 0 : 1
      bytes.set(ip, offset + 1)
      new DataView(bytes.buffer, at + offset + 1 + ip.byteLength, 2).setUint16(0, port)
      return offset + 3 + ip.byteLength
    },
    readAddress: (offset) => {
      const bytes = buffer()
      const length = bytes[offset] === 0 ? 4 : 16
      const ip = bytes.slice(offset + 1, offset + 1 + length)
      const port = new DataView(bytes.buffer, at + offset + 1 + length, 2).getUint16(0)
      return { address: { ip, port }, end: offset + 3 + length }
    },
    kick,
    watch: (id, wake) => {
      watchers.set(id, wake)
      return () => {
        if (watchers.get(id) === wake) watchers.delete(id)
      }
    },
    ended: () => ended,
  }
}
