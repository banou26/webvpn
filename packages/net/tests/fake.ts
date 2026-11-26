import type { Address, TcpListener, TcpOption, TcpSocket } from '@webvpn/client'
import type { Provider } from '../src'

import { ErrorCode, parseIp, WebVpnError } from '@webvpn/client'

export const address = (text: string, port: number): Address => ({ ip: parseIp(text)!, port })

export const relayError = (code: number, message = 'the relay refused') => new WebVpnError(code, message)

export const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

/** A socket as the relay hands it over, played by the test: the peer's bytes, end and reset, and the page's writes. */
export const fakeSocket = (local = address('10.0.0.1', 40000), remote = address('198.51.100.9', 443)) => {
  let down!: ReadableStreamDefaultController<Uint8Array>
  let writeError: unknown
  let endError: unknown
  let stalled: { promise: Promise<never>, cut: (error: Error) => void } | undefined
  let release: (() => void) | undefined
  const received: Uint8Array[] = []
  const teardown: string[] = []
  const options: TcpOption[] = []
  const state = { finished: false, pulls: 0 }

  const step = async () => {
    if (stalled) await stalled.promise
    if (release) await new Promise<void>((resolve) => { release = resolve })
  }
  const stop = (kind: string) => async () => {
    teardown.push(kind)
    stalled?.cut(new Error('the stream was reset'))
    try {
      down.close()
    } catch {}
  }

  const socket: TcpSocket = {
    id: 1,
    local,
    remote,
    readable: new ReadableStream<Uint8Array>({
      start: (controller) => { down = controller },
      pull: () => { state.pulls++ },
    }),
    writable: new WritableStream<Uint8Array>({
      write: async (chunk) => {
        await step()
        if (writeError) throw writeError
        received.push(chunk.slice())
      },
      close: async () => {
        await step()
        if (endError) throw endError
        state.finished = true
      },
    }),
    setOption: async (option) => {
      await step()
      options.push(option)
    },
    close: stop('close'),
    reset: stop('reset'),
  }

  return {
    socket,
    teardown,
    options,
    state,
    received: () => received.reduce((all, chunk) => all + new TextDecoder().decode(chunk), ''),
    sent: () => received.reduce((total, chunk) => total + chunk.byteLength, 0),
    /** The chunks the peer sent that the socket has not taken yet. */
    queued: () => 1 - (down.desiredSize ?? 1),
    send: (bytes: Uint8Array | string) => down.enqueue(typeof bytes === 'string' ? new TextEncoder().encode(bytes) : bytes),
    end: () => down.close(),
    reset: () => down.error(relayError(ErrorCode.CONNECTION_RESET, 'the peer reset the connection')),
    failWrites: (error: unknown) => { writeError = error },
    failEnd: (error: unknown) => { endError = error },
    /** Holds every write, end and option until the socket is closed or reset, which fails them as a reset does. */
    stall: () => {
      let cut!: (error: Error) => void
      const promise = new Promise<never>((_, reject) => { cut = reject })
      promise.catch(() => {})
      stalled = { promise, cut }
    },
    /** Holds the next write until `drain` is called. */
    hold: () => { release = () => {} },
    drain: () => {
      const go = release
      release = undefined
      go?.()
    },
  }
}

export type FakeSocket = ReturnType<typeof fakeSocket>

/** A listener as the relay hands it over: the test accepts connections on it and may end it. */
export const fakeListener = (local: Address) => {
  let accepted!: ReadableStreamDefaultController<TcpSocket>
  let finish!: (code?: number) => void
  const closed = new Promise<number | undefined>((resolve) => { finish = resolve })
  const stop = (code?: number) => {
    try {
      accepted.close()
    } catch {}
    finish(code)
  }
  const listener: TcpListener = {
    id: 2,
    local,
    connections: new ReadableStream({ start: (controller) => { accepted = controller } }),
    closed,
    close: async () => stop(),
  }
  return { listener, accept: (socket: TcpSocket) => accepted.enqueue(socket), end: stop }
}

const decodeName = (query: Uint8Array) => {
  const labels: string[] = []
  for (let at = 12; query[at]; at += 1 + query[at]!) labels.push(new TextDecoder().decode(query.subarray(at + 1, at + 1 + query[at]!)))
  return labels.join('.')
}

// a DNS answer with no question and one record per address, under the root name
const dnsAnswer = (ips: Uint8Array[]) => {
  const header = Uint8Array.of(0, 0, 0x81, 0x80, 0, 0, 0, ips.length, 0, 0, 0, 0)
  const records = ips.map((ip) => [Uint8Array.of(0, 0, ip.byteLength === 4 ? 1 : 28, 0, 1, 0, 0, 0, 60, 0, ip.byteLength), ip])
  const parts = [header, ...records.flat()]
  const message = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0))
  let at = 0
  for (const part of parts) {
    message.set(part, at)
    at += part.byteLength
  }
  return message
}

/**
 * A provider the test drives: `next` is what a connect gives (a socket, a function making one, or an error to reject
 * with), `names`
 * what a lookup answers, and every request is recorded.
 */
export const fakeProvider = () => {
  const calls: { connects: Parameters<Provider['tcpConnect']>[0][], listens: Address[], lookups: string[] } = {
    connects: [],
    listens: [],
    lookups: [],
  }
  const relay = {
    calls,
    next: undefined as TcpSocket | Error | Promise<TcpSocket> | (() => TcpSocket) | undefined,
    listenError: undefined as Error | ((local: Address) => Error | undefined) | undefined,
    listeners: [] as ReturnType<typeof fakeListener>[],
    names: new Map<string, string[]>(),
    provider: undefined as unknown as Provider,
  }
  relay.provider = {
    tcpConnect: async (target) => {
      calls.connects.push(target)
      const next = await (typeof relay.next === 'function' ? relay.next() : relay.next)
      if (next instanceof Error) throw next
      if (!next) throw new Error('the test set no socket')
      return next
    },
    tcpListen: async (local) => {
      calls.listens.push(local)
      const error = typeof relay.listenError === 'function' ? relay.listenError(local) : relay.listenError
      if (error) throw error
      const made = fakeListener({ ip: local.ip, port: local.port || 51413 })
      relay.listeners.push(made)
      return made.listener
    },
    lookup: async (query) => {
      const name = decodeName(query)
      calls.lookups.push(name)
      return dnsAnswer((relay.names.get(name) ?? []).map((text) => parseIp(text)!))
    },
  }
  return relay
}
