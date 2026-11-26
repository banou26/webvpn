import type { Session } from '@webvpn/client'
import type * as NodeDgram from 'node:dgram'

import { build } from './dgram'

/**
 * What the module needs of a relay. A `@webvpn/client` `Session` is one as it is. A host name given to `bind`,
 * `connect` or `send` is looked up with `lookup`: an A record for a udp4 socket, an AAAA record for a udp6 one.
 */
export type Provider = Pick<Session, 'udpBind' | 'lookup'>

/**
 * A provider, or a function that makes one, so that an app can open its session at the first socket. The function is
 * called once, at the first call that needs a provider, and again only after the promise it returned rejected.
 */
export type ProviderSource = Provider | (() => Promise<Provider>)

/**
 * Node's `dgram` as far as this package has it, typed with Node's own types, every socket on one provider. Missing:
 * the `reuseAddr`, `ipv6Only`, buffer size, `lookup` and `signal` options of `createSocket`; `setMulticastInterface`
 * and the source specific memberships are there but do nothing.
 */
export type Dgram = {
  /**
   * Node's `dgram.Socket`: `bind` in its forms, `send` in its forms (with an offset and a length, a list of buffers,
   * to a name, on a connected socket with no address), `connect`, `disconnect`, `close`, `address`, `remoteAddress`,
   * the broadcast, TTL, multicast TTL and loopback, buffer size and membership options, and the `listening`,
   * `message`, `connect`, `error` and `close` events. A `send` or `connect` before `bind` binds to a free port on
   * every address first, and the sends made meanwhile go out in order once it is bound. A datagram over 65507 bytes to
   * IPv4, or 65527 to IPv6, fails with EMSGSIZE as on Linux. Unlike Node: an option set before `bind` emits an
   * `error`, and so does one the relay refuses; the relay closing the socket, or the session ending, emits an `error`
   * when there is a listener for it, then `close`; `close` is emitted once the relay closed the socket; the send queue
   * getters answer 0, and the buffer size getters the last value set.
   */
  Socket: typeof NodeDgram.Socket,
  /** Node's `dgram.createSocket`, from a type or an options object, with an optional `message` listener. */
  createSocket: typeof NodeDgram.createSocket,
}

const lazy = (source: ProviderSource): (() => Promise<Provider>) => {
  if (typeof source !== 'function') {
    const ready = Promise.resolve(source)
    return () => ready
  }
  let made: Promise<Provider> | undefined
  return () => made ??= new Promise<Provider>((resolve) => resolve(source())).catch((error: unknown) => {
    made = undefined
    throw error
  })
}

/** Builds the module for one provider, apart from the module-level one `setProvider` sets. */
export const createDgram = (provider: ProviderSource): Dgram => build(lazy(provider)) as unknown as Dgram

let current: (() => Promise<Provider>) | undefined

/**
 * Sets the provider of the module-level exports, the ones an app reaches by aliasing `dgram` to this package. It
 * replaces the one set before for the sockets bound from then on. Until it is called, `bind`, `send` and `connect`
 * throw.
 */
export const setProvider = (provider: ProviderSource) => {
  current = lazy(provider)
}

const dgram = build(() => {
  if (!current) throw new Error('no provider is set: call setProvider() from @webvpn/dgram first')
  return current()
}) as unknown as Dgram

/** `Dgram.Socket`, on the provider `setProvider` set. */
export const Socket = dgram.Socket
/** `Dgram.createSocket`, on the provider `setProvider` set. */
export const createSocket = dgram.createSocket

/** The module-level exports as one object, for `import dgram from 'dgram'`, with `setProvider` and `createDgram`. */
export default { ...dgram, setProvider, createDgram }
