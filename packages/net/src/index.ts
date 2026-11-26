import type { Session } from '@webvpn/client'
import type * as NodeNet from 'node:net'

import { build } from './net'

/**
 * What the module needs of a relay. A `@webvpn/client` `Session` is one as it is. A host name given to `connect` goes
 * to the relay with the connect (the relay's `DNS` feature); a name given to `listen` is looked up with `lookup` first.
 */
export type Provider = Pick<Session, 'tcpConnect' | 'tcpListen' | 'lookup'>

/**
 * A provider, or a function that makes one, so that an app can open its session at the first socket. The function is
 * called once, at the first call that needs a provider, and again only after the promise it returned rejected.
 */
export type ProviderSource = Provider | (() => Promise<Provider>)

/**
 * Node's `net` as far as this package has it, typed with Node's own types. Every socket and server reaches the relay
 * through one provider. A socket has no path (IPC) form and no file descriptor; `getConnections`,
 * `maxConnections`, `connections`, `BlockList`, `SocketAddress`, `Stream` and the auto family selection settings are
 * missing.
 */
export type Net = {
  /**
   * Node's `net.Socket`, a Duplex: `connect`, `write`, `end` as a half close, `destroy`, `resetAndDestroy`, the
   * events in Node's order (`connect`, `ready`, `data`, `end`, `finish`, `timeout`, `error`, `close`), `setNoDelay`,
   * `setKeepAlive`, `setTimeout`, `address()`, the local and remote endpoint getters, `bytesRead` and
   * `bytesWritten`, and, beyond Node, `setSendBufferSize` and `setRecvBufferSize`. Unlike Node: `bytesWritten`
   * counts what the relay took, not what waits in the buffer; setting an option before `connect` emits an `error`,
   * and so does an option the relay refuses; the type of service is kept but not sent; there is no `lookup` event,
   * and `connect` reads only `host`, `port` and `allowHalfOpen`; a failed connect to a host name names the host in
   * its message where Node names the address it tried, and has no `address`, since the relay does not say which.
   */
  Socket: typeof NodeNet.Socket,
  /**
   * Node's `net.Server`: `listen` on a port, a port and a host (a name is looked up through the relay), or an
   * options object, `close`, `address`, and the `listening`, `connection`, `error` and `close` events. The backlog
   * argument is taken and ignored: the relay holds its own. Sockets the relay accepted wait in order until they are
   * handed out, and those left when the server closes are closed. Unlike Node, `close` is emitted once the relay
   * closed the listener, without waiting for the accepted sockets to end.
   */
  Server: typeof NodeNet.Server,
  /** Node's `net.connect`: a new `Socket`, connecting. A host name goes to the relay, which looks it up. */
  connect: typeof NodeNet.connect,
  /** The same as `connect`. */
  createConnection: typeof NodeNet.createConnection,
  /** Node's `net.createServer`. */
  createServer: typeof NodeNet.createServer,
  /** 4 for an IPv4 address in dotted decimal, 6 for an IPv6 address (a zone is allowed), 0 for anything else. */
  isIP: typeof NodeNet.isIP,
  /** Whether the text is an IPv4 address in dotted decimal, with no leading zero. */
  isIPv4: typeof NodeNet.isIPv4,
  /** Whether the text is an IPv6 address, a zone allowed. */
  isIPv6: typeof NodeNet.isIPv6,
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
export const createNet = (provider: ProviderSource): Net => build(lazy(provider)) as unknown as Net

let current: (() => Promise<Provider>) | undefined

/**
 * Sets the provider of the module-level exports, the ones an app reaches by aliasing `net` to this package. It
 * replaces the one set before for the sockets and servers made from then on. Until it is called, `connect`,
 * `Socket.connect` and `Server.listen` throw.
 */
export const setProvider = (provider: ProviderSource) => {
  current = lazy(provider)
}

const net = build(() => {
  if (!current) throw new Error('no provider is set: call setProvider() from @webvpn/net first')
  return current()
}) as unknown as Net

/** `Net.Socket`, on the provider `setProvider` set. */
export const Socket = net.Socket
/** `Net.Server`, on the provider `setProvider` set. */
export const Server = net.Server
/** `Net.connect`, on the provider `setProvider` set. */
export const connect = net.connect
/** `Net.createConnection`, on the provider `setProvider` set. */
export const createConnection = net.createConnection
/** `Net.createServer`, on the provider `setProvider` set. */
export const createServer = net.createServer
/** `Net.isIP`. */
export const isIP = net.isIP
/** `Net.isIPv4`. */
export const isIPv4 = net.isIPv4
/** `Net.isIPv6`. */
export const isIPv6 = net.isIPv6

/** The module-level exports as one object, for `import net from 'net'`, with `setProvider` and `createNet`. */
export default { ...net, setProvider, createNet }
