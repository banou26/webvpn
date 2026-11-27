import type { Address, ClosedBy, UdpOption, UdpSocket } from '@webvpn/client'
import type { Provider } from './index'

import { dnsAddresses, dnsQuery, ErrorCode, formatIp, parseIp, WebVpnError } from '@webvpn/client'
import { Buffer } from 'buffer'
import { EventEmitter } from 'events'

import { lookupError, nodeError, systemError } from './errors'

type Type = 'udp4' | 'udp6'
type Endpoint = { address: string, family: 'IPv4' | 'IPv6', port: number }
type Bound = { provider: Provider, socket: UdpSocket, writer: WritableStreamDefaultWriter<{ remote?: Address, data: Uint8Array }> }
type SendCallback = (error: Error | null, bytes?: number) => void

const encoder = new TextEncoder()

const noop = () => {}

const coded = (message: string, code: string) => Object.assign(new Error(message), { code })

const notRunning = () => coded('Not running', 'ERR_SOCKET_DGRAM_NOT_RUNNING')

const endpoint = ({ ip, port }: Address): Endpoint =>
  ({ address: formatIp(ip), family: ip.byteLength === 4 ? 'IPv4' : 'IPv6', port })

// what Linux takes in one datagram: 65535 bytes less the IPv4 and UDP headers, or less the UDP header alone over IPv6
const MAX_IPV4_PAYLOAD = 65507
const MAX_IPV6_PAYLOAD = 65527

const bytes = (message: unknown): Uint8Array => {
  if (typeof message === 'string') return encoder.encode(message)
  if (ArrayBuffer.isView(message)) return new Uint8Array(message.buffer, message.byteOffset, message.byteLength)
  if (Array.isArray(message)) {
    const parts = message.map(bytes)
    const all = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0))
    let at = 0
    for (const part of parts) {
      all.set(part, at)
      at += part.byteLength
    }
    return all
  }
  return new Uint8Array(message as ArrayBuffer)
}

const outOfBounds = (name: string) =>
  Object.assign(new RangeError(`"${name}" is outside of buffer bounds`), { code: 'ERR_BUFFER_OUT_OF_BOUNDS' })

/** The message, port, address and callback of Node's `send` argument forms, with or without an offset and a length. */
const sendArgs = (args: unknown[]) => {
  const callback = typeof args.at(-1) === 'function' ? args.at(-1) as SendCallback : undefined
  // a copy, so the caller may reuse its buffer once `send` returned, though the bind or a lookup is still to come
  let data = bytes(args[0]).slice()
  // a number in third place pins the forms with a range, where the second is the offset
  const ranged = typeof args[2] === 'number'
  if (ranged) {
    const [offset, length] = [args[1] as number, args[2] as number]
    if (!Number.isInteger(offset) || offset < 0 || offset > data.byteLength) throw outOfBounds('offset')
    if (!Number.isInteger(length) || length < 0 || length > data.byteLength - offset) throw outOfBounds('length')
    data = data.subarray(offset, offset + length)
  }
  const [port, address] = ranged ? [args[3], args[4]] : [args[1], args[2]]
  return { data, port, address: typeof address === 'string' ? address : undefined, callback }
}

const received = (value: unknown) => {
  if (value == null) return `${value}`
  if (typeof value === 'function') return `function ${value.name}`
  return `type ${typeof value} (${typeof value === 'string' ? `'${value}'` : String(value)})`
}

/** Node's check of a send's port: a number or a string of digits, from 1 to 65535. */
const sendPort = (port: unknown) => {
  const value = typeof port === 'string' && port.trim() ? Number(port) : port
  if (typeof value === 'number' && Number.isInteger(value) && value > 0 && value < 65536) return value
  throw Object.assign(new RangeError(`Port should be > 0 and < 65536. Received ${received(port)}.`), { code: 'ERR_SOCKET_BAD_PORT' })
}

class Socket extends EventEmitter {
  declare _provider: () => Promise<Provider>
  _type: Type
  _bound?: Promise<Bound | undefined>
  _local?: Endpoint
  _remote?: Endpoint
  _generation = 0
  _connecting = false
  _closed = false
  // the last values asked for, so the getters answer them rather than 0; the relay's system may have changed them
  _recvBufferSize = 0
  _sendBufferSize = 0

  constructor(type: Type | { type: Type }, listener?: (message: Buffer, remote: Endpoint & { size: number }) => void) {
    super()
    this._type = typeof type === 'string' ? type : type?.type
    if (this._type !== 'udp4' && this._type !== 'udp6') {
      throw coded('Bad socket type specified. Valid types are: udp4, udp6', 'ERR_SOCKET_BAD_TYPE')
    }
    if (listener) this.on('message', listener)
  }

  async _resolve(provider: Provider, host: string) {
    const ip = parseIp(host)
    if (ip) return ip
    const [first] = dnsAddresses(await provider.lookup(dnsQuery(host, this._type === 'udp6' ? 'AAAA' : 'A')))
    if (!first) throw lookupError(host)
    return first
  }

  async _receive(socket: UdpSocket) {
    const reader = socket.readable.getReader()
    for (let read = await reader.read(); !read.done && !this._closed; read = await reader.read()) {
      const { remote, data } = read.value
      // a listener that throws is reported as uncaught, as in Node, and the next datagrams are still delivered
      try {
        this.emit('message', Buffer.from(data.buffer, data.byteOffset, data.byteLength), { ...endpoint(remote), size: data.byteLength })
      } catch (error) {
        queueMicrotask(() => { throw error })
      }
    }
  }

  // a socket the relay ended on its own, or whose session ended; one this socket's close() ended is _closed already
  _ended(closed: ClosedBy) {
    if (this._closed) return
    this._closed = true
    const error = closed.by === 'relay'
      ? new WebVpnError(closed.code, 'the relay closed the socket')
      : new WebVpnError(ErrorCode.OTHER, 'the session ended')
    // with no 'error' listener, emit('error') throws, and an unfenced one would lose 'close' too
    try {
      if (this.listenerCount('error') > 0) this.emit('error', error)
    } finally {
      this.emit('close')
    }
  }

  bind(...args: unknown[]): this {
    if (this._closed) throw notRunning()
    if (this._bound) throw coded('Socket is already bound', 'ERR_SOCKET_ALREADY_BOUND')
    const callback = typeof args.at(-1) === 'function' ? args.at(-1) as () => void : undefined
    const options = args[0] !== null && typeof args[0] === 'object' ? args[0] as { port?: number, address?: string } : undefined
    const port = Number((options ? options.port : typeof args[0] === 'number' ? args[0] : 0) ?? 0)
    const address = options ? options.address : typeof args[1] === 'string' ? args[1] : undefined
    const provider = this._provider()
    if (callback) this.once('listening', callback)
    const host = address ?? (this._type === 'udp6' ? '::' : '0.0.0.0')
    this._bound = provider.then(async (ready) => {
      const ip = await this._resolve(ready, host)
      const socket = await ready.udpBind({ ip, port }).catch((error: unknown) => {
        throw nodeError(error, 'bind', formatIp(ip), port)
      })
      this._local = endpoint(socket.local)
      this._receive(socket)
      socket.closed.then((closed) => this._ended(closed))
      return { provider: ready, socket, writer: socket.writable.getWriter() }
    }).catch((error: unknown) => {
      if (!this._closed) this.emit('error', error)
      return undefined
    })
    this._bound.then((bound) => {
      if (bound && !this._closed) this.emit('listening')
    })
    return this
  }

  send(...args: unknown[]): void {
    if (this._closed) throw notRunning()
    const { data, port: given, address, callback } = sendArgs(args)
    const target = address === undefined && this._remote ? undefined : address ?? (this._type === 'udp6' ? '::1' : '127.0.0.1')
    const port = target === undefined ? 0 : sendPort(given)
    const bound = this._bound ?? this.bind()._bound!
    const ip = target === undefined ? undefined : parseIp(target)
    // waits for the bind in the order of the calls; one a failed bind or close() cut off ends silently, as in Node.
    // A send to the connected peer has no lookup to wait for, so as in Node a close() after it does not cut it off:
    // it is written ahead of the close, which waits on the same bind
    bound.then(async (ready) => {
      if (!ready || (this._closed && target !== undefined)) return
      let remote: Address | undefined
      if (target !== undefined) {
        try {
          remote = { ip: ip ?? await this._resolve(ready.provider, target), port }
        } catch (error) {
          if (this._closed) return
          return callback ? callback(error as Error) : void this.emit('error', error)
        }
      }
      const v4 = remote ? remote.ip.byteLength === 4 : this._remote?.family === 'IPv4'
      if (data.byteLength > (v4 ? MAX_IPV4_PAYLOAD : MAX_IPV6_PAYLOAD)) {
        // a send that fails with no callback is dropped silently, as in Node
        return callback?.(systemError('send', 'EMSGSIZE', remote && formatIp(remote.ip), remote?.port))
      }
      try {
        await ready.writer.write({ remote, data })
      } catch (error) {
        return this._closed ? undefined : callback?.(error as Error)
      }
      callback?.(null, data.byteLength)
    })
  }

  connect(port: number, address?: string | ((error?: Error) => void), callback?: (error?: Error) => void): void {
    if (typeof address === 'function') [callback, address] = [address, undefined]
    if (this._closed) throw notRunning()
    // as Node, a connect on its way counts as connected until it fails
    if (this._remote || this._connecting) throw coded('Already connected', 'ERR_SOCKET_DGRAM_IS_CONNECTED')
    const bound = this._bound ?? this.bind()._bound!
    if (callback) this.once('connect', callback)
    const host = address ?? (this._type === 'udp6' ? '::1' : '127.0.0.1')
    const generation = ++this._generation
    this._connecting = true
    bound.then(async (ready) => {
      if (!ready || this._closed) return void (this._connecting = false)
      const ip = await this._resolve(ready.provider, host)
      await ready.socket.connect({ ip, port }).catch((error: unknown) => {
        throw nodeError(error, 'connect', formatIp(ip), port)
      })
      this._connecting = false
      if (this._closed || generation !== this._generation) return
      this._remote = endpoint({ ip, port })
      this.emit('connect')
    }).catch((error: unknown) => {
      this._connecting = false
      if (this._closed) return
      if (!callback) return void this.emit('error', error)
      this.removeListener('connect', callback)
      callback.call(this, error as Error)
    })
  }

  disconnect(): void {
    if (this._closed) throw notRunning()
    if (!this._remote) throw coded('Not connected', 'ERR_SOCKET_DGRAM_NOT_CONNECTED')
    // the peer is kept aside so a failed disconnect can put it back, unless a newer connect() took its place
    const previous = this._remote
    const generation = this._generation
    this._remote = undefined
    this._bound!.then((bound) => bound?.socket.disconnect()).catch((error: unknown) => {
      if (this._generation === generation) this._remote = previous
      this.emit('error', error)
    })
  }

  close(callback?: () => void): this {
    if (this._closed) throw notRunning()
    this._closed = true
    // as Node, the callback is a 'close' listener, and a socket whose bind failed or never ran still closes
    if (callback) this.once('close', callback)
    const bound = this._bound ?? Promise.resolve(undefined)
    bound.then((ready) => ready?.socket.close()).catch(noop).then(() => this.emit('close'))
    return this
  }

  address(): Endpoint {
    if (!this._local) throw Object.assign(new Error('getsockname EBADF'), { errno: -9, code: 'EBADF', syscall: 'getsockname' })
    return this._local
  }

  remoteAddress(): Endpoint {
    if (!this._remote) throw coded('Not connected', 'ERR_SOCKET_DGRAM_NOT_CONNECTED')
    return this._remote
  }

  _setOption(option: UdpOption) {
    if (!this._bound) return void this.emit('error', new Error('a socket option needs a bind first'))
    this._bound.then(async (bound) => {
      try {
        await bound?.socket.setOption(option)
      } catch (error) {
        if (!this._closed) this.emit('error', error)
      }
    })
  }

  _membership(add: boolean, group: string, local?: string) {
    const ip = parseIp(group)
    if (ip?.byteLength === 4) {
      const chosen = local === undefined ? undefined : parseIp(local)
      const iface = chosen?.byteLength === 4 ? chosen : new Uint8Array(4)
      return this._setOption({ type: add ? 'addMembershipV4' : 'dropMembershipV4', group: ip, interface: iface })
    }
    // the protocol carries an interface index, 0 for the default one; a page cannot turn a name like eth0 into one
    if (ip) return this._setOption({ type: add ? 'addMembershipV6' : 'dropMembershipV6', group: ip, interface: 0 })
    this.emit('error', new Error(`not a multicast address: ${group}`))
  }

  addMembership(group: string, local?: string): void {
    this._membership(true, group, local)
  }

  dropMembership(group: string, local?: string): void {
    this._membership(false, group, local)
  }

  setBroadcast(flag: boolean): void {
    this._setOption({ type: 'broadcast', value: flag })
  }

  setTTL(ttl: number): number {
    this._setOption({ type: 'ttl', value: ttl })
    return ttl
  }

  // the protocol has a multicast TTL for IPv4 alone, which a udp6 socket gets too
  setMulticastTTL(ttl: number): number {
    this._setOption({ type: 'multicastTtlV4', value: ttl })
    return ttl
  }

  setMulticastLoopback(flag: boolean): boolean {
    this._setOption({ type: this._type === 'udp6' ? 'multicastLoopV6' : 'multicastLoopV4', value: flag })
    return flag
  }

  setRecvBufferSize(size: number): void {
    this._setOption({ type: 'recvBufferSize', value: size })
    this._recvBufferSize = size
  }

  setSendBufferSize(size: number): void {
    this._setOption({ type: 'sendBufferSize', value: size })
    this._sendBufferSize = size
  }

  getRecvBufferSize(): number {
    return this._recvBufferSize
  }

  getSendBufferSize(): number {
    return this._sendBufferSize
  }

  getSendQueueSize(): number {
    return 0
  }

  getSendQueueCount(): number {
    return 0
  }

  // the protocol has no option for these, so they do nothing rather than break a library that calls them
  setMulticastInterface(): void {}
  addSourceSpecificMembership(): void {}
  dropSourceSpecificMembership(): void {}

  ref(): this {
    return this
  }

  unref(): this {
    return this
  }

  async [Symbol.asyncDispose]() {
    await new Promise<void>((resolve) => this.close(resolve))
  }
}

/** The module's class and function, bound to the provider `get` returns. */
export const build = (get: () => Promise<Provider>) => {
  class BoundSocket extends Socket {
    _provider = get
  }
  const createSocket = (type: Type | { type: Type }, listener?: (message: Buffer, remote: Endpoint & { size: number }) => void) =>
    new BoundSocket(type, listener)
  return { Socket: BoundSocket, createSocket }
}
