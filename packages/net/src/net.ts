import type { Address, TcpListener, TcpOption, TcpSocket } from '@webvpn/client'
import type { DuplexOptions } from 'node:stream'
import type { Provider } from './index'

import { dnsAddresses, dnsQuery, formatIp, parseIp, WebVpnError } from '@webvpn/client'
import { EventEmitter } from 'events'
import { Duplex } from 'readable-stream'

import { lookupError, nodeError } from './errors'

type Endpoint = { address: string, family: string, port: number }
type Connected = {
  socket: TcpSocket,
  reader: ReadableStreamDefaultReader<Uint8Array>,
  writer: WritableStreamDefaultWriter<Uint8Array>,
}
type Callback = (error?: Error | null) => void

const IPV4_ANY = new Uint8Array(4)
const IPV6_ANY = new Uint8Array(16)

const noop = () => {}

const coded = (message: string, code: string) => Object.assign(new Error(message), { code })

const endpoint = ({ ip, port }: Address): Endpoint =>
  ({ address: formatIp(ip), family: ip.byteLength === 4 ? 'IPv4' : 'IPv6', port })

/** The port, the host and the callback of Node's `connect` and `listen` argument forms. */
const netArgs = (args: unknown[]) => {
  const callback = typeof args.at(-1) === 'function' ? args.at(-1) as () => void : undefined
  const first = args[0]
  const options = first !== null && typeof first === 'object' ? first as { port?: unknown, host?: string, path?: string } : undefined
  if (options?.path !== undefined || (typeof first === 'string' && !/^\d+$/.test(first))) {
    throw new Error('IPC paths are not supported')
  }
  if (options) return { ...options, port: Number(options.port ?? 0), callback }
  return { port: typeof first === 'function' ? 0 : Number(first ?? 0), host: typeof args[1] === 'string' ? args[1] : undefined, callback }
}

const resolve = async (provider: Provider, host: string) => {
  const ip = parseIp(host)
  if (ip) return ip
  const [first] = dnsAddresses(await provider.lookup(dnsQuery(host, 'A')))
  if (!first) throw lookupError(host)
  return first
}

class Socket extends Duplex {
  declare _provider: () => Promise<Provider>
  _local?: Endpoint
  _remote?: Endpoint
  _connection?: Promise<Connected | undefined>
  _connected = false
  _destroyError?: Error
  _resetRequested = false
  _timer?: ReturnType<typeof setTimeout>
  connecting = false
  bytesRead = 0
  bytesWritten = 0
  timeout?: number
  /** The server that accepted this socket, or null for a socket this page connected. */
  server: Server | null = null

  constructor(options?: DuplexOptions & { allowHalfOpen?: boolean, fd?: number }) {
    if (options?.fd !== undefined) throw new Error('file descriptors are not supported')
    // as Node's net.Socket: not half open unless asked, and destroyed once both sides ended
    super({ ...options, allowHalfOpen: Boolean(options?.allowHalfOpen), autoDestroy: true })
  }

  _use(socket: TcpSocket): Connected {
    this._local = endpoint(socket.local)
    this._remote = endpoint(socket.remote)
    return { socket, reader: socket.readable.getReader(), writer: socket.writable.getWriter() }
  }

  // the endpoints are known before 'connection' is emitted: Node lets its handler read them, and libtorrent drops a
  // peer whose address it cannot read
  _accept(socket: TcpSocket) {
    this._connection = Promise.resolve(this._use(socket))
    this._connected = true
    this.read(0)
  }

  _open(connection: Promise<TcpSocket>, host: string, port: number) {
    this.connecting = true
    this._connection = connection.then((socket) => this._use(socket), (error: unknown) => {
      this.connecting = false
      if (!this.destroyed) this.destroy(nodeError(error, 'connect', host, port))
      return undefined
    })
    this._connection.then((connected) => {
      if (!connected || this.destroyed) return
      this.connecting = false
      this._connected = true
      this.emit('connect')
      this.emit('ready')
      // as Node, a socket reads from the start unless paused, so a far side's end is seen with no reader attached
      if (!this.isPaused()) this.read(0)
    })
  }

  _read(): void {
    const connection = this._connection
    if (!connection) return void this.once('connect', () => this._read())
    connection.then((connected) => {
      if (!connected) return void this.push(null)
      connected.reader.read().then(({ value, done }) => {
        if (this.destroyed) return
        if (done) {
          this.push(null)
          // as Node: 'end' is emitted once the buffer is empty, even with no reader
          this.read(0)
          return
        }
        this.bytesRead += value.byteLength
        this._restartTimer()
        this.push(value)
      }, (error: unknown) => {
        // destroy() emits 'error' itself; emitting it first would let a listener read again
        this.destroy(nodeError(error, 'read'))
      })
    })
  }

  _write(chunk: Uint8Array, _encoding: string, callback: Callback): void {
    const connection = this._connection
    if (!connection) return callback(new Error('the socket is not connected'))
    connection
      .then(async (connected) => {
        if (!connected) throw new Error('the socket is not connected')
        // the write is awaited before Node hears of it, or its count of buffered bytes never brings 'drain'
        await connected.writer.ready
        await connected.writer.write(chunk)
      })
      // once destroyed, the stream hears no more of this write: 'close' settles its callback
      .then(() => {
        if (this.destroyed) return
        this.bytesWritten += chunk.byteLength
        this._restartTimer()
        callback()
      }, (error: unknown) => this._fail(error))
  }

  /**
   * As Node: a write or an end that fails destroys the socket with its error, which every pending write and end
   * callback gets first. The stream is not told: it would call back only that write and the writes behind it, and
   * leave the end callbacks this class keeps to 'close'.
   */
  _fail(error: unknown) {
    if (this.destroyed) return
    const failure = nodeError(error, 'read')
    for (const settle of this._pending) settle(failure)
    this.destroy(failure)
  }

  // closing the writer is the half close; the whole teardown stays with _destroy
  _final(callback: Callback): void {
    const connection = this._connection
    if (!connection) return callback()
    connection
      .then((connected) => connected?.writer.close())
      .then(() => {
        if (!this.destroyed) callback()
      }, (error: unknown) => this._fail(error))
  }

  // The relay closes in order on `close`, sending the peer what it holds of this side, as Linux sends what Node handed
  // it before the close, and resets on `reset`. The writer is left alone: aborting it would drop what the browser has
  // not sent yet, and the relay takes that reset as a half close (spec/protocol.md, TCP), so the peer would read a
  // cut stream as whole. Node emits 'close' once the handle closed, a turn of the event loop later, so what destroy()
  // put on the next tick (a write's callback, then 'error') comes first; a timer is that turn here, and also where
  // `process.nextTick` is one
  _destroy(error: Error | null, callback: Callback): void {
    this._destroyError = error ?? undefined
    clearTimeout(this._timer)
    this._connection
      ?.then((connected) => connected && (this._resetRequested ? connected.socket.reset() : connected.socket.close()))
      .catch(noop)
    setTimeout(() => callback(error))
  }

  /**
   * As Node's net.Socket: the end callbacks run before 'finish', and once destroyed every pending write and end
   * callback runs, the write in flight failing with ECANCELED and the ones behind it with the destroy's error, before
   * 'close'. A socket that never connected runs them after 'close', the first failing with
   * ERR_SOCKET_CLOSED_BEFORE_CONNECTION instead. 'close' carries whether the destroy had an error.
   */
  emit(event: string | symbol, ...args: any[]): boolean {
    if (event === 'finish') for (const settle of this._endCallbacks.splice(0)) settle()
    if (event !== 'close' || !this.destroyed) return super.emit(event, ...args)
    const hadError = this._destroyError !== undefined
    if (!this._connected) {
      const emitted = super.emit('close', hadError)
      this._settlePending(coded('Socket closed before the connection was established', 'ERR_SOCKET_CLOSED_BEFORE_CONNECTION'))
      return emitted
    }
    this._settlePending(Object.assign(coded('write ECANCELED', 'ECANCELED'), { syscall: 'write' }))
    return super.emit('close', hadError)
  }

  _settlePending(first: Error) {
    let error = first
    for (const settle of this._pending) {
      settle(error)
      error = this._destroyError ?? error
    }
  }

  destroySoon(): void {
    if (this.writableFinished) return void this.destroy()
    this.once('finish', () => this.destroy())
    this.end()
  }

  resetAndDestroy(): this {
    this._resetRequested = true
    return this.destroy()
  }

  _restartTimer() {
    clearTimeout(this._timer)
    if (!this.timeout || this.destroyed) return
    this._timer = setTimeout(() => this.emit('timeout'), this.timeout)
  }

  setTimeout(timeout: number, callback?: () => void): this {
    if (callback) this.on('timeout', callback)
    this.timeout = timeout
    this._restartTimer()
    return this
  }

  setNoDelay(noDelay = true): this {
    this._setOption({ type: 'noDelay', value: noDelay })
    return this
  }

  /**
   * Node's keep-alive, as arguments or as Node 26's options object. The relay takes `enable` and `initialDelay` (in
   * whole seconds); Node's `interval` and `count` have no counterpart, so the relay's system defaults apply.
   */
  setKeepAlive(enable?: boolean | { enable?: boolean, initialDelay?: number }, initialDelay?: number): this {
    const options = typeof enable === 'object' && enable !== null ? enable : { enable, initialDelay }
    const delay = options.initialDelay
    // Node's `initialDelay` is in milliseconds, the relay's in seconds
    const seconds = delay !== undefined && delay > 0 ? Math.max(1, Math.round(delay / 1000)) : 0
    this._setOption({ type: 'keepAlive', enabled: options.enable ?? false, initialDelaySeconds: seconds })
    return this
  }

  setSendBufferSize(size: number): this {
    this._setOption({ type: 'sendBufferSize', value: size })
    return this
  }

  setRecvBufferSize(size: number): this {
    this._setOption({ type: 'recvBufferSize', value: size })
    return this
  }

  // the relay has no type of service option; the value is kept only so the getter answers what was set
  _typeOfService = 0

  getTypeOfService(): number {
    return this._typeOfService
  }

  setTypeOfService(tos: number): this {
    this._typeOfService = tos
    return this
  }

  _setOption(option: TcpOption) {
    if (!this._connection) return void this.emit('error', new Error('a socket option needs a connect first'))
    this._connection.then(async (connected) => {
      try {
        await connected?.socket.setOption(option)
      } catch (error) {
        if (!this.destroyed) this.emit('error', error)
      }
    })
  }

  /**
   * The callbacks of the writes and ends not done yet, in call order. A write the destroy cut off never calls back,
   * and the stream settles none of the ones behind it while a write is in flight, so 'close' settles them.
   */
  _pending = new Set<Callback>()
  _endCallbacks: Callback[] = []

  _settleOnClose(callback: Callback) {
    const settle = (error?: Error | null) => {
      if (this._pending.delete(settle)) callback(error)
    }
    this._pending.add(settle)
    return settle
  }

  end(callback?: Callback): this
  end(chunk: Uint8Array | string, callback?: Callback): this
  end(chunk: Uint8Array | string, encoding?: BufferEncoding, callback?: Callback): this
  end(chunk?: Uint8Array | string | Callback, encoding?: BufferEncoding | Callback, callback?: Callback): this {
    if (typeof encoding === 'function') [callback, encoding] = [encoding, undefined]
    if (typeof chunk === 'function') [callback, chunk] = [chunk, undefined]
    // as Node: an end after the socket finished calls back with ERR_STREAM_ALREADY_FINISHED, and once destroyed, a
    // chunk fails as a write after destroy does and an end alone does nothing
    if (chunk == null && this.writableFinished) {
      const error = coded('Cannot call end after a stream was finished', 'ERR_STREAM_ALREADY_FINISHED')
      if (callback) queueMicrotask(() => callback(error))
      return this
    }
    if (this.destroyed) {
      if (chunk != null) this.write(chunk, encoding as BufferEncoding, callback)
      return this
    }
    if (callback) this._endCallbacks.push(this._settleOnClose(callback))
    return Reflect.apply(super.end, this, [chunk, encoding])
  }

  write(chunk: Uint8Array | string, callback?: Callback): boolean
  write(chunk: Uint8Array | string, encoding?: BufferEncoding, callback?: Callback): boolean
  write(chunk: Uint8Array | string, encoding?: BufferEncoding | Callback, callback?: Callback): boolean {
    if (typeof encoding === 'function') [callback, encoding] = [encoding, undefined]
    const settle = callback && this._settleOnClose(callback)
    return Reflect.apply(super.write, this, encoding ? [chunk, encoding, settle] : [chunk, settle])
  }

  connect(...args: unknown[]): this {
    const { host = 'localhost', port, callback } = netArgs(args)
    const provider = this._provider()
    if (callback) this.once('connect', callback)
    const ip = parseIp(host)
    this._open(provider.then((ready) => ready.tcpConnect(ip ? { ip, port } : { name: host, port })), host, port)
    return this
  }

  address(): Endpoint | {} {
    return this._local ?? {}
  }

  get localAddress() { return this._local?.address }
  get localPort() { return this._local?.port }
  get localFamily() { return this._local?.family }
  get remoteAddress() { return this._remote?.address }
  get remotePort() { return this._remote?.port }
  get remoteFamily() { return this._remote?.family }
  get pending() { return !this._connected || this.connecting }

  get readyState() {
    if (this.connecting) return 'opening'
    if (this.readable) return this.writable ? 'open' : 'readOnly'
    return this.writable ? 'writeOnly' : 'closed'
  }

  ref(): this {
    return this
  }

  unref(): this {
    return this
  }
}

class Server extends EventEmitter {
  declare _provider: () => Promise<Provider>
  declare _Socket: typeof Socket
  _local?: Endpoint
  _listening?: Promise<TcpListener | undefined>
  _allowHalfOpen: boolean
  _closeEmitted = false

  constructor(options?: { allowHalfOpen?: boolean } | ((socket: Socket) => void), listener?: (socket: Socket) => void) {
    super()
    if (typeof options === 'function') [listener, options] = [options, undefined]
    this._allowHalfOpen = Boolean(options?.allowHalfOpen)
    if (listener) this.on('connection', listener)
  }

  // A socket can come out of `connections` in the same turn as close(), before the listener heard of it, and Node hands
  // out none after close(), so that one is closed here; the listener closes the ones still waiting
  async _serve(listener: TcpListener, listening: Promise<unknown>) {
    const reader = listener.connections.getReader()
    for (let read = await reader.read(); !read.done; read = await reader.read()) {
      if (this._listening !== listening) return void read.value.close().catch(noop)
      const socket = new this._Socket({ allowHalfOpen: this._allowHalfOpen })
      socket.server = this
      socket._accept(read.value)
      // a listener that throws is reported as uncaught, as in Node, and the next sockets are still handed out
      try {
        this.emit('connection', socket)
      } catch (error) {
        queueMicrotask(() => { throw error })
      }
    }
  }

  listen(...args: unknown[]): this {
    if (this._listening) throw coded('Listen method has been called more than once without closing.', 'ERR_SERVER_ALREADY_LISTEN')
    const { port, host, callback } = netArgs(args)
    const provider = this._provider()
    if (callback) this.once('listening', callback)
    this._closeEmitted = false
    const listening: Promise<TcpListener | undefined> = provider.then(async (ready) => {
      const listen = (ip: Uint8Array) => ready.tcpListen({ ip, port }).catch((error: unknown) => {
        throw nodeError(error, 'listen', formatIp(ip), port)
      })
      // as Node, a server with no host takes the IPv6 wildcard, and the IPv4 one where IPv6 is missing
      return host ? listen(await resolve(ready, host)) : listen(IPV6_ANY).catch(() => listen(IPV4_ANY))
    }).catch((error: unknown) => {
      // as Node, a server whose listen failed is not listening, and may listen again
      if (this._listening !== listening) return undefined
      this._listening = undefined
      this.emit('error', error)
      return undefined
    })
    this._listening = listening
    listening.then((listener) => {
      if (!listener) return
      this._serve(listener, listening)
      if (this._listening !== listening) return
      this._local = endpoint(listener.local)
      this.emit('listening')
      listener.closed.then((closed) => {
        if (this._listening !== listening) return
        this._listening = this._local = undefined
        // with no 'error' listener, emit('error') throws, and an unfenced one would lose 'close' too
        try {
          if (closed.by === 'relay' && this.listenerCount('error') > 0) this.emit('error', new WebVpnError(closed.code, 'the relay closed the listener'))
        } finally {
          this._emitClose()
        }
      })
    })
    return this
  }

  _emitClose() {
    if (this._closeEmitted) return
    this._closeEmitted = true
    this.emit('close')
  }

  close(callback?: (error?: Error) => void): this {
    const listening = this._listening
    this._listening = this._local = undefined
    // as Node, a server that is not listening still emits 'close', and the callback is one of its listeners
    if (!listening) {
      if (callback) this.once('close', () => callback(coded('Server is not running.', 'ERR_SERVER_NOT_RUNNING')))
      queueMicrotask(() => this.emit('close'))
      return this
    }
    listening.then(async (listener) => {
      let failure: Error | undefined
      try {
        await listener?.close()
      } catch (error) {
        failure = error as Error
      }
      this._emitClose()
      callback?.(failure)
    })
    return this
  }

  address(): Endpoint | null {
    return this._local ?? null
  }

  get listening() {
    return this._local !== undefined
  }

  getConnections(): this {
    throw new Error('getConnections is not supported')
  }

  ref(): this {
    return this
  }

  unref(): this {
    return this
  }

  async [Symbol.asyncDispose]() {
    await new Promise((settle) => this.close(settle))
  }
}

const isIPv4 = (input: string) => parseIp(`${input}`)?.byteLength === 4
const isIPv6 = (input: string) => parseIp(`${input}`.replace(/%[\w.:-]+$/, ''))?.byteLength === 16
const isIP = (input: string) => isIPv4(input) ? 4 : isIPv6(input) ? 6 : 0

/** The module's classes and functions, bound to the provider `get` returns. */
export const build = (get: () => Promise<Provider>) => {
  class BoundSocket extends Socket {
    _provider = get
  }
  class BoundServer extends Server {
    _provider = get
    _Socket = BoundSocket
  }
  const connect = (...args: unknown[]) => {
    const options = args[0] !== null && typeof args[0] === 'object' ? args[0] as { allowHalfOpen?: boolean } : undefined
    return new BoundSocket({ allowHalfOpen: options?.allowHalfOpen }).connect(...args)
  }
  const createServer = (
    options?: { allowHalfOpen?: boolean } | ((socket: Socket) => void),
    listener?: (socket: Socket) => void,
  ) => new BoundServer(options, listener)
  return { Socket: BoundSocket, Server: BoundServer, connect, createConnection: connect, createServer, isIP, isIPv4, isIPv6 }
}
