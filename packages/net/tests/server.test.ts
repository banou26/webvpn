import type { Socket } from 'node:net'

import { ErrorCode } from '@webvpn/client'
import { describe, expect, it } from 'vite-plus/test'

import { createNet } from '../src'
import { address, fakeProvider, fakeSocket, relayError, wait } from './fake'

const setup = () => {
  const relay = fakeProvider()
  return { relay, net: createNet(relay.provider) }
}

const listening = async (options: { allowHalfOpen?: boolean } = {}) => {
  const { relay, net } = setup()
  const server = net.createServer(options)
  server.listen(51413, '0.0.0.0')
  await new Promise((resolve) => server.once('listening', resolve))
  return { relay, net, server, listener: relay.listeners.at(-1)! }
}

const flags = (socket: Socket) => `d=${+socket.destroyed} r=${+socket.readable} w=${+socket.writable}`
const describeError = (error?: Error | null) => error ? (error as { code?: string }).code ?? error.message : 'ok'

describe('listen', () => {
  it('listens on a port and a host, emits listening, and runs the callback', async () => {
    const { relay, net } = setup()
    const server = net.createServer()
    const log: string[] = []
    server.on('listening', () => log.push('listening'))
    server.listen(6881, '127.0.0.1', 511, () => log.push('callback'))
    expect(server.listening).toBe(false)
    await wait(0)
    expect(log).toEqual(['listening', 'callback'])
    expect(server.listening).toBe(true)
    expect(server.address()).toEqual({ address: '127.0.0.1', family: 'IPv4', port: 6881 })
    expect(relay.calls.listens).toEqual([address('127.0.0.1', 6881)])
    expect(() => server.listen(6882)).toThrow(expect.objectContaining({ code: 'ERR_SERVER_ALREADY_LISTEN' }))
  })

  it('takes the IPv6 wildcard with no host, and the IPv4 one when the relay refuses it', async () => {
    const { relay, net } = setup()
    const server = net.createServer().listen(0)
    await new Promise((resolve) => server.once('listening', resolve))
    expect(server.address()).toEqual({ address: '::', family: 'IPv6', port: 51413 })

    relay.listenError = (local) => local.ip.byteLength === 16 ? relayError(ErrorCode.UNSUPPORTED) : undefined
    const fallback = net.createServer().listen({ port: 0 })
    await new Promise((resolve) => fallback.once('listening', resolve))
    expect(fallback.address()).toEqual({ address: '0.0.0.0', family: 'IPv4', port: 51413 })
  })

  it('looks a host name up through the relay', async () => {
    const { relay, net } = setup()
    relay.names.set('home.example', ['192.0.2.4'])
    const server = net.createServer().listen(6881, 'home.example')
    await new Promise((resolve) => server.once('listening', resolve))
    expect(relay.calls.lookups).toEqual(['home.example'])
    expect(server.address()).toEqual({ address: '192.0.2.4', family: 'IPv4', port: 6881 })
  })

  // Node 26.12.1 on Linux (measured 2026-11-15), a server listening on a name with no address
  it('fails with Node\'s ENOTFOUND on a name with no address', async () => {
    const { net } = setup()
    const server = net.createServer()
    const failed = new Promise<Error>((resolve) => server.once('error', resolve))
    server.listen(51413, 'missing.invalid')
    const error = await failed
    expect(error).toMatchObject({ message: 'getaddrinfo ENOTFOUND missing.invalid', errno: -3008, code: 'ENOTFOUND', syscall: 'getaddrinfo', hostname: 'missing.invalid' })
    expect(server.address()).toBe(null)
  })

  // Node 26.12.1 on Linux (measured 2026-11-27), with `code` before `errno` as Node sets them for a listen
  it.each([
    [ErrorCode.ADDRESS_IN_USE, '127.0.0.1', 'listen EADDRINUSE: address already in use 127.0.0.1:6881', { code: 'EADDRINUSE', errno: -98 }],
    [ErrorCode.ADDRESS_IN_USE, '::', 'listen EADDRINUSE: address already in use :::6881', { code: 'EADDRINUSE', errno: -98 }],
    [ErrorCode.REFUSED, '0.0.0.0', 'listen EACCES: permission denied 0.0.0.0:6881', { code: 'EACCES', errno: -13 }],
    [ErrorCode.ADDRESS_NOT_AVAILABLE, '192.0.2.1', 'listen EADDRNOTAVAIL: address not available 192.0.2.1:6881', { code: 'EADDRNOTAVAIL', errno: -99 }],
  ])('fails a refused listen with Node\'s error: code %i on %s', async (code, host, message, fields) => {
    const { relay, net } = setup()
    relay.listenError = relayError(code)
    const server = net.createServer()
    const failed = new Promise<Error>((resolve) => server.once('error', resolve))
    server.listen(6881, host)
    const error = await failed
    const expected = { ...fields, syscall: 'listen', address: host, port: 6881 }
    expect(error).toMatchObject({ message, ...expected })
    expect(Object.keys(error)).toEqual(Object.keys(expected))
    expect(server.address()).toBe(null)
  })

  it('keeps an error Node has no counterpart for as the relay gave it', async () => {
    const { relay, net } = setup()
    relay.listenError = relayError(ErrorCode.CAPACITY, 'too many sockets')
    const server = net.createServer().listen(6881, '0.0.0.0')
    const error = await new Promise<Error>((resolve) => server.once('error', resolve))
    expect(error).toBe(relay.listenError)
  })

  it('refuses an IPC path', () => {
    const { net } = setup()
    expect(() => net.createServer().listen('/tmp/socket')).toThrow('IPC paths are not supported')
  })

  // Node 26.12.1 on Linux (measured 2026-11-28): a server whose listen failed is not running, so close() emits close
  // and calls back with ERR_SERVER_NOT_RUNNING, and it may listen again, on the next port say
  it('listens again after a listen that failed, and closes as a server that is not running', async () => {
    const { relay, net } = setup()
    relay.listenError = (local) => local.port === 6881 ? relayError(ErrorCode.ADDRESS_IN_USE) : undefined
    const server = net.createServer()
    const log: string[] = []
    server.on('error', (error: Error & { code?: string }) => log.push(`error ${error.code}`))
    server.on('close', () => log.push('close'))
    server.listen(6881, '0.0.0.0')
    await wait(10)
    server.close((error) => log.push(`callback ${(error as Error & { code?: string })?.code}`))
    await wait(10)
    expect(log).toEqual(['error EADDRINUSE', 'close', 'callback ERR_SERVER_NOT_RUNNING'])
    server.listen(6881, '0.0.0.0')
    await wait(10)
    server.listen(6882, '0.0.0.0')
    await Promise.race([new Promise((resolve) => server.once('listening', resolve)), wait(100)])
    expect(server.address()).toEqual({ address: '0.0.0.0', family: 'IPv4', port: 6882 })
  })

})

describe('connections', () => {
  /**
   * Node fills an accepted socket's endpoints in before it emits 'connection'. Measured against a live relay on
   * 2026-08-15, a socket whose endpoints came a microtask later threw inside the handler, and libtorrent drops a peer
   * whose remote endpoint it cannot read, with no alert, which looks like the relay never delivering the connection.
   */
  it('hands out each accepted socket with its endpoints and its server, and carries its bytes', async () => {
    const { server, listener } = await listening()
    const seen = new Promise<{ socket: Socket, endpoints: unknown[] }>((resolve) => server.once('connection', (socket: Socket) => {
      resolve({ socket, endpoints: [socket.localAddress, socket.localPort, socket.remoteAddress, socket.remotePort, socket.remoteFamily] })
    }))
    const peer = fakeSocket(address('10.0.0.1', 51413), address('198.51.100.9', 6881))
    listener.accept(peer.socket)
    const { socket, endpoints } = await seen
    expect(endpoints).toEqual(['10.0.0.1', 51413, '198.51.100.9', 6881, 'IPv4'])
    expect((socket as Socket & { server: unknown }).server).toBe(server)
    const read = new Promise<string>((resolve) => socket.once('data', (chunk: Uint8Array) => resolve(new TextDecoder().decode(chunk))))
    peer.send('hello')
    expect(await read).toBe('hello')
    await new Promise<void>((resolve) => socket.end('bye', () => resolve()))
    expect(peer.received()).toBe('bye')
    expect(peer.state.finished).toBe(true)
  })

  it('a socket this page connected has no server, as in Node', () => {
    const { net } = setup()
    expect((new net.Socket() as Socket & { server: unknown }).server).toBe(null)
  })

  it('a socket a server accepted ends and closes when the far side ends, unless the server is half open', async () => {
    for (const allowHalfOpen of [false, true]) {
      const { server, listener } = await listening({ allowHalfOpen })
      const accepted = new Promise<Socket>((resolve) => server.once('connection', resolve))
      const peer = fakeSocket()
      listener.accept(peer.socket)
      const socket = await accepted
      const log: string[] = []
      for (const event of ['connect', 'finish', 'end']) socket.on(event, () => log.push(`${event} ${flags(socket)}`))
      const closed = new Promise((resolve) => socket.once('close', resolve))
      socket.on('close', (hadError) => log.push(`close ${hadError} ${flags(socket)}`))
      socket.resume()
      peer.end()
      await wait(10)
      log.push(`mid ${flags(socket)}`)
      socket.end()
      await closed
      // and an accepted socket emits no 'connect', as in Node
      expect(log).toEqual(allowHalfOpen
        ? ['end d=0 r=0 w=1', 'mid d=0 r=0 w=1', 'finish d=0 r=0 w=0', 'close false d=1 r=0 w=0']
        : ['end d=0 r=0 w=1', 'finish d=0 r=0 w=0', 'close false d=1 r=0 w=0', 'mid d=1 r=0 w=0'])
      server.close()
    }
  })

  it('a socket a server accepted and destroyed at once fails its writes before close, as a connected socket does', async () => {
    const { server, listener } = await listening()
    for (const error of [undefined, Object.assign(new Error('EBOOM'), { code: 'EBOOM' })]) {
      const log: string[] = []
      const closed = new Promise((resolve) => server.once('connection', (socket: Socket) => {
        socket.on('error', (failure) => log.push(`error ${describeError(failure)}`))
        socket.on('close', (hadError) => {
          log.push(`close ${hadError}`)
          resolve(undefined)
        })
        socket.write(new Uint8Array(1), (failure) => log.push(`a ${describeError(failure)}`))
        socket.write(new Uint8Array(1), (failure) => log.push(`b ${describeError(failure)}`))
        socket.destroy(error)
      }))
      const peer = fakeSocket()
      peer.stall()
      listener.accept(peer.socket)
      await closed
      await wait(20)
      expect(log).toEqual(error
        ? ['error EBOOM', 'a ECANCELED', 'b EBOOM', 'close true']
        : ['a ECANCELED', 'b ECANCELED', 'close false'])
    }
    server.close()
  })
})

describe('close', () => {
  it('closes the relay\'s listener, emits close, runs the callback, and forgets the address', async () => {
    const { server, listener } = await listening()
    const log: string[] = []
    server.on('close', () => log.push('close'))
    server.close((error) => log.push(`callback ${error}`))
    expect(server.address()).toBe(null)
    expect(server.listening).toBe(false)
    await wait(0)
    expect(log).toEqual(['close', 'callback undefined'])
    expect(await listener.listener.closed).toEqual({ by: 'client' })
  })

  // the listener closes the sockets still waiting in it, and this one already left it
  it('hands out no socket after close, and closes one the listener gave it in the same turn', async () => {
    const { server, listener } = await listening()
    const handed: Socket[] = []
    server.on('connection', (socket: Socket) => handed.push(socket))
    const late = fakeSocket()
    listener.accept(late.socket)
    server.close()
    await wait(10)
    expect(handed).toEqual([])
    expect(late.teardown).toEqual(['close'])
  })

  it('calls back with ERR_SERVER_NOT_RUNNING when the server is not listening', async () => {
    const { net } = setup()
    const error = await new Promise<Error | undefined>((resolve) => net.createServer().close(resolve))
    expect(error).toMatchObject({ code: 'ERR_SERVER_NOT_RUNNING' })
  })

  it('emits error then close when the relay ends the listener on its own, and close alone with no error listener', async () => {
    const watched = await listening()
    const log: string[] = []
    watched.server.on('error', (error) => log.push(`error ${error.message} ${(error as { code?: number }).code}`))
    watched.server.on('close', () => log.push('close'))
    watched.listener.end({ by: 'relay', code: ErrorCode.CAPACITY })
    await wait(0)
    expect(log).toEqual([`error the relay closed the listener ${ErrorCode.CAPACITY}`, 'close'])
    expect(watched.server.address()).toBe(null)

    const bare = await listening()
    const closed = new Promise((resolve) => bare.server.once('close', resolve))
    bare.listener.end({ by: 'relay', code: ErrorCode.CAPACITY })
    await closed
  })

  it('emits close alone when the session ends', async () => {
    const { server, listener } = await listening()
    const log: string[] = []
    server.on('error', (error) => log.push(`error ${error.message}`))
    server.on('close', () => log.push('close'))
    listener.end({ by: 'session' })
    await wait(0)
    expect(log).toEqual(['close'])
    expect(server.address()).toBe(null)
  })

  it('closes on Symbol.asyncDispose', async () => {
    const { server, listener } = await listening()
    await (server as unknown as AsyncDisposable)[Symbol.asyncDispose]()
    expect(await listener.listener.closed).toEqual({ by: 'client' })
  })
})
