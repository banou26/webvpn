import type { RemoteInfo, Socket } from 'node:dgram'

import { ErrorCode } from '@webvpn/client'
import { describe, expect, it } from 'vite-plus/test'

import { createDgram } from '../src'
import { address, fakeProvider, gate, relayError, wait } from './fake'

const setup = () => {
  const relay = fakeProvider()
  return { relay, dgram: createDgram(relay.provider) }
}

const bound = async (type: 'udp4' | 'udp6' = 'udp4') => {
  const { relay, dgram } = setup()
  const socket = dgram.createSocket(type)
  socket.bind()
  await new Promise((resolve) => socket.once('listening', resolve))
  return { relay, dgram, socket, udp: relay.sockets.at(-1)! }
}

const outcome = (send: (callback: (error: Error | null, bytes?: number) => void) => void) =>
  new Promise<Error | number | undefined>((resolve) => send((error, bytes) => resolve(error ?? bytes)))

// Node 26.12.1 on Linux (measured 2026-11-15): a bind, a connect and a send to a name with no address all fail with
// this error, a send with a callback through it
const NOT_FOUND = { message: 'getaddrinfo ENOTFOUND missing.invalid', errno: -3008, code: 'ENOTFOUND', syscall: 'getaddrinfo', hostname: 'missing.invalid' }

describe('bind', () => {
  it('binds in each of Node\'s forms, and reports the port the relay gave', async () => {
    const { relay, dgram } = setup()
    const forms: [string, (socket: Socket, done: () => void) => void][] = [
      ['0.0.0.0:0', (socket, done) => socket.bind(done)],
      ['0.0.0.0:6881', (socket, done) => socket.bind(6881, done)],
      ['127.0.0.1:6881', (socket, done) => socket.bind(6881, '127.0.0.1', done)],
      ['192.0.2.4:0', (socket, done) => socket.bind({ address: '192.0.2.4' }, done)],
      ['0.0.0.0:7000', (socket, done) => socket.bind({ port: 7000 }, done)],
    ]
    for (const [local, bind] of forms) {
      const socket = dgram.createSocket('udp4')
      const log: string[] = []
      socket.on('listening', () => log.push('listening'))
      await new Promise<void>((resolve) => bind(socket, () => {
        log.push('callback')
        resolve()
      }))
      expect(log).toEqual(['listening', 'callback'])
      expect(relay.binds.at(-1)).toBe(local)
    }
    const socket = dgram.createSocket('udp4')
    socket.bind(0, '127.0.0.1')
    await new Promise((resolve) => socket.once('listening', resolve))
    expect(socket.address()).toEqual({ address: '127.0.0.1', family: 'IPv4', port: 41234 })

    const six = dgram.createSocket({ type: 'udp6' })
    six.bind()
    await new Promise((resolve) => six.once('listening', resolve))
    expect(six.address()).toEqual({ address: '::', family: 'IPv6', port: 41234 })
  })

  // Node 26.12.1 on Linux (measured 2026-11-28): a bind and a connect take their port as a string of digits too, as
  // one read from a setting is
  it('binds and connects to a port given as a string', async () => {
    const { relay, dgram } = setup()
    const socket = dgram.createSocket('udp4')
    socket.bind('6881' as unknown as number, '127.0.0.1')
    await Promise.race([new Promise((resolve) => socket.once('listening', resolve)), wait(100)])
    expect(relay.binds.at(-1)).toBe('127.0.0.1:6881')
    socket.connect('7000' as unknown as number, '192.0.2.9')
    await Promise.race([new Promise((resolve) => socket.once('connect', resolve)), wait(100)])
    expect(socket.remoteAddress()).toEqual({ address: '192.0.2.9', family: 'IPv4', port: 7000 })
  })

  it('looks a name up, an A record for udp4', async () => {
    const { relay, dgram } = setup()
    relay.names.set('home.example', ['192.0.2.4', '2001:db8::4'])
    const socket = dgram.createSocket('udp4')
    socket.bind(6881, 'home.example')
    await new Promise((resolve) => socket.once('listening', resolve))
    expect(relay.lookups).toEqual(['A home.example'])
    expect(relay.binds).toEqual(['192.0.2.4:6881'])
  })

  it('throws when bound already, and for a type that is not udp4 or udp6', async () => {
    const { socket, dgram } = await bound()
    expect(() => socket.bind()).toThrow(expect.objectContaining({ code: 'ERR_SOCKET_ALREADY_BOUND', message: 'Socket is already bound' }))
    expect(() => dgram.createSocket('tcp' as 'udp4'))
      .toThrow(expect.objectContaining({ code: 'ERR_SOCKET_BAD_TYPE', message: 'Bad socket type specified. Valid types are: udp4, udp6' }))
  })

  // Node 26.12.1 on Linux (measured 2026-11-27)
  it.each([
    [ErrorCode.ADDRESS_IN_USE, '127.0.0.1', 'bind EADDRINUSE 127.0.0.1:6881', { errno: -98, code: 'EADDRINUSE' }],
    [ErrorCode.REFUSED, '0.0.0.0', 'bind EACCES 0.0.0.0:6881', { errno: -13, code: 'EACCES' }],
    [ErrorCode.ADDRESS_NOT_AVAILABLE, '192.0.2.1', 'bind EADDRNOTAVAIL 192.0.2.1:6881', { errno: -99, code: 'EADDRNOTAVAIL' }],
  ])('fails a refused bind with Node\'s error and never reports it listening: code %i', async (code, host, message, fields) => {
    const { relay, dgram } = setup()
    relay.bindError = relayError(code)
    const socket = dgram.createSocket('udp4')
    const log: string[] = []
    socket.on('listening', () => log.push('listening'))
    const failed = new Promise<Error>((resolve) => socket.once('error', resolve))
    socket.bind(6881, host, () => log.push('callback'))
    const error = await failed
    await wait(0)
    const expected = { ...fields, syscall: 'bind', address: host, port: 6881 }
    expect(error).toMatchObject({ message, ...expected })
    expect(Object.keys(error)).toEqual(Object.keys(expected))
    expect(log).toEqual([])
    expect(() => socket.address()).toThrow(expect.objectContaining({ message: 'getsockname EBADF', errno: -9, code: 'EBADF', syscall: 'getsockname' }))
  })

  it('fails a bind to a name with no address with Node\'s ENOTFOUND, and keeps other errors as they are', async () => {
    const { relay, dgram } = setup()
    const named = dgram.createSocket('udp4')
    const notFound = new Promise<Error>((resolve) => named.once('error', resolve))
    named.bind(6881, 'missing.invalid')
    expect(await notFound).toMatchObject(NOT_FOUND)

    relay.bindError = relayError(ErrorCode.CAPACITY, 'too many sockets')
    const full = dgram.createSocket('udp4')
    const capacity = new Promise<Error>((resolve) => full.once('error', resolve))
    full.bind()
    expect(await capacity).toBe(relay.bindError)
  })
})

describe('send', () => {
  it('sends in each of Node\'s forms and calls back with the bytes sent', async () => {
    const { socket, udp } = await bound()
    expect(await outcome((done) => socket.send('a', 7000, '192.0.2.9', done))).toBe(1)
    expect(await outcome((done) => socket.send(new TextEncoder().encode('bb'), 7000, done))).toBe(2)
    expect(await outcome((done) => socket.send('-ccc-', 1, 3, 7000, '192.0.2.9', done))).toBe(3)
    expect(await outcome((done) => socket.send(new TextEncoder().encode('-dd'), 1, 2, 7000, done))).toBe(2)
    expect(await outcome((done) => socket.send(['e', new TextEncoder().encode('ee')], 7000, '2001:db8::9', done))).toBe(3)
    expect(udp.sent).toEqual([
      { to: '192.0.2.9:7000', data: 'a' },
      { to: '127.0.0.1:7000', data: 'bb' },
      { to: '192.0.2.9:7000', data: 'ccc' },
      { to: '127.0.0.1:7000', data: 'dd' },
      { to: '2001:db8::9:7000', data: 'eee' },
    ])
  })

  // Node 26.12.1 on Linux (measured 2026-11-28): the port of a send that is not to a connected peer may be a string
  // of digits, as one read from a setting is; one that is missing or no port at all throws, before any bind
  it('takes a port given as a string, and throws Node\'s ERR_SOCKET_BAD_PORT for a port missing or out of range', async () => {
    const { socket, udp } = await bound()
    expect(await outcome((done) => socket.send('a', '7000' as unknown as number, '192.0.2.9', done))).toBe(1)
    expect(await outcome((done) => socket.send('-b-', 1, 1, '7001' as unknown as number, '192.0.2.9', done))).toBe(1)
    expect(udp.sent).toEqual([{ to: '192.0.2.9:7000', data: 'a' }, { to: '192.0.2.9:7001', data: 'b' }])
    const bad = (received: string) => expect.objectContaining({ name: 'RangeError', code: 'ERR_SOCKET_BAD_PORT', message: `Port should be > 0 and < 65536. Received ${received}.` })
    expect(() => socket.send('x')).toThrow(bad('undefined'))
    expect(() => socket.send('x', () => {})).toThrow(bad('function '))
    expect(() => socket.send('x', 0, '192.0.2.9')).toThrow(bad('type number (0)'))
    expect(() => socket.send('x', 70000, '192.0.2.9')).toThrow(bad('type number (70000)'))
    expect(() => socket.send('x', 'abc' as unknown as number, '192.0.2.9')).toThrow(bad('type string (\'abc\')'))
    await wait(10)
    expect(udp.sent).toHaveLength(2)
  })

  it('takes a copy of the message, so the caller may reuse its buffer at once', async () => {
    const { socket, udp } = await bound()
    const buffer = new TextEncoder().encode('first')
    const sent = outcome((done) => socket.send(buffer, 7000, '192.0.2.9', done))
    buffer.set(new TextEncoder().encode('later'))
    await sent
    expect(udp.sent).toEqual([{ to: '192.0.2.9:7000', data: 'first' }])
  })

  it('throws Node\'s error for an offset or a length outside the message', async () => {
    const { socket } = await bound()
    expect(() => socket.send('abc', 4, 1, 7000)).toThrow(expect.objectContaining({ code: 'ERR_BUFFER_OUT_OF_BOUNDS', message: '"offset" is outside of buffer bounds' }))
    expect(() => socket.send('abc', 1, 3, 7000)).toThrow(expect.objectContaining({ code: 'ERR_BUFFER_OUT_OF_BOUNDS', message: '"length" is outside of buffer bounds' }))
  })

  it('binds first on a send to an unbound socket, and sends what waited in the order it was sent', async () => {
    const { relay, dgram } = setup()
    const held = gate()
    relay.holdBind = held.opened
    const socket = dgram.createSocket('udp4')
    const log: string[] = []
    socket.on('listening', () => log.push('listening'))
    for (const text of ['a', 'b', 'c']) socket.send(text, 7000, '192.0.2.9', () => log.push(`sent ${text}`))
    await wait(10)
    expect(relay.binds).toEqual(['0.0.0.0:0'])
    expect(log).toEqual([])
    held.open()
    await wait(10)
    expect(log).toEqual(['listening', 'sent a', 'sent b', 'sent c'])
    expect(relay.sockets[0]!.sent.map(({ data }) => data)).toEqual(['a', 'b', 'c'])
  })

  // Node 26.12.1 on Linux (measured 2026-11-27): what waited on a bind that failed is dropped with no callback, and
  // the bind's own error is the one emitted
  it('drops the sends that waited on a bind that failed', async () => {
    const { relay, dgram } = setup()
    relay.bindError = relayError(ErrorCode.REFUSED)
    const socket = dgram.createSocket('udp4')
    const log: string[] = []
    socket.on('error', (error: Error & { code?: string }) => log.push(`error ${error.code}`))
    socket.send('a', 7000, '192.0.2.9', (error) => log.push(`callback ${error}`))
    await wait(10)
    expect(log).toEqual(['error EACCES'])
  })

  it('looks a name up, an A record for udp4 and an AAAA one for udp6', async () => {
    const four = await bound('udp4')
    four.relay.names.set('tracker.example', ['192.0.2.10', '2001:db8::10'])
    await outcome((done) => four.socket.send('a', 6969, 'tracker.example', done))
    expect(four.relay.lookups).toEqual(['A tracker.example'])
    expect(four.udp.sent).toEqual([{ to: '192.0.2.10:6969', data: 'a' }])

    const six = await bound('udp6')
    six.relay.names.set('tracker.example', ['192.0.2.10', '2001:db8::10'])
    await outcome((done) => six.socket.send('a', 6969, 'tracker.example', done))
    expect(six.relay.lookups).toEqual(['AAAA tracker.example'])
    expect(six.udp.sent).toEqual([{ to: '2001:db8::10:6969', data: 'a' }])
  })

  it('fails a send to a name with no address with Node\'s ENOTFOUND, through the callback or as an error', async () => {
    const { socket } = await bound()
    expect(await outcome((done) => socket.send('a', 6969, 'missing.invalid', done))).toMatchObject(NOT_FOUND)
    const emitted = new Promise((resolve) => socket.once('error', resolve))
    socket.send('b', 6969, 'missing.invalid')
    expect(await emitted).toMatchObject(NOT_FOUND)
  })

  // Node 26.12.1 on Linux (measured 2026-11-27): 65507 bytes go out to IPv4 and 65508 fail, 65527 and 65528 to IPv6;
  // a send with no callback fails silently, and one on a connected socket names no address
  it('fails a datagram over what Linux sends with EMSGSIZE', async () => {
    const { socket, udp } = await bound()
    expect(await outcome((done) => socket.send(new Uint8Array(65507), 7000, '192.0.2.9', done))).toBe(65507)
    const big = await outcome((done) => socket.send(new Uint8Array(65508), 7000, '192.0.2.9', done))
    const expected = { errno: -90, code: 'EMSGSIZE', syscall: 'send', address: '192.0.2.9', port: 7000 }
    expect(big).toMatchObject({ message: 'send EMSGSIZE 192.0.2.9:7000', ...expected })
    expect(Object.keys(big as Error)).toEqual(Object.keys(expected))
    expect(await outcome((done) => socket.send(new Uint8Array(65527), 7000, '2001:db8::9', done))).toBe(65527)
    expect(await outcome((done) => socket.send(new Uint8Array(65528), 7000, '2001:db8::9', done))).toMatchObject({ code: 'EMSGSIZE' })

    const errors: Error[] = []
    socket.on('error', (error) => errors.push(error))
    socket.send(new Uint8Array(65508), 7000, '192.0.2.9')
    socket.connect(7000, '192.0.2.9')
    await new Promise((resolve) => socket.once('connect', resolve))
    const connected = await outcome((done) => socket.send(new Uint8Array(65508), done))
    expect(connected).toMatchObject({ message: 'send EMSGSIZE', errno: -90, code: 'EMSGSIZE', syscall: 'send', address: undefined })
    expect(Object.keys(connected as Error)).toEqual(['errno', 'code', 'syscall', 'address'])
    await wait(10)
    expect(errors).toEqual([])
    expect(udp.sent.map(({ data }) => data.length)).toEqual([65507, 65527])
  })
})

describe('connect', () => {
  it('fixes the peer: emits connect, sends to it with no address, and reports it', async () => {
    const { socket, udp } = await bound()
    const log: string[] = []
    socket.connect(7000, '192.0.2.9', () => log.push('callback'))
    socket.on('connect', () => log.push('connect'))
    await new Promise((resolve) => socket.once('connect', resolve))
    expect(log).toEqual(['callback', 'connect'])
    expect(udp.calls).toEqual(['connect 192.0.2.9:7000'])
    expect(socket.remoteAddress()).toEqual({ address: '192.0.2.9', family: 'IPv4', port: 7000 })
    await outcome((done) => socket.send('to the peer', done))
    expect(udp.sent).toEqual([{ to: 'peer', data: 'to the peer' }])
    expect(() => socket.connect(7001, '192.0.2.9')).toThrow(expect.objectContaining({ code: 'ERR_SOCKET_DGRAM_IS_CONNECTED', message: 'Already connected' }))
  })

  // Node 26.12.1 on Linux (measured 2026-11-28): a second connect throws while the first is still on its way, and a
  // connect that failed leaves the socket free to connect again
  it('throws on a connect while one is on its way, and connects again after one failed', async () => {
    const { socket, udp } = await bound()
    socket.on('error', () => {})
    socket.connect(7000, '192.0.2.9')
    expect(() => socket.connect(7001, '192.0.2.9')).toThrow(expect.objectContaining({ code: 'ERR_SOCKET_DGRAM_IS_CONNECTED' }))
    await Promise.race([new Promise((resolve) => socket.once('connect', resolve)), wait(100)])
    expect(udp.calls).toEqual(['connect 192.0.2.9:7000'])
    socket.disconnect()
    await wait(0)

    udp.failures.connect = relayError(ErrorCode.REFUSED)
    await new Promise((resolve) => socket.connect(9, '255.255.255.255', resolve as () => void))
    udp.failures.connect = undefined
    socket.connect(7000, '192.0.2.9')
    await Promise.race([new Promise((resolve) => socket.once('connect', resolve)), wait(100)])
    expect(socket.remoteAddress()).toEqual({ address: '192.0.2.9', family: 'IPv4', port: 7000 })
  })

  it('binds first when the socket is not bound, as Node does', async () => {
    const { relay, dgram } = setup()
    const socket = dgram.createSocket('udp4')
    const log: string[] = []
    socket.on('listening', () => log.push('listening'))
    socket.on('connect', () => log.push('connect'))
    socket.connect(7000)
    await new Promise((resolve) => socket.once('connect', resolve))
    expect(log).toEqual(['listening', 'connect'])
    expect(relay.sockets[0]!.calls).toEqual(['connect 127.0.0.1:7000'])
  })

  // Node 26.12.1 on Linux (measured 2026-11-27): a connect the system refuses, here to a broadcast address
  it('gives a refused connect Node\'s EACCES, to the callback or as an error, and keeps the socket unconnected', async () => {
    const { socket, udp } = await bound()
    udp.failures.connect = relayError(ErrorCode.REFUSED)
    const error = await new Promise<Error>((resolve) => socket.connect(9, '255.255.255.255', resolve as () => void))
    const expected = { errno: -13, code: 'EACCES', syscall: 'connect', address: '255.255.255.255', port: 9 }
    expect(error).toMatchObject({ message: 'connect EACCES 255.255.255.255:9', ...expected })
    expect(Object.keys(error)).toEqual(Object.keys(expected))
    expect(socket.listenerCount('connect')).toBe(0)
    expect(() => socket.remoteAddress()).toThrow(expect.objectContaining({ code: 'ERR_SOCKET_DGRAM_NOT_CONNECTED', message: 'Not connected' }))

    const emitted = new Promise((resolve) => socket.once('error', resolve))
    socket.connect(6969, 'missing.invalid')
    expect(await emitted).toMatchObject(NOT_FOUND)
  })

  it('disconnects, and puts the peer back when the relay refuses the disconnect', async () => {
    const { socket, udp } = await bound()
    socket.connect(7000, '192.0.2.9')
    await new Promise((resolve) => socket.once('connect', resolve))
    socket.disconnect()
    expect(() => socket.remoteAddress()).toThrow(expect.objectContaining({ code: 'ERR_SOCKET_DGRAM_NOT_CONNECTED' }))
    await wait(0)
    expect(udp.calls).toEqual(['connect 192.0.2.9:7000', 'disconnect'])
    expect(() => socket.disconnect()).toThrow(expect.objectContaining({ code: 'ERR_SOCKET_DGRAM_NOT_CONNECTED' }))

    socket.connect(7000, '192.0.2.9')
    await new Promise((resolve) => socket.once('connect', resolve))
    udp.failures.disconnect = relayError(ErrorCode.OTHER, 'the relay could not disconnect')
    const failed = new Promise<Error>((resolve) => socket.once('error', resolve))
    socket.disconnect()
    expect((await failed).message).toBe('the relay could not disconnect')
    expect(socket.remoteAddress()).toEqual({ address: '192.0.2.9', family: 'IPv4', port: 7000 })
  })
})

describe('messages', () => {
  it('emits each datagram as a Buffer, with where it came from', async () => {
    const { socket, udp } = await bound()
    const received: [string, RemoteInfo][] = []
    socket.on('message', (message: Buffer, remote: RemoteInfo) => received.push([message.toString(), remote]))
    udp.deliver(address('192.0.2.9', 7000), 'hello')
    udp.deliver(address('2001:db8::9', 7001), 'again')
    await wait(0)
    expect(received).toEqual([
      ['hello', { address: '192.0.2.9', family: 'IPv4', port: 7000, size: 5 }],
      ['again', { address: '2001:db8::9', family: 'IPv6', port: 7001, size: 5 }],
    ])
  })
})

describe('options', () => {
  it('maps each option to the relay\'s UdpOption', async () => {
    const four = await bound('udp4')
    four.socket.setBroadcast(true)
    expect(four.socket.setTTL(32)).toBe(32)
    expect(four.socket.setMulticastTTL(4)).toBe(4)
    expect(four.socket.setMulticastLoopback(false)).toBe(false)
    four.socket.setRecvBufferSize(1 << 20)
    four.socket.setSendBufferSize(1 << 19)
    four.socket.addMembership('239.1.2.3')
    four.socket.addMembership('239.1.2.3', '192.0.2.4')
    four.socket.dropMembership('239.1.2.3')
    four.socket.addMembership('ff02::fb')
    four.socket.dropMembership('ff02::fb', 'eth0')
    await wait(0)
    expect(four.udp.options).toEqual([
      { type: 'broadcast', value: true },
      { type: 'ttl', value: 32 },
      { type: 'multicastTtlV4', value: 4 },
      { type: 'multicastLoopV4', value: false },
      { type: 'recvBufferSize', value: 1 << 20 },
      { type: 'sendBufferSize', value: 1 << 19 },
      { type: 'addMembershipV4', group: Uint8Array.of(239, 1, 2, 3), interface: Uint8Array.of(0, 0, 0, 0) },
      { type: 'addMembershipV4', group: Uint8Array.of(239, 1, 2, 3), interface: Uint8Array.of(192, 0, 2, 4) },
      { type: 'dropMembershipV4', group: Uint8Array.of(239, 1, 2, 3), interface: Uint8Array.of(0, 0, 0, 0) },
      { type: 'addMembershipV6', group: Uint8Array.of(0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb), interface: 0 },
      { type: 'dropMembershipV6', group: Uint8Array.of(0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb), interface: 0 },
    ])
    expect([four.socket.getRecvBufferSize(), four.socket.getSendBufferSize()]).toEqual([1 << 20, 1 << 19])

    const six = await bound('udp6')
    six.socket.setMulticastLoopback(true)
    await wait(0)
    expect(six.udp.options).toEqual([{ type: 'multicastLoopV6', value: true }])
  })

  it('emits an error for an option set before bind, one the relay refuses, and a group that is no address', async () => {
    const { dgram } = setup()
    const early = dgram.createSocket('udp4')
    const errors: string[] = []
    early.on('error', (error) => errors.push(error.message))
    early.setBroadcast(true)

    const { socket, udp } = await bound()
    socket.on('error', (error) => errors.push(error.message))
    socket.addMembership('not a group')
    udp.failures.option = relayError(ErrorCode.UNSUPPORTED, 'the relay does not take this option')
    socket.setTTL(1)
    await wait(0)
    expect(errors).toEqual(['a socket option needs a bind first', 'not a multicast address: not a group', 'the relay does not take this option'])
  })
})

describe('close', () => {
  it('closes the relay\'s socket, emits close then runs the callback, and refuses what comes after', async () => {
    const { socket, udp } = await bound()
    const log: string[] = []
    socket.on('close', () => log.push('close'))
    socket.close(() => log.push('callback'))
    await wait(0)
    expect(log).toEqual(['close', 'callback'])
    expect(udp.calls).toEqual(['close'])
    const notRunning = expect.objectContaining({ code: 'ERR_SOCKET_DGRAM_NOT_RUNNING', message: 'Not running' })
    expect(() => socket.close()).toThrow(notRunning)
    expect(() => socket.send('late', 7000)).toThrow(notRunning)
  })

  // Node 26.12.1, a udp4 socket closed after its bind succeeded or failed with EADDRINUSE (measured 2026-11-10), and
  // one never bound (measured 2026-11-27): 'close', then the close callback, once each
  it('closes a socket whose bind failed or never ran, emitting close before the callback', async () => {
    for (const state of ['refused', 'unbound']) {
      const { relay, dgram } = setup()
      relay.bindError = relayError(ErrorCode.ADDRESS_IN_USE)
      const socket = dgram.createSocket('udp4')
      const log: string[] = []
      socket.on('error', (error: Error & { code?: string }) => log.push(`error ${error.code}`))
      socket.on('close', () => log.push('close'))
      if (state === 'refused') socket.bind(6881)
      await wait(0)
      socket.close(() => log.push('close callback'))
      await wait(10)
      expect(log).toEqual([...state === 'refused' ? ['error EADDRINUSE'] : [], 'close', 'close callback'])
    }
  })

  /**
   * Node 26.12.1, a bound udp4 socket sending to a host name or connecting to one and closed in the same turn
   * (measured 2026-11-09): neither callback runs and no 'error' follows, only 'close'.
   */
  it('ends a send or a connect that close() cut off silently, as in Node', async () => {
    const { relay, socket } = await bound()
    const held = gate()
    relay.holdLookup = held.opened
    const log: string[] = []
    socket.on('error', (error) => log.push(`error ${error.message}`))
    socket.on('close', () => log.push('close'))
    socket.send('without a callback', 6969, 'tracker.example')
    socket.send('with a callback', 6969, 'tracker.example', (error) => log.push(`callback ${error}`))
    socket.connect(6969, 'tracker.example', () => log.push('connect'))
    socket.close()
    held.open()
    await wait(10)
    expect(log).toEqual(['close'])
  })

  // Node 26.12.1 on Linux (measured 2026-11-28): a connected socket's send needs no lookup, so it goes out and calls
  // back even when close() follows it in the same turn
  it('sends what a connected socket sent just before close()', async () => {
    const { socket, udp } = await bound()
    socket.connect(7000, '192.0.2.9')
    await new Promise((resolve) => socket.once('connect', resolve))
    const log: string[] = []
    socket.on('close', () => log.push('close'))
    socket.send('last words', (error, bytes) => log.push(`callback ${error} ${bytes}`))
    socket.close()
    await Promise.race([new Promise((resolve) => socket.once('close', resolve)), wait(100)])
    await wait(10)
    expect(udp.sent).toEqual([{ to: 'peer', data: 'last words' }])
    expect(log).toEqual(['callback null 10', 'close'])
  })

  it('emits error then close when the relay ends the socket or the session ends, and close alone with no error listener', async () => {
    for (const closed of [{ by: 'relay', code: ErrorCode.CAPACITY }, { by: 'session' }] as const) {
      const { socket, udp } = await bound()
      const log: string[] = []
      socket.on('error', (error) => log.push(`error ${error.message} ${(error as { code?: number }).code}`))
      socket.on('close', () => log.push('close'))
      udp.end(closed)
      await wait(0)
      expect(log).toEqual([closed.by === 'relay'
        ? `error the relay closed the socket ${ErrorCode.CAPACITY}`
        : `error the session ended ${ErrorCode.OTHER}`, 'close'])
    }

    const bare = await bound()
    const closed = new Promise((resolve) => bare.socket.once('close', resolve))
    bare.udp.end({ by: 'session' })
    await closed
  })

  it('closes on Symbol.asyncDispose', async () => {
    const { socket, udp } = await bound()
    await (socket as unknown as AsyncDisposable)[Symbol.asyncDispose]()
    expect(udp.calls).toEqual(['close'])
  })
})
