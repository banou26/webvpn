import type { Provider } from '../src'

import { ErrorCode, WebVpnError } from '@webvpn/client'
import { describe, expect, it } from 'vite-plus/test'

import { WebVpnError as SourceWebVpnError } from '../../client/src'
import net, { connect, createNet, createServer, isIP, isIPv4, isIPv6, Server, setProvider, Socket } from '../src'
import { fakeProvider, fakeSocket, relayError, wait } from './fake'

describe('the module-level exports', () => {
  // first in the file: the provider set below stays set for the rest of it
  it('throw a clear error before any provider is set', () => {
    const message = 'no provider is set: call setProvider() from @webvpn/net first'
    expect(() => connect(443, 'example.com')).toThrow(message)
    expect(() => new Socket().connect(443, 'example.com')).toThrow(message)
    expect(() => createServer().listen(0)).toThrow(message)
    expect(() => new Server().listen(0)).toThrow(message)
  })

  it('use the provider setProvider set, and the next one for the sockets made after it', async () => {
    const first = fakeProvider()
    first.next = () => fakeSocket().socket
    setProvider(first.provider)
    const socket = connect(443, '198.51.100.9')
    await new Promise((resolve) => socket.once('connect', resolve))
    expect(first.calls.connects).toHaveLength(1)

    const second = fakeProvider()
    second.next = fakeSocket().socket
    setProvider(second.provider)
    const next = net.connect(443, '198.51.100.9')
    await new Promise((resolve) => next.once('connect', resolve))
    expect([first.calls.connects.length, second.calls.connects.length]).toEqual([1, 1])
    expect(next).toBeInstanceOf(Socket)
    socket.destroy()
    next.destroy()
  })

  it('make a provider from a function once, at the first call, and again after it rejected', async () => {
    const relay = fakeProvider()
    relay.next = () => fakeSocket().socket
    let made = 0
    let fail = true
    setProvider(async () => {
      made++
      await wait(1)
      if (fail) throw new Error('the relay is down')
      return relay.provider
    })
    expect(made).toBe(0)

    const failing = connect(443, 'example.com')
    const error = await new Promise<Error>((resolve) => failing.once('error', resolve))
    expect(error.message).toBe('the relay is down')
    expect(made).toBe(1)

    fail = false
    const sockets = [connect(443, 'example.com'), connect(443, 'example.com')]
    await Promise.all(sockets.map((socket) => new Promise((resolve) => socket.once('connect', resolve))))
    expect(made).toBe(2)
    expect(relay.calls.connects).toHaveLength(2)
    for (const socket of sockets) socket.destroy()
  })
})

describe('createNet', () => {
  it('builds a module of its own, apart from the module-level one', async () => {
    const relay = fakeProvider()
    relay.next = fakeSocket().socket
    const own = createNet(relay.provider)
    expect(own.Socket).not.toBe(Socket)
    const socket = own.connect(443, '198.51.100.9')
    await new Promise((resolve) => socket.once('connect', resolve))
    expect(socket).toBeInstanceOf(own.Socket)
    expect(relay.calls.connects).toHaveLength(1)
    socket.destroy()
  })

  it('takes a provider\'s promise from a function', async () => {
    const relay = fakeProvider()
    relay.next = fakeSocket().socket
    const own = createNet(async () => relay.provider as Provider)
    const socket = own.connect(443, '198.51.100.9')
    await new Promise((resolve) => socket.once('connect', resolve))
    socket.destroy()
  })
})

// Node 26.12.1 on Linux (measured 2026-11-15): a refused port, a connect the kernel gave up on, an address whose
// neighbour never answered, and one with no route, which the kernel refuses at once, so Node names the local end.
// A target the relay refuses is the kernel's refusal at once too (EACCES), and so is a local address it cannot take
describe('a failed connect', () => {
  it.each([
    [ErrorCode.CONNECTION_REFUSED, '127.0.0.1', 1, 'connect ECONNREFUSED 127.0.0.1:1', { errno: -111, code: 'ECONNREFUSED' }],
    [ErrorCode.CONNECTION_REFUSED, '::1', 1, 'connect ECONNREFUSED ::1:1', { errno: -111, code: 'ECONNREFUSED' }],
    [ErrorCode.TIMED_OUT, '127.0.0.1', 29811, 'connect ETIMEDOUT 127.0.0.1:29811', { errno: -110, code: 'ETIMEDOUT' }],
    [ErrorCode.HOST_UNREACHABLE, '172.17.255.200', 80, 'connect EHOSTUNREACH 172.17.255.200:80', { errno: -113, code: 'EHOSTUNREACH' }],
    [ErrorCode.NETWORK_UNREACHABLE, '10.1.2.3', 80, 'connect ENETUNREACH 10.1.2.3:80 - Local (0.0.0.0:0)', { errno: -101, code: 'ENETUNREACH' }],
    [ErrorCode.NETWORK_UNREACHABLE, '2001:db8::1', 80, 'connect ENETUNREACH 2001:db8::1:80 - Local (:::0)', { errno: -101, code: 'ENETUNREACH' }],
    [ErrorCode.REFUSED, '192.0.2.1', 25, 'connect EACCES 192.0.2.1:25 - Local (0.0.0.0:0)', { errno: -13, code: 'EACCES' }],
    [ErrorCode.ADDRESS_NOT_AVAILABLE, '192.0.2.1', 80, 'connect EADDRNOTAVAIL 192.0.2.1:80 - Local (0.0.0.0:0)', { errno: -99, code: 'EADDRNOTAVAIL' }],
    [ErrorCode.ADDRESS_IN_USE, '192.0.2.1', 80, 'connect EADDRINUSE 192.0.2.1:80 - Local (0.0.0.0:0)', { errno: -98, code: 'EADDRINUSE' }],
  ])('is Node\'s error, then close: code %i to %s', async (code, host, port, message, fields) => {
    const relay = fakeProvider()
    relay.next = relayError(code)
    const socket = createNet(relay.provider).connect(port, host)
    const log: string[] = []
    const errors: Error[] = []
    socket.on('error', (error) => errors.push(error))
    socket.on('close', (hadError) => log.push(`close ${hadError}`))
    await new Promise((resolve) => socket.once('close', resolve))
    const expected = { ...fields, syscall: 'connect', address: host, port }
    expect(errors).toHaveLength(1)
    expect(errors[0]).toMatchObject({ message, ...expected })
    expect(Object.keys(errors[0]!)).toEqual(Object.keys(expected))
    expect(log).toEqual(['close true'])
  })

  // Node 26.12.1 on Linux (measured 2026-11-15): a connect to a name with no address
  it('to a name with no address is Node\'s ENOTFOUND', async () => {
    const relay = fakeProvider()
    relay.next = relayError(ErrorCode.NAME_NOT_FOUND, 'the name has no address')
    const socket = createNet(relay.provider).connect(443, 'missing.invalid')
    const error = await new Promise<Error>((resolve) => socket.once('error', resolve))
    const expected = { errno: -3008, code: 'ENOTFOUND', syscall: 'getaddrinfo', hostname: 'missing.invalid' }
    expect(error).toMatchObject({ message: 'getaddrinfo ENOTFOUND missing.invalid', ...expected })
    expect(Object.keys(error)).toEqual(Object.keys(expected))
  })

  it('keeps an error Node has no counterpart for as the relay gave it', async () => {
    for (const failure of [relayError(ErrorCode.CAPACITY, 'too many sockets'), relayError(0x1234, 'something new'), new TypeError('a browser error')]) {
      const relay = fakeProvider()
      relay.next = failure
      const socket = createNet(relay.provider).connect(443, 'example.com')
      expect(await new Promise((resolve) => socket.once('error', resolve))).toBe(failure)
    }
  })
})

describe('@webvpn/client', () => {
  // so the tests run on a fresh checkout, before any build of the client, and never on a stale one
  it('is the client\'s source', () => {
    expect(WebVpnError).toBe(SourceWebVpnError)
  })
})

describe('isIP', () => {
  it('tells IPv4 from IPv6 as Node does', () => {
    expect(['192.0.2.7', '2001:db8::7', 'fe80::1%eth0', '::ffff:192.0.2.7', '01.2.3.4', 'example.com', '[::1]', ''].map(isIP))
      .toEqual([4, 6, 6, 6, 0, 0, 0, 0])
    expect([isIPv4('192.0.2.7'), isIPv4('::1'), isIPv6('::1'), isIPv6('192.0.2.7')]).toEqual([true, false, true, false])
  })
})
