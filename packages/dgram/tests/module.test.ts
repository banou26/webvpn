import type { Provider } from '../src'

import { WebVpnError } from '@webvpn/client'
import { describe, expect, it } from 'vite-plus/test'

import { WebVpnError as SourceWebVpnError } from '../../client/src'
import dgram, { createDgram, createSocket, setProvider, Socket } from '../src'
import { fakeProvider, wait } from './fake'

describe('the module-level exports', () => {
  // first in the file: the provider set below stays set for the rest of it
  it('throw a clear error before any provider is set', () => {
    const message = 'no provider is set: call setProvider() from @webvpn/dgram first'
    const socket = createSocket('udp4')
    expect(() => socket.bind()).toThrow(message)
    expect(() => createSocket('udp4').send('a', 7000, '192.0.2.9')).toThrow(message)
    expect(() => createSocket({ type: 'udp4' }).connect(7000)).toThrow(message)
  })

  it('use the provider setProvider set, and the next one for the sockets bound after it', async () => {
    const first = fakeProvider()
    setProvider(first.provider)
    const socket = createSocket('udp4')
    socket.bind()
    await new Promise((resolve) => socket.once('listening', resolve))

    const second = fakeProvider()
    setProvider(second.provider)
    const next = dgram.createSocket('udp4')
    next.bind()
    await new Promise((resolve) => next.once('listening', resolve))
    expect([first.binds.length, second.binds.length]).toEqual([1, 1])
    expect(next).toBeInstanceOf(Socket)
  })

  it('make a provider from a function once, at the first call, and again after it rejected', async () => {
    const relay = fakeProvider()
    let made = 0
    let fail = true
    setProvider(async () => {
      made++
      await wait(1)
      if (fail) throw new Error('the relay is down')
      return relay.provider
    })
    expect(made).toBe(0)
    const failing = createSocket('udp4')
    failing.bind()
    expect((await new Promise<Error>((resolve) => failing.once('error', resolve))).message).toBe('the relay is down')
    expect(made).toBe(1)

    fail = false
    const sockets = [createSocket('udp4'), createSocket('udp6')]
    for (const socket of sockets) socket.bind()
    await Promise.all(sockets.map((socket) => new Promise((resolve) => socket.once('listening', resolve))))
    expect(made).toBe(2)
    expect(relay.binds).toEqual(['0.0.0.0:0', ':::0'])
  })
})

describe('@webvpn/client', () => {
  // so the tests run on a fresh checkout, before any build of the client, and never on a stale one
  it('is the client\'s source', () => {
    expect(WebVpnError).toBe(SourceWebVpnError)
  })
})

describe('createDgram', () => {
  it('builds a module of its own, on a provider or a function making one', async () => {
    const relay = fakeProvider()
    for (const own of [createDgram(relay.provider), createDgram(async () => relay.provider as Provider)]) {
      expect(own.Socket).not.toBe(Socket)
      const socket = own.createSocket('udp4', () => {})
      expect(socket).toBeInstanceOf(own.Socket)
      socket.bind()
      await new Promise((resolve) => socket.once('listening', resolve))
    }
    expect(relay.binds).toHaveLength(2)
  })
})
