import type { Socket } from 'node:net'

import { ErrorCode } from '@webvpn/client'
import { describe, expect, it } from 'vite-plus/test'

import { createNet } from '../src'
import { address, fakeProvider, fakeSocket, relayError, wait } from './fake'

/**
 * The expected logs are Node 26.12.1's net.Socket against a real local TCP server (measured 2026-11-10): each event
 * with the socket's destroyed, readable and writable flags at that moment, and each callback with its error code.
 * Here the fake relay socket stands in for the server: the far side ends with `end`, resets with `reset`, and
 * `failWrites` makes the writes after it fail, as a write to a server that is gone fails with EPIPE.
 */
const describeError = (error?: Error | null) => error ? (error as { code?: string }).code ?? error.message : 'ok'
const flags = (socket: Socket) => `d=${+socket.destroyed} r=${+socket.readable} w=${+socket.writable}`
const coded = (code: string) => Object.assign(new Error(code), { code })
const BIG = new Uint8Array(4 * 1024 * 1024)

const watch = (socket: Socket) => {
  const log: string[] = []
  for (const event of ['connect', 'ready', 'finish', 'end', 'timeout']) socket.on(event, () => log.push(`${event} ${flags(socket)}`))
  socket.on('error', (error) => log.push(`error ${describeError(error)} ${flags(socket)}`))
  socket.on('close', (hadError) => log.push(`close ${hadError} ${flags(socket)}`))
  const write = (name: string, chunk: Uint8Array = new Uint8Array(1)) =>
    socket.write(chunk, (error) => log.push(`${name} ${describeError(error)}`))
  const end = (name = 'end') => socket.end((error?: Error | null) => log.push(`${name} ${describeError(error)}`))
  const closed = new Promise((resolve) => socket.once('close', resolve))
  // 'close' plus a few turns more, so a callback that lands after it is caught too; a socket that never closes says so
  const settled = async () => {
    await Promise.race([closed, wait(300).then(() => log.push(`no close ${flags(socket)}`))])
    await wait(20)
    return log
  }
  return { log, write, end, settled }
}

const setup = () => {
  const relay = fakeProvider()
  return { relay, net: createNet(relay.provider) }
}

const refused = () => {
  const { relay, net } = setup()
  relay.next = relayError(ErrorCode.CONNECTION_REFUSED)
  const socket = new net.Socket()
  const watched = watch(socket)
  socket.connect(443, '198.51.100.9')
  return { socket, ...watched }
}

const connected = async (options?: { allowHalfOpen?: boolean }) => {
  const { relay, net } = setup()
  const peer = fakeSocket()
  relay.next = peer.socket
  const socket = new net.Socket(options)
  const watched = watch(socket)
  socket.connect(443, 'example.com')
  await new Promise((resolve) => socket.once('ready', resolve))
  watched.log.length = 0
  socket.resume()
  return { relay, net, socket, peer, ...watched }
}

describe('connect', () => {
  it('connects to an address, or to a name the relay looks up, and emits connect then ready', async () => {
    const { relay, net } = setup()
    relay.next = fakeSocket().socket
    const log: string[] = []
    const socket = net.connect(443, '198.51.100.9', () => log.push('callback'))
    log.push(`connecting ${socket.connecting} ${socket.pending} ${socket.readyState}`)
    socket.on('connect', () => log.push('connect')).on('ready', () => log.push('ready'))
    await new Promise((resolve) => socket.once('ready', resolve))
    log.push(`connecting ${socket.connecting} ${socket.pending} ${socket.readyState}`)
    // as Node 26.12.1: the callback, added first, runs as the first 'connect' listener, then 'ready'
    expect(log).toEqual(['connecting true true opening', 'callback', 'connect', 'ready', 'connecting false false open'])
    expect(socket.remoteAddress).toBe('198.51.100.9')
    expect(socket.remotePort).toBe(443)
    expect(socket.remoteFamily).toBe('IPv4')
    expect(socket.address()).toEqual({ address: '10.0.0.1', family: 'IPv4', port: 40000 })
    socket.destroy()

    relay.next = () => fakeSocket().socket
    net.connect({ port: 6667, host: 'irc.example' })
    net.connect(80, '2001:db8::1')
    await wait(0)
    expect(relay.calls.connects).toEqual([
      address('198.51.100.9', 443),
      { name: 'irc.example', port: 6667 },
      address('2001:db8::1', 80),
    ])
  })

  it('knows no endpoint before it connected, as Node', () => {
    const { net } = setup()
    const socket = new net.Socket()
    expect([socket.remoteAddress, socket.localPort, socket.address(), socket.bytesRead, socket.bytesWritten])
      .toEqual([undefined, undefined, {}, 0, 0])
  })

  it('refuses an IPC path and a file descriptor', () => {
    const { net } = setup()
    expect(() => net.connect('/tmp/socket')).toThrow('IPC paths are not supported')
    expect(() => new net.Socket({ fd: 3 })).toThrow('file descriptors are not supported')
  })
})

describe('the data', () => {
  it('carries bytes both ways and counts them', async () => {
    const { socket, peer } = await connected()
    const read: string[] = []
    socket.setEncoding('utf8')
    socket.on('data', (chunk: string) => read.push(chunk))
    peer.send('from the peer')
    await new Promise((resolve) => socket.write('from the page', resolve))
    await wait(0)
    expect(read).toEqual(['from the peer'])
    expect(peer.received()).toBe('from the page')
    expect([socket.bytesRead, socket.bytesWritten]).toEqual([13, 13])
    socket.destroy()
  })

  it('returns false past the high water mark, and emits drain only once the relay took the bytes', async () => {
    const { socket, peer } = await connected()
    peer.hold()
    expect(socket.write(new Uint8Array(8 * 1024))).toBe(true)
    expect(socket.write(new Uint8Array(16 * 1024))).toBe(false)
    let drained = false
    socket.once('drain', () => { drained = true })
    await wait(20)
    expect(drained).toBe(false)
    expect(peer.sent()).toBe(0)
    peer.drain()
    await wait(20)
    expect(drained).toBe(true)
    expect(peer.sent()).toBe(24 * 1024)
    socket.destroy()
  })

  it('stops taking the peer\'s bytes while paused, so they wait at the relay, and takes them on resume', async () => {
    const { socket, peer } = await connected()
    socket.pause()
    for (let chunk = 0; chunk < 64; chunk++) peer.send(new Uint8Array(4096))
    await wait(20)
    // what the stream buffers is bounded by its high water mark of 16 KiB, give or take one chunk
    expect(socket.bytesRead).toBeLessThanOrEqual(20 * 1024)
    expect(peer.queued()).toBeGreaterThanOrEqual(59)
    let read = 0
    socket.on('data', (chunk: Uint8Array) => { read += chunk.byteLength })
    socket.resume()
    await wait(20)
    expect(read).toBe(64 * 4096)
    socket.destroy()
  })
})

describe('the lifecycle', () => {
  it('a refused connection destroys the socket, with one error and then close', async () => {
    const { settled } = refused()
    expect(await settled()).toEqual(['error ECONNREFUSED d=1 r=0 w=0', 'close true d=1 r=0 w=0'])
  })

  it('the writes and the end made during a refused connection fail after close, the first as closed before connecting', async () => {
    const { write, end, settled } = refused()
    write('a')
    write('b')
    end()
    expect(await settled()).toEqual([
      'error ECONNREFUSED d=1 r=0 w=0',
      'close true d=1 r=0 w=0',
      'a ERR_SOCKET_CLOSED_BEFORE_CONNECTION',
      'b ECONNREFUSED',
      'end ECONNREFUSED',
    ])
  })

  it('destroy() during the connection fails its writes after close, the first as closed before connecting', async () => {
    for (const error of [undefined, coded('EBOOM')]) {
      const { relay, net } = setup()
      const peer = fakeSocket()
      relay.next = peer.socket
      const socket = new net.Socket()
      const { write, end, settled } = watch(socket)
      socket.connect(443, 'example.com')
      write('a')
      write('b')
      end()
      socket.destroy(error)
      expect(await settled()).toEqual(error
        ? ['error EBOOM d=1 r=0 w=0', 'close true d=1 r=0 w=0', 'a ERR_SOCKET_CLOSED_BEFORE_CONNECTION', 'b EBOOM', 'end EBOOM']
        : ['close false d=1 r=0 w=0', 'a ERR_SOCKET_CLOSED_BEFORE_CONNECTION', 'b ERR_SOCKET_CLOSED_BEFORE_CONNECTION', 'end ERR_SOCKET_CLOSED_BEFORE_CONNECTION'])
      // the connection that came after the destroy is closed at the relay
      await wait(0)
      expect(peer.teardown).toEqual(['close'])
    }
  })

  it('an idle timeout only emits timeout, and the socket stays open', async () => {
    const { socket, log, settled } = await connected()
    socket.setTimeout(20)
    expect(socket.timeout).toBe(20)
    await wait(50)
    log.push(`after ${flags(socket)}`)
    socket.destroy()
    expect(await settled()).toEqual(['timeout d=0 r=1 w=1', 'after d=0 r=1 w=1', 'close false d=1 r=0 w=0'])
  })

  it('a reset from the far side destroys the socket with Node\'s ECONNRESET', async () => {
    const { socket, peer, settled } = await connected()
    const errors: Error[] = []
    socket.on('error', (error) => errors.push(error))
    peer.reset()
    expect(await settled()).toEqual(['error ECONNRESET d=1 r=0 w=0', 'close true d=1 r=0 w=0'])
    expect(errors[0]).toMatchObject({ message: 'read ECONNRESET', errno: -104, code: 'ECONNRESET', syscall: 'read' })
  })

  it('a reset the upload meets fails the write, then errors with ECONNRESET and closes', async () => {
    const { peer, write, settled } = await connected()
    peer.failWrites(relayError(ErrorCode.CONNECTION_RESET, 'the peer reset the connection'))
    write('a')
    expect(await settled()).toEqual(['a ECONNRESET', 'error ECONNRESET d=1 r=0 w=0', 'close true d=1 r=0 w=0'])
  })

  it('a write that fails destroys the socket: it and everything behind it get the error, then error, then close', async () => {
    const { peer, write, end, settled } = await connected()
    write('a')
    await wait(10)
    peer.failWrites(coded('EPIPE'))
    write('b')
    write('c')
    end()
    expect(await settled()).toEqual([
      'a ok', 'b EPIPE', 'c EPIPE', 'end EPIPE', 'error EPIPE d=1 r=0 w=0', 'close true d=1 r=0 w=0',
    ])
  })

  // a real TCP shutdown cannot be made to fail, so this one follows Node's own stream code: callFinal hands the error
  // to the end callbacks, then destroys with it
  it('an end that fails destroys the socket with its error, and never finishes', async () => {
    const { peer, end, settled } = await connected()
    peer.failEnd(coded('EPIPE'))
    end()
    expect(await settled()).toEqual(['end EPIPE', 'error EPIPE d=1 r=0 w=0', 'close true d=1 r=0 w=0'])
  })

  it('end() is a half close: the peer reads the end, and the peer\'s bytes still arrive until its own end', async () => {
    const { socket, peer, log, end, settled } = await connected()
    const read: string[] = []
    socket.on('data', (chunk: Uint8Array) => read.push(new TextDecoder().decode(chunk)))
    end()
    await wait(10)
    expect(peer.state.finished).toBe(true)
    peer.send('after the half close')
    await wait(10)
    log.push(`mid ${flags(socket)}`)
    peer.end()
    expect(await settled()).toEqual([
      'end ok', 'finish d=0 r=1 w=0', 'mid d=0 r=1 w=0', 'end d=0 r=0 w=0', 'close false d=1 r=0 w=0',
    ])
    expect(read).toEqual(['after the half close'])
  })

  it('both sides ending, this side first, closes the socket, half open or not', async () => {
    for (const allowHalfOpen of [false, true]) {
      const { socket, peer, log, end, settled } = await connected({ allowHalfOpen })
      end()
      await wait(10)
      log.push(`mid ${flags(socket)}`)
      peer.end()
      expect(await settled()).toEqual([
        'end ok', 'finish d=0 r=1 w=0', 'mid d=0 r=1 w=0', 'end d=0 r=0 w=0', 'close false d=1 r=0 w=0',
      ])
      expect(peer.teardown).toEqual(['close'])
    }
  })

  it('the far side ending first ends this side too and closes, and a later end() calls back as already finished', async () => {
    const { socket, peer, log, end, settled } = await connected()
    peer.end()
    await wait(10)
    log.push(`mid ${flags(socket)}`)
    end()
    expect(await settled()).toEqual([
      'end d=0 r=0 w=1', 'finish d=0 r=0 w=0', 'close false d=1 r=0 w=0', 'mid d=1 r=0 w=0', 'end ERR_STREAM_ALREADY_FINISHED',
    ])
  })

  it('a socket nobody reads still sees the far side end, and closes once both sides ended', async () => {
    const { relay, net } = setup()
    const peer = fakeSocket()
    relay.next = peer.socket
    const socket = net.connect(443, 'example.com')
    const { log, end, settled } = watch(socket)
    await new Promise((resolve) => socket.once('connect', resolve))
    log.length = 0
    end()
    await wait(10)
    peer.end()
    expect(await settled()).toEqual(['end ok', 'finish d=0 r=1 w=0', 'end d=0 r=0 w=0', 'close false d=1 r=0 w=0'])
  })

  it('a half open socket stays writable once the far side ended, and closes when it ends too', async () => {
    const { socket, peer, log, write, end, settled } = await connected({ allowHalfOpen: true })
    peer.end()
    await wait(10)
    log.push(`mid ${flags(socket)}`)
    write('a')
    end()
    expect(await settled()).toEqual([
      'end d=0 r=0 w=1', 'mid d=0 r=0 w=1', 'a ok', 'end ok', 'finish d=0 r=0 w=0', 'close false d=1 r=0 w=0',
    ])
  })

  it('net.connect() makes a half open socket when its options ask for one', async () => {
    const { relay, net } = setup()
    const peer = fakeSocket()
    relay.next = peer.socket
    const socket = net.connect({ host: 'example.com', port: 443, allowHalfOpen: true })
    const { log, write, end, settled } = watch(socket)
    await new Promise((resolve) => socket.once('ready', resolve))
    log.length = 0
    socket.resume()
    peer.end()
    await wait(10)
    log.push(`mid ${flags(socket)}`)
    write('a')
    end()
    expect(await settled()).toEqual([
      'end d=0 r=0 w=1', 'mid d=0 r=0 w=1', 'a ok', 'end ok', 'finish d=0 r=0 w=0', 'close false d=1 r=0 w=0',
    ])
  })

  it('a write after end() destroys the socket with ERR_STREAM_WRITE_AFTER_END', async () => {
    const { socket, write, settled } = await connected()
    socket.end()
    write('late')
    expect(await settled()).toEqual([
      'late ERR_STREAM_WRITE_AFTER_END', 'error ERR_STREAM_WRITE_AFTER_END d=1 r=0 w=0', 'close true d=1 r=0 w=0',
    ])
  })

  it('every end callback runs, before finish', async () => {
    const { peer, end, settled } = await connected()
    end('end 1')
    end('end 2')
    await wait(10)
    peer.end()
    expect(await settled()).toEqual([
      'end 1 ok', 'end 2 ok', 'finish d=0 r=1 w=0', 'end d=0 r=0 w=0', 'close false d=1 r=0 w=0',
    ])
  })

  it('destroySoon() on a socket that already finished destroys it', async () => {
    const { socket, log, settled } = await connected()
    socket.end()
    await wait(10)
    log.push(`mid ${flags(socket)}`)
    socket.destroySoon()
    expect(await settled()).toEqual(['finish d=0 r=1 w=0', 'mid d=0 r=1 w=0', 'close false d=1 r=0 w=0'])
  })

  it('destroy() closes the socket at the relay, and resetAndDestroy() resets it', async () => {
    const closing = await connected()
    closing.socket.destroy()
    await closing.settled()
    expect(closing.peer.teardown).toEqual(['close'])

    const resetting = await connected()
    resetting.socket.resetAndDestroy()
    expect(await resetting.settled()).toEqual(['close false d=1 r=0 w=0'])
    expect(resetting.peer.teardown).toEqual(['reset'])
  })
})

/**
 * Here the relay socket's writes, end and options stay in flight until it is closed, and then fail as the relay's
 * reset of the stream fails them. The expected events are Node 26.12.1's net.Socket against a real local TCP server
 * that never reads (measured 2026-11-09), with a 4 MiB write to keep a write in flight.
 */
describe('destroy', () => {
  const stalled = async () => {
    const made = await connected()
    made.peer.stall()
    made.log.length = 0
    return made
  }

  it('fails the writes it cuts off with ECANCELED, in order, and emits no error', async () => {
    const { socket, write, settled } = await stalled()
    write('big', BIG)
    write('a')
    write('b')
    await wait(0)
    socket.destroy()
    expect(await settled()).toEqual(['big ECANCELED', 'a ECANCELED', 'b ECANCELED', 'close false d=1 r=0 w=0'])
  })

  it('end() then destroy() with a write in flight emits neither error nor finish', async () => {
    const { socket, write, settled } = await stalled()
    write('big', BIG)
    socket.end()
    await wait(0)
    socket.destroy()
    expect(await settled()).toEqual(['big ECANCELED', 'close false d=1 r=0 w=0'])
  })

  it('an end that destroy() cuts off emits no error', async () => {
    const { socket, settled } = await stalled()
    socket.end()
    await wait(0)
    socket.destroy()
    expect(await settled()).toEqual(['close false d=1 r=0 w=0'])
  })

  it('a write after destroy() fails its callback with ERR_STREAM_DESTROYED and emits nothing', async () => {
    const { socket, write, log, settled } = await stalled()
    socket.destroy()
    log.push(`returned ${write('after')}`)
    expect(await settled()).toEqual(['returned false', 'after ERR_STREAM_DESTROYED', 'close false d=1 r=0 w=0'])
  })

  it('destroy(error) emits that error once, then fails the writes, then closes with hadError', async () => {
    const { socket, write, settled } = await stalled()
    write('big', BIG)
    write('a')
    await wait(0)
    socket.destroy(coded('EBOOM'))
    expect(await settled()).toEqual(['error EBOOM d=1 r=0 w=0', 'big ECANCELED', 'a EBOOM', 'close true d=1 r=0 w=0'])
  })

  it('destroy(error) keeps its error when a write follows it', async () => {
    const { socket, write, settled } = await stalled()
    socket.destroy(coded('EBOOM'))
    write('after')
    const log = await settled()
    expect(log.filter((line) => line.startsWith('error'))).toEqual(['error EBOOM d=1 r=0 w=0'])
    expect(log).toContain('after ERR_STREAM_DESTROYED')
    expect(log.at(-1)).toBe('close true d=1 r=0 w=0')
  })

  it('does nothing once the socket is destroyed, whatever error a later call carries', async () => {
    const plain = await stalled()
    plain.socket.destroy()
    plain.socket.destroy(coded('ELATE'))
    expect(await plain.settled()).toEqual(['close false d=1 r=0 w=0'])

    const errored = await stalled()
    errored.socket.destroy(coded('EFIRST'))
    errored.socket.destroy(coded('ESECOND'))
    expect(await errored.settled()).toEqual(['error EFIRST d=1 r=0 w=0', 'close true d=1 r=0 w=0'])
  })

  it('a connection refused after destroy() emits no error', async () => {
    const { relay, net } = setup()
    let refuse!: (error: Error) => void
    relay.next = new Promise((_, reject) => { refuse = reject })
    const socket = new net.Socket()
    const { settled } = watch(socket)
    socket.connect(443, 'example.com')
    socket.destroy()
    refuse(relayError(ErrorCode.CONNECTION_REFUSED))
    expect(await settled()).toEqual(['close false d=1 r=0 w=0'])
  })

  it('a connection granted after destroy() reports no connect, to listeners or to the connect callback', async () => {
    const { relay, net } = setup()
    relay.next = fakeSocket().socket
    const socket = new net.Socket()
    const { log, settled } = watch(socket)
    socket.connect(443, 'example.com', () => log.push('connect callback'))
    socket.destroy()
    expect(await settled()).toEqual(['close false d=1 r=0 w=0'])
  })

  it('a socket option that fails after destroy() emits no error', async () => {
    const { socket, settled } = await stalled()
    socket.setNoDelay(true)
    socket.destroy()
    expect(await settled()).toEqual(['close false d=1 r=0 w=0'])
  })

  it('a socket destroyed with its timeout armed never times out, even when data lands after the destroy', async () => {
    const { socket, peer, settled } = await stalled()
    socket.setTimeout(30)
    await wait(0)
    socket.destroy()
    try {
      peer.send('late')
    } catch {}
    await wait(60)
    expect(await settled()).toEqual(['close false d=1 r=0 w=0'])
  })

  // Node 26.12.1 against a real local TCP server (measured 2026-11-27): a break destroys the socket with ABORT_ERR,
  // unless the loop destroyed it first
  it('breaking out of a for await loop over the socket ends the loop, and destroys it as Node does', async () => {
    for (const destroyInLoop of [false, true]) {
      const { socket, peer, settled } = await stalled()
      peer.send('x')
      for await (const _chunk of socket) {
        if (destroyInLoop) socket.destroy()
        break
      }
      expect(await settled()).toEqual(destroyInLoop
        ? ['close false d=1 r=0 w=0']
        : ['error ABORT_ERR d=1 r=0 w=0', 'close true d=1 r=0 w=0'])
    }
  })

  it('an end that destroy() cuts off calls back with the error its write gets, or with the destroy\'s own', async () => {
    const plain = await stalled()
    plain.write('big', BIG)
    plain.socket.end((error?: Error | null) => plain.log.push(`end ${describeError(error)}`))
    await wait(0)
    plain.socket.destroy()
    expect(await plain.settled()).toEqual(['big ECANCELED', 'end ECANCELED', 'close false d=1 r=0 w=0'])

    const errored = await stalled()
    errored.write('big', BIG)
    errored.socket.end((error?: Error | null) => errored.log.push(`end ${describeError(error)}`))
    await wait(0)
    errored.socket.destroy(coded('EBOOM'))
    expect(await errored.settled()).toEqual(['error EBOOM d=1 r=0 w=0', 'big ECANCELED', 'end EBOOM', 'close true d=1 r=0 w=0'])
  })

  it('an end after destroy() emits no finish, and its chunk fails as a write after destroy() does', async () => {
    const { socket, log, settled } = await stalled()
    socket.destroy()
    socket.end(new Uint8Array(1), (error?: Error | null) => log.push(`end ${describeError(error)}`))
    socket.end()
    expect(await settled()).toEqual(['end ERR_STREAM_DESTROYED', 'close false d=1 r=0 w=0'])
  })

  it('leaves the socket neither readable nor writable', async () => {
    const { socket } = await stalled()
    socket.destroy()
    expect({ readable: socket.readable, writable: socket.writable, destroyed: socket.destroyed, readyState: socket.readyState })
      .toEqual({ readable: false, writable: false, destroyed: true, readyState: 'closed' })
  })

  it('a write or an end the relay completes only as destroy() lands still counts as cut off', async () => {
    const writing = await stalled()
    writing.write('big', BIG)
    writing.write('a')
    await wait(0)
    writing.socket.destroy()
    expect(await writing.settled()).toEqual(['big ECANCELED', 'a ECANCELED', 'close false d=1 r=0 w=0'])

    const ending = await stalled()
    ending.socket.end()
    await wait(0)
    ending.socket.destroy()
    expect(await ending.settled()).toEqual(['close false d=1 r=0 w=0'])
  })
})

describe('the options', () => {
  it('sends no delay, keep-alive (Node 26\'s options object too) and the buffer sizes to the relay', async () => {
    const { socket, peer } = await connected()
    socket.setNoDelay()
    // `@types/node` 25 describes neither Node 26's options object nor the buffer sizes this package adds
    const node26 = socket as unknown as {
      setKeepAlive: (options: { enable?: boolean, initialDelay?: number }) => void,
      setSendBufferSize: (size: number) => void,
    }
    node26.setKeepAlive({ enable: true, initialDelay: 1500 })
    socket.setKeepAlive(true, 1500)
    socket.setKeepAlive(false)
    node26.setSendBufferSize(65536)
    await wait(0)
    expect(peer.options).toEqual([
      { type: 'noDelay', value: true },
      { type: 'keepAlive', enabled: true, initialDelaySeconds: 2 },
      { type: 'keepAlive', enabled: true, initialDelaySeconds: 2 },
      { type: 'keepAlive', enabled: false, initialDelaySeconds: 0 },
      { type: 'sendBufferSize', value: 65536 },
    ])
    socket.destroy()
  })

  it('emits an error for an option set before connect, and for one the relay refuses', async () => {
    const { relay, net } = setup()
    const early = new net.Socket()
    const errors: Error[] = []
    early.on('error', (error) => errors.push(error))
    early.setNoDelay()
    expect(errors.map(({ message }) => message)).toEqual(['a socket option needs a connect first'])

    const peer = fakeSocket()
    peer.socket.setOption = async () => { throw relayError(ErrorCode.UNSUPPORTED, 'the relay does not take this option') }
    relay.next = peer.socket
    const socket = net.connect(443, 'example.com')
    socket.on('error', (error) => errors.push(error))
    socket.setKeepAlive(true)
    await wait(10)
    expect(errors.map(({ message }) => message)).toEqual(['a socket option needs a connect first', 'the relay does not take this option'])
    socket.destroy()
  })
})
