import type { Carrier, Duplex } from '../src/context'

import { afterEach, describe, expect, it, vi } from 'vite-plus/test'

import { readU32, WebVpnError } from '../src/context'
import { CloseCode, CONTROL_STREAM, decodeMuxFrame, encodeMuxFrame, ErrorCode, MuxKind, MuxStreamType } from '../src/protocol'
import { webSocketCarrier } from '../src/websocket'
import { settle } from './relay'

/** A WebSocket that is open from the start and keeps what the client sends, as mux frames. */
class FakeSocket {
  readyState = 1
  bufferedAmount = 0
  binaryType = 'blob'
  sent: { kind: number, stream: number, payload: Uint8Array }[] = []
  closedWith: [number, string] | undefined
  onmessage: ((event: { data: ArrayBuffer }) => void) | undefined
  onclose: ((event: { code: number, reason: string }) => void) | undefined
  closeListeners: ((event: { code: number, reason: string }) => void)[] = []

  send(data: Uint8Array) {
    this.sent.push(decodeMuxFrame(data.slice())!)
  }

  close(code: number, reason: string) {
    this.closedWith = [code, reason]
  }

  addEventListener(type: string, listener: (event: { code: number, reason: string }) => void) {
    if (type === 'close') this.closeListeners.push(listener)
  }

  receive(kind: number, stream: number, payload?: Uint8Array) {
    this.onmessage?.({ data: encodeMuxFrame(kind, stream, payload).buffer as ArrayBuffer })
  }

  end(code: number, reason: string) {
    this.readyState = 3
    this.onclose?.({ code, reason })
    for (const listener of this.closeListeners) listener({ code, reason })
  }

  frames(kind: number, stream?: number) {
    return this.sent.filter((frame) => frame.kind === kind && (stream === undefined || frame.stream === stream))
  }
}

const mux = async () => {
  const socket = new FakeSocket()
  const carrier = await webSocketCarrier(socket as unknown as WebSocket)
  const incoming = carrier.incoming.getReader()
  const control = (await incoming.read()).value!
  const open = async (stream: number) => {
    socket.receive(MuxKind.OPEN, stream, Uint8Array.of(MuxStreamType.TCP))
    return (await incoming.read()).value as Duplex
  }
  return { socket, carrier, control, open }
}

const credits = (socket: FakeSocket, stream: number) => socket.frames(MuxKind.CREDIT, stream).map(({ payload }) => readU32(payload))

afterEach(() => {
  vi.useRealTimers()
})

describe('the WebSocket mux', () => {
  it('opens with the control stream, whose frames go on stream 0', async () => {
    const { socket, control } = await mux()
    expect(socket.binaryType).toBe('arraybuffer')
    await control.writable.getWriter().write(Uint8Array.of(1, 2))
    expect(socket.sent).toEqual([{ kind: MuxKind.DATA, stream: CONTROL_STREAM, payload: Uint8Array.of(1, 2) }])
    socket.receive(MuxKind.DATA, CONTROL_STREAM, Uint8Array.of(3))
    expect((await control.readable.getReader().read()).value).toEqual(Uint8Array.of(3))
    expect(socket.frames(MuxKind.CREDIT)).toEqual([])
  })

  it('grants no credit up front, and credits the bytes the reader took off the stream', async () => {
    const { socket, open } = await mux()
    const { readable } = await open(3)
    socket.receive(MuxKind.DATA, 3, new Uint8Array(1000))
    socket.receive(MuxKind.DATA, 3, new Uint8Array(500))
    await settle()
    expect(credits(socket, 3)).toEqual([])
    const reader = readable.getReader()
    expect((await reader.read()).value?.byteLength).toBe(1000)
    expect(credits(socket, 3)).toEqual([1000])
    expect((await reader.read()).value?.byteLength).toBe(500)
    expect(credits(socket, 3)).toEqual([1000, 500])
  })

  it('resets a stream the relay sent past its window', async () => {
    const { socket, open } = await mux()
    const { readable } = await open(3)
    socket.receive(MuxKind.DATA, 3, new Uint8Array(1048576))
    expect(socket.frames(MuxKind.RESET, 3)).toEqual([])
    socket.receive(MuxKind.DATA, 3, Uint8Array.of(1))
    expect(socket.frames(MuxKind.RESET, 3)).toHaveLength(1)
    await expect(readable.getReader().read()).rejects.toThrow('the relay sent past the window')
  })

  it('cuts what a stream writes into DATA frames of at most 256 KiB', async () => {
    const { socket, open } = await mux()
    const { writable } = await open(3)
    await writable.getWriter().write(new Uint8Array(600 * 1024))
    expect(socket.frames(MuxKind.DATA, 3).map(({ payload }) => payload.byteLength)).toEqual([262144, 262144, 90112])
  })

  it('sends control frames at once, ahead of bulk data waiting for the socket\'s buffer to drain', async () => {
    vi.useFakeTimers()
    const { socket, control, open } = await mux()
    const { writable } = await open(3)
    socket.bufferedAmount = 2 * 1024 * 1024
    const written = writable.getWriter().write(Uint8Array.of(7))
    await control.writable.getWriter().write(Uint8Array.of(1))
    await vi.advanceTimersByTimeAsync(100)
    expect(socket.sent.map(({ stream }) => stream)).toEqual([CONTROL_STREAM])
    socket.bufferedAmount = 0
    await vi.advanceTimersByTimeAsync(40)
    await written
    expect(socket.sent.map(({ stream }) => stream)).toEqual([CONTROL_STREAM, 3])
  })

  it('takes turns between streams, one piece each', async () => {
    vi.useFakeTimers()
    const { socket, open } = await mux()
    const [one, two] = [await open(3), await open(5)]
    socket.bufferedAmount = 2 * 1024 * 1024
    const written = Promise.all([
      one.writable.getWriter().write(new Uint8Array(600 * 1024)),
      two.writable.getWriter().write(new Uint8Array(300 * 1024)),
    ])
    await vi.advanceTimersByTimeAsync(10)
    socket.bufferedAmount = 0
    await vi.advanceTimersByTimeAsync(40)
    await written
    expect(socket.frames(MuxKind.DATA).map(({ stream }) => stream)).toEqual([3, 5, 3, 5, 3])
  })

  it('finishes and resets streams both ways', async () => {
    const { socket, open } = await mux()
    const first = await open(3)
    socket.receive(MuxKind.FIN, 3)
    expect(await first.readable.getReader().read()).toEqual({ done: true, value: undefined })
    await first.writable.close()
    expect(socket.frames(MuxKind.FIN, 3)).toHaveLength(1)

    const second = await open(5)
    socket.receive(MuxKind.RESET, 5, Uint8Array.of(0, 0, 0, 1))
    await expect(second.readable.getReader().read()).rejects.toMatchObject({ streamErrorCode: 1 })
    await expect(second.writable.getWriter().write(Uint8Array.of(1))).rejects.toThrow()

    const third = await open(7)
    await third.readable.cancel()
    expect(socket.frames(MuxKind.RESET, 7)).toHaveLength(1)
  })

  it('hands a UDP stream over as a stream toward the client, and sends datagrams as DATAGRAM frames', async () => {
    const { socket, carrier } = await mux()
    socket.receive(MuxKind.OPEN, 9, Uint8Array.of(MuxStreamType.UDP_DOWNLOAD))
    const readable = (await carrier.incomingUni.getReader().read()).value!
    socket.receive(MuxKind.DATA, 9, Uint8Array.of(4))
    expect((await readable.getReader().read()).value).toEqual(Uint8Array.of(4))
    carrier.sendDatagram(Uint8Array.of(5))
    socket.bufferedAmount = 3 * 1024 * 1024
    carrier.sendDatagram(Uint8Array.of(6))
    expect(socket.frames(MuxKind.DATAGRAM).map(({ payload }) => payload)).toEqual([Uint8Array.of(5)])
  })

  it('reads the session close code from the WebSocket close code, and LOST from any other', async () => {
    const closes: [number, Promise<unknown>][] = []
    for (const code of [4004, 1006]) {
      const { socket, carrier } = await mux()
      socket.end(code, 'stopping')
      closes.push([code, carrier.closed])
    }
    expect(await closes[0]![1]).toEqual({ code: CloseCode.RESTARTING, reason: 'stopping' })
    expect(await closes[1]![1]).toEqual({ code: CloseCode.LOST, reason: 'stopping' })
  })

  it('reads a close before the WebSocket opened as the session\'s end when it carries the relay\'s code', async () => {
    const outcomes: unknown[] = []
    for (const code of [4003, 1006]) {
      const socket = new FakeSocket()
      socket.readyState = 0
      const opening = webSocketCarrier(socket as unknown as WebSocket).catch((error: unknown) => error)
      socket.end(code, 'the relay is full')
      outcomes.push(await opening)
    }
    expect(outcomes[0]).toBeInstanceOf(WebVpnError)
    expect(outcomes[0]).toMatchObject({
      code: ErrorCode.CAPACITY,
      closeCode: CloseCode.SESSION_LIMIT,
      message: 'the session closed: the relay is full',
    })
    expect(outcomes[1]).toMatchObject({ code: ErrorCode.OTHER, closeCode: undefined, message: 'the WebSocket did not open' })
  })

  it('closes the WebSocket with 4000 and the session close code', async () => {
    const { socket, carrier } = await mux()
    const ending: Carrier['closed'] = carrier.closed
    carrier.close(CloseCode.NORMAL, 'done')
    expect(socket.closedWith).toEqual([4000, 'done'])
    expect(await ending).toEqual({ code: CloseCode.NORMAL, reason: 'done' })
  })
})
