import type { Carrier, CloseInfo, Duplex } from './context'

import { readU32, u32, WebVpnError, within } from './context'
import { CloseCode, CONTROL_STREAM, decodeMuxFrame, encodeMuxFrame, ErrorCode, MuxKind, MuxStreamType } from './protocol'

const OPEN_TIMEOUT_MS = 6000
const MAX_DATA_BYTES = 256 * 1024
// what the WebSocket may hold unsent before bulk data waits here instead, so a control frame never queues behind it
const SOCKET_BUFFER_TARGET = 1024 * 1024
// a datagram is dropped rather than queued past this
const DATAGRAM_SHED_BYTES = 2 * 1024 * 1024
// the WebSocket says nothing when its buffer drains, so the sender looks again, less often while nothing moves
const POLL_MIN_MS = 5
const POLL_MAX_MS = 40
// every stream but the control stream starts with this window, and the relay sends nothing past it
const STREAM_WINDOW_BYTES = 1048576
const OPEN = 1

type Send = { chunk: Uint8Array, at: number, resolve: () => void, reject: (error: unknown) => void }

type MuxStream = {
  id: number,
  chunks: Uint8Array[],
  unread: number,
  wake?: () => void,
  /** The relay finished its side. */
  finished: boolean,
  /** The client finished its side, or the stream has none. */
  sent: boolean,
  failure?: unknown,
  sends: Send[],
  writable?: WritableStreamDefaultController,
}

/**
 * The carrier of a WebSocket session: the mux of `spec/protocol.md` over `socket`, which the caller made just before.
 * Rejects, with the socket closed, when it does not open in 6 seconds.
 */
export const webSocketCarrier = async (socket: WebSocket): Promise<Carrier> => {
  socket.binaryType = 'arraybuffer'
  const streams = new Map<number, MuxStream>()
  let incoming!: ReadableStreamDefaultController<Duplex>
  let incomingUni!: ReadableStreamDefaultController<ReadableStream<Uint8Array>>
  let control!: ReadableStreamDefaultController<Uint8Array>

  // straight to the socket, ahead of whatever bulk data waits below
  const send = (kind: number, stream: number, payload?: Uint8Array) => {
    if (socket.readyState === OPEN) socket.send(encodeMuxFrame(kind, stream, payload))
  }

  const ready: MuxStream[] = []
  let timer: ReturnType<typeof setTimeout> | undefined
  let poll = POLL_MIN_MS
  // one piece of at most 256 KiB per stream in turn
  const pump = () => {
    timer = undefined
    let moved = false
    while (ready.length && socket.readyState === OPEN && socket.bufferedAmount < SOCKET_BUFFER_TARGET) {
      const stream = ready.shift()!
      const head = stream.sends[0]!
      const end = Math.min(head.at + MAX_DATA_BYTES, head.chunk.byteLength)
      send(MuxKind.DATA, stream.id, head.chunk.subarray(head.at, end))
      head.at = end
      moved = true
      if (end === head.chunk.byteLength) {
        stream.sends.shift()
        head.resolve()
      }
      if (stream.sends.length) ready.push(stream)
    }
    if (!ready.length || socket.readyState !== OPEN) {
      poll = POLL_MIN_MS
      return
    }
    poll = moved ? POLL_MIN_MS : Math.min(poll * 2, POLL_MAX_MS)
    timer = setTimeout(pump, poll)
  }
  const write = (stream: MuxStream, chunk: Uint8Array) => new Promise<void>((resolve, reject) => {
    if (stream.failure) return reject(stream.failure)
    if (!chunk.byteLength) return resolve()
    stream.sends.push({ chunk, at: 0, resolve, reject })
    if (stream.sends.length === 1) ready.push(stream)
    if (timer !== undefined && socket.bufferedAmount >= SOCKET_BUFFER_TARGET) return
    clearTimeout(timer)
    pump()
  })

  const forget = (stream: MuxStream) => {
    if (stream.finished && stream.sent && streams.get(stream.id) === stream) streams.delete(stream.id)
  }

  const terminate = (stream: MuxStream, failure: unknown, tellRelay: boolean) => {
    if (stream.failure) return
    stream.failure = failure
    // a reset of the client's own drops what the reader did not take; the relay's keeps it ahead of the error
    if (tellRelay) stream.chunks.length = 0
    if (streams.get(stream.id) === stream) streams.delete(stream.id)
    const at = ready.indexOf(stream)
    if (at >= 0) ready.splice(at, 1)
    for (const waiting of stream.sends.splice(0)) waiting.reject(failure)
    try {
      stream.writable?.error(failure)
    } catch {}
    stream.wake?.()
    if (tellRelay) send(MuxKind.RESET, stream.id)
  }

  const open = (id: number, both: boolean) => {
    const stream: MuxStream = { id, chunks: [], unread: 0, finished: false, sent: !both, sends: [] }
    streams.set(id, stream)
    const readable = new ReadableStream<Uint8Array>({
      pull: async (controller) => {
        while (!stream.chunks.length) {
          if (stream.failure) throw stream.failure
          if (stream.finished) return controller.close()
          await new Promise<void>((resolve) => { stream.wake = resolve })
        }
        const chunk = stream.chunks.shift()!
        stream.unread -= chunk.byteLength
        controller.enqueue(chunk)
        // the bytes the reader took, so the window moves only as fast as this stream is read
        send(MuxKind.CREDIT, id, u32(chunk.byteLength))
      },
      cancel: () => terminate(stream, new Error('the stream was cancelled'), true),
    }, { highWaterMark: 0 })
    if (!both) return incomingUni.enqueue(readable)
    const writable = new WritableStream<Uint8Array>({
      start: (controller) => { stream.writable = controller },
      write: (chunk) => write(stream, chunk),
      close: () => {
        stream.sent = true
        send(MuxKind.FIN, id)
        forget(stream)
      },
      abort: () => terminate(stream, new Error('the stream was aborted'), true),
    })
    incoming.enqueue({ readable, writable })
  }

  const receive = (message: Uint8Array) => {
    const frame = decodeMuxFrame(message)
    if (!frame) return
    const { kind, stream: id, payload } = frame
    if (kind === MuxKind.OPEN) {
      if (id === CONTROL_STREAM || streams.has(id)) return
      if (payload[0] === MuxStreamType.TCP) open(id, true)
      else if (payload[0] === MuxStreamType.UDP_DOWNLOAD) open(id, false)
      return
    }
    if (kind === MuxKind.DATA && id === CONTROL_STREAM) return control.enqueue(payload)
    const stream = streams.get(id)
    if (!stream) return
    if (kind === MuxKind.DATA && payload.byteLength && !stream.finished) {
      stream.unread += payload.byteLength
      if (stream.unread > STREAM_WINDOW_BYTES) return terminate(stream, new Error('the relay sent past the window'), true)
      stream.chunks.push(payload)
      stream.wake?.()
    } else if (kind === MuxKind.FIN) {
      stream.finished = true
      stream.wake?.()
      forget(stream)
    } else if (kind === MuxKind.RESET) {
      const streamErrorCode = payload.byteLength >= 4 ? readU32(payload) : undefined
      terminate(stream, Object.assign(new Error('the relay reset the stream'), { streamErrorCode }), false)
    }
  }

  let settle!: (info: CloseInfo) => void
  const closed = new Promise<CloseInfo>((resolve) => { settle = resolve })
  const close = (code: number, reason: string) => {
    settle({ code, reason })
    try {
      socket.close(4000 + code, reason.slice(0, 123))
    } catch {}
  }

  socket.onmessage = (event: MessageEvent) => {
    if (event.data instanceof ArrayBuffer) receive(new Uint8Array(event.data))
  }
  socket.onclose = (event: CloseEvent) => {
    // first, so whoever reads the streams' end below finds the code already there
    const code = event.code >= 4000 && event.code < 5000 ? event.code - 4000 : CloseCode.PROTOCOL_ERROR
    settle({ code, reason: event.reason })
    clearTimeout(timer)
    const failure = new Error('the WebSocket closed')
    for (const stream of [...streams.values()]) terminate(stream, failure, false)
    for (const controller of [control, incoming, incomingUni]) {
      try {
        controller.close()
      } catch {}
    }
  }

  const controlStream: Duplex = {
    readable: new ReadableStream<Uint8Array>({ start: (controller) => { control = controller } }),
    writable: new WritableStream<Uint8Array>({
      write: (chunk) => {
        if (socket.readyState !== OPEN) throw new WebVpnError(ErrorCode.OTHER, 'the WebSocket is closed')
        send(MuxKind.DATA, CONTROL_STREAM, chunk)
      },
    }),
  }
  const carrier: Carrier = {
    kind: 'websocket',
    incoming: new ReadableStream<Duplex>({
      start: (controller) => {
        incoming = controller
        // never opened: stream 0 is the control stream from the start
        controller.enqueue(controlStream)
      },
    }),
    incomingUni: new ReadableStream({ start: (controller) => { incomingUni = controller } }),
    sendDatagram: (packet) => {
      if (socket.bufferedAmount <= DATAGRAM_SHED_BYTES) send(MuxKind.DATAGRAM, 0, packet)
    },
    closed,
    close,
  }

  const opened = new Promise<void>((resolve, reject) => {
    if (socket.readyState === OPEN) return resolve()
    socket.addEventListener('open', () => resolve(), { once: true })
    socket.addEventListener('close', () => reject(new WebVpnError(ErrorCode.OTHER, 'the WebSocket did not open')), { once: true })
  })
  await within(opened, OPEN_TIMEOUT_MS, ErrorCode.TIMED_OUT, `the WebSocket did not open in ${OPEN_TIMEOUT_MS} ms`)
    .catch((error: unknown) => {
      close(CloseCode.PROTOCOL_ERROR, 'the session did not open')
      throw error
    })
  return carrier
}
