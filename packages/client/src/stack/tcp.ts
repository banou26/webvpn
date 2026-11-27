import type { Address } from '../protocol'
import type { TcpSocket } from '../tcp'
import type { WebVpnError } from '../context'
import type { Engine } from './engine'

import { ErrorCode } from '../protocol'
import { changes, stackError, TcpState } from './engine'

const CHUNK_BYTES = 64 * 1024

/** The sizes, in bytes, of a TCP socket's receive and send buffers. */
export type Buffers = { receive: number, send: number }

const closed = () => stackError(ErrorCode.UNKNOWN_SOCKET)

/**
 * The `TcpSocket` of a connection the stack holds as `id`. Its streams are paced by the stack's buffers: `readable`
 * takes bytes only as it is read, so a slow reader closes the window the peer sees, and a write waits for room in the
 * send buffer.
 */
export const stackTcpSocket = (engine: Engine, id: number, local: Address, remote: Address): TcpSocket => {
  const { calls, kick } = engine
  const { next, wake } = changes()
  let stopped = false
  let released = false
  let readDone = false
  let reset: WebVpnError | undefined
  let ending: Promise<void> | undefined
  let controller!: ReadableStreamDefaultController<Uint8Array>

  const release = () => {
    if (released || engine.ended()) return
    released = true
    unwatch()
    calls.stack_release(id)
    kick()
  }

  // a connection that ended both ways and was read to its end is let go of even when nobody closes it
  const settle = () => {
    if (readDone && !engine.ended() && calls.tcp_state(id) === TcpState.CLOSED) release()
  }

  const unwatch = engine.watch(id, () => {
    wake()
    settle()
  })

  const finish = (error?: unknown) => {
    readDone = true
    try {
      if (error) controller.error(error)
      else controller.close()
    } catch {}
    settle()
  }

  const readable = new ReadableStream<Uint8Array>({
    start: (started) => { controller = started },
    pull: async () => {
      for (;;) {
        if (stopped) return finish()
        const error = engine.ended()
        if (error) return finish(error)
        const length = calls.tcp_recv(id, CHUNK_BYTES)
        if (length > 0) {
          controller.enqueue(engine.buffer().slice(0, length))
          kick()
          return
        }
        if (length < 0) {
          // kept for the writes, since a connection that ended is let go of
          if (calls.tcp_error(id) === ErrorCode.CONNECTION_RESET) reset = stackError(ErrorCode.CONNECTION_RESET)
          return finish(reset)
        }
        await next()
      }
    },
    cancel: () => {
      readDone = true
      settle()
    },
  }, { highWaterMark: 0 })

  const halfClose = () => {
    if (stopped || engine.ended()) return
    calls.tcp_close(id)
    kick()
  }

  const writable = new WritableStream<Uint8Array>({
    write: async (chunk) => {
      for (let at = 0; at < chunk.byteLength;) {
        const error = engine.ended()
        if (error) throw error
        if (stopped) throw closed()
        if (reset) throw reset
        const length = Math.min(chunk.byteLength - at, CHUNK_BYTES)
        engine.buffer().set(chunk.subarray(at, at + length))
        const taken = calls.tcp_send(id, length)
        if (taken < 0) throw -taken === ErrorCode.CONNECTION_RESET ? stackError(-taken) : closed()
        at += taken
        kick()
        if (!taken) await next()
      }
    },
    close: halfClose,
    abort: halfClose,
  })

  const end = (abort: boolean) => ending ??= (async () => {
    if (engine.ended()) return
    stopped = true
    if (abort) calls.tcp_abort(id)
    else calls.tcp_close(id)
    release()
    wake()
  })()

  return {
    id,
    local,
    remote,
    readable,
    writable,
    setOption: async (option) => {
      const error = engine.ended()
      if (error) throw error
      const code = option.type === 'noDelay' ? calls.tcp_option(id, 0, +option.value)
        : option.type === 'ttl' ? calls.tcp_option(id, 1, option.value)
        : option.type === 'keepAlive' ? calls.tcp_option(id, option.enabled ? 2 : 3, option.initialDelaySeconds)
        : -ErrorCode.UNSUPPORTED
      kick()
      if (code < 0) throw stackError(-code)
    },
    close: () => end(false),
    reset: () => end(true),
  }
}

/**
 * Connects to `remote` and resolves once the connection is established, or rejects as a session's connect would:
 * `CONNECTION_REFUSED`, `TIMED_OUT`, `HOST_UNREACHABLE`, `NETWORK_UNREACHABLE`, or the tunnel's end.
 */
export const stackConnect = async (engine: Engine, remote: Address, buffers: Buffers): Promise<TcpSocket> => {
  const { calls, kick } = engine
  const error = engine.ended()
  if (error) throw error
  engine.putAddress(remote)
  const id = calls.tcp_connect(buffers.receive, buffers.send)
  if (id < 0) throw stackError(-id)
  kick()
  const { next, wake } = changes()
  const unwatch = engine.watch(id, wake)
  try {
    for (;;) {
      const error = engine.ended()
      if (error) throw error
      const state = calls.tcp_state(id)
      if (state >= TcpState.ESTABLISHED) break
      if (state === TcpState.CLOSED) {
        const code = calls.tcp_error(id) || ErrorCode.CONNECTION_REFUSED
        calls.stack_release(id)
        kick()
        throw stackError(code)
      }
      await next()
    }
  } finally {
    unwatch()
  }
  calls.tcp_endpoints(id)
  const { address: local, end } = engine.readAddress(0)
  return stackTcpSocket(engine, id, local, engine.readAddress(end).address)
}
