import type { Context, SocketStream } from './context'
import type { Address, TcpOption } from './protocol'

import { EMPTY, ok, streamErrorCode, WebVpnError } from './context'
import { ErrorCode, ResetCode } from './protocol'

// Firefox 151 fails a stream's upload as the relay resets its download, and that error came up to 20 ms ahead of the
// reset (36 of 256 sockets writing as their peer reset, on a machine at load 40, measured 2026-11-11), so a failed
// write waits this long for the download to tell whether the peer reset
const PEER_RESET_WAIT_MS = 1000

/**
 * A TCP connection through the relay, from `Session.tcpConnect` or a listener.
 *
 * `readable` carries the peer's bytes and ends when the peer finished its side. It errors with a `WebVpnError` of
 * `CONNECTION_RESET` when the peer reset the connection, and with the session's error when the session ended first.
 * `writable` carries bytes to the peer, and closing it is a half close: the peer reads its end, and `readable` stays
 * open. Aborting it resets this side of the socket's stream, which the relay also takes as a half close, so the peer
 * reads a clean end and never gets what the abort dropped; over the WebSocket mux it ends `readable` too. `reset` is
 * the way to reset the connection. After `close` or `reset`, `readable` ends without an error, and what the relay
 * still sends is dropped.
 */
export type TcpSocket = {
  /** The socket's id in its session. */
  id: number,
  /** The relay's end of the connection. */
  local: Address,
  remote: Address,
  readable: ReadableStream<Uint8Array>,
  writable: WritableStream<Uint8Array>,
  setOption: (option: TcpOption) => Promise<void>,
  /** Ends the connection in order: the relay sends the peer what it holds of this side, then closes. */
  close: () => Promise<void>,
  /** Ends the connection with a reset toward the peer, dropping what was not sent. */
  reset: () => Promise<void>,
}

const peerReset = () => new WebVpnError(ErrorCode.CONNECTION_RESET, 'the peer reset the connection')

export const tcpSocket = (
  context: Context,
  { socket, local, remote }: { socket: number, local: Address, remote: Address },
  { head, reader, writable: upload }: SocketStream,
): TcpSocket => {
  let closing = false
  let stopped = false
  let ending: Promise<void> | undefined
  let downloadEnded!: (error?: unknown) => void
  const downloadEnd = new Promise<unknown>((resolve) => { downloadEnded = resolve })
  // watched on the reader rather than in pull, so a write learns of the peer's reset on a socket nobody reads
  reader.closed.then(() => downloadEnded(), downloadEnded)
  let controller!: ReadableStreamDefaultController<Uint8Array>

  // pulled only as the reader reads, so a slow reader holds back this socket's stream and nothing else
  const readable = new ReadableStream<Uint8Array>({
    start: (started) => { controller = started },
    pull: async () => {
      if (head.byteLength) {
        controller.enqueue(head)
        head = EMPTY
        return
      }
      try {
        const { value, done } = await reader.read()
        if (stopped) return
        if (done) return controller.close()
        controller.enqueue(value)
      } catch (error) {
        if (stopped) return
        const code = streamErrorCode(error)
        if (code === ResetCode.PEER_RESET) return controller.error(peerReset())
        // the relay resets its side with code 0 once the client closed the socket, which is no error to the reader
        if (closing || code === ResetCode.CLOSED) return controller.close()
        controller.error(context.ended() ?? error)
      }
    },
    cancel: (reason) => reader.cancel(reason),
  }, { highWaterMark: 0 })

  // Chrome 156 counts a stream's unread bytes against the whole session's flow-control window: 1 MiB left unread in
  // each of 14 to 22 closed sockets stalled every stream, then Chrome closed the session (2026-11-06). So the stream
  // is read to its end and dropped, even under a reader that holds the lock and stopped reading. Not cancelled:
  // Firefox 151 and 158 free a stream only once they read its end, and a cancel lost one in up to 39 of 48 sockets
  // closed as that end landed.
  const stopReading = async () => {
    if (stopped) return
    stopped = true
    try {
      controller.close()
    } catch {}
    try {
      while (!(await reader.read()).done) {}
    } catch {}
  }

  const writer = upload!.getWriter()
  const failed = async (error: unknown): Promise<never> => {
    let timer: ReturnType<typeof setTimeout> | undefined
    const end = await Promise.race([downloadEnd, new Promise((resolve) => { timer = setTimeout(resolve, PEER_RESET_WAIT_MS) })])
    clearTimeout(timer)
    throw streamErrorCode(end) === ResetCode.PEER_RESET ? peerReset() : error
  }
  const writable = new WritableStream<Uint8Array>({
    write: (chunk) => writer.write(chunk).catch(failed),
    close: () => writer.close().catch(failed),
    abort: (reason) => writer.abort(reason),
  })

  // close and reset share it, so a socket sends at most one of them
  const end = (type: 'tcpClose' | 'tcpReset') => ending ??= (async () => {
    closing = true
    if (context.ended()) return
    try {
      await context.request({ type, socket }, ok)
    } catch (error) {
      if (!context.ended()) throw error
      return
    }
    // only once the relay answered, so that it sends no more of what nobody would read
    stopReading()
  })()

  return {
    id: socket,
    local,
    remote,
    readable,
    writable,
    setOption: (option) => context.request({ type: 'tcpSetOption', socket, option }, ok),
    close: () => end('tcpClose'),
    reset: () => end('tcpReset'),
  }
}
