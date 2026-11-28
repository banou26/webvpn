import type { ClosedBy, Context, Opened } from './context'
import type { Address } from './protocol'
import type { TcpSocket } from './tcp'

import { noop, ok } from './context'
import { tcpSocket } from './tcp'

const ACCEPTED_STREAM_MS = 30_000

/**
 * A port the relay listens on for the client, from `Session.tcpListen`. Each connection the relay accepts comes on
 * `connections`, in order; one the relay turned away (`AcceptRefused`) is not told. The listener stops at its own
 * `close()`, at the relay's `Closed` notice, or when the session ends. Then `connections` ends, `closed` resolves with
 * which of the three it was, and the client closes every connection not handed out yet, as well as any the relay
 * accepts after.
 */
export type TcpListener = {
  /** The listener's id in its session. */
  id: number,
  /** The bound address, with the port the relay took for port 0. */
  local: Address,
  connections: ReadableStream<TcpSocket>,
  /** Resolves once the listener stopped, with who stopped it. Never rejects. */
  closed: Promise<ClosedBy>,
  /** Stops the listener at once and closes it at the relay. Rejects with the relay's refusal while the session lasts. */
  close: () => Promise<void>,
}

export const tcpListener = (context: Context, { socket, local }: Opened): TcpListener => {
  let done = false
  let closing: Promise<void> | undefined
  let finish!: (by: ClosedBy) => void
  const closed = new Promise<ClosedBy>((resolve) => { finish = resolve })
  const waiting: TcpSocket[] = []
  let cancelled = false
  let wake: (() => void) | undefined

  // a connection is handed out only as the reader reads, so the ones it never took are still here for stop to close;
  // a cancelled stream takes none, since its enqueue would throw and the connection would be lost
  const connections = new ReadableStream<TcpSocket>({
    pull: async (controller) => {
      while (!waiting.length) {
        if (done) return controller.close()
        await new Promise<void>((resolve) => { wake = resolve })
        if (cancelled) return
      }
      controller.enqueue(waiting.shift()!)
    },
    cancel: () => {
      cancelled = true
      wake?.()
    },
  }, { highWaterMark: 0 })

  const stop = (by: ClosedBy) => {
    if (done) return
    done = true
    unown()
    context.retire(socket)
    for (const connection of waiting.splice(0)) connection.close().catch(noop)
    wake?.()
    finish(by)
  }

  const accept = async (accepted: { socket: number, local: Address, remote: Address }) => {
    try {
      const connection = tcpSocket(context, accepted, await context.claim(accepted.socket, ACCEPTED_STREAM_MS))
      if (done) return connection.close().catch(noop)
      waiting.push(connection)
      wake?.()
    } catch {
      context.release('tcp', accepted.socket)
    }
  }

  const unown = context.own(socket, {
    notice: (packet) => {
      if (packet.type === 'accepted') accept(packet)
      if (packet.type === 'closed') stop({ by: 'relay', code: packet.code })
    },
    end: () => stop({ by: 'session' }),
  })

  return {
    id: socket,
    local,
    connections,
    closed,
    // the unlisten goes out ahead of the closes of the waiting connections
    close: () => closing ??= (async () => {
      if (done) return
      const unlisten = context.request({ type: 'tcpUnlisten', socket }, ok)
      stop({ by: 'client' })
      try {
        await unlisten
      } catch (error) {
        if (!context.ended()) throw error
      }
    })(),
  }
}
