import type { Context, Opened } from './context'
import type { Address } from './protocol'
import type { TcpSocket } from './tcp'

import { noop, ok } from './context'
import { tcpSocket } from './tcp'

const ACCEPTED_STREAM_MS = 30_000

/**
 * A port the relay listens on for the client, from `Session.tcpListen`. Each connection the relay accepts comes on
 * `connections`; one the relay turned away (`AcceptRefused`) is not told. `connections` ends when the listener
 * closed, and `closed` resolves then: with the code of the relay's `Closed` notice when the relay ended the listener
 * on its own, and `undefined` when the client closed it or the session ended.
 */
export type TcpListener = {
  /** The listener's id in its session. */
  id: number,
  /** The bound address, with the port the relay took for port 0. */
  local: Address,
  connections: ReadableStream<TcpSocket>,
  closed: Promise<number | undefined>,
  close: () => Promise<void>,
}

export const tcpListener = (context: Context, { socket, local }: Opened): TcpListener => {
  let done = false
  let closing: Promise<void> | undefined
  let finish!: (code?: number) => void
  const closed = new Promise<number | undefined>((resolve) => { finish = resolve })
  let controller!: ReadableStreamDefaultController<TcpSocket>
  const connections = new ReadableStream<TcpSocket>({ start: (started) => { controller = started } })

  const stop = (code?: number) => {
    if (done) return
    done = true
    unown()
    context.retire(socket)
    controller.close()
    finish(code)
  }

  const accept = async (accepted: { socket: number, local: Address, remote: Address }) => {
    try {
      const connection = tcpSocket(context, accepted, await context.claim(accepted.socket, ACCEPTED_STREAM_MS))
      if (done) return connection.close().catch(noop)
      controller.enqueue(connection)
    } catch {
      context.release('tcp', accepted.socket)
    }
  }

  const unown = context.own(socket, {
    notice: (packet) => {
      if (packet.type === 'accepted') accept(packet)
      if (packet.type === 'closed') stop(packet.code)
    },
    end: () => stop(),
  })

  return {
    id: socket,
    local,
    connections,
    closed,
    close: () => closing ??= (async () => {
      if (done) return
      try {
        await context.request({ type: 'tcpUnlisten', socket }, ok)
      } catch (error) {
        if (!context.ended()) throw error
      } finally {
        stop()
      }
    })(),
  }
}
