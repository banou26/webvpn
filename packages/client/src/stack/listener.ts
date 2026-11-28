import type { ClosedBy } from '../context'
import type { TcpListener } from '../listener'
import type { Address } from '../protocol'
import type { TcpSocket } from '../tcp'
import type { Engine } from './engine'
import type { Buffers } from './tcp'

import { changes, stackError } from './engine'
import { stackTcpSocket } from './tcp'

/**
 * Listens on `port` of the stack, which `local` names as a peer dials it, and gives the listener as a session's
 * `TcpListener`. Each connection waits in the stack's backlog, in order, until `connections` hands it out; one more
 * than the backlog holds is refused with a reset. The listener closes the ones nobody took when it stops.
 */
export const stackListen = (engine: Engine, local: Address, backlog: number, buffers: Buffers): TcpListener => {
  const { calls, kick } = engine
  const error = engine.ended()
  if (error) throw error
  const id = calls.tcp_listen(local.port, backlog, buffers.receive, buffers.send)
  if (id < 0) throw stackError(-id)
  const { next, wake } = changes()
  let done = false
  let cancelled = false
  let finish!: (by: ClosedBy) => void
  const closed = new Promise<ClosedBy>((resolve) => { finish = resolve })

  const stop = (by: ClosedBy) => {
    if (done) return
    done = true
    unwatch()
    try {
      if (!engine.ended()) {
        // the stack would reset the connections nobody took, where a session's listener closes them
        for (let accepted = calls.tcp_accept(id); accepted; accepted = calls.tcp_accept(id)) {
          calls.tcp_close(accepted)
          calls.stack_release(accepted)
        }
        calls.stack_release(id)
        kick()
      }
    } finally {
      // a trap in these calls ends the stack, whose end no longer reaches this listener
      wake()
      finish(by)
    }
  }

  const unwatch = engine.watch(id, () => {
    if (engine.ended()) stop({ by: 'session' })
    wake()
  })

  return {
    id,
    local,
    connections: new ReadableStream<TcpSocket>({
      pull: async (controller) => {
        for (;;) {
          // a cancelled stream takes nothing, so what comes stays in the backlog for stop to close
          if (cancelled) return
          // once stop released the id, it may name another listener
          if (done) return controller.close()
          const accepted = calls.tcp_accept(id)
          if (accepted) {
            calls.tcp_endpoints(accepted)
            const { end } = engine.readAddress(0)
            controller.enqueue(stackTcpSocket(engine, accepted, local, engine.readAddress(end).address))
            // the poll puts a socket back to listen in the room the accept made
            kick()
            return
          }
          await next()
        }
      },
      cancel: () => {
        cancelled = true
        wake()
      },
    }, { highWaterMark: 0 }),
    closed,
    close: async () => stop({ by: 'client' }),
  }
}
