import type { ClosedBy } from '../context'
import type { TcpListener } from '../listener'
import type { Address } from '../protocol'
import type { TcpSocket } from '../tcp'
import type { Engine } from './engine'
import type { Buffers } from './tcp'

import { noop } from '../context'
import { changes, stackError } from './engine'
import { stackTcpSocket } from './tcp'

/**
 * Listens on `port` of the stack, which `local` names as a peer dials it, and gives the listener as a session's
 * `TcpListener`. Each connection is taken from the stack as soon as it is established, which makes room in the
 * backlog, and waits in order until `connections` hands it out.
 */
export const stackListen = (engine: Engine, local: Address, backlog: number, buffers: Buffers): TcpListener => {
  const { calls, kick } = engine
  const error = engine.ended()
  if (error) throw error
  const id = calls.tcp_listen(local.port, backlog, buffers.receive, buffers.send)
  if (id < 0) throw stackError(-id)
  const { next, wake } = changes()
  const waiting: TcpSocket[] = []
  let done = false
  let finish!: (by: ClosedBy) => void
  const closed = new Promise<ClosedBy>((resolve) => { finish = resolve })

  const stop = (by: ClosedBy) => {
    if (done) return
    done = true
    unwatch()
    if (!engine.ended()) {
      calls.stack_release(id)
      kick()
    }
    for (const connection of waiting.splice(0)) connection.close().catch(noop)
    wake()
    finish(by)
  }

  const take = () => {
    for (let accepted = calls.tcp_accept(id); accepted; accepted = calls.tcp_accept(id)) {
      calls.tcp_endpoints(accepted)
      const { end } = engine.readAddress(0)
      waiting.push(stackTcpSocket(engine, accepted, local, engine.readAddress(end).address))
    }
    kick()
  }

  const unwatch = engine.watch(id, () => {
    if (engine.ended()) stop({ by: 'session' })
    else take()
    wake()
  })

  return {
    id,
    local,
    connections: new ReadableStream<TcpSocket>({
      pull: async (controller) => {
        while (!waiting.length) {
          if (done) return controller.close()
          await next()
        }
        controller.enqueue(waiting.shift()!)
      },
    }, { highWaterMark: 0 }),
    closed,
    close: async () => stop({ by: 'client' }),
  }
}
