import type { ClosedBy } from '../context'
import type { Address } from '../protocol'
import type { UdpDatagram, UdpSocket } from '../udp'
import type { Engine } from './engine'
import type { Buffers } from './tcp'

import { noop, WebVpnError } from '../context'
import { ErrorCode, MAX_UDP_PAYLOAD_BYTES } from '../protocol'
import { changes, stackError } from './engine'

const same = (one: Address, other: Address) =>
  one.port === other.port && one.ip.byteLength === other.ip.byteLength && one.ip.every((byte, at) => byte === other.ip[at])

/**
 * Binds a UDP socket on `port` of the stack, or on a free private port for 0, and gives it as a session's `UdpSocket`
 * whose local address is `ip` with the port it got. Datagrams wait for the reader in the stack's receive buffer,
 * and one that finds it full is dropped; a send never waits, and one that finds the send buffer full is dropped.
 */
export const stackUdpBind = (engine: Engine, port: number, ip: Uint8Array, buffers: Buffers): UdpSocket => {
  const { calls, kick } = engine
  const error = engine.ended()
  if (error) throw error
  const id = calls.udp_bind(port, buffers.receive, buffers.send)
  if (id < 0) throw stackError(-id)
  const { next, wake } = changes()
  let peer: Address | undefined
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
    wake()
    finish(by)
  }

  const unwatch = engine.watch(id, () => {
    if (engine.ended()) stop({ by: 'session' })
    wake()
  })

  const close = async () => stop({ by: 'client' })

  const readable = new ReadableStream<UdpDatagram>({
    pull: async (controller) => {
      for (;;) {
        if (done) return controller.close()
        const length = calls.udp_recv(id)
        if (length < 0) {
          await next()
          continue
        }
        const { address: remote, end } = engine.readAddress(0)
        const data = engine.buffer().slice(end, end + length)
        if (peer && !same(peer, remote)) continue
        return controller.enqueue({ remote, data })
      }
    },
    cancel: () => close().catch(noop),
  }, { highWaterMark: 0 })

  const writable = new WritableStream<{ remote?: Address, data: Uint8Array }>({
    write: ({ remote = peer, data }) => {
      if (done) throw engine.ended() ?? new WebVpnError(ErrorCode.OTHER, 'the socket is closed')
      if (data.byteLength > MAX_UDP_PAYLOAD_BYTES) {
        throw new WebVpnError(ErrorCode.OTHER, `the datagram is too large: a UDP payload holds at most ${MAX_UDP_PAYLOAD_BYTES} bytes`)
      }
      if (!remote) return
      engine.buffer().set(data, engine.putAddress(remote))
      const sent = calls.udp_send(id, data.byteLength)
      kick()
      if (sent < 0) throw new WebVpnError(ErrorCode.OTHER, 'the datagram is too large for the tunnel, which does not fragment')
    },
  })

  return {
    id,
    local: { ip, port: calls.udp_port(id) },
    readable,
    writable,
    connect: async (remote) => { peer = remote },
    disconnect: async () => { peer = undefined },
    setOption: async (option) => {
      if (done) throw engine.ended() ?? stackError(ErrorCode.UNKNOWN_SOCKET)
      const code = option.type === 'ttl' ? calls.udp_ttl(id, option.value) : -ErrorCode.UNSUPPORTED
      if (code < 0) throw stackError(-code)
    },
    closed,
    close,
  }
}
