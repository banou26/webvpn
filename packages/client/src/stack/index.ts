import type { ClosedBy } from '../context'
import type { IpTunnel } from '../ip'
import type { Address } from '../protocol'
import type { Session } from '../session'

import { formatIp, parseIp } from '../address'
import { dnsAddresses, dnsQuery } from '../dns'
import { ErrorCode } from '../protocol'
import { stackError, startEngine } from './engine'
import { stackListen } from './listener'
import { stackLookup } from './lookup'
import { stackConnect } from './tcp'
import { stackUdpBind } from './udp'

const KIB = 1024
const RESOLVER_V4: Address = { ip: Uint8Array.of(1, 1, 1, 1), port: 53 }
const RESOLVER_V6: Address = { ip: parseIp('2606:4700:4700::1111')!, port: 53 }

/** How a stack sizes its sockets and where it looks names up. Every size is in bytes and fixed when a socket is made. */
export type StackOptions = {
  /** The DNS resolver `lookup` asks through the tunnel: 1.1.1.1 port 53, or 2606:4700:4700::1111 on a tunnel without IPv4. */
  resolver?: Address,
  /**
   * A TCP socket's receive buffer, 128 KiB by default. It is the most the socket's window offers, so a connection
   * carries at most this much per round trip: about 10 Mbit/s at a 100 ms round trip.
   */
  tcpReceiveBuffer?: number,
  /** A TCP socket's send buffer, 64 KiB by default, which bounds what it sends per round trip the same way. */
  tcpSendBuffer?: number,
  /** A UDP socket's receive buffer, 64 KiB by default. A datagram that finds it full is dropped. */
  udpReceiveBuffer?: number,
  /** A UDP socket's send buffer, 64 KiB by default. A datagram that finds it full is dropped. */
  udpSendBuffer?: number,
  /** How many connections a listener holds while they open or wait to be taken, 8 by default; one more is refused. */
  backlog?: number,
  /** How long a connect waits for the peer before it fails with `TIMED_OUT`: 10 seconds, as long as a relay waits. */
  connectTimeoutMs?: number,
  /** How long `lookup` waits for the resolver before it fails with `LOOKUP_FAILED`: 5 seconds, as a relay waits. */
  lookupTimeoutMs?: number,
}

/**
 * TCP and UDP over an IP tunnel, from `openStack`: the socket calls of a `Session`, with the same arguments, results
 * and `WebVpnError` codes, so code written against a session's sockets runs on a tunnel unchanged. TCP and UDP run
 * in the page, in a TCP/IP stack (smoltcp, as WebAssembly), and the tunnel carries only IP packets.
 *
 * What differs from a session: `tcpListen` takes one of the tunnel's public ports (port 0 takes a free one, another
 * port must be one of them, or it rejects with `ADDRESS_NOT_AVAILABLE`), rejects with `UNSUPPORTED` on a tunnel with
 * none, and names the relay's public address, which a peer dials. `udpBind` on port 0 takes a free public port while
 * the tunnel has one, and a private port otherwise, which only answers reach; its local address says which. A name
 * is looked up by the resolver in `StackOptions`, through the tunnel, and a connect by name takes its first A record,
 * or its first AAAA record on a tunnel without IPv4. Each socket's buffers are fixed when it is made, and the options
 * that cannot change them (`sendBufferSize`, `recvBufferSize`, broadcast and multicast) reject with `UNSUPPORTED`. A
 * UDP datagram must fit the tunnel's MTU, since the stack does not fragment.
 *
 * The stack owns the tunnel: it reads every packet from `tunnel.readable` and sends with `tunnel.send`, whose dropped
 * packets its TCP treats as loss on the path. When the tunnel ends, whoever ended it, every socket ends as a
 * session's sockets do when the session ends, and `closed` resolves with the tunnel's `ClosedBy`.
 */
export type Stack = Pick<Session, 'tcpConnect' | 'tcpListen' | 'udpBind' | 'lookup'> & {
  /** Resolves once the tunnel stopped, with who stopped it. Never rejects. */
  closed: Promise<ClosedBy>,
  /** Closes the tunnel, and so every socket. Rejects with the relay's refusal while the session lasts. */
  close: () => Promise<void>,
}

/** Starts a stack on `tunnel`, which nothing else may read or send on from then on. */
export const openStack = async (tunnel: IpTunnel, options: StackOptions = {}): Promise<Stack> => {
  const {
    resolver = tunnel.ipv4 ? RESOLVER_V4 : RESOLVER_V6,
    tcpReceiveBuffer = 128 * KIB,
    tcpSendBuffer = 64 * KIB,
    udpReceiveBuffer = 64 * KIB,
    udpSendBuffer = 64 * KIB,
    backlog = 8,
    connectTimeoutMs = 10_000,
    lookupTimeoutMs = 5000,
  } = options
  const engine = await startEngine(tunnel, connectTimeoutMs)
  const tcp = { receive: tcpReceiveBuffer, send: tcpSendBuffer }
  const udp = { receive: udpReceiveBuffer, send: udpSendBuffer }

  const isPublic = (port: number) => port >= tunnel.firstPort && port < tunnel.firstPort + tunnel.ports

  // the address a bind is reached at: the relay's public one on a public port, the tunnel's own otherwise, of the
  // family asked for first; the stack's sockets take both families, so an unspecified address is either
  const reachedAt = ({ ip }: Address, port: number) => {
    const v4 = ip.byteLength === 4
    const owns = v4 ? [tunnel.ipv4, tunnel.ipv6] : [tunnel.ipv6, tunnel.ipv4]
    const opens = v4 ? [tunnel.publicIpv4, tunnel.publicIpv6] : [tunnel.publicIpv6, tunnel.publicIpv4]
    if (!ip.every((byte) => byte === 0)) {
      const named = formatIp(ip)
      if (named !== owns[0] && named !== opens[0]) throw stackError(ErrorCode.ADDRESS_NOT_AVAILABLE)
      return parseIp(isPublic(port) && opens[0] ? opens[0] : owns[0]!)!
    }
    return parseIp((isPublic(port) && (opens[0] ?? opens[1])) || owns[0] || owns[1]!)!
  }

  const lookup = (query: Uint8Array) => stackLookup(engine, resolver, query, lookupTimeoutMs, udp, isPublic)

  return {
    closed: tunnel.closed,
    close: () => tunnel.close(),
    tcpConnect: async (target) => {
      if (!('name' in target)) return stackConnect(engine, target, tcp)
      const v4 = Boolean(tunnel.ipv4)
      const answer = await lookup(dnsQuery(target.name, v4 ? 'A' : 'AAAA'))
      const ip = dnsAddresses(answer).find((address) => address.byteLength === (v4 ? 4 : 16))
      if (!ip) throw stackError(ErrorCode.NAME_NOT_FOUND, 'the name has no address')
      return stackConnect(engine, { ip, port: target.port }, tcp)
    },
    tcpListen: async (local) => {
      if (!tunnel.ports) throw stackError(ErrorCode.UNSUPPORTED, 'the tunnel has no public port to listen on')
      const port = local.port || engine.calls.stack_public_port(0)
      if (!port) throw stackError(ErrorCode.ADDRESS_IN_USE, 'every public port of the tunnel is taken')
      if (!isPublic(port)) throw stackError(ErrorCode.ADDRESS_NOT_AVAILABLE, 'the port is not a public port of the tunnel')
      return stackListen(engine, { ip: reachedAt(local, port), port }, backlog, tcp)
    },
    udpBind: async (local) => {
      const port = local.port || engine.calls.stack_public_port(1)
      return stackUdpBind(engine, port, reachedAt(local, port), udp)
    },
    lookup,
  }
}
