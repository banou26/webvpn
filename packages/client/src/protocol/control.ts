import type { TcpOption, UdpOption } from './options'
import type { Address, Reader, Writer } from './wire'

import { putTcpOption, putUdpOption, readTcpOption, readUdpOption } from './options'
import { ProtocolError, reader, sized, writer } from './wire'

/** The version this package speaks. While the major is 0, peers need the same minor. */
export const VERSION = { major: 0, minor: 1 } as const
/** The longest frame body a relay reads from a client. */
export const MAX_CLIENT_FRAME_BYTES = 4096
/** The longest frame body a client reads from a relay; a whole DNS answer fits. */
export const MAX_RELAY_FRAME_BYTES = 128 * 1024
/** The longest agent a hello carries; a longer one is cut when it is written. */
export const MAX_AGENT_BYTES = 255

const HEADER_BYTES = 5
const MAGIC = Uint8Array.of(0x57, 0x56, 0x50, 0x4e)
const encoder = new TextEncoder()
const decoder = new TextDecoder()

/** The first frame each side writes: the relay first, then the client. */
export type Hello = {
  type: 'hello'
  major: number
  minor: number
  /** Bits of `Feature`. A client sends 0. */
  features: number
  /** Names the implementation for a person reading a log. Nothing may branch on it. */
  agent: string
}

/** A hello at this package's version. */
export const hello = (features: number, agent: string): Hello => ({ type: 'hello', ...VERSION, features, agent })

/** Whether this package can speak to the peer that sent `peer`. */
export const compatible = (peer: Hello) =>
  peer.major === VERSION.major && (peer.major !== 0 || peer.minor === VERSION.minor)

/** A control frame a client sends. `id` names the request in its reply. */
export type ClientPacket =
  | Hello
  /** Presents a credential, whose bytes the relay's operator defines. Answered `ok`. */
  | { type: 'auth', id: number, credential: Uint8Array }
  /** Returns the session to no identity. Answered `ok`. */
  | { type: 'authClear', id: number }
  /** Answered `socket`. */
  | { type: 'tcpConnect', id: number, remote: Address }
  /** Connects to the first A record the relay's resolver answers for `query`, a whole DNS message. Answered `socket`. */
  | { type: 'tcpConnectName', id: number, port: number, query: Uint8Array }
  /** Ends the socket in order. Answered `ok`, also for a socket that is gone. */
  | { type: 'tcpClose', id: number, socket: number }
  /** Ends the socket with a reset toward its peer. Answered `ok`, also for a socket that is gone. */
  | { type: 'tcpReset', id: number, socket: number }
  | { type: 'tcpSetOption', id: number, socket: number, option: TcpOption }
  /** Port 0 takes a free port. Answered `socket` with the bound address and no remote. */
  | { type: 'tcpListen', id: number, local: Address }
  | { type: 'tcpUnlisten', id: number, socket: number }
  /** Port 0 takes a free port. Answered `socket` with the bound address and no remote. */
  | { type: 'udpBind', id: number, local: Address }
  | { type: 'udpClose', id: number, socket: number }
  | { type: 'udpConnect', id: number, socket: number, remote: Address }
  | { type: 'udpDisconnect', id: number, socket: number }
  | { type: 'udpSetOption', id: number, socket: number, option: UdpOption }
  /** `query` is a whole DNS message. Answered `dnsAnswer`. */
  | { type: 'dnsQuery', id: number, query: Uint8Array }
  /** Answered `ipTunnel`. */
  | { type: 'ipOpen', id: number }
  /** Ends the tunnel. Answered `ok`, also for a tunnel that is gone. */
  | { type: 'ipClose', id: number, socket: number }
  /** A type this package does not name. A relay answers `id`, when the body held one, with `UNSUPPORTED`. */
  | { type: 'unknown', kind: number, id?: number }

/** A control frame a relay sends: a reply, which carries the request's `id`, or a notice. */
export type RelayPacket =
  | Hello
  /** The request was done and has nothing to return. */
  | { type: 'ok', id: number }
  /** The request was not done. `code` is an `ErrorCode`; `message` is for a person. */
  | { type: 'error', id: number, code: number, message: string }
  /** The socket a connect, a listen or a bind opened. `remote` is the peer of a connect and absent otherwise. */
  | { type: 'socket', id: number, socket: number, local: Address, remote?: Address }
  /** The resolver's whole DNS message. */
  | { type: 'dnsAnswer', id: number, answer: Uint8Array }
  /**
   * The tunnel an `ipOpen` opened: the largest packet it carries, and the addresses the relay gave the client's end,
   * 4 and 16 bytes, at least one of them. A family with no address is absent here and all zero bytes on the wire.
   */
  | { type: 'ipTunnel', id: number, socket: number, mtu: number, ipv4?: Uint8Array, ipv6?: Uint8Array }
  /** A listener accepted a connection, which is socket `socket` from now on. */
  | { type: 'accepted', listener: number, socket: number, local: Address, remote: Address }
  /** A listener had a connection the relay turned away. */
  | { type: 'acceptRefused', listener: number, code: number, remote: Address }
  /** The relay ended a listener, a UDP socket or an IP tunnel on its own, and `code` says why. The socket is gone. */
  | { type: 'closed', socket: number, code: number }
  /** The relay is about to stop: this session keeps its sockets, and new ones belong on a new session. */
  | { type: 'draining' }
  /**
   * The relay closes the session on its own right after this frame, the last on the control stream. `code` is the
   * `CloseCode` it closes with and `reason` is for a person. The session's code comes from it, since a carrier may
   * not show its own close to the page.
   */
  | { type: 'bye', code: number, reason: string }
  /** A type this package does not name, which a client skips. */
  | { type: 'unknown', kind: number }

const CLIENT = {
  hello: 0x00,
  auth: 0x01,
  authClear: 0x02,
  tcpConnect: 0x10,
  tcpConnectName: 0x11,
  tcpClose: 0x12,
  tcpReset: 0x13,
  tcpSetOption: 0x14,
  tcpListen: 0x20,
  tcpUnlisten: 0x21,
  udpBind: 0x30,
  udpClose: 0x31,
  udpConnect: 0x32,
  udpDisconnect: 0x33,
  udpSetOption: 0x34,
  dnsQuery: 0x40,
  ipOpen: 0x50,
  ipClose: 0x51,
} as const

const RELAY = {
  hello: 0x00,
  ok: 0x01,
  error: 0x02,
  socket: 0x03,
  dnsAnswer: 0x04,
  ipTunnel: 0x05,
  accepted: 0x10,
  acceptRefused: 0x11,
  closed: 0x12,
  draining: 0x20,
  bye: 0x21,
} as const

const putHello = (w: Writer, packet: Hello) => {
  let agent = encoder.encode(packet.agent)
  if (agent.byteLength > MAX_AGENT_BYTES) {
    let end = MAX_AGENT_BYTES
    while ((agent[end]! & 0xc0) === 0x80) end--
    agent = agent.subarray(0, end)
  }
  w.put(MAGIC).u8(packet.major).u8(packet.minor).u32(packet.features).put(agent)
}

const readHello = (r: Reader): Hello => {
  const magic = r.take(MAGIC.byteLength)
  if (MAGIC.some((byte, at) => magic[at] !== byte)) throw new ProtocolError('not a WebVPN hello')
  return {
    type: 'hello',
    major: r.u8(),
    minor: r.u8(),
    features: r.u32(),
    agent: decoder.decode(r.rest().subarray(0, MAX_AGENT_BYTES)),
  }
}

const NO_IPV4 = new Uint8Array(4)
const NO_IPV6 = new Uint8Array(16)

const given = (ip: Uint8Array) => ip.some((byte) => byte !== 0) ? ip.slice() : undefined

const open = (kind: number) => writer().u8(kind).u32(0)

const seal = (w: Writer) => w.setU32(1, w.length() - HEADER_BYTES).done()

const split = (bytes: Uint8Array, limit: number) => {
  if (bytes.byteLength < HEADER_BYTES) return undefined
  const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(1)
  if (length > limit) throw new ProtocolError('a length is over the limit')
  const taken = HEADER_BYTES + length
  if (bytes.byteLength < taken) return undefined
  return { kind: bytes[0]!, body: reader(bytes.subarray(HEADER_BYTES, taken)), taken }
}

/** The packet as one frame. */
export const encodeClientPacket = (packet: ClientPacket) => {
  const w = open(packet.type === 'unknown' ? packet.kind : CLIENT[packet.type])
  switch (packet.type) {
    case 'hello':
      putHello(w, packet)
      break
    case 'auth':
      w.u32(packet.id).put(packet.credential)
      break
    case 'authClear':
    case 'ipOpen':
      w.u32(packet.id)
      break
    case 'tcpConnect':
      w.u32(packet.id).address(packet.remote)
      break
    case 'tcpConnectName':
      w.u32(packet.id).u16(packet.port).put(packet.query)
      break
    case 'tcpClose':
    case 'tcpReset':
    case 'tcpUnlisten':
    case 'udpClose':
    case 'udpDisconnect':
    case 'ipClose':
      w.u32(packet.id).u32(packet.socket)
      break
    case 'tcpSetOption':
      putTcpOption(w.u32(packet.id).u32(packet.socket), packet.option)
      break
    case 'tcpListen':
    case 'udpBind':
      w.u32(packet.id).address(packet.local)
      break
    case 'udpConnect':
      w.u32(packet.id).u32(packet.socket).address(packet.remote)
      break
    case 'udpSetOption':
      putUdpOption(w.u32(packet.id).u32(packet.socket), packet.option)
      break
    case 'dnsQuery':
      w.u32(packet.id).put(packet.query)
      break
    case 'unknown':
      if (packet.id !== undefined) w.u32(packet.id)
      break
  }
  return seal(w)
}

const readClientPacket = (kind: number, r: Reader): ClientPacket => {
  switch (kind) {
    case CLIENT.hello: return readHello(r)
    case CLIENT.auth: return { type: 'auth', id: r.u32(), credential: r.rest().slice() }
    case CLIENT.authClear: return { type: 'authClear', id: r.u32() }
    case CLIENT.tcpConnect: return { type: 'tcpConnect', id: r.u32(), remote: r.address() }
    case CLIENT.tcpConnectName:
      return { type: 'tcpConnectName', id: r.u32(), port: r.u16(), query: r.rest().slice() }
    case CLIENT.tcpClose: return { type: 'tcpClose', id: r.u32(), socket: r.u32() }
    case CLIENT.tcpReset: return { type: 'tcpReset', id: r.u32(), socket: r.u32() }
    case CLIENT.tcpSetOption:
      return { type: 'tcpSetOption', id: r.u32(), socket: r.u32(), option: readTcpOption(r) }
    case CLIENT.tcpListen: return { type: 'tcpListen', id: r.u32(), local: r.address() }
    case CLIENT.tcpUnlisten: return { type: 'tcpUnlisten', id: r.u32(), socket: r.u32() }
    case CLIENT.udpBind: return { type: 'udpBind', id: r.u32(), local: r.address() }
    case CLIENT.udpClose: return { type: 'udpClose', id: r.u32(), socket: r.u32() }
    case CLIENT.udpConnect:
      return { type: 'udpConnect', id: r.u32(), socket: r.u32(), remote: r.address() }
    case CLIENT.udpDisconnect: return { type: 'udpDisconnect', id: r.u32(), socket: r.u32() }
    case CLIENT.udpSetOption:
      return { type: 'udpSetOption', id: r.u32(), socket: r.u32(), option: readUdpOption(r) }
    case CLIENT.dnsQuery: return { type: 'dnsQuery', id: r.u32(), query: r.rest().slice() }
    case CLIENT.ipOpen: return { type: 'ipOpen', id: r.u32() }
    case CLIENT.ipClose: return { type: 'ipClose', id: r.u32(), socket: r.u32() }
    default: return { type: 'unknown', kind, id: r.left() >= 4 ? r.u32() : undefined }
  }
}

/**
 * Reads one packet off the front of `bytes`: the packet and how many bytes it took, or `undefined` until a whole
 * frame is there. The packet holds copies, so `bytes` may be reused.
 */
export const decodeClientPacket = (bytes: Uint8Array) => {
  const frame = split(bytes, MAX_CLIENT_FRAME_BYTES)
  return frame && { packet: readClientPacket(frame.kind, frame.body), taken: frame.taken }
}

/** The packet as one frame. */
export const encodeRelayPacket = (packet: RelayPacket) => {
  const w = open(packet.type === 'unknown' ? packet.kind : RELAY[packet.type])
  switch (packet.type) {
    case 'hello':
      putHello(w, packet)
      break
    case 'ok':
      w.u32(packet.id)
      break
    case 'error':
      w.u32(packet.id).u16(packet.code).put(encoder.encode(packet.message))
      break
    case 'socket':
      w.u32(packet.id).u32(packet.socket).address(packet.local).address(packet.remote)
      break
    case 'dnsAnswer':
      w.u32(packet.id).put(packet.answer)
      break
    case 'ipTunnel':
      w.u32(packet.id).u32(packet.socket).u16(packet.mtu)
        .put(sized(packet.ipv4 ?? NO_IPV4, 4))
        .put(sized(packet.ipv6 ?? NO_IPV6, 16))
      break
    case 'accepted':
      w.u32(packet.listener).u32(packet.socket).address(packet.local).address(packet.remote)
      break
    case 'acceptRefused':
      w.u32(packet.listener).u16(packet.code).address(packet.remote)
      break
    case 'closed':
      w.u32(packet.socket).u16(packet.code)
      break
    case 'bye':
      w.u32(packet.code).put(encoder.encode(packet.reason))
      break
  }
  return seal(w)
}

const readRelayPacket = (kind: number, r: Reader): RelayPacket => {
  switch (kind) {
    case RELAY.hello: return readHello(r)
    case RELAY.ok: return { type: 'ok', id: r.u32() }
    case RELAY.error: return { type: 'error', id: r.u32(), code: r.u16(), message: decoder.decode(r.rest()) }
    case RELAY.socket:
      return { type: 'socket', id: r.u32(), socket: r.u32(), local: r.address(), remote: r.optionalAddress() }
    case RELAY.dnsAnswer: return { type: 'dnsAnswer', id: r.u32(), answer: r.rest().slice() }
    case RELAY.ipTunnel:
      return { type: 'ipTunnel', id: r.u32(), socket: r.u32(), mtu: r.u16(), ipv4: given(r.take(4)), ipv6: given(r.take(16)) }
    case RELAY.accepted:
      return { type: 'accepted', listener: r.u32(), socket: r.u32(), local: r.address(), remote: r.address() }
    case RELAY.acceptRefused:
      return { type: 'acceptRefused', listener: r.u32(), code: r.u16(), remote: r.address() }
    case RELAY.closed: return { type: 'closed', socket: r.u32(), code: r.u16() }
    case RELAY.draining: return { type: 'draining' }
    case RELAY.bye: return { type: 'bye', code: r.u32(), reason: decoder.decode(r.rest()) }
    default: return { type: 'unknown', kind }
  }
}

/**
 * Reads one packet off the front of `bytes`: the packet and how many bytes it took, or `undefined` until a whole
 * frame is there. The packet holds copies, so `bytes` may be reused.
 */
export const decodeRelayPacket = (bytes: Uint8Array) => {
  const frame = split(bytes, MAX_RELAY_FRAME_BYTES)
  return frame && { packet: readRelayPacket(frame.kind, frame.body), taken: frame.taken }
}
