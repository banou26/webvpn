import type { Address, ClientPacket, RelayPacket } from '../src'

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { expect, it } from 'vite-plus/test'

import {
  CloseCode,
  compatible,
  decodeClientPacket,
  decodeIpFrame,
  decodeMuxFrame,
  decodeRelayPacket,
  decodeUdpPacket,
  encodeClientPacket,
  encodeFramedUdpPacket,
  encodeIpFrame,
  encodeMuxFrame,
  encodeRelayPacket,
  encodeUdpPacket,
  ErrorCode,
  Feature,
  hello,
  MAX_CLIENT_FRAME_BYTES,
  MAX_UDP_PAYLOAD_BYTES,
  MuxKind,
  MuxStreamType,
  ProtocolError,
  VERSION,
} from '../src'
import { concat } from '../src/context'

const hex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')

const unhex = (text: string) => Uint8Array.from(text.match(/../g) ?? [], (pair) => parseInt(pair, 16))

const vectors = (group: string) =>
  readFileSync(join(import.meta.dirname, '../../../spec/vectors/v0.txt'), 'utf8')
    .split('\n')
    .filter((line) => line.trim() && !line.startsWith('#'))
    .map((line) => line.trim().split(/\s+/) as [string, string, string])
    .filter(([of]) => of === group)
    .map(([, name, bytes]) => ({ name, bytes: unhex(bytes) }))

const v4 = (text: string, port: number): Address => ({ ip: Uint8Array.from(text.split('.'), Number), port })

const SITE = v4('192.0.2.7', 443)
const RESOLVER = v4('192.0.2.7', 53)
const RELAY_PORT = v4('198.51.100.4', 50000)
const LISTENER = v4('203.0.113.9', 8080)

const clientPackets: Record<string, ClientPacket> = {
  'hello': hello(0, 'example'),
  'auth': { type: 'auth', id: 6, credential: Uint8Array.of(0xde, 0xad, 0xbe, 0xef) },
  'auth-clear': { type: 'authClear', id: 6 },
  'tcp-connect': { type: 'tcpConnect', id: 1, remote: SITE },
  'tcp-connect-name': { type: 'tcpConnectName', id: 9, port: 443, query: Uint8Array.of(1, 2) },
  'tcp-close': { type: 'tcpClose', id: 11, socket: 5 },
  'tcp-reset': { type: 'tcpReset', id: 12, socket: 5 },
  'tcp-set-option': {
    type: 'tcpSetOption',
    id: 5,
    socket: 5,
    option: { type: 'keepAlive', enabled: true, initialDelaySeconds: 30 },
  },
  'tcp-listen': { type: 'tcpListen', id: 4, local: LISTENER },
  'tcp-unlisten': { type: 'tcpUnlisten', id: 13, socket: 6 },
  'udp-bind': { type: 'udpBind', id: 3, local: { ip: new Uint8Array(16), port: 0 } },
  'udp-close': { type: 'udpClose', id: 14, socket: 9 },
  'udp-connect': { type: 'udpConnect', id: 15, socket: 9, remote: RESOLVER },
  'udp-disconnect': { type: 'udpDisconnect', id: 16, socket: 9 },
  'udp-set-option': {
    type: 'udpSetOption',
    id: 10,
    socket: 9,
    option: { type: 'addMembershipV4', group: Uint8Array.of(239, 1, 2, 3), interface: new Uint8Array(4) },
  },
  'dns-query': { type: 'dnsQuery', id: 8, query: Uint8Array.of(1, 2, 3) },
  'ip-open': { type: 'ipOpen', id: 10 },
  'ip-close': { type: 'ipClose', id: 11, socket: 12 },
}

const TUNNEL_V4 = Uint8Array.of(198, 18, 0, 2)
const TUNNEL_V6 = Uint8Array.of(0xfd, ...new Uint8Array(14), 2)
const PUBLIC_V4 = Uint8Array.of(203, 0, 113, 9)
const PUBLIC_V6 = Uint8Array.of(0x20, 0x01, 0x0d, 0xb8, ...new Uint8Array(11), 9)

const relayPackets: Record<string, RelayPacket> = {
  'hello': hello(Feature.LISTEN | Feature.DNS, 'webvpnd'),
  'ok': { type: 'ok', id: 7 },
  'error': { type: 'error', id: 2, code: ErrorCode.CONNECTION_REFUSED, message: 'connection refused' },
  'socket-connected': { type: 'socket', id: 1, socket: 5, local: RELAY_PORT, remote: SITE },
  'socket-bound': { type: 'socket', id: 4, socket: 6, local: LISTENER, remote: undefined },
  'dns-answer': { type: 'dnsAnswer', id: 8, answer: Uint8Array.of(9, 8) },
  'ip-tunnel': {
    type: 'ipTunnel',
    id: 10,
    socket: 12,
    mtu: 1500,
    ipv4: TUNNEL_V4,
    ipv6: TUNNEL_V6,
    publicIpv4: PUBLIC_V4,
    publicIpv6: PUBLIC_V6,
    firstPort: 40000,
    ports: 8,
  },
  'ip-tunnel-v4': { type: 'ipTunnel', id: 10, socket: 12, mtu: 1500, ipv4: TUNNEL_V4, firstPort: 0, ports: 0 },
  'accepted': { type: 'accepted', listener: 6, socket: 7, local: LISTENER, remote: RELAY_PORT },
  'accept-refused': { type: 'acceptRefused', listener: 6, code: ErrorCode.CAPACITY, remote: RELAY_PORT },
  'closed': { type: 'closed', socket: 9, code: ErrorCode.CAPACITY },
  'draining': { type: 'draining' },
  'bye': { type: 'bye', code: CloseCode.RESTARTING, reason: 'the relay is stopping' },
}

it('client frames match the vectors both ways', () => {
  const group = vectors('client')
  expect(group).toHaveLength(18)
  for (const { name, bytes } of group) {
    const packet = clientPackets[name]
    expect(packet, name).toBeDefined()
    expect(hex(encodeClientPacket(packet!)), name).toBe(hex(bytes))
    expect(decodeClientPacket(bytes), name).toEqual({ packet, taken: bytes.byteLength })
  }
})

it('relay frames match the vectors both ways', () => {
  const group = vectors('relay')
  expect(group).toHaveLength(13)
  for (const { name, bytes } of group) {
    const packet = relayPackets[name]
    expect(packet, name).toBeDefined()
    expect(hex(encodeRelayPacket(packet!)), name).toBe(hex(bytes))
    expect(decodeRelayPacket(bytes), name).toEqual({ packet, taken: bytes.byteLength })
  }
})

it('data packets match the vectors both ways', () => {
  const group = vectors('data')
  expect(group).toHaveLength(5)
  const opens: Record<string, [number, number]> = { 'mux-open-tcp': [3, MuxStreamType.TCP], 'mux-open-ip': [5, MuxStreamType.IP] }
  for (const { name, bytes } of group) {
    const opened = opens[name]
    if (opened) {
      const [stream, type] = opened
      const payload = Uint8Array.of(type)
      expect(hex(encodeMuxFrame(MuxKind.OPEN, stream, payload)), name).toBe(hex(bytes))
      expect(decodeMuxFrame(bytes), name).toEqual({ kind: MuxKind.OPEN, stream, payload })
      continue
    }
    if (name === 'ip-frame') {
      const packet = unhex('4500001400004000400100000a0000010a000002')
      expect(hex(encodeIpFrame(packet))).toBe(hex(bytes))
      expect(decodeIpFrame(bytes)).toEqual({ packet, taken: bytes.byteLength })
      continue
    }
    const remotes: Record<string, Address | undefined> = { 'udp-packet': RESOLVER, 'udp-packet-bare': undefined }
    expect(name in remotes, name).toBe(true)
    const packet = { socket: 9, remote: remotes[name], data: Uint8Array.of(0x68, 0x69) }
    expect(hex(encodeUdpPacket(packet)), name).toBe(hex(bytes))
    expect(decodeUdpPacket(bytes), name).toEqual(packet)

    const framed = encodeFramedUdpPacket(packet)
    expect(new DataView(framed.buffer).getUint32(0), name).toBe(bytes.byteLength)
    expect(hex(framed.subarray(4)), name).toBe(hex(bytes))
  }
})

it('a frame is read only once it is whole, at every cut, and leaves the next one', () => {
  const draining = Uint8Array.of(0x20, 0, 0, 0, 0)
  for (const { name, bytes } of vectors('relay')) {
    for (let cut = 0; cut < bytes.byteLength; cut++) {
      expect(decodeRelayPacket(bytes.subarray(0, cut)), `${name} cut at ${cut}`).toBeUndefined()
    }
    const two = new Uint8Array(bytes.byteLength + draining.byteLength)
    two.set(bytes)
    two.set(draining, bytes.byteLength)
    expect(decodeRelayPacket(two)?.taken, name).toBe(bytes.byteLength)
    expect(decodeRelayPacket(two.subarray(bytes.byteLength))).toEqual({ packet: { type: 'draining' }, taken: 5 })
  }
})

it('a frame over the limit is refused from its header alone', () => {
  const header = new Uint8Array(5)
  header[0] = 0x01
  const view = new DataView(header.buffer)
  view.setUint32(1, MAX_CLIENT_FRAME_BYTES + 1)
  expect(() => decodeClientPacket(header)).toThrow(ProtocolError)

  view.setUint32(1, MAX_CLIENT_FRAME_BYTES)
  expect(decodeClientPacket(header)).toBeUndefined()
})

it('a request of an unknown type keeps its id for the refusal', () => {
  const frame = Uint8Array.of(0x7f, 0, 0, 0, 6, 0, 0, 0, 42, 1, 2)
  expect(decodeClientPacket(frame)).toEqual({ packet: { type: 'unknown', kind: 0x7f, id: 42 }, taken: 11 })

  const noId = Uint8Array.of(0x7f, 0, 0, 0, 2, 1, 2)
  expect(decodeClientPacket(noId)?.packet).toStrictEqual({ type: 'unknown', kind: 0x7f, id: undefined })
})

it('a relay frame of an unknown type is skipped by its length', () => {
  const ok = encodeRelayPacket({ type: 'ok', id: 7 })
  const bytes = Uint8Array.of(0x7f, 0, 0, 0, 3, 1, 2, 3, ...ok)
  expect(decodeRelayPacket(bytes)).toEqual({ packet: { type: 'unknown', kind: 0x7f }, taken: 8 })
  expect(decodeRelayPacket(bytes.subarray(8))).toEqual({ packet: { type: 'ok', id: 7 }, taken: 9 })
})

it('bytes after the known fields are ignored and missing ones are not', () => {
  const longer = Uint8Array.of(0x01, 0, 0, 0, 6, 0, 0, 0, 7, 0xaa, 0xbb)
  expect(decodeRelayPacket(longer)).toEqual({ packet: { type: 'ok', id: 7 }, taken: 11 })

  const shorter = Uint8Array.of(0x01, 0, 0, 0, 3, 0, 0, 0)
  expect(() => decodeRelayPacket(shorter)).toThrow(ProtocolError)
})

it('an option of an unknown tag is kept for the refusal', () => {
  const frame = Uint8Array.of(0x14, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 5, 0x63)
  expect(decodeClientPacket(frame)?.packet).toEqual({
    type: 'tcpSetOption',
    id: 1,
    socket: 5,
    option: { type: 'unknown', tag: 0x63 },
  })
})

it('a hello suits only the same minor while the major is 0', () => {
  expect(compatible(hello(0, ''))).toBe(true)
  expect(compatible({ ...hello(0, ''), minor: VERSION.minor + 1 })).toBe(false)
  expect(compatible({ ...hello(0, ''), major: 1 })).toBe(false)

  const notWebVpn = Uint8Array.of(0x00, 0, 0, 0, 10, 0x48, 0x54, 0x54, 0x50, 0, 1, 0, 0, 0, 0)
  expect(() => decodeRelayPacket(notWebVpn)).toThrow('not a WebVPN hello')
})

it('an agent is cut at 255 bytes on a character', () => {
  const decoded = decodeClientPacket(encodeClientPacket(hello(0, 'é'.repeat(200))))
  expect(decoded?.packet).toMatchObject({ agent: 'é'.repeat(127) })
})

it('a tunnel frame is read only once it is whole, and leaves the next one', () => {
  const two = concat(encodeIpFrame(Uint8Array.of(1, 2, 3, 4, 5)), encodeIpFrame(new Uint8Array(0)))
  for (let cut = 0; cut < 7; cut++) expect(decodeIpFrame(two.subarray(0, cut)), `cut at ${cut}`).toBeUndefined()
  expect(decodeIpFrame(two)).toEqual({ packet: Uint8Array.of(1, 2, 3, 4, 5), taken: 7 })
  expect(decodeIpFrame(two.subarray(7))).toEqual({ packet: new Uint8Array(0), taken: 2 })
})

it('a tunnel\'s address is checked for its length when it is written', () => {
  const packet: RelayPacket = { type: 'ipTunnel', id: 1, socket: 2, mtu: 1500, ipv6: TUNNEL_V4, firstPort: 0, ports: 0 }
  expect(() => encodeRelayPacket(packet)).toThrow(TypeError)
})

it('a udp payload over the limit is refused from its length', () => {
  const packet = Uint8Array.of(0, 0, 0, 9, 2, 0, 0, 0, 0)
  new DataView(packet.buffer).setUint32(5, MAX_UDP_PAYLOAD_BYTES + 1)
  expect(() => decodeUdpPacket(packet)).toThrow('a length is over the limit')

  const cutShort = Uint8Array.of(0, 0, 0, 9, 2, 0, 0, 0, 4, 0x68, 0x69)
  expect(() => decodeUdpPacket(cutShort)).toThrow('a body ends before its fields do')
})

// a stream reader reuses its buffer for the next chunk, so a control packet that kept views into it would change
// under the code that holds it
it('a control packet holds copies, so the bytes it was read from may be reused', () => {
  for (const { name, bytes } of vectors('relay')) {
    const source = bytes.slice()
    const decoded = decodeRelayPacket(source)
    source.fill(0xff)
    expect(decoded?.packet, name).toEqual(relayPackets[name])
  }
  for (const { name, bytes } of vectors('client')) {
    const source = bytes.slice()
    const decoded = decodeClientPacket(source)
    source.fill(0xff)
    expect(decoded?.packet, name).toEqual(clientPackets[name])
  }
})
