import type { ClosedBy } from '../../src/context'
import type { IpTunnel } from '../../src/ip'
import type { Address } from '../../src/protocol'
import type { Stack, StackOptions } from '../../src/stack'

import { parseIp } from '../../src/address'
import { openStack } from '../../src/stack'

export const CLIENT = '10.0.0.2'
export const CLIENT_V6 = 'fd00::2'
export const CLIENT_PUBLIC = '203.0.113.9'
export const FIRST_PORT = 40000
export const SITE = '192.0.2.1'
export const SITE_V6 = '2001:db8::1'

export const at = (text: string, port: number): Address => ({ ip: parseIp(text)!, port })

type Fields = Omit<IpTunnel, 'readable' | 'send' | 'closed' | 'close' | 'carrier'> & { carrier?: IpTunnel['carrier'] }

/** A tunnel played by the test: what it reads is what `deliver` gives it, and what it sends goes to `send`. */
export const fakeTunnel = (fields: Fields, send: (packet: Uint8Array) => boolean) => {
  let controller!: ReadableStreamDefaultController<Uint8Array>
  let stop!: (by: ClosedBy) => void
  let done = false
  const closed = new Promise<ClosedBy>((resolve) => { stop = resolve })
  const end = (by: ClosedBy) => {
    if (done) return
    done = true
    try {
      controller.close()
    } catch {}
    stop(by)
  }
  const tunnel: IpTunnel = {
    carrier: 'websocket',
    ...fields,
    readable: new ReadableStream({ start: (started) => { controller = started } }),
    send: (packet) => !done && send(packet),
    closed,
    close: async () => end({ by: 'client' }),
  }
  return { tunnel, end, deliver: (packet: Uint8Array) => !done && controller.enqueue(packet) }
}

const sum = (bytes: Uint8Array, start = 0) => {
  let total = start
  for (let at = 0; at < bytes.byteLength; at += 2) total += (bytes[at]! << 8) | (bytes[at + 1] ?? 0)
  while (total > 0xffff) total = (total & 0xffff) + (total >>> 16)
  return total
}

const checksum = (bytes: Uint8Array, start = 0) => ~sum(bytes, start) & 0xffff

/** The IPv4 packet with the address at `offset` (12 the source, 16 the destination) moved from `from` to `to`. */
const translate = (packet: Uint8Array, offset: number, from: Uint8Array, to: Uint8Array) => {
  if (packet[0]! >> 4 !== 4 || !from.every((byte, at) => packet[offset + at] === byte)) return packet
  const out = packet.slice()
  const view = new DataView(out.buffer)
  out.set(to, offset)
  const header = (out[0]! & 0x0f) * 4
  view.setUint16(10, 0)
  view.setUint16(10, checksum(out.subarray(0, header)))
  const field = out[9] === 6 ? 16 : out[9] === 17 ? 6 : undefined
  if (field === undefined || (out[9] === 17 && view.getUint16(header + 6) === 0)) return out
  const segment = out.subarray(header)
  const pseudo = new Uint8Array(12)
  pseudo.set(out.subarray(12, 20))
  pseudo[9] = out[9]!
  new DataView(pseudo.buffer).setUint16(10, segment.byteLength)
  view.setUint16(header + field, 0)
  view.setUint16(header + field, checksum(segment, sum(pseudo)) || 0xffff)
  return out
}

/** An ICMP destination unreachable from a router, quoting the start of `packet`, toward its source. */
export const unreachable = (packet: Uint8Array, code: number) => {
  const icmp = new Uint8Array(8 + 28)
  icmp.set([3, code])
  icmp.set(packet.subarray(0, 28), 8)
  new DataView(icmp.buffer).setUint16(2, checksum(icmp))
  const out = new Uint8Array(20 + icmp.byteLength)
  out.set([0x45, 0, 0, out.byteLength, 0, 0, 0, 0, 64, 1])
  out.set([198, 51, 100, 1], 12)
  out.set(packet.subarray(12, 16), 16)
  new DataView(out.buffer).setUint16(10, checksum(out.subarray(0, 20)))
  out.set(icmp, 20)
  return out
}

/** An IPv4 UDP packet from `from` to `to` that carries `data`, with no UDP checksum, which IPv4 allows. */
export const udpPacket = (from: Address, to: Address, data: Uint8Array) => {
  const out = new Uint8Array(28 + data.byteLength)
  const view = new DataView(out.buffer)
  out.set([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17])
  view.setUint16(2, out.byteLength)
  out.set(from.ip, 12)
  out.set(to.ip, 16)
  view.setUint16(10, checksum(out.subarray(0, 20)))
  view.setUint16(20, from.port)
  view.setUint16(22, to.port)
  view.setUint16(24, 8 + data.byteLength)
  out.set(data, 28)
  return out
}

export type Toward = 'site' | 'client'

/** How the pipe between the two tunnels behaves, which a test may change at any time. */
export type Pipe = {
  /** Drops the packet when it returns true. */
  drop: (toward: Toward, packet: Uint8Array) => boolean,
  /** Answers a packet the client sent with this packet instead of carrying it. */
  answer: (packet: Uint8Array) => Uint8Array | undefined,
  /** The client tunnel's `send` returns false and drops when this returns true, as a full queue does. */
  refuse: (packet: Uint8Array) => boolean,
  delayMs: number,
  /** Packets carried each way, and sends the client tunnel refused. */
  counts: { site: number, client: number, refused: number },
}

type Setup = { client?: StackOptions, site?: StackOptions, ports?: number, mtu?: number, carrier?: IpTunnel['carrier'] }

/**
 * The client's stack on a tunnel, and a second stack that plays the internet as `SITE` and `SITE_V6` on a tunnel of
 * its own, joined by a pipe that translates the client's IPv4 address to its public one both ways, as a relay does,
 * and carries IPv6 as it is. The site may listen and bind on any port below the private ones.
 */
export const internet = async (setup: Setup = {}) => {
  const { client: clientOptions, site: siteOptions, ports = 8, mtu = 1500, carrier } = setup
  const pipe: Pipe = {
    drop: () => false,
    answer: () => undefined,
    refuse: () => false,
    delayMs: 0,
    counts: { site: 0, client: 0, refused: 0 },
  }
  const [own, open] = [parseIp(CLIENT)!, parseIp(CLIENT_PUBLIC)!]
  const carry = (toward: Toward, packet: Uint8Array) => {
    if (pipe.drop(toward, packet)) return
    pipe.counts[toward]++
    const moved = toward === 'site' ? translate(packet, 12, own, open) : translate(packet, 16, open, own)
    const target = toward === 'site' ? site : client
    if (pipe.delayMs) setTimeout(() => target.deliver(moved), pipe.delayMs)
    else target.deliver(moved)
  }
  const client = fakeTunnel(
    { id: 1, ipv4: CLIENT, ipv6: CLIENT_V6, mtu, publicIpv4: CLIENT_PUBLIC, firstPort: FIRST_PORT, ports, carrier },
    (packet) => {
      if (pipe.refuse(packet)) {
        pipe.counts.refused++
        return false
      }
      const answer = pipe.answer(packet)
      if (answer) queueMicrotask(() => client.deliver(answer))
      else carry('site', packet)
      return true
    },
  )
  const site = fakeTunnel(
    { id: 2, ipv4: SITE, ipv6: SITE_V6, mtu, publicIpv4: SITE, firstPort: 1, ports: 49151 },
    (packet) => {
      carry('client', packet)
      return true
    },
  )
  const [clientStack, siteStack]: Stack[] = await Promise.all([
    openStack(client.tunnel, { resolver: at(SITE, 53), ...clientOptions }),
    openStack(site.tunnel, siteOptions),
  ])
  return { pipe, client: clientStack, site: siteStack, clientTunnel: client, siteTunnel: site }
}

/** The bytes 0, 1, ... 250, 0, 1, ... up to `length`. */
export const pattern = (length: number) => Uint8Array.from({ length }, (_, at) => at % 251)

/** Everything a stream gives until its end. */
export const readAll = async (readable: ReadableStream<Uint8Array>) => {
  const chunks: Uint8Array[] = []
  for await (const chunk of readable) chunks.push(chunk)
  const all = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.byteLength, 0))
  let offset = 0
  for (const chunk of chunks) {
    all.set(chunk, offset)
    offset += chunk.byteLength
  }
  return all
}

/** A whole DNS answer to `query` with an A or AAAA record for each of `ips`, or no records and the truncated bit. */
export const dnsAnswer = (query: Uint8Array, ips: string[], truncated = false) => {
  const records = truncated ? [] : ips.map((text) => {
    const ip = parseIp(text)!
    return [0xc0, 12, 0, ip.byteLength === 4 ? 1 : 28, 0, 1, 0, 0, 0, 60, 0, ip.byteLength, ...ip]
  })
  const answer = new Uint8Array(query.byteLength + records.flat().length)
  answer.set(query)
  answer.set(records.flat(), query.byteLength)
  answer[2] = 0x81 | (truncated ? 0x02 : 0)
  answer[3] = 0x80
  new DataView(answer.buffer).setUint16(6, records.length)
  return answer
}
