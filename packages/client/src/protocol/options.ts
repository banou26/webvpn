import type { Reader, Writer } from './wire'

/**
 * A TCP socket option a client may set. `unknown` holds the tag of an option this package does not name, which a
 * relay answers with `UNSUPPORTED`.
 */
export type TcpOption =
  | { type: 'noDelay', value: boolean }
  | { type: 'ttl', value: number }
  /** `initialDelaySeconds` is the idle time before the first probe; 0 leaves the system's default. */
  | { type: 'keepAlive', enabled: boolean, initialDelaySeconds: number }
  | { type: 'sendBufferSize', value: number }
  | { type: 'recvBufferSize', value: number }
  | { type: 'unknown', tag: number }

/** A UDP socket option a client may set. `unknown` is as for `TcpOption`. */
export type UdpOption =
  | { type: 'broadcast', value: boolean }
  | { type: 'ttl', value: number }
  | { type: 'multicastTtlV4', value: number }
  | { type: 'multicastLoopV4', value: boolean }
  | { type: 'multicastLoopV6', value: boolean }
  /** 4 bytes each; an `interface` of 0.0.0.0 lets the system pick. */
  | { type: 'addMembershipV4' | 'dropMembershipV4', group: Uint8Array, interface: Uint8Array }
  /** `group` holds 16 bytes; `interface` is an index, 0 for the default interface. */
  | { type: 'addMembershipV6' | 'dropMembershipV6', group: Uint8Array, interface: number }
  | { type: 'sendBufferSize', value: number }
  | { type: 'recvBufferSize', value: number }
  | { type: 'unknown', tag: number }

const sized = (bytes: Uint8Array, length: number) => {
  if (bytes.byteLength !== length) throw new TypeError(`expected ${length} bytes, not ${bytes.byteLength}`)
  return bytes
}

export const putTcpOption = (w: Writer, option: TcpOption) => {
  switch (option.type) {
    case 'noDelay': return w.u8(0).bool(option.value)
    case 'ttl': return w.u8(1).u32(option.value)
    case 'keepAlive': return w.u8(2).bool(option.enabled).u32(option.initialDelaySeconds)
    case 'sendBufferSize': return w.u8(3).u32(option.value)
    case 'recvBufferSize': return w.u8(4).u32(option.value)
    case 'unknown': return w.u8(option.tag)
  }
}

export const readTcpOption = (r: Reader): TcpOption => {
  const tag = r.u8()
  switch (tag) {
    case 0: return { type: 'noDelay', value: r.bool() }
    case 1: return { type: 'ttl', value: r.u32() }
    case 2: return { type: 'keepAlive', enabled: r.bool(), initialDelaySeconds: r.u32() }
    case 3: return { type: 'sendBufferSize', value: r.u32() }
    case 4: return { type: 'recvBufferSize', value: r.u32() }
    default: return { type: 'unknown', tag }
  }
}

export const putUdpOption = (w: Writer, option: UdpOption) => {
  switch (option.type) {
    case 'broadcast': return w.u8(0).bool(option.value)
    case 'ttl': return w.u8(1).u32(option.value)
    case 'multicastTtlV4': return w.u8(2).u32(option.value)
    case 'multicastLoopV4': return w.u8(3).bool(option.value)
    case 'multicastLoopV6': return w.u8(4).bool(option.value)
    case 'addMembershipV4':
    case 'dropMembershipV4':
      return w
        .u8(option.type === 'addMembershipV4' ? 5 : 6)
        .put(sized(option.group, 4))
        .put(sized(option.interface, 4))
    case 'addMembershipV6':
    case 'dropMembershipV6':
      return w
        .u8(option.type === 'addMembershipV6' ? 7 : 8)
        .put(sized(option.group, 16))
        .u32(option.interface)
    case 'sendBufferSize': return w.u8(9).u32(option.value)
    case 'recvBufferSize': return w.u8(10).u32(option.value)
    case 'unknown': return w.u8(option.tag)
  }
}

export const readUdpOption = (r: Reader): UdpOption => {
  const tag = r.u8()
  switch (tag) {
    case 0: return { type: 'broadcast', value: r.bool() }
    case 1: return { type: 'ttl', value: r.u32() }
    case 2: return { type: 'multicastTtlV4', value: r.u32() }
    case 3: return { type: 'multicastLoopV4', value: r.bool() }
    case 4: return { type: 'multicastLoopV6', value: r.bool() }
    case 5:
    case 6:
      return {
        type: tag === 5 ? 'addMembershipV4' : 'dropMembershipV4',
        group: r.take(4).slice(),
        interface: r.take(4).slice(),
      }
    case 7:
    case 8:
      return {
        type: tag === 7 ? 'addMembershipV6' : 'dropMembershipV6',
        group: r.take(16).slice(),
        interface: r.u32(),
      }
    case 9: return { type: 'sendBufferSize', value: r.u32() }
    case 10: return { type: 'recvBufferSize', value: r.u32() }
    default: return { type: 'unknown', tag }
  }
}
