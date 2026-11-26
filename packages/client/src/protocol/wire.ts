/** Bytes that are not laid out as the protocol says. It ends the session. */
export class ProtocolError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ProtocolError'
  }
}

/** A socket address. `ip` holds 4 bytes for IPv4 or 16 for IPv6. */
export type Address = { ip: Uint8Array, port: number }

export const addressFamily = (ip: Uint8Array) => {
  if (ip.byteLength === 4) return 0
  if (ip.byteLength === 16) return 1
  throw new TypeError(`an address holds 4 or 16 bytes, not ${ip.byteLength}`)
}

/** Reads fields off `bytes` in order. `take` and `rest` return views into `bytes`, not copies. */
export const reader = (bytes: Uint8Array) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  let at = 0
  const advance = (length: number) => {
    if (at + length > bytes.byteLength) throw new ProtocolError('a body ends before its fields do')
    at += length
    return at - length
  }
  const take = (length: number) => {
    const from = advance(length)
    return bytes.subarray(from, from + length)
  }
  const u8 = () => view.getUint8(advance(1))
  const u16 = () => view.getUint16(advance(2))
  const optionalAddress = (): Address | undefined => {
    const family = u8()
    if (family === 2) return undefined
    if (family > 2) throw new ProtocolError('unknown address family')
    return { ip: take(family === 0 ? 4 : 16).slice(), port: u16() }
  }
  return {
    u8,
    u16,
    u32: () => view.getUint32(advance(4)),
    bool: () => u8() !== 0,
    take,
    rest: () => take(bytes.byteLength - at),
    left: () => bytes.byteLength - at,
    optionalAddress,
    address: () => {
      const address = optionalAddress()
      if (!address) throw new ProtocolError('an address is required here')
      return address
    },
  }
}

export type Reader = ReturnType<typeof reader>

export type Writer = {
  u8(value: number): Writer
  bool(value: boolean): Writer
  u16(value: number): Writer
  u32(value: number): Writer
  put(bytes: Uint8Array): Writer
  address(address: Address | undefined): Writer
  setU32(at: number, value: number): Writer
  length(): number
  done(): Uint8Array
}

export const writer = (): Writer => {
  let bytes = new Uint8Array(64)
  let view = new DataView(bytes.buffer)
  let length = 0
  // returns the offset before anything touches `view`, which a growth replaces
  const advance = (more: number) => {
    if (length + more > bytes.byteLength) {
      const grown = new Uint8Array(Math.max(bytes.byteLength * 2, length + more))
      grown.set(bytes.subarray(0, length))
      bytes = grown
      view = new DataView(grown.buffer)
    }
    length += more
    return length - more
  }
  const self: Writer = {
    u8: (value) => {
      const at = advance(1)
      view.setUint8(at, value)
      return self
    },
    bool: (value) => self.u8(value ? 1 : 0),
    u16: (value) => {
      const at = advance(2)
      view.setUint16(at, value)
      return self
    },
    u32: (value) => {
      const at = advance(4)
      view.setUint32(at, value)
      return self
    },
    put: (source) => {
      const at = advance(source.byteLength)
      bytes.set(source, at)
      return self
    },
    address: (address) => {
      if (!address) return self.u8(2)
      return self.u8(addressFamily(address.ip)).put(address.ip).u16(address.port)
    },
    setU32: (at, value) => {
      view.setUint32(at, value)
      return self
    },
    length: () => length,
    done: () => bytes.slice(0, length),
  }
  return self
}
