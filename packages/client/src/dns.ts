const TYPES = { A: 1, AAAA: 28 } as const

const encoder = new TextEncoder()

/**
 * A whole DNS message asking for the `A` or `AAAA` records of `name`, with recursion desired, as `Session.lookup`
 * and a connect by name send it. The message id is 0, as RFC 8484 asks of a query that may reach a DNS over HTTPS
 * resolver. The name goes as written, so a name outside ASCII must be given in its `xn--` form. Throws `TypeError`
 * for a name DNS cannot carry: an empty label, a label over 63 bytes or a name over 253.
 */
export const dnsQuery = (name: string, type: keyof typeof TYPES = 'A'): Uint8Array => {
  const labels = name.replace(/\.$/, '').split('.').map((label) => encoder.encode(label))
  if (labels.some((label) => !label.byteLength || label.byteLength > 63) || name.replace(/\.$/, '').length > 253) {
    throw new TypeError('the name is not one DNS can carry')
  }
  const length = labels.reduce((total, label) => total + 1 + label.byteLength, 1)
  const message = new Uint8Array(12 + length + 4)
  const view = new DataView(message.buffer)
  view.setUint16(2, 0x0100)
  view.setUint16(4, 1)
  let at = 12
  for (const label of labels) {
    message[at] = label.byteLength
    message.set(label, at + 1)
    at += 1 + label.byteLength
  }
  view.setUint16(at + 1, TYPES[type])
  view.setUint16(at + 3, 1)
  return message
}

// a name is walked by its length bytes and never read, and a pointer always ends one
export const pastName = (message: Uint8Array, at: number) => {
  while (at < message.byteLength) {
    const length = message[at]!
    if (length === 0) return at + 1
    if (length >= 0xc0) return at + 2
    at += 1 + length
  }
  return undefined
}

/**
 * The addresses of the `A` and `AAAA` records in the answer section of a whole DNS message, as `Session.lookup`
 * returns it, in the order the message gives them: 4 bytes for an `A` record, 16 for an `AAAA`. Other records, a
 * `CNAME` among them, are skipped, and a message that ends early gives the records read before its end.
 */
export const dnsAddresses = (message: Uint8Array): Uint8Array[] => {
  if (message.byteLength < 12) return []
  const view = new DataView(message.buffer, message.byteOffset, message.byteLength)
  const addresses: Uint8Array[] = []
  let at: number | undefined = 12
  for (let question = view.getUint16(4); question > 0 && at !== undefined; question--) {
    at = pastName(message, at)
    if (at !== undefined) at += 4
  }
  for (let answer = view.getUint16(6); answer > 0 && at !== undefined; answer--) {
    at = pastName(message, at)
    if (at === undefined || at + 10 > message.byteLength) break
    const [type, length] = [view.getUint16(at), view.getUint16(at + 8)]
    const data = message.subarray(at + 10, at + 10 + length)
    if (data.byteLength < length) break
    if ((type === TYPES.A && length === 4) || (type === TYPES.AAAA && length === 16)) addresses.push(data.slice())
    at += 10 + length
  }
  return addresses
}
