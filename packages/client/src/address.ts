const parseV4 = (text: string) => {
  const parts = text.split('.')
  if (parts.length !== 4) return undefined
  const bytes = new Uint8Array(4)
  for (const [at, part] of parts.entries()) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part) || Number(part) > 255) return undefined
    bytes[at] = Number(part)
  }
  return bytes
}

// the groups of one side of `::`, where only the very last part may spell IPv4
const parseGroups = (text: string, last: boolean) => {
  if (!text) return []
  const groups: number[] = []
  const parts = text.split(':')
  for (const [at, part] of parts.entries()) {
    if (last && at === parts.length - 1 && part.includes('.')) {
      const v4 = parseV4(part)
      if (!v4) return undefined
      groups.push(v4[0]! << 8 | v4[1]!, v4[2]! << 8 | v4[3]!)
    } else if (/^[0-9a-f]{1,4}$/i.test(part)) {
      groups.push(parseInt(part, 16))
    } else {
      return undefined
    }
  }
  return groups
}

const parseV6 = (text: string) => {
  const halves = text.split('::')
  if (halves.length > 2) return undefined
  const head = parseGroups(halves[0]!, halves.length === 1)
  const tail = halves.length === 2 ? parseGroups(halves[1]!, true) : []
  if (!head || !tail) return undefined
  const missing = 8 - head.length - tail.length
  if (halves.length === 1 ? missing !== 0 : missing < 1) return undefined
  const bytes = new Uint8Array(16)
  const view = new DataView(bytes.buffer)
  head.forEach((group, at) => view.setUint16(at * 2, group))
  tail.forEach((group, at) => view.setUint16((8 - tail.length + at) * 2, group))
  return bytes
}

/**
 * The bytes of an IPv4 address in dotted decimal (`192.0.2.7`, 4 bytes) or of an IPv6 address in RFC 4291 text
 * (`2001:db8::7`, `::ffff:192.0.2.7`, 16 bytes), as an `Address` holds them. `undefined` for anything else: a name,
 * brackets, a port, a zone (`%eth0`) or an IPv4 part with a leading zero.
 */
export const parseIp = (text: string): Uint8Array | undefined => parseV4(text) ?? parseV6(text)

/**
 * The text of an address's 4 or 16 bytes: dotted decimal for IPv4, and for IPv6 the RFC 5952 form, in lower case
 * with the longest run of zero groups shortened to `::` and an IPv4-mapped address ending in dotted decimal.
 * Throws `TypeError` for any other length.
 */
export const formatIp = (ip: Uint8Array): string => {
  if (ip.byteLength === 4) return ip.join('.')
  if (ip.byteLength !== 16) throw new TypeError(`an address holds 4 or 16 bytes, not ${ip.byteLength}`)
  const view = new DataView(ip.buffer, ip.byteOffset, 16)
  const groups = Array.from({ length: 8 }, (_, at) => view.getUint16(at * 2))
  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
    return `::ffff:${ip.subarray(12).join('.')}`
  }
  let [start, length] = [-1, 1]
  for (let at = 0; at < 8; at++) {
    let end = at
    while (end < 8 && groups[end] === 0) end++
    if (end - at > length) [start, length] = [at, end - at]
  }
  const hex = (part: number[]) => part.map((group) => group.toString(16)).join(':')
  if (start < 0) return hex(groups)
  return `${hex(groups.slice(0, start))}::${hex(groups.slice(start + length))}`
}
