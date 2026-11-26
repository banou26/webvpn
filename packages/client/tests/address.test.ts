import { describe, expect, it } from 'vite-plus/test'

import { dnsAddresses, dnsQuery, formatIp, parseIp } from '../src'

describe('address text', () => {
  it('reads IPv4 and IPv6 and writes them back in their canonical form', () => {
    const cases: [string, number[], string?][] = [
      ['192.0.2.7', [192, 0, 2, 7]],
      ['0.0.0.0', [0, 0, 0, 0]],
      ['::', new Array(16).fill(0)],
      ['::1', [...new Array(15).fill(0), 1]],
      ['2001:db8::7', [0x20, 0x01, 0x0d, 0xb8, ...new Array(11).fill(0), 7]],
      ['2001:DB8:0:0:1:0:0:1', [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1], '2001:db8::1:0:0:1'],
      ['2001:db8:0:1:1:1:1:1', [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]],
      ['::ffff:192.0.2.7', [...new Array(10).fill(0), 0xff, 0xff, 192, 0, 2, 7]],
      ['64:ff9b::192.0.2.7', [0, 0x64, 0xff, 0x9b, ...new Array(8).fill(0), 192, 0, 2, 7], '64:ff9b::c000:207'],
      ['fe80::', [0xfe, 0x80, ...new Array(14).fill(0)]],
    ]
    for (const [text, bytes, canonical = text] of cases) {
      expect(parseIp(text), text).toEqual(Uint8Array.from(bytes))
      expect(formatIp(Uint8Array.from(bytes)), text).toBe(canonical)
    }
  })

  it('refuses what is not an address', () => {
    const refused = [
      '', 'example.com', '192.0.2', '192.0.2.256', '192.0.2.07', '1.2.3.4.5', ':', ':::', '1::2::3', '1:2:3:4:5:6:7',
      '1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7::8', '12345::', 'fe80::1%eth0', '[::1]', '::192.0.2.7:1', '192.0.2.7::',
    ]
    for (const text of refused) expect(parseIp(text), text).toBeUndefined()
    expect(() => formatIp(new Uint8Array(5))).toThrow(TypeError)
  })
})

describe('DNS messages', () => {
  it('ask for the A or AAAA records of a name, with id 0 and recursion desired', () => {
    const name = [7, ...new TextEncoder().encode('example'), 3, ...new TextEncoder().encode('com'), 0]
    expect(dnsQuery('example.com.')).toEqual(Uint8Array.of(0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...name, 0, 1, 0, 1))
    expect(dnsQuery('example.com', 'AAAA').subarray(-4)).toEqual(Uint8Array.of(0, 28, 0, 1))
    expect(() => dnsQuery('a..b')).toThrow(TypeError)
    expect(() => dnsQuery('a'.repeat(64))).toThrow(TypeError)
  })

  it('give the A and AAAA records of an answer, past its question and a CNAME', () => {
    const query = dnsQuery('example.com')
    const answer = Uint8Array.of(
      ...query.subarray(0, 2), 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0, ...query.subarray(12),
      0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12,
      0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7,
      0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16, 0x20, 0x01, 0x0d, 0xb8, ...new Array(11).fill(0), 7,
    )
    expect(dnsAddresses(answer).map(formatIp)).toEqual(['192.0.2.7', '2001:db8::7'])
    expect(dnsAddresses(answer.subarray(0, answer.byteLength - 4)).map(formatIp)).toEqual(['192.0.2.7'])
    expect(dnsAddresses(Uint8Array.of(1, 2))).toEqual([])
  })
})
