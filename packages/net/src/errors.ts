import { ErrorCode, parseIp } from '@webvpn/client'

// errno and the text libuv gives for each code, on Linux
const ERRORS = {
  EACCES: [-13, 'permission denied'],
  EADDRINUSE: [-98, 'address already in use'],
  EADDRNOTAVAIL: [-99, 'address not available'],
  ENETUNREACH: [-101, 'network is unreachable'],
  ETIMEDOUT: [-110, 'connection timed out'],
  ECONNREFUSED: [-111, 'connection refused'],
  EHOSTUNREACH: [-113, 'host is unreachable'],
} as const

type Code = keyof typeof ERRORS

const CODES: Partial<Record<number, Code>> = {
  [ErrorCode.REFUSED]: 'EACCES',
  [ErrorCode.CONNECTION_REFUSED]: 'ECONNREFUSED',
  [ErrorCode.TIMED_OUT]: 'ETIMEDOUT',
  [ErrorCode.HOST_UNREACHABLE]: 'EHOSTUNREACH',
  [ErrorCode.NETWORK_UNREACHABLE]: 'ENETUNREACH',
  [ErrorCode.ADDRESS_IN_USE]: 'EADDRINUSE',
  [ErrorCode.ADDRESS_NOT_AVAILABLE]: 'EADDRNOTAVAIL',
}

// Node names the unbound local end when the kernel refuses the connect at once: measured for ENETUNREACH, and the
// other three take the same path in Node's net.js
const AT_ONCE = new Set<Code>(['ENETUNREACH', 'EACCES', 'EADDRINUSE', 'EADDRNOTAVAIL'])

/**
 * What a socket fails with when its peer resets the connection: Node's own error for it on Linux (Node 26.12.1
 * against a site that resets, measured 2026-11-11).
 */
const resetError = () => Object.assign(new Error('read ECONNRESET'), { errno: -104, code: 'ECONNRESET', syscall: 'read' })

/** What a socket or a server fails with when its name has no address, as Node 26.12.1 gives it on Linux. */
export const lookupError = (hostname: string) =>
  Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), { errno: -3008, code: 'ENOTFOUND', syscall: 'getaddrinfo', hostname })

/**
 * What a socket fails with when its connect to `host` does, as Node 26.12.1 gives it on Linux (measured
 * 2026-11-15): refused, timed out, no route to the host or its network. For a host name with one address, Node names
 * that address in the message and in `address`, and the name nowhere (measured 2026-11-27). The relay connects to the
 * name's first A record and its refusal does not say which address that was, so the message names the host instead,
 * and `address`, which Node only ever gives an address, is left out.
 */
const connectError = (code: Code, host: string, port: number) => {
  const local = AT_ONCE.has(code) ? ` - Local (${host.includes(':') ? '::' : '0.0.0.0'}:0)` : ''
  return Object.assign(
    new Error(`connect ${code} ${host}:${port}${local}`),
    { errno: ERRORS[code][0], code, syscall: 'connect', ...parseIp(host) ? { address: host } : {}, port },
  )
}

/**
 * What a server fails with when its listen does, as Node 26.12.1 gives it on Linux (measured 2026-11-27): an address
 * in use, a port the system keeps for itself, an address that is not the host's. Node puts `code` first here.
 */
const listenError = (code: Code, address: string, port: number) => Object.assign(
  new Error(`listen ${code}: ${ERRORS[code][1]} ${address}:${port}`),
  { code, errno: ERRORS[code][0], syscall: 'listen', address, port },
)

/**
 * Node's error for a request the relay refused, as a connect to `address` (an address or a host name) or a listen on
 * it, or on the socket's data (`read`). A `WebVpnError` whose code Node has no counterpart for, and any other error,
 * comes back as it is.
 */
export const nodeError = (error: unknown, syscall: 'connect' | 'listen' | 'read', address = '', port = 0) => {
  const { name, code } = (error ?? {}) as { name?: unknown, code?: unknown }
  if (name !== 'WebVpnError' || typeof code !== 'number') return error as Error
  if (code === ErrorCode.CONNECTION_RESET) return resetError()
  if (code === ErrorCode.NAME_NOT_FOUND) return lookupError(address)
  const known = CODES[code]
  if (!known || syscall === 'read') return error as Error
  return syscall === 'listen' ? listenError(known, address, port) : connectError(known, address, port)
}
