import { ErrorCode } from '@webvpn/client'

// errno as Node gives it on Linux
const ERRNOS = { EACCES: -13, EMSGSIZE: -90, EADDRINUSE: -98, EADDRNOTAVAIL: -99 } as const

const CODES: Partial<Record<number, keyof typeof ERRNOS>> = {
  [ErrorCode.REFUSED]: 'EACCES',
  [ErrorCode.ADDRESS_IN_USE]: 'EADDRINUSE',
  [ErrorCode.ADDRESS_NOT_AVAILABLE]: 'EADDRNOTAVAIL',
}

/**
 * What a bind, a connect or a send fails with, as Node 26.12.1 gives it on Linux (measured 2026-11-27): an address in
 * use, a port the system keeps for itself or a peer it refuses, an address that is not the host's, a datagram too
 * big. A send on a connected socket names no address.
 */
export const systemError = (syscall: 'bind' | 'connect' | 'send', code: keyof typeof ERRNOS, address?: string, port?: number) =>
  Object.assign(
    new Error(address === undefined ? `${syscall} ${code}` : `${syscall} ${code} ${address}:${port}`),
    { errno: ERRNOS[code], code, syscall, address, ...port === undefined ? {} : { port } },
  )

/**
 * What a bind, a connect or a send to a name with no address fails with, as Node 26.12.1 gives it on Linux (measured
 * 2026-11-15).
 */
export const lookupError = (hostname: string) =>
  Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), { errno: -3008, code: 'ENOTFOUND', syscall: 'getaddrinfo', hostname })

/**
 * Node's error for a bind or a connect the relay refused. A `WebVpnError` whose code Node has no counterpart for, and
 * any other error, comes back as it is.
 */
export const nodeError = (error: unknown, syscall: 'bind' | 'connect', address: string, port: number) => {
  const { name, code } = (error ?? {}) as { name?: unknown, code?: unknown }
  const known = name === 'WebVpnError' && typeof code === 'number' ? CODES[code] : undefined
  return known ? systemError(syscall, known, address, port) : error as Error
}
