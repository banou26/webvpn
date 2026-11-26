/** What a relay offers, as the bits of a hello's `features`. A client sends a request only when its bit is set. */
export const Feature = {
  /** `tcpListen` and `tcpUnlisten`. */
  LISTEN: 1 << 0,
  /** `dnsQuery` and `tcpConnectName`. */
  DNS: 1 << 1,
  /** `auth` and `authClear`. */
  AUTH: 1 << 2,
  /** Socket requests are answered `AUTH_REQUIRED` until an `auth` succeeded. */
  AUTH_REQUIRED: 1 << 3,
} as const

/** Why a request failed, as an `error` reply carries it. A code not named here is treated as `OTHER`. */
export const ErrorCode = {
  /** The relay does not know the request or the option, or has the feature off. */
  UNSUPPORTED: 1,
  /** The relay's policy refuses this target, port or option. */
  REFUSED: 2,
  /** A limit is reached; the same request may pass later. */
  CAPACITY: 3,
  /** The socket has too many requests waiting; nothing was applied. */
  BUSY: 4,
  AUTH_REQUIRED: 5,
  /** The credential was not accepted; the session is as it was. */
  AUTH_FAILED: 6,
  UNKNOWN_SOCKET: 7,
  CONNECTION_REFUSED: 16,
  TIMED_OUT: 17,
  HOST_UNREACHABLE: 18,
  NETWORK_UNREACHABLE: 19,
  CONNECTION_RESET: 20,
  ADDRESS_IN_USE: 21,
  ADDRESS_NOT_AVAILABLE: 22,
  /** The name has no address. */
  NAME_NOT_FOUND: 23,
  /** The resolver did not answer. */
  LOOKUP_FAILED: 24,
  /** The message says what happened. */
  OTHER: 0xffff,
} as const

/** The code a session is closed with. */
export const CloseCode = {
  NORMAL: 0,
  /** A frame could not be read, or setup did not finish in time. */
  PROTOCOL_ERROR: 1,
  VERSION_MISMATCH: 2,
  SESSION_LIMIT: 3,
  /** The relay is stopping; another session may be opened at once. */
  RESTARTING: 4,
} as const

/** The WebSocket close code that carries a session close code. */
export const websocketCloseCode = (code: number) => 4000 + code

/** The code the relay resets its side of a socket's stream with. */
export const ResetCode = {
  /** The client closed the socket. */
  CLOSED: 0,
  /** The peer reset the connection. */
  PEER_RESET: 1,
} as const
