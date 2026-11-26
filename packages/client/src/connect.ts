import type { Session } from './session'

import { openSession } from './session'
import { webSocketCarrier } from './websocket'
import { webTransportCarrier } from './webtransport'

const WEBTRANSPORT_TIMEOUT_MS = 4000

/** Where and how `connect` reaches a relay. */
export type ConnectOptions = {
  /** The relay's WebTransport URL, `https://host:port`. */
  url?: string,
  /** The relay's WebSocket URL, `wss://host:port`. */
  webSocketUrl?: string,
  /**
   * `auto`, the default, takes WebTransport when the page has it and `url` is given, and the WebSocket when either
   * is missing or the WebTransport session does not open. The other two take that carrier only.
   */
  transport?: 'auto' | 'webtransport' | 'websocket',
  /** The certificate hashes of a relay with a self-signed certificate, for WebTransport only. */
  serverCertificateHashes?: { algorithm: string, value: BufferSource }[],
  /** How long WebTransport may take to be ready, 4000 ms by default. */
  webTransportTimeoutMs?: number,
  /** Presented right after the hello. `connect` rejects, with the session closed, when the relay refuses it. */
  credential?: Uint8Array,
  /** Names this client in its hello, for a person reading the relay's logs. */
  agent?: string,
}

/**
 * Opens a session with a relay. Rejects with `TypeError` when the options name no URL for the carrier to take, and
 * otherwise with the last carrier's failure: a `WebVpnError` (the relay closed or refused the session, a version
 * that does not suit, a refused credential, a setup that took too long) or the browser's own error.
 */
export const connect = async (options: ConnectOptions): Promise<Session> => {
  const { url, webSocketUrl, transport = 'auto', agent } = options
  let session: Session | undefined
  if (transport === 'webtransport' || (transport === 'auto' && url && typeof WebTransport === 'function')) {
    if (!url) throw new TypeError('WebTransport needs `url`')
    try {
      const { serverCertificateHashes, webTransportTimeoutMs = WEBTRANSPORT_TIMEOUT_MS } = options
      const webTransport = new WebTransport(url, { congestionControl: 'throughput', serverCertificateHashes })
      session = await openSession(await webTransportCarrier(webTransport, webTransportTimeoutMs), { agent })
    } catch (error) {
      if (transport === 'webtransport' || !webSocketUrl) throw error
    }
  }
  if (!session) {
    if (!webSocketUrl) throw new TypeError('the WebSocket needs `webSocketUrl`')
    session = await openSession(await webSocketCarrier(new WebSocket(webSocketUrl)), { agent })
  }
  if (options.credential) {
    const opened = session
    await opened.authenticate(options.credential).catch((error: unknown) => {
      opened.close()
      throw error
    })
  }
  return session
}
