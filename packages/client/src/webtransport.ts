import type { Carrier, CloseInfo, Duplex } from './context'

import { createWritable, setOutgoingMaxBufferedDatagrams } from '@banou/ponyfill/webtransport'

import { noop, within } from './context'
import { CloseCode, ErrorCode } from './protocol'

// Chromium's default of 1 makes each awaited datagram write wait a task turn: on a busy event loop 2,000 writes took
// 2.0 s, and about 40 ms at 256 (measured 2026-10-11)
const OUTGOING_DATAGRAMS = 256
const DATAGRAM_MAX_AGE_MS = 600
// datagrams waiting past the browser's own queue, beyond which a send is dropped
const DATAGRAM_BACKLOG = 4096

/**
 * The carrier of a WebTransport session, `transport` made by the caller just before: its first incoming stream must
 * be read before anything is awaited. Rejects, with the transport closed, when it is not ready in `readyTimeoutMs`.
 */
export const webTransportCarrier = async (transport: WebTransport, readyTimeoutMs: number): Promise<Carrier> => {
  // Read before `ready`, never after it. Firefox before 153 and ESR 140 (bug 2046262) never settle a read that finds
  // a stream already queued, so a control stream landing ahead of this read stopped every stream of the session:
  // through a page on Firefox 151, 2 session starts in 20 hung, 22 in 40 with the browser short of CPU, and none of
  // 40 read this way; Firefox 158 hung on 0 of 60 (2026-10-30). A read waiting when a stream lands is not affected,
  // and the next read is in place first, since the relay opens those streams only once this client asks.
  const bidi = transport.incomingBidirectionalStreams.getReader() as ReadableStreamDefaultReader<Duplex>
  let first: Promise<ReadableStreamReadResult<Duplex>> | undefined = bidi.read()
  first.catch(noop)

  let settle!: (info: CloseInfo) => void
  const closed = new Promise<CloseInfo>((resolve) => { settle = resolve })
  // A relay's QUIC close rejects with no code (Chromium 156: "Connection lost."), which is why the relay says `bye`
  transport.closed.then(
    (info) => settle({ code: info.closeCode ?? CloseCode.LOST, reason: info.reason ?? '' }),
    (error: unknown) => settle({ code: CloseCode.LOST, reason: error instanceof Error ? error.message : '' }),
  )
  const close = (code: number, reason: string) => {
    settle({ code, reason })
    try {
      transport.close({ closeCode: code, reason })
    } catch {}
  }

  const message = `WebTransport was not ready in ${readyTimeoutMs} ms`
  await within(transport.ready, readyTimeoutMs, ErrorCode.TIMED_OUT, message).catch((error: unknown) => {
    close(CloseCode.PROTOCOL_ERROR, 'the session did not open')
    throw error
  })
  try {
    transport.datagrams.outgoingMaxAge = DATAGRAM_MAX_AGE_MS
    setOutgoingMaxBufferedDatagrams(transport.datagrams, OUTGOING_DATAGRAMS)
  } catch {}
  const datagrams = createWritable(transport.datagrams).getWriter()

  return {
    kind: 'webtransport',
    incoming: new ReadableStream<Duplex>({
      pull: async (controller) => {
        const { value, done } = await (first ?? bidi.read())
        first = undefined
        if (done) controller.close()
        else controller.enqueue(value)
      },
      cancel: (reason) => bidi.cancel(reason),
    }, { highWaterMark: 0 }),
    incomingUni: transport.incomingUnidirectionalStreams as ReadableStream<ReadableStream<Uint8Array>>,
    datagrams: transport.datagrams.readable as ReadableStream<Uint8Array>,
    sendDatagram: (packet) => {
      if ((datagrams.desiredSize ?? 0) > -DATAGRAM_BACKLOG) datagrams.write(packet).catch(noop)
    },
    openUni: () => transport.createUnidirectionalStream(),
    closed,
    close,
  }
}
