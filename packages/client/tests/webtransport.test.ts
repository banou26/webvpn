import { describe, expect, it } from 'vite-plus/test'

import { CloseCode } from '../src/protocol'
import { webTransportCarrier } from '../src/webtransport'

/** A WebTransport that is ready at once and ends as `closed` settles. */
const fakeWebTransport = (closed: Promise<WebTransportCloseInfo>) => ({
  ready: Promise.resolve(),
  closed,
  incomingBidirectionalStreams: new ReadableStream(),
  incomingUnidirectionalStreams: new ReadableStream(),
  datagrams: { readable: new ReadableStream(), createWritable: () => new WritableStream() },
  close: () => {},
  createUnidirectionalStream: async () => new WritableStream(),
}) as unknown as WebTransport

describe('the WebTransport carrier', () => {
  it('reads the session close code of a session close, and LOST from an end that carried none', async () => {
    const closing = await webTransportCarrier(fakeWebTransport(Promise.resolve({ closeCode: 3, reason: 'full' })), 1000)
    expect(await closing.closed).toEqual({ code: CloseCode.SESSION_LIMIT, reason: 'full' })
    const lost = await webTransportCarrier(fakeWebTransport(Promise.reject(new Error('Connection lost.'))), 1000)
    expect(await lost.closed).toEqual({ code: CloseCode.LOST, reason: 'Connection lost.' })
  })
})
