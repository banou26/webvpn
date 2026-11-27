# @webvpn/client

The [WebVPN](https://webvpn.dev) client for a web page or a worker: real TCP connections, listening ports, UDP sockets
and name lookups, through a relay, as Web Streams. It runs over WebTransport, and over a WebSocket where WebTransport
is missing or fails.

## Use

```js
import { connect } from '@webvpn/client'

const session = await connect({ url: 'https://relay.example:4433', webSocketUrl: 'wss://relay.example:8443' })
const socket = await session.tcpConnect({ name: 'example.org', port: 80 })

const writer = socket.writable.getWriter()
await writer.write(new TextEncoder().encode('GET / HTTP/1.0\r\nHost: example.org\r\n\r\n'))
await writer.close()

const reader = socket.readable.getReader()
const decoder = new TextDecoder()
while (true) {
  const { value, done } = await reader.read()
  if (done) break
  console.log(decoder.decode(value))
}
```

[Using it from an app](https://webvpn.dev/docs/using/) is the guide: listening ports, UDP sockets, name lookups,
credentials, and how a session ends. `@webvpn/net` and `@webvpn/dgram` put Node's `net` and `dgram` modules on a
session, for code written for Node.

## What it needs

- A relay to connect to: [run your own](https://webvpn.dev/docs/running-a-relay/).
- A browser with WebTransport or WebSocket. The tests run in Chromium and in Firefox.

Version 0 of the protocol is not stable: a new minor version of this package may change the wire and its own
interfaces.
