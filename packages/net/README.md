# @webvpn/net

Node's `net` module for a web page, with every TCP connection and server on a WebVPN relay through a
`@webvpn/client` session. Code written for Node's `net`, such as a torrent engine or an IRC client, runs in the page
as it is.

## Use

```sh
npm install @webvpn/client @webvpn/net
```

```js
import { connect as openSession } from '@webvpn/client'
import net, { setProvider } from '@webvpn/net'

// the session opens at the first socket; a session already open is taken too
setProvider(() => openSession({ url: 'https://relay.example:4433', webSocketUrl: 'wss://relay.example:8443' }))

const socket = net.connect(6667, 'irc.example')
socket.on('data', (data) => console.log(data.toString()))
socket.write('NICK page\r\n')
```

`createNet(session)` builds a copy of the module of its own, on that session alone.

## Alias `net` to it

With Vite:

```js
export default {
  resolve: { alias: { net: '@webvpn/net', 'node:net': '@webvpn/net' } },
}
```

webpack and esbuild have the same setting, `resolve.alias` and `alias`. The package brings the browser builds of
`stream` and `events` it needs (`readable-stream` and `events`), so the page needs no Node polyfills for it.

## What it does not have

- IPC paths and file descriptors.
- `server.getConnections`, `maxConnections` and `connections`; `BlockList`, `SocketAddress` and `Stream`; the auto
  family selection settings.
- The `lookup` event, and `connect` options other than `host`, `port` and `allowHalfOpen`.
- The relay looks host names up, A records only, and needs its `DNS` feature for them; a server needs its `LISTEN`
  feature.
- A failed connect to a host name names the host in its message, where Node names the address it tried, and has no
  `address`: the relay does not say which address of the name it tried.
- `server.close()` emits `close` once the relay closed the listener, without waiting for the accepted sockets to end.
- `bytesWritten` counts what the relay took, not what waits in the buffer.
- A socket option set before `connect`, or one the relay refuses, emits `error`. `setTypeOfService` keeps the value
  but does not send it.
