# @webvpn/dgram

Node's `dgram` module for a web page, with every UDP socket on a WebVPN relay through a `@webvpn/client` session.
Code written for Node's `dgram`, such as a DHT or a tracker client, runs in the page as it is.

## Use

```sh
npm install @webvpn/client @webvpn/dgram
```

```js
import { connect as openSession } from '@webvpn/client'
import dgram, { setProvider } from '@webvpn/dgram'

// the session opens at the first socket; a session already open is taken too
setProvider(() => openSession({ url: 'https://relay.example:4433', webSocketUrl: 'wss://relay.example:8443' }))

const socket = dgram.createSocket('udp4')
socket.on('message', (message, remote) => console.log(remote.address, message.toString()))
socket.send('ping', 6881, 'router.example')
```

`createDgram(session)` builds a copy of the module of its own, on that session alone.

## Alias `dgram` to it

With Vite:

```js
export default {
  resolve: { alias: { dgram: '@webvpn/dgram', 'node:dgram': '@webvpn/dgram' } },
}
```

webpack and esbuild have the same setting, `resolve.alias` and `alias`. The package brings the browser builds of
`buffer` and `events` it needs, so the page needs no Node polyfills for it.

## What it does not have

- The `reuseAddr`, `ipv6Only`, buffer size, `lookup` and `signal` options of `createSocket`.
- `setMulticastInterface` and the source specific memberships, which do nothing: the relay has no option for them.
- Host names are looked up through the relay (A records for `udp4`, AAAA for `udp6`), which needs its `DNS` feature.
- `close` is emitted once the relay closed the socket. The relay closing a socket on its own, or the session ending,
  emits `error` when there is a listener for it, then `close`.
- A socket option set before `bind`, or one the relay refuses, emits `error`. The send queue getters answer 0, and the
  buffer size getters the last value set.
