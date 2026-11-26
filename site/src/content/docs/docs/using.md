---
title: Using it from an app
description: Open TCP connections, listen on a port, use UDP and look names up with @fkn/lib.
---

The client library is [`@fkn/lib`](https://www.npmjs.com/package/@fkn/lib). Its socket modules follow Node's, so code written for Node's `net` and `dgram` runs in a page.

```sh
npm install @fkn/lib
```

| Import | What it has |
| --- | --- |
| `@fkn/lib/net` | `connect`, `createConnection`, `createServer`, `Socket` and `Server`, with the events and callbacks of Node's `net`. |
| `@fkn/lib/dgram` | `createSocket` and `Socket`, as in Node's `dgram`. |
| `@fkn/lib/dns` | `lookup`, which returns a promise. |
| `@fkn/lib/http` | `request`, `get` and `createServer`: HTTP/1.1 over `net`. |
| `@fkn/lib` | `relayOf` and `isRelayUnavailable`, for [choosing a relay](#choosing-a-relay). |

The examples use Node's `Buffer`, which a browser bundle has to provide: see [install](https://docs.fkn.dev/start/install/). The full reference, with every option and error, is at [docs.fkn.dev](https://docs.fkn.dev/guides/sockets/).

## Open a TCP connection

```ts
import * as net from '@fkn/lib/net'

const socket = net.connect({ host: 'example.org', port: 80 }, () => {
  socket.write('GET / HTTP/1.0\r\nHost: example.org\r\n\r\n')
})
socket.on('data', (chunk) => console.log(chunk.toString()))
socket.on('error', (error) => console.error(error.message))
```

The callback runs once the relay has opened the connection. A refused connection emits `error` instead.

## Listen on a port

```ts
import * as net from '@fkn/lib/net'

const server = net.createServer((peer) => {
  peer.end('hello\n')
})
server.on('error', (error) => console.error(error.message))
server.listen(0, () => {
  const address = server.address()
  if (address && typeof address === 'object') console.log(address.port)
})
```

The port is a port on the relay's address, and other computers connect to the relay's address on it. Port `0` asks for any free port. A named port is granted only when it is free and allowed, and ports below 1024 never are.

## Use UDP

```ts
import * as dgram from '@fkn/lib/dgram'
import { lookup } from '@fkn/lib/dns'

const socket = dgram.createSocket('udp4')
socket.on('message', (message, rinfo) => console.log(rinfo.address, message))
socket.on('error', (error) => console.error(error.message))

socket.bind(0, async () => {
  const peer = await lookup('example.org', { family: 4 })
  if (peer) socket.send(Buffer.from('ping'), 6881, peer.address)
})
```

A bound socket receives datagrams sent to the relay's address on its port. `connect(port, address)` fixes a peer, after which `send(message)` needs no target.

## Look names up

```ts
import { lookup } from '@fkn/lib/dns'

// [{ address, family }, ...]
const addresses = await lookup('example.org', { all: true })
```

The relay asks the DNS resolver, so the resolver sees the relay's address. `net.connect` and `socket.send` take names too.

## Loopback stays in the browser

A server that listens on all addresses, or on loopback, can also be reached at `127.0.0.1` or `::1` from pages that share its session. Those connections, and UDP datagrams sent the same way, are paired inside the browser and never reach the relay.

## Choosing a relay

Without a choice, sockets go through the relay the client [picked](/docs/how-it-works/#how-a-relay-is-chosen). `net.connect`, `net.createServer` and `dgram.createSocket` also take a `relay` option: `{ id }` for one relay, `{ region }` for any relay of a region, or `{ exclude }` to skip relays. `relayOf` answers which relay a socket or server is on. When no relay can serve the choice, the call fails with an error that `isRelayUnavailable` recognizes.

```ts
import * as net from '@fkn/lib/net'
import { relayOf } from '@fkn/lib'

const server = net.createServer({ relay: { region: 'asia' } }, (peer) => {
  peer.end('hello\n')
})
server.listen(0, () => console.log(relayOf(server))) // 'hk-hkg-001'
```

The relay ids and regions are on [Relays](/docs/relays/).
