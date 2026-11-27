---
title: What WebVPN is
description: WebVPN is a protocol and a relay that give a browser app TCP connections, UDP sockets, listening ports and name lookups.
---

A web page can fetch and open WebSockets, but it cannot dial a TCP port, send a UDP datagram or wait for another computer to connect to it. WebVPN gives it those sockets. The page speaks the WebVPN protocol to a relay over one WebTransport session, or over a WebSocket where WebTransport is not available, and the relay opens the real sockets for it.

## What an app can do with it

- **Open TCP connections** to public addresses and ports.
- **Use UDP sockets:** bind one, send and receive datagrams, and connect it to a peer.
- **Listen on a port.** Other computers connect to the relay's address on that port, and each connection arrives in the app.
- **Look names up.** The relay asks its DNS resolver, so the resolver sees the relay and not the person.
- **Carry IP packets** through a tunnel, for a program that brings its own network stack, on a relay that offers tunnels.

## The parts

- **The protocol:** small binary control frames on one stream, and a stream of its own for each socket. See [how it works](/docs/how-it-works/), and [the protocol](/docs/protocol/) for every frame.
- **The relay:** a server written in Rust that holds the sessions and opens an operating system socket for each socket an app opens. [`webvpnd`](/docs/running-a-relay/) runs it as a program, and the `webvpn-server` library [embeds it](/docs/embedding/) in a program of your own, under a policy of your own.
- **The client:** [`@webvpn/client`](/docs/using/) opens a session with a relay, and gives a page TCP connections, listening ports, UDP sockets and name lookups as Web Streams. `@webvpn/net` and `@webvpn/dgram` put Node's `net` and `dgram` modules on a session, so code written for Node, such as a torrent engine or an IRC client, can run in a page.

## On this site

- [How it works](/docs/how-it-works/): the session, the streams, the real sockets, and who sees what.
- [The protocol](/docs/protocol/): every frame, code and carrier, version 0.1.
- [Using it from an app](/docs/using/): the session, TCP, listening ports, UDP and lookups with `@webvpn/client`, and Node's `net` and `dgram`.
- [Running a relay](/docs/running-a-relay/): host your own relay with `webvpnd`, its ports, certificate and settings.
- [Embedding the relay](/docs/embedding/): the relay inside a Rust program, under a policy of your own.

## Who makes it

WebVPN is made by Horion for [FKN](https://fkn.app), which runs public relays. The source is on [GitHub](https://github.com/banou26/webvpn), under the MIT license.
