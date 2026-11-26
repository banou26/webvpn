---
title: How it works
description: The session to a relay, the streams that carry each socket, the real sockets on the relay, how a relay is chosen, and what each side sees.
---

## The session

A client opens one session to a relay and carries every socket over it.

The session is **WebTransport**, which is HTTP/3 over QUIC, on UDP port 443 of the relay. The client uses a **WebSocket** over TLS on TCP port 8443 instead when:

- the browser has no WebTransport,
- a WebTransport session fails to open, or does not open within 4 seconds, or
- for a minute after a WebTransport session stalled right after it opened.

Both carry the same protocol. When a session ends, every socket on it closes, and the next socket call opens a new session.

### Where the client runs

With [`@fkn/lib`](/docs/using/), the client is not in the app's own page. The library loads a frame of fkn.app, and fkn.app's code opens the session and carries the app's sockets over it. It holds the session in a shared worker where the browser has one, so pages that share fkn.app's storage in a browser share one session.

## The protocol

**Setup.** The relay opens the session's first stream, the control stream, and each side sends a hello on it: the protocol's version and, from the relay, the optional parts it offers, such as listening ports, name lookups and credentials.

**Control frames.** Everything else on the control stream is a frame: a one-byte type, a length, then big-endian fields. The client asks to:

- open a TCP connection to an address, or to a name in a single round trip,
- close or reset a connection,
- open or close a listening port,
- bind, connect, disconnect or close a UDP socket,
- set a socket option, such as `TCP_NODELAY`, keepalive or a buffer size,
- look a name up,
- present a credential, whose meaning the relay's operator defines. The public relays take a signed token that moves the session onto an account's limits.

The relay answers each request under the request's id, with the socket it opened or with an error code and a message, and announces each connection that arrives on a listening port. It numbers sockets in the order they open, and never reuses a number within a session. A frame of a type one side does not know is skipped by its length, or refused under its id, so the protocol can grow.

[The protocol](/docs/protocol/) lists every frame, code and limit.

**Data streams.** Each socket's bytes travel on a stream of its own, so one busy socket does not hold up the others:

- **A TCP connection** gets a bidirectional stream, opened by the relay. It starts with the socket's 4-byte number, then carries the connection's bytes both ways, unchanged.
- **A UDP socket** gets a bidirectional stream too, opened by the relay once the socket is bound. It starts with the socket's number, then carries one frame per datagram, with the datagram's length and the peer's address. When that stream cannot be opened, the socket's datagrams use WebTransport datagrams and a one-way stream instead.

UDP rides streams rather than WebTransport datagrams because Chromium paces datagrams, and both ends queue them in small buffers that drop on a burst, which a protocol such as uTP reads as congestion.

**Over the WebSocket,** the same streams are frames on the one connection: a one-byte kind, a 4-byte stream id, then the payload. Stream 0 is the control stream, and goes ahead of bulk data. The relay announces each new stream with an `OPEN` frame, and the client grants each stream credit for the bytes it can take, so a slow reader on one stream does not stall the rest. A UDP socket there gets a one-way stream from the relay, and the client sends its datagrams in `DATAGRAM` frames.

## The relay opens the real connections

For each socket the relay opens a real operating system socket, from its own address:

- **A TCP connection** is dialed by the relay. Given a name, the relay looks it up and dials the first address, in the same round trip.
- **A UDP socket** is bound on the relay, and its datagrams leave from the relay's address.
- **A listening port** is a port on the relay's address. Each connection to it is announced on the control stream and carried on a new stream.
- **A name** is looked up by the relay. The client sends a whole DNS query, the relay sends it over HTTPS to a public resolver, Cloudflare's 1.1.1.1, and passes the answer back.

A relay does not connect to private or local addresses, or to the relays' own servers, except the ports apps listen on through a relay. Every byte, in both directions, is paced to the [fair use rate](/docs/relays/#fair-use-limits) of the person's address or account, DNS answers included.

## How a relay is chosen

The client reads the relay directory, for the public relays [fkn.app/v1/relays](https://fkn.app/v1/relays), then sends one request to each relay's `/load` address on port 8443. That one round trip measures how far the relay is, over the TCP and TLS path the WebSocket would use, and reads how many sessions it holds.

Each relay's score is its round trip time multiplied by 1 plus how full it is, or by 4 once it is 90% full. The lowest score wins. A relay the directory marks unhealthy or draining is left out.

When a relay cannot be reached, the client tries the next one. A relay whose session ended unexpectedly is set aside for a minute.

An app can [ask for a relay](/docs/using/#choosing-a-relay) for each socket, and a person can [pick one](/docs/relays/#choosing-a-relay) instead of the automatic choice.

## Who sees what

| Who | What they see |
| --- | --- |
| The person's network | An encrypted connection to the relay: its name, its address and how much data passes. Not where the sockets go or what they carry. |
| The relay | The person's IP address, each socket's destination address and port, and how much data passes. It carries the bytes as the app sent them: what the app's protocol encrypts, such as HTTPS, it cannot read. See [what it keeps](/docs/what-the-relay-keeps/). |
| The DNS resolver | The names looked up, asked by the relay's address. |
| The other end | A connection from the relay's address, never the person's. |
