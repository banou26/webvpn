---
title: How it works
description: The session to a relay, the streams that carry each socket, the real sockets on the relay, and what each side sees.
---

## The session

A client opens one session to a relay and carries every socket over it.

The session is **WebTransport**, which is HTTP/3 over QUIC, or a **WebSocket** over TLS where WebTransport is missing or does not open. [`webvpnd`](/docs/running-a-relay/#ports) takes WebTransport on UDP port 4433 and the WebSocket on TCP port 8443 by default. `@webvpn/client` takes the WebSocket when:

- the browser has no WebTransport, or the page gave no WebTransport URL, or
- the WebTransport session fails to open, or is not ready within 4 seconds by default.

Both carry the same protocol. When a session ends, every socket on it closes.

### Where the client runs

`@webvpn/client` runs in the page or the worker that calls `connect`, and the session it opens belongs to that page or worker. Two pages that each call `connect` hold two sessions. Nothing is shared between them, and no session outlives its page.

## The protocol

**Setup.** The relay opens the session's first stream, the control stream, and writes its hello: the protocol's version, the optional parts it offers, and the name of its implementation for a person. The optional parts are listening ports, name lookups and credentials, and the hello says whether the relay requires a credential. The client answers with its own hello. A side whose peer's version does not suit it closes the session with `VERSION_MISMATCH`. A relay that turns a client away writes a `Bye` instead of its hello.

**Control frames.** Everything else on the control stream is a frame: a one-byte type, a length, then big-endian fields. The client asks to:

- open a TCP connection to an address, or to a name in a single round trip,
- close or reset a connection,
- open or close a listening port,
- bind, connect, disconnect or close a UDP socket,
- set a socket option, such as `TCP_NODELAY`, keepalive or a buffer size,
- look a name up,
- present a credential, or give it up.

The relay answers each request under the request's id, with the socket it opened or with an error code and a message, and announces each connection that arrives on a listening port. It numbers sockets in the order they open, and never reuses a number within a session. A frame of a type one side does not know is skipped by its length, or refused under its id, so the protocol can grow.

**Credentials.** A credential is bytes whose meaning the relay's operator defines. The client may present one at any time, and again later, for example a renewed one. A refused credential leaves the session as it was. A relay that requires a credential refuses socket requests and lookups with `AUTH_REQUIRED` until the client has presented one. `webvpnd` takes the credentials listed in [`WEBVPN_CREDENTIALS`](/docs/running-a-relay/#credentials).

**Draining and closing.** A relay that is about to stop sends `Draining` once. The session keeps its sockets, and the client opens new sockets on a new session. Before the relay closes a session on its own, it sends a `Bye` on the control stream, with a close code and a reason for a person, such as `RESTARTING` once it stops. The client reads the code from the `Bye`, since a browser shows a page no code of a QUIC connection's close. Over the WebSocket, the relay also closes with close code 4000 plus the session's code.

[The protocol](/docs/protocol/) lists every frame, code and limit.

**Data streams.** Each socket's bytes travel on a stream of its own, so one busy socket does not hold up the others:

- **A TCP connection** gets a bidirectional stream, opened by the relay. It starts with the socket's 4-byte number, then carries the connection's bytes both ways, unchanged.
- **A UDP socket** gets a bidirectional stream too, opened by the relay once the socket is bound. It starts with the socket's number, then carries one frame per datagram, with the datagram's length and the peer's address. When that stream cannot be opened, the socket's datagrams use WebTransport datagrams and a one-way stream instead.

UDP rides streams rather than WebTransport datagrams because Chromium paces datagrams, and both ends queue them in small buffers that drop on a burst, which a protocol such as uTP reads as congestion.

**Over the WebSocket,** the same streams are frames on the one connection: a one-byte kind, a 4-byte stream id, then the payload. Stream 0 is the control stream, and goes ahead of bulk data. The relay announces each new stream with an `OPEN` frame, and the client grants each stream credit for the bytes it can take, so a slow reader on one stream does not stall the rest. A UDP socket there gets a one-way stream from the relay, and the client sends its datagrams in `DATAGRAM` frames.

## The relay opens the real connections

For each socket the relay opens a real operating system socket, from its own address:

- **A TCP connection** is dialed by the relay. Given a name, the relay looks it up and dials its first IPv4 address, in the same round trip.
- **A UDP socket** is bound on the relay, and its datagrams leave from the relay's address.
- **A listening port** is a port on the relay's address. Each connection to it is announced on the control stream and carried on a new stream.
- **A name** is looked up by the relay. The client sends a whole DNS query, the relay sends it over HTTPS to the resolver its operator set, and passes the whole answer back. A relay with no resolver set looks no name up.

The relay's policy decides which addresses a session may reach and which ports it may bind, and may pace and count its bytes. The default rules of `webvpnd` reach public addresses only, bind ports from 1024 up, and neither pace nor count: see [what the default rules allow](/docs/running-a-relay/#what-the-default-rules-allow). The public relays pace each person to their [fair use limits](/docs/relays/#fair-use-limits).

## Who sees what

| Who | What they see |
| --- | --- |
| The person's network | An encrypted connection to the relay: its name, its address and how much data passes. Not where the sockets go or what they carry. |
| The relay | The person's IP address, each socket's destination address and port, and how much data passes. It carries the bytes as the app sent them: what the app's protocol encrypts, such as HTTPS, it cannot read. [What the relay keeps](/docs/what-the-relay-keeps/) says what the public relays keep. |
| The DNS resolver | The names looked up, asked by the relay's address. |
| The other end | A connection from the relay's address, never the person's. |
