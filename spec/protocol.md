# WebVPN protocol, version 0.1

WebVPN gives a client real TCP and UDP sockets through a relay. The client asks for a socket on a control stream, the
relay opens the operating system socket, and the socket's bytes travel on a stream of their own.

Version 0 is not stable: the wire may change between minor versions, and peers need the same minor. Every integer is
big-endian. A boolean is one byte, 0 for false and any other value for true.

## Session

A session is one WebTransport session, or one WebSocket connection carrying the [mux](#websocket-mux). The relay
opens every stream. The first bidirectional stream it opens is the control stream.

1. The relay writes `Hello`.
2. The client reads it. If the version does not suit it, it closes the session with `VERSION_MISMATCH`.
3. The client writes `Hello` as its first frame. A relay that the version does not suit closes with
   `VERSION_MISMATCH`.
4. Requests and replies follow, in any order and interleaved.

Either side may close the session at any time. Closing it closes every socket it holds.

## Control frames

```
[u8 type][u32 length][body: length bytes]
```

- A frame toward the relay holds at most 4096 body bytes, a frame toward the client at most 131072. A longer one
  ends the session with `PROTOCOL_ERROR`.
- A receiver ignores bytes that follow the fields it knows, so a later version may append fields.
- Every request body starts with `id u32`, chosen by the client and unique among its unanswered requests. Every reply
  starts with the id it answers. A relay answers a request type it does not know with `Error` and `UNSUPPORTED`.
- A client skips a relay frame whose type it does not know.

### Addresses

| Name | Layout |
| --- | --- |
| `Address` | `u8 family`, then `0`: 4 address bytes and `u16 port`, or `1`: 16 address bytes and `u16 port` |
| `OptionalAddress` | an `Address`, or `u8 family` = `2` and nothing after it |

### Hello

Type `0x00` in both directions.

| Field | Type | Meaning |
| --- | --- | --- |
| `magic` | 4 bytes | `WVPN` |
| `major`, `minor` | `u8`, `u8` | the version, `0`, `1` |
| `features` | `u32` | a bit set; a client sends 0 |
| `agent` | the rest, UTF-8, at most 255 bytes | names the implementation for a person; nothing branches on it |

Feature bits a relay sets:

| Bit | Name | The relay takes |
| --- | --- | --- |
| 0 | `LISTEN` | `TcpListen`, `TcpUnlisten` |
| 1 | `DNS` | `DnsQuery`, `TcpConnectName` |
| 2 | `AUTH` | `Auth`, `AuthClear` |
| 3 | `AUTH_REQUIRED` | no socket request until an `Auth` succeeded; it answers `AUTH_REQUIRED` before that |

A client sends a request only when the relay set its bit. Unknown bits are ignored.

### Requests, client to relay

| Type | Name | Body after `id u32` | Answered by |
| --- | --- | --- | --- |
| `0x01` | `Auth` | `credential`, the rest | `Ok` |
| `0x02` | `AuthClear` | nothing | `Ok` |
| `0x10` | `TcpConnect` | `remote Address` | `Socket` |
| `0x11` | `TcpConnectName` | `port u16`, `query`, the rest: a whole DNS message asking for A records | `Socket` |
| `0x12` | `TcpClose` | `socket u32` | `Ok` |
| `0x13` | `TcpReset` | `socket u32` | `Ok` |
| `0x14` | `TcpSetOption` | `socket u32`, `TcpOption` | `Ok` |
| `0x20` | `TcpListen` | `local Address` | `Socket` |
| `0x21` | `TcpUnlisten` | `socket u32` | `Ok` |
| `0x30` | `UdpBind` | `local Address` | `Socket` |
| `0x31` | `UdpClose` | `socket u32` | `Ok` |
| `0x32` | `UdpConnect` | `socket u32`, `remote Address` | `Ok` |
| `0x33` | `UdpDisconnect` | `socket u32` | `Ok` |
| `0x34` | `UdpSetOption` | `socket u32`, `UdpOption` | `Ok` |
| `0x40` | `DnsQuery` | `query`, the rest: a whole DNS message | `DnsAnswer` |

Any request may be answered by `Error` instead.

### Replies and notices, relay to client

| Type | Name | Body |
| --- | --- | --- |
| `0x01` | `Ok` | `id u32` |
| `0x02` | `Error` | `id u32`, `code u16`, `message`, the rest, UTF-8, for a person |
| `0x03` | `Socket` | `id u32`, `socket u32`, `local Address`, `remote OptionalAddress` |
| `0x04` | `DnsAnswer` | `id u32`, `answer`, the rest: the resolver's whole DNS message |
| `0x10` | `Accepted` | `listener u32`, `socket u32`, `local Address`, `remote Address` |
| `0x11` | `AcceptRefused` | `listener u32`, `code u16`, `remote Address` |
| `0x20` | `Draining` | nothing |

### Error codes

| Code | Name | Meaning |
| --- | --- | --- |
| 1 | `UNSUPPORTED` | the relay does not know the request, the option, or has the feature off |
| 2 | `REFUSED` | the relay's policy refuses this target, port or option |
| 3 | `CAPACITY` | a limit is reached; the same request may pass later |
| 4 | `BUSY` | the socket has too many requests waiting; nothing was applied |
| 5 | `AUTH_REQUIRED` | the relay takes this only after an `Auth` |
| 6 | `AUTH_FAILED` | the credential was not accepted; the session is as it was |
| 7 | `UNKNOWN_SOCKET` | no open socket has this id |
| 8 | `NO_STREAM` | the relay could not open the socket's stream in time; the session has no room for more streams, and a new session has |
| 16 | `CONNECTION_REFUSED` | the peer refused the connection |
| 17 | `TIMED_OUT` | the peer did not answer in time |
| 18 | `HOST_UNREACHABLE` | no route to the host |
| 19 | `NETWORK_UNREACHABLE` | no route to the network |
| 20 | `CONNECTION_RESET` | the peer reset the connection |
| 21 | `ADDRESS_IN_USE` | the local address is taken |
| 22 | `ADDRESS_NOT_AVAILABLE` | the relay cannot bind the local address |
| 23 | `NAME_NOT_FOUND` | the name has no address |
| 24 | `LOOKUP_FAILED` | the resolver did not answer |
| 65535 | `OTHER` | the message says what happened |

A client keeps a code it does not know and treats it as `OTHER`.

## Authentication

A credential is opaque to the protocol: the relay's operator defines its bytes and what it grants. A client may send
`Auth` at any time and again later, for example with a renewed credential. `Ok` means the session now carries that
identity. `Error` leaves the session exactly as it was. `AuthClear` returns the session to no identity.

## Sockets

The relay names each socket with a `u32` id. Ids rise through a session and are never used twice, and TCP sockets,
listeners and UDP sockets share them. A relay that runs out of ids refuses new sockets with `CAPACITY`.

For every TCP socket the relay opens one bidirectional stream whose first four bytes are the socket id. The stream and
the reply that names the socket may arrive in either order, so a client holds a stream whose socket it does not know
yet.

### TCP

- `TcpConnect` connects to an address. `TcpConnectName` connects to the first A record the relay's resolver answers
  for the query, in one round trip.
- After the id, the stream carries the connection's bytes in both directions.
- The client finishing its side of the stream is a half close toward the peer. The peer's half close finishes the
  relay's side.
- A peer that resets the connection makes the relay reset its side of the stream with code 1.
- `TcpClose` ends the socket in order. `TcpReset` ends it with a reset toward the peer and drops what was not sent.
  Both are answered `Ok`, also for a socket that is already gone, and the relay then ends its side of the stream:
  over WebTransport with a reset of code 0, over the mux with `FIN`.

| `TcpOption` tag | Name | Value |
| --- | --- | --- |
| 0 | `NoDelay` | boolean |
| 1 | `Ttl` | `u32` |
| 2 | `KeepAlive` | boolean, then `u32` seconds idle before the first probe, 0 for the system's default |
| 3 | `SendBufferSize` | `u32` bytes |
| 4 | `RecvBufferSize` | `u32` bytes |

### TCP listeners

`TcpListen` binds as a BSD socket does: port 0 takes a free port, any other port is bound exactly or refused. `Socket`
carries the bound address and no remote address. For each connection the listener accepts, the relay sends `Accepted`
and opens that socket's stream. A connection the relay had to turn away is told with `AcceptRefused`.

### UDP

`UdpBind` binds as `TcpListen` does. `UdpConnect` fixes the peer, `UdpDisconnect` clears it, and both are answered
`Ok`. `UdpClose` ends the socket.

A datagram travels as a `UdpPacket`:

| Field | Type | Meaning |
| --- | --- | --- |
| `socket` | `u32` | the socket it belongs to |
| `remote` | `OptionalAddress` | toward the relay: where to send it, none on a connected socket. Toward the client: where it came from |
| `length` | `u32` | at most 65536 |
| `data` | `length` bytes | the payload |

A stream that carries datagrams starts with the socket id and then repeats `[u32 length][UdpPacket]`.

| `UdpOption` tag | Name | Value |
| --- | --- | --- |
| 0 | `Broadcast` | boolean |
| 1 | `Ttl` | `u32` |
| 2 | `MulticastTtlV4` | `u32` |
| 3 | `MulticastLoopV4` | boolean |
| 4 | `MulticastLoopV6` | boolean |
| 5, 6 | `AddMembershipV4`, `DropMembershipV4` | 4 group bytes, 4 interface bytes, `0.0.0.0` for any |
| 7, 8 | `AddMembershipV6`, `DropMembershipV6` | 16 group bytes, `u32` interface index, 0 for the default |
| 9 | `SendBufferSize` | `u32` bytes |
| 10 | `RecvBufferSize` | `u32` bytes |

### UDP carriers over WebTransport

1. After `Socket`, the relay opens one bidirectional stream for the socket. Datagrams toward the client travel on the
   relay's side, datagrams toward the relay on the client's side, each side starting with the socket id.
2. If the relay cannot open that stream within 5 seconds, it sends each datagram as one WebTransport datagram holding
   one `UdpPacket`.
3. Until its stream arrives the client sends WebTransport datagrams. If no stream arrived after 8 seconds, the client
   may open one unidirectional stream and write the socket id and its framed packets there.

A reliable stream under UDP is deliberate: a browser paces and drops WebTransport datagrams, which a protocol on top
reads as loss on the path.

## Names

`DnsQuery` carries a whole DNS message. The relay hands it to its resolver and returns the resolver's whole message
in `DnsAnswer`, so a name with no records is an answer and not an error. A relay applies its egress rules to the
address a name resolves to exactly as to an address the client gave.

## Draining

A relay that is about to stop sends `Draining` once. The session keeps its sockets until they end or the relay
closes it with `RESTARTING`. The client opens new sockets on a new session.

## Closing a session

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | `NORMAL` | the side that closed was done |
| 1 | `PROTOCOL_ERROR` | a frame could not be read, or setup did not finish in time |
| 2 | `VERSION_MISMATCH` | the peer's version does not suit |
| 3 | `SESSION_LIMIT` | the relay holds as many sessions as it allows for this client or in all |
| 4 | `RESTARTING` | the relay is stopping; another session may be opened at once |

WebTransport carries the code and a reason for a person in its session close. A WebSocket closes with close code
4000 plus the code.

## WebSocket mux

For a client without WebTransport, one WebSocket carries the same streams. Every message is binary:

```
[u8 kind][u32 stream][payload]
```

| Kind | Name | Sent by | Payload |
| --- | --- | --- | --- |
| 0 | `OPEN` | relay | `u8` stream type: 0 a TCP socket's stream, 1 a UDP socket's stream toward the client |
| 1 | `DATA` | both | bytes of the stream |
| 2 | `FIN` | both | nothing; this side of the stream is finished |
| 3 | `RESET` | both | nothing, or a `u32` code as a stream reset carries it |
| 4 | `DATAGRAM` | client | one `UdpPacket` |
| 5 | `CREDIT` | client | `u32`: more `DATA` bytes the relay may send on this stream |

- Stream 0 is the control stream. It is never opened, never credited, and its frames go ahead of other streams'.
- Every other stream starts with a window of 1048576 bytes. The relay sends no `DATA` byte past the window, and each
  `CREDIT` adds to it. A client credits the bytes it has taken off a stream, so a slow reader on one stream holds
  back that stream only.
- Every other stream starts as its WebTransport twin does, with the socket id.
- A UDP socket has one stream toward the client, and its datagrams toward the relay travel as `DATAGRAM` frames.
- A receiver ignores a message shorter than five bytes and a kind it does not know.
