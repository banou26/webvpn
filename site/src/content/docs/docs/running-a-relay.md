---
title: Running a relay
description: Host a WebVPN relay with webvpnd, from a checkout or with its Dockerfile, with its ports, its certificate, its settings and its endpoints.
---

`webvpnd` is the WebVPN relay as a program. It runs one relay on WebTransport and on a WebSocket, under the default rules, and takes every setting from an environment variable.

## Start it

From a checkout of the source:

```sh
cargo run --release -p webvpnd
```

With no setting, the relay listens on every IPv4 address and serves a self-signed certificate. It writes its logs to stdout, and `RUST_LOG` sets their level, `info` by default.

With the `Dockerfile` at the root of the checkout:

```sh
docker build -t webvpnd .
docker run --rm -p 4433:4433/udp -p 8443:8443/tcp webvpnd
```

The image runs `webvpnd` and exposes the two carrier ports. It takes the same settings, with `docker run -e`. The HTTP listener binds `127.0.0.1` by default, so to reach it from outside the container, set `WEBVPN_HTTP_ADDRESS=0.0.0.0` and publish its port:

```sh
docker run --rm -p 4433:4433/udp -p 8443:8443/tcp -p 127.0.0.1:8080:8080/tcp -e WEBVPN_HTTP_ADDRESS=0.0.0.0 webvpnd
```

`docker stop` sends SIGTERM, which [stops the relay](#stopping).

## Ports

| Port | Setting | What it serves |
| --- | --- | --- |
| UDP `4433` | `WEBVPN_WEBTRANSPORT_PORT` | WebTransport, HTTP/3 over QUIC. |
| TCP `8443` | `WEBVPN_WEBSOCKET_PORT` | The WebSocket over TLS, and [`GET /load`](#the-load-probe). |
| TCP `8080`, on `127.0.0.1` | `WEBVPN_HTTP_PORT` | Plain HTTP: [`/health`, `/ready`, `/metrics` and `/cert-hash`](#health-readiness-and-metrics). |

Both carriers bind `WEBVPN_ADDRESS`, `0.0.0.0` by default. A port set to `0` is left to the system. The log names each port the relay takes, as in `WebTransport listening on udp/4433`.

A WebTransport or HTTP port that cannot be taken stops the program at start. A WebSocket port that cannot be taken is logged as an error, and the relay serves on WebTransport alone.

## The certificate

Both carriers serve the same certificate.

**A certificate of your own:** set `WEBVPN_CERT` to the path of a PEM certificate chain and `WEBVPN_KEY` to the path of its private key. A certificate that cannot be read stops the program at start. The relay reads the two files again every 60 seconds and serves a renewed certificate to every session that opens after it, so a renewal needs no restart and closes no session. A read that fails keeps the certificate in use, and the log says so.

**The self-signed certificate,** for development: with neither variable set, the relay makes one at start, and the log says so. It names `localhost`, `127.0.0.1`, `::1`, and `WEBVPN_ADDRESS` when that is an address other than `0.0.0.0`, `::` or loopback. It is valid for 14 days, and each start makes a new one, with a new hash.

A browser takes the self-signed certificate only by its hash, which it does for a certificate valid for 14 days at most. `/cert-hash` on the HTTP listener answers the SHA-256 of the certificate in use, as a JSON array of 32 numbers that any origin may read:

```sh
curl http://127.0.0.1:8080/cert-hash
```

A page passes that array to `new WebTransport()` in the `serverCertificateHashes` option, as `{ algorithm: 'sha-256', value: new Uint8Array(hash) }`.

## Settings

Every setting is optional. A boolean is `true` or `false`, and a list is comma separated. A value that does not parse stops the program at start, with a message that names the variable and never repeats its value.

### Addresses and ports

| Setting | Default | What it does |
| --- | --- | --- |
| `WEBVPN_ADDRESS` | `0.0.0.0` | The address both carriers bind. |
| `WEBVPN_WEBTRANSPORT_PORT` | `4433` | The UDP port of WebTransport. |
| `WEBVPN_WEBSOCKET_PORT` | `8443` | The TCP port of the WebSocket and of `/load`. |
| `WEBVPN_HTTP_ADDRESS` | `127.0.0.1` | The address of the plain HTTP listener. |
| `WEBVPN_HTTP_PORT` | `8080` | The port of the plain HTTP listener. |
| `WEBVPN_OWN_ADDRESSES` | none | A list of the relay's own public addresses. See [own addresses](#own-addresses). |
| `WEBVPN_WATCH_OWN_IPV6` | `false` | Reads the relay's own global IPv6 addresses from the system at start and every second after, and treats each as an own address. Linux only. |

### Certificate

| Setting | Default | What it does |
| --- | --- | --- |
| `WEBVPN_CERT` | none | The path of a PEM certificate chain. |
| `WEBVPN_KEY` | none | The path of its private key. |

Set both or neither. With neither, the relay serves a [self-signed certificate](#the-certificate).

### What clients may do

| Setting | Default | What it does |
| --- | --- | --- |
| `WEBVPN_LISTEN` | `true` | Lets clients listen for inbound TCP connections. |
| `WEBVPN_DNS_UPSTREAM` | none | The DNS over HTTPS endpoint (RFC 8484) that answers the clients' name lookups. Unset, the relay looks up no names, for a lookup or for a connection to a name. |
| `WEBVPN_ALLOW_PRIVATE_TARGETS` | `false` | Lets clients reach private, local and reserved addresses. |
| `WEBVPN_MIN_BIND_PORT` | `1024` | The lowest port a client may bind a UDP socket or listen on. Port `0`, any free port, always passes. |

### Limits

| Setting | Default | What it does |
| --- | --- | --- |
| `WEBVPN_MAX_SESSIONS` | `1024` | Sessions the relay holds at once. |
| `WEBVPN_MAX_SOCKETS` | `65536` | Sockets the relay holds at once, across sessions. |
| `WEBVPN_MAX_SOCKETS_PER_SESSION` | `4096` | Sockets one session holds at once. |

Every socket a client holds is an open file. The program raises its open-files limit as far as the system allows, and says so in its log when the limit stays under `WEBVPN_MAX_SOCKETS`.

Two limits have no setting. The relay holds 256 sessions in setup at once, and a client that arrives while 256 are in setup is turned away at once. A session has 15 seconds from its client's arrival to the client's hello, and is closed past that.

### Credentials

| Setting | Default | What it does |
| --- | --- | --- |
| `WEBVPN_CREDENTIALS` | none | A list of credentials. When set, a client presents one of them before it opens a socket or looks a name up. |

Each credential in the list is trimmed, so none can hold a comma or begin or end with white space. An empty item stops the program at start.

### Stopping

| Setting | Default | What it does |
| --- | --- | --- |
| `WEBVPN_DRAIN_SECONDS` | `5` | How long open sessions keep their sockets once the relay is stopping. |

## What the default rules allow

`webvpnd` runs `Basic`, the library's [default policy](/docs/embedding/#basic), with `WEBVPN_CREDENTIALS` on top of it.

- **Public addresses only.** A client reaches addresses on the public internet, as IANA's special-purpose address registries define them, and no private, loopback, link-local, shared, documentation, multicast or reserved address. An IPv6 address that spells an IPv4 one, such as `::ffff:10.0.0.1`, counts as that IPv4 address. The rule applies to every TCP connection, after its name is looked up, to the destination of every UDP datagram, and to every multicast group a socket joins.
- **No port under 1024.** A client binds a UDP socket or listens on port 1024 or above, or on port `0` for any free port.
- **Ceilings.** The relay holds 1024 sessions, 65536 sockets across sessions, and 4096 sockets in one session. A session over the ceiling is told `SESSION_LIMIT` in a `Bye` and closed. A socket over a ceiling is refused with `CAPACITY`, and the same request may pass later.
- **No pacing and no count per client.** The rules do not limit how fast a client moves bytes, or how many. To pace or meter, [embed the relay](/docs/embedding/) with a policy of your own.
- **Open to every client.** Any client that reaches the relay may open sockets.

`WEBVPN_ALLOW_PRIVATE_TARGETS=true` lifts the first rule: clients also reach private, local and reserved addresses, such as the other machines on the relay's network. It is for a relay on a network you trust.

`WEBVPN_CREDENTIALS` lifts the last rule. The relay's hello tells each client that a credential is required. Until the client presents one from the list, the relay answers its socket requests and its lookups with `AUTH_REQUIRED`. A credential not on the list is answered `AUTH_FAILED`, and the session stays as it was. The other rules still apply.

### Own addresses

The relay decides about its own addresses itself, before the rules above. A connection or a datagram to an address in `WEBVPN_OWN_ADDRESSES` reaches the client socket bound on the relay at that port, or is refused. With `WEBVPN_WATCH_OWN_IPV6`, the relay also refuses the other addresses on the links of its own IPv6 addresses.

Set `WEBVPN_OWN_ADDRESSES` to every public address of the relay's host. An address left out of it is a public address like any other, and a client that connects to it reaches whatever listens on that host.

## Health, readiness and metrics

The HTTP listener speaks plain HTTP, on `127.0.0.1:8080` by default. It starts after both carriers, so it answers once they serve.

| Request | Answer |
| --- | --- |
| `GET /health` | `200` and `OK`. |
| `GET /ready` | `200` and `Ready`, or `503` and `Draining` once the relay is stopping. |
| `GET /metrics` | The relay's counters in the Prometheus text format. |
| `GET /cert-hash` | The SHA-256 of the certificate in use, as a JSON array of 32 numbers, with `access-control-allow-origin: *`. |

```sh
curl http://127.0.0.1:8080/health
```

The metrics include `webvpn_active_connections_total`, the open sessions, `webvpn_active_sockets`, `webvpn_bandwidth_bytes_total` by direction, and `webvpn_handshakes_total`. No series carries a label about a client, an address or a destination.

## The load probe

The WebSocket port answers `GET /load` with the open sessions, `WEBVPN_MAX_SESSIONS` and the relay's version, as JSON:

```json
{"sessions":0,"maxSessions":1024,"version":"0.1.0"}
```

Any origin may read the answer, and nothing may cache it. The relay ignores the query string. The request takes the same TCP and TLS path as a session, so a client that times it measures the round trip its session would have. Every other request that is not a WebSocket upgrade is answered `404`.

```sh
curl -k https://127.0.0.1:8443/load
```

`-k` lets curl take the self-signed certificate.

## Stopping

On SIGTERM or SIGINT, the relay:

1. takes no new session: WebTransport refuses each arrival, the WebSocket port closes, and `/ready` answers `503`;
2. sends each open session `Draining` once, and the session keeps its sockets;
3. after `WEBVPN_DRAIN_SECONDS`, sends each session still open a `Bye` with `RESTARTING` and the reason `the relay is stopping`, then closes it with the same, which a WebSocket client also reads as close code `4004`;
4. exits with code `0`, as soon as every session has ended and at most 4 seconds after the grace. Its last log line counts the sessions it closed when the grace ran out.

## On macOS

`webvpnd` builds and runs on macOS as on Linux. A client can see these differences there:

- A UDP socket bound to one address, and not to `0.0.0.0` or `::`, ends when it disconnects from a peer, or connects while it already has one, if macOS moved it to another address. The relay answers the request first, then sends `Closed` with `ADDRESS_NOT_AVAILABLE`.
- A UDP connect that fails on a socket that already has a peer leaves the socket with no peer. On Linux the socket keeps the peer it had.
- A TTL of 0 is accepted. Linux refuses it.
- `WEBVPN_WATCH_OWN_IPV6` does nothing.
