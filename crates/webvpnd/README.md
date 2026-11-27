# webvpnd

The WebVPN relay as a program. It runs one relay on WebTransport and on WebSocket, with the default policy, and takes
its settings from environment variables only.

```sh
cargo run --release -p webvpnd
```

## Settings

Every setting is optional. A boolean is `true` or `false`, and a list is comma separated. A value that does not parse
stops the program at start, with a message that names the variable. Logs go to stdout, and `RUST_LOG` sets their
level (`info` by default).

| Name | Default | Meaning |
| --- | --- | --- |
| `WEBVPN_ADDRESS` | `0.0.0.0` | The address both carriers bind. |
| `WEBVPN_WEBTRANSPORT_PORT` | `4433` | The UDP port of the WebTransport carrier. |
| `WEBVPN_WEBSOCKET_PORT` | `8443` | The TCP port of the WebSocket carrier. It also answers `GET /load` with the open sessions, `WEBVPN_MAX_SESSIONS` and the version, as JSON. When the port cannot be taken, the relay serves on WebTransport alone. |
| `WEBVPN_HTTP_ADDRESS` | `127.0.0.1` | The address of the plain HTTP listener. |
| `WEBVPN_HTTP_PORT` | `8080` | The port of the plain HTTP listener: `/health`, `/ready` (503 once the relay is stopping), `/metrics` in the Prometheus format, and `/cert-hash`, the SHA-256 of the certificate for `serverCertificateHashes`. |
| `WEBVPN_CERT`, `WEBVPN_KEY` | none | The paths of a PEM certificate chain and of its private key. Set both or neither. Both carriers use them, and the files are read again every 60 seconds, so a renewed certificate is served without closing a session. With neither, the relay makes a self-signed certificate at start, which a browser takes only by its hash and for 14 days at most. |
| `WEBVPN_OWN_ADDRESSES` | none | The relay's own public addresses. A client that connects to one of them reaches a socket another client bound on the relay, or is refused. |
| `WEBVPN_WATCH_OWN_IPV6` | `false` | Reads the relay's own global IPv6 addresses from the system every second, and treats them as own addresses. Linux only: on another system the setting does nothing. |
| `WEBVPN_LISTEN` | `true` | Lets clients listen for inbound TCP connections. |
| `WEBVPN_DNS_UPSTREAM` | none | The DNS over HTTPS endpoint (RFC 8484) that answers the clients' name lookups. Unset, the relay looks up no names. |
| `WEBVPN_MAX_SOCKETS_PER_SESSION` | `4096` | Sockets one session may hold at once. |
| `WEBVPN_MAX_SESSIONS` | `1024` | Sessions the relay holds at once. |
| `WEBVPN_MAX_SOCKETS` | `65536` | Sockets the relay holds at once, across sessions. The program raises its open-files limit, and warns when the limit stays under this. |
| `WEBVPN_ALLOW_PRIVATE_TARGETS` | `false` | Lets clients reach private, local and reserved addresses. For a relay on a network you trust. |
| `WEBVPN_MIN_BIND_PORT` | `1024` | The lowest port a client may bind. Port 0, any free port, always passes. |
| `WEBVPN_CREDENTIALS` | none | When set, a client must present one of these credentials before it opens a socket. Unset, the relay is open to every client. |
| `WEBVPN_DRAIN_SECONDS` | `5` | On SIGTERM or SIGINT the relay takes no new session and tells the open ones it is stopping. They keep their sockets this long, then the relay closes them and the program exits with code 0. |
