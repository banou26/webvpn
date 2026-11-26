# WebVPN

Real TCP and UDP sockets for a web page, through a relay, over WebTransport with a WebSocket fallback.

- [`spec/protocol.md`](spec/protocol.md): the wire protocol, version 0.1. Version 0 is not stable.
- [`spec/vectors/v0.txt`](spec/vectors/v0.txt): the bytes every implementation's tests are checked against.
- [`crates/webvpn-proto`](crates/webvpn-proto): the protocol in Rust, with no I/O and no dependencies.
- [`crates/webvpn-server`](crates/webvpn-server): the relay as a library: sessions, sockets, both carriers, and the policy a relay's operator plugs in.
- [`crates/webvpnd`](crates/webvpnd): the relay as a program, set up by environment variables. The
  [`Dockerfile`](Dockerfile) builds it into an image.
- [`packages/client`](packages/client): `@webvpn/client`, the client for a page or a worker: sessions over WebTransport or the WebSocket mux, with TCP and UDP sockets, listeners and name lookups.
- [`site`](site): the webvpn.dev site, whose protocol page is the spec above.

```sh
cargo test
npm install && npm test
```
