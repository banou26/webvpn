# WebVPN

Real TCP and UDP sockets for a web page, through a relay, over WebTransport with a WebSocket fallback.

- [`spec/protocol.md`](spec/protocol.md): the wire protocol, version 0.1. Version 0 is not stable.
- [`spec/vectors/v0.txt`](spec/vectors/v0.txt): the bytes every implementation's tests are checked against.
- [`crates/webvpn-proto`](crates/webvpn-proto): the protocol in Rust, with no I/O and no dependencies.
- [`packages/client`](packages/client): `@webvpn/client`, so far the protocol in TypeScript.

```sh
cargo test
npm install && npm test
```
