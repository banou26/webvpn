# webvpn-server

The [WebVPN](https://webvpn.dev) relay as a library. It holds the sessions and the sockets and moves the bytes, over
WebTransport and over a WebSocket. A policy you write decides who may open a session, what a credential means, which
sockets and destinations a session may use, and how fast its bytes move.

- [Embedding the relay](https://webvpn.dev/docs/embedding/) is the guide.
- `examples/embed.rs` is a whole program with a policy of its own.
- [`webvpnd`](https://webvpn.dev/docs/running-a-relay/) is the relay as a program, built on this crate with its
  default policy.

The two carriers are cargo features, `webtransport` and `websocket`, both on by default. The feature `close-capsule`
needs a patched `wtransport` and is off by default.

The relay runs on Linux and on macOS. [Running a relay](https://webvpn.dev/docs/running-a-relay/#on-macos) lists what a
client sees differently on macOS.

Version 0 of the protocol is not stable: a new minor version of this crate may change the wire and its own interfaces.
