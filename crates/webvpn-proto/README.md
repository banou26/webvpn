# webvpn-proto

The [WebVPN](https://webvpn.dev) wire protocol in Rust: the control frames, the UDP data packet and the WebSocket mux
frame of [protocol 0.1](https://webvpn.dev/docs/protocol/). It does no I/O and has no dependencies: the caller owns
the streams and hands bytes in.

A relay or a client of your own encodes and decodes with it. `webvpn-server` is the relay built on it. Its tests check
the codec both ways against the spec's byte vectors, `spec/vectors/v0.txt` in the repository.

Version 0 of the protocol is not stable: a new minor version of this crate may change the wire.
