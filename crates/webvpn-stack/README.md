# webvpn-stack

The client's end of a [WebVPN](https://webvpn.dev) IP tunnel: a TCP/IP stack on
[smoltcp](https://github.com/smoltcp-rs/smoltcp), which `@webvpn/client` runs in a page as WebAssembly so that TCP and
UDP work over a tunnel that carries nothing but IP packets.

It builds with `cargo build --release --target wasm32-unknown-unknown -p webvpn-stack`, with no binding generator: the
module exports plain functions over integers and one shared buffer, which the crate's documentation lists. The same
code builds natively, where its tests join two stacks back to back.

It is not published on its own: `@webvpn/client` carries the module.
