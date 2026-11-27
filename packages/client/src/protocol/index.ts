/**
 * The WebVPN wire protocol as `spec/protocol.md` lays it out: control frames, the UDP data packet, the IP tunnel's
 * frame and the WebSocket mux frame. No I/O: the caller owns the streams and hands bytes in.
 */
export * from './codes'
export * from './control'
export * from './ip'
export * from './mux'
export type { TcpOption, UdpOption } from './options'
export * from './udp'
export { ProtocolError } from './wire'
export type { Address } from './wire'
