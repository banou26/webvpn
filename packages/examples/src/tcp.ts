import { connect } from '@webvpn/client'

const session = await connect({ webSocketUrl: 'wss://relay.example:8443' })
const socket = await session.tcpConnect({ name: 'example.org', port: 80 })

const request = 'GET / HTTP/1.0\r\nHost: example.org\r\n\r\n'
const writer = socket.writable.getWriter()
await writer.write(new TextEncoder().encode(request))
await writer.close()

const reader = socket.readable.getReader()
const decoder = new TextDecoder()
while (true) {
  const { value, done } = await reader.read()
  if (done) break
  console.log(decoder.decode(value))
}
