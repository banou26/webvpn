import { connect } from '@webvpn/client'
import { createNet } from '@webvpn/net'

const session = await connect({
  url: 'https://relay.example:4433',
  webSocketUrl: 'wss://relay.example:8443',
})
const net = createNet(session)

const socket = net.connect(80, 'example.org', () => {
  socket.write('GET / HTTP/1.0\r\nHost: example.org\r\n\r\n')
})
socket.on('data', (chunk) => console.log(chunk.toString()))
socket.on('error', (error) => console.error(error.message))
