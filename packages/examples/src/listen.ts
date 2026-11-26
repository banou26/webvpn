import { connect, formatIp } from '@webvpn/client'

const session = await connect({ webSocketUrl: 'wss://relay.example:8443' })
const listener = await session.tcpListen({ ip: new Uint8Array(4), port: 0 })
console.log(`echoing on port ${listener.local.port}`)

const reader = listener.connections.getReader()
while (true) {
  const { value: peer, done } = await reader.read()
  if (done) break
  console.log(`a connection from ${formatIp(peer.remote.ip)}`)
  peer.readable.pipeTo(peer.writable).catch(console.error)
}
