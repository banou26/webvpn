import { connect, Feature, formatIp } from '@webvpn/client'
import { openStack } from '@webvpn/client/stack'
import { createNet } from '@webvpn/net'

const session = await connect({ webSocketUrl: 'wss://relay.example:8443' })
if (!(session.features & Feature.IP)) throw new Error('the relay offers no IP tunnels')
const tunnel = await session.ipOpen()
const stack = await openStack(tunnel)

const socket = await stack.tcpConnect({ name: 'example.org', port: 80 })
const writer = socket.writable.getWriter()
await writer.write(new TextEncoder().encode('GET / HTTP/1.0\r\nHost: example.org\r\n\r\n'))
for await (const chunk of socket.readable) console.log(new TextDecoder().decode(chunk))

// a listener needs public ports, which a relay may give a tunnel or not
if (tunnel.ports) {
  const listener = await stack.tcpListen({ ip: new Uint8Array(4), port: 0 })
  console.log(`peers connect to ${formatIp(listener.local.ip)}:${listener.local.port}`)
}

const net = createNet(stack)
net.connect(443, 'example.org').on('connect', () => console.log('Node\'s net, over the tunnel'))
