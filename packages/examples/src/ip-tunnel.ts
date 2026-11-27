import { connect, Feature } from '@webvpn/client'

const session = await connect({ webSocketUrl: 'wss://relay.example:8443' })
if (!(session.features & Feature.IP)) throw new Error('the relay offers no IP tunnels')
const tunnel = await session.ipOpen()

const stack = new Worker(new URL('./stack.js', import.meta.url), { type: 'module' })
stack.postMessage({ ipv4: tunnel.ipv4, ipv6: tunnel.ipv6, mtu: tunnel.mtu })
stack.onmessage = (event: MessageEvent<Uint8Array>) => {
  if (!tunnel.send(event.data)) console.log('dropped, as a busy link drops a packet')
}

const reader = tunnel.readable.getReader()
while (true) {
  const { value, done } = await reader.read()
  if (done) break
  stack.postMessage(value, [value.buffer])
}
