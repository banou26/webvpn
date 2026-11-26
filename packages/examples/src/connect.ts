import { connect } from '@webvpn/client'

const session = await connect({
  url: 'https://relay.example:4433',
  webSocketUrl: 'wss://relay.example:8443',
})
console.log(`connected over ${session.carrier}`)
