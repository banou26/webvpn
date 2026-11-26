import { connect } from '@webvpn/client'
import dgram, { setProvider as setDgram } from '@webvpn/dgram'
import { setProvider as setNet } from '@webvpn/net'

const session = await connect({ webSocketUrl: 'wss://relay.example:8443' })
setNet(session)
setDgram(session)

const socket = dgram.createSocket('udp4')
socket.on('message', (message) => console.log(message.toString()))
socket.send('ping', 6881, '203.0.113.7')
