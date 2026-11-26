import { connect, formatIp } from '@webvpn/client'

const session = await connect({ webSocketUrl: 'wss://relay.example:8443' })
const socket = await session.udpBind({ ip: new Uint8Array(4), port: 0 })

const peer = { ip: new Uint8Array([203, 0, 113, 7]), port: 6881 }
const writer = socket.writable.getWriter()
await writer.write({ remote: peer, data: new TextEncoder().encode('ping') })

const reader = socket.readable.getReader()
const { value } = await reader.read()
if (value) console.log(formatIp(value.remote.ip), value.data)
await socket.close()
