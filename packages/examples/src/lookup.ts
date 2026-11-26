import { connect, dnsAddresses, dnsQuery, formatIp } from '@webvpn/client'

const session = await connect({ webSocketUrl: 'wss://relay.example:8443' })
const answer = await session.lookup(dnsQuery('example.org', 'AAAA'))
console.log(dnsAddresses(answer).map(formatIp))
