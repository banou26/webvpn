import { CloseCode, connect } from '@webvpn/client'

const session = await connect({ webSocketUrl: 'wss://relay.example:8443' })

session.draining.then(() => console.log('new sockets go on a new session'))

session.closed.then(({ code, reason }) => {
  if (code === CloseCode.RESTARTING) console.log('a new session may open now')
  else console.log(`the session closed: ${reason}`)
})
