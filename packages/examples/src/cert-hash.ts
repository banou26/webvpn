import { connect } from '@webvpn/client'

const response = await fetch('http://127.0.0.1:8080/cert-hash')
const hash: number[] = await response.json()

const session = await connect({
  url: 'https://127.0.0.1:4433',
  transport: 'webtransport',
  serverCertificateHashes: [
    { algorithm: 'sha-256', value: new Uint8Array(hash) },
  ],
})
