import type { Address, UdpDatagram, UdpOption, UdpSocket } from '@webvpn/client'
import type { Provider } from '../src'

import { ErrorCode, formatIp, parseIp, WebVpnError } from '@webvpn/client'

export const address = (text: string, port: number): Address => ({ ip: parseIp(text)!, port })

export const relayError = (code: number, message = 'the relay refused') => new WebVpnError(code, message)

export const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

/** A promise the test settles by hand. */
export const gate = () => {
  let open!: () => void
  const opened = new Promise<void>((resolve) => { open = resolve })
  return { opened, open }
}

/** A UDP socket as the relay hands it over: the test delivers datagrams to it and reads what it sent. */
export const fakeUdp = (local: Address) => {
  let down!: ReadableStreamDefaultController<UdpDatagram>
  let finish!: (code?: number) => void
  let done = false
  const sent: { to: string, data: string }[] = []
  const options: UdpOption[] = []
  const calls: string[] = []
  const failures: { connect?: Error, disconnect?: Error, option?: Error } = {}
  const stop = (code?: number) => {
    done = true
    try {
      down.close()
    } catch {}
    finish(code)
  }
  const socket: UdpSocket = {
    id: 3,
    local,
    readable: new ReadableStream({ start: (controller) => { down = controller } }),
    writable: new WritableStream({
      write: ({ remote, data }) => {
        if (done) throw new WebVpnError(ErrorCode.OTHER, 'the socket is closed')
        sent.push({ to: remote ? `${formatIp(remote.ip)}:${remote.port}` : 'peer', data: new TextDecoder().decode(data) })
      },
    }),
    connect: async (remote) => {
      calls.push(`connect ${formatIp(remote.ip)}:${remote.port}`)
      if (failures.connect) throw failures.connect
    },
    disconnect: async () => {
      calls.push('disconnect')
      if (failures.disconnect) throw failures.disconnect
    },
    setOption: async (option) => {
      if (failures.option) throw failures.option
      options.push(option)
    },
    closed: new Promise((resolve) => { finish = resolve }),
    close: async () => {
      calls.push('close')
      stop()
    },
  }
  return {
    socket,
    sent,
    options,
    calls,
    failures,
    deliver: (from: Address, data: string) => down.enqueue({ remote: from, data: new TextEncoder().encode(data) }),
    /** Ends the socket from the relay's side, with the code of a `Closed` notice, or none as when the session ended. */
    end: stop,
  }
}

const decodeName = (query: Uint8Array) => {
  const labels: string[] = []
  let at = 12
  for (; query[at]; at += 1 + query[at]!) labels.push(new TextDecoder().decode(query.subarray(at + 1, at + 1 + query[at]!)))
  return { name: labels.join('.'), type: query[at + 2] === 28 ? 'AAAA' : 'A' }
}

// a DNS answer with no question and one record per address, under the root name
const dnsAnswer = (ips: Uint8Array[]) => {
  const parts: Uint8Array[] = [Uint8Array.of(0, 0, 0x81, 0x80, 0, 0, 0, ips.length, 0, 0, 0, 0)]
  for (const ip of ips) parts.push(Uint8Array.of(0, 0, ip.byteLength === 4 ? 1 : 28, 0, 1, 0, 0, 0, 60, 0, ip.byteLength), ip)
  const message = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0))
  let at = 0
  for (const part of parts) {
    message.set(part, at)
    at += part.byteLength
  }
  return message
}

/**
 * A provider the test drives: `bindError` refuses binds, `holdBind` and `holdLookup` keep them in flight until
 * opened, `names` is what a lookup answers, and every request is recorded.
 */
export const fakeProvider = () => {
  const relay = {
    binds: [] as string[],
    lookups: [] as string[],
    sockets: [] as ReturnType<typeof fakeUdp>[],
    bindError: undefined as Error | undefined,
    holdBind: undefined as Promise<void> | undefined,
    holdLookup: undefined as Promise<void> | undefined,
    names: new Map<string, string[]>(),
    provider: undefined as unknown as Provider,
  }
  relay.provider = {
    udpBind: async (local) => {
      relay.binds.push(`${formatIp(local.ip)}:${local.port}`)
      await relay.holdBind
      if (relay.bindError) throw relay.bindError
      const made = fakeUdp({ ip: local.ip, port: local.port || 41234 })
      relay.sockets.push(made)
      return made.socket
    },
    lookup: async (query) => {
      const { name, type } = decodeName(query)
      relay.lookups.push(`${type} ${name}`)
      await relay.holdLookup
      const ips = (relay.names.get(name) ?? []).map((text) => parseIp(text)!)
      return dnsAnswer(ips.filter((ip) => ip.byteLength === (type === 'A' ? 4 : 16)))
    },
  }
  return relay
}
