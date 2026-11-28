---
title: Running a relay
description: Host a WebVPN relay with webvpnd, installed with cargo or built with its Dockerfile, with its ports, its certificate, its settings and its endpoints.
---

`webvpnd` is the WebVPN relay as a program. It runs one relay on WebTransport and on a WebSocket, under the default rules, and takes every setting from an environment variable.

## Start it

With cargo:

```sh
cargo install webvpnd
webvpnd
```

With no setting, the relay listens on every IPv4 address and serves a self-signed certificate. It writes its logs to stdout, and `RUST_LOG` sets their level, `info` by default.

With the `Dockerfile` at the root of a checkout of [the source](https://github.com/banou26/webvpn):

```sh
docker build -t webvpnd .
docker run --rm -p 4433:4433/udp -p 8443:8443/tcp webvpnd
```

The image runs `webvpnd` and exposes the two carrier ports. It takes the same settings, with `docker run -e`. The HTTP listener binds `127.0.0.1` by default, so to reach it from outside the container, set `WEBVPN_HTTP_ADDRESS=0.0.0.0` and publish its port:

```sh
docker run --rm -p 4433:4433/udp -p 8443:8443/tcp -p 127.0.0.1:8080:8080/tcp -e WEBVPN_HTTP_ADDRESS=0.0.0.0 webvpnd
```

`docker stop` sends SIGTERM, which [stops the relay](#stopping).

## Ports

| Port | Setting | What it serves |
| --- | --- | --- |
| UDP `4433` | `WEBVPN_WEBTRANSPORT_PORT` | WebTransport, HTTP/3 over QUIC. |
| TCP `8443` | `WEBVPN_WEBSOCKET_PORT` | The WebSocket over TLS, and [`GET /load`](#the-load-probe). |
| TCP `8080`, on `127.0.0.1` | `WEBVPN_HTTP_PORT` | Plain HTTP: [`/health`, `/ready`, `/metrics` and `/cert-hash`](#health-readiness-and-metrics). |

Both carriers bind `WEBVPN_ADDRESS`, `0.0.0.0` by default. A port set to `0` is left to the system. The log names each port the relay takes, as in `WebTransport listening on udp/4433`.

A WebTransport or HTTP port that cannot be taken stops the program at start. A WebSocket port that cannot be taken is logged as an error, and the relay serves on WebTransport alone.

## The certificate

Both carriers serve the same certificate.

**A certificate of your own:** set `WEBVPN_CERT` to the path of a PEM certificate chain and `WEBVPN_KEY` to the path of its private key. A certificate that cannot be read stops the program at start. The relay reads the two files again every 60 seconds and serves a renewed certificate to every session that opens after it, so a renewal needs no restart and closes no session. A read that fails keeps the certificate in use, and the log says so.

**The self-signed certificate,** for development: with neither variable set, the relay makes one at start, and the log says so. It names `localhost`, `127.0.0.1`, `::1`, and `WEBVPN_ADDRESS` when that is an address other than `0.0.0.0`, `::` or loopback. It is valid for 14 days, and each start makes a new one, with a new hash.

A browser takes the self-signed certificate only by its hash, which it does for a certificate valid for 14 days at most. `/cert-hash` on the HTTP listener answers the SHA-256 of the certificate in use, as a JSON array of 32 numbers that any origin may read:

```sh
curl http://127.0.0.1:8080/cert-hash
```

A page passes that array to `new WebTransport()` in the `serverCertificateHashes` option, as `{ algorithm: 'sha-256', value: new Uint8Array(hash) }`.

## Settings

Every setting is optional. A boolean is `true` or `false`, and a list is comma separated. A value that does not parse stops the program at start, with a message that names the variable and never repeats its value.

### Addresses and ports

| Setting | Default | What it does |
| --- | --- | --- |
| `WEBVPN_ADDRESS` | `0.0.0.0` | The address both carriers bind. |
| `WEBVPN_WEBTRANSPORT_PORT` | `4433` | The UDP port of WebTransport. |
| `WEBVPN_WEBSOCKET_PORT` | `8443` | The TCP port of the WebSocket and of `/load`. |
| `WEBVPN_HTTP_ADDRESS` | `127.0.0.1` | The address of the plain HTTP listener. |
| `WEBVPN_HTTP_PORT` | `8080` | The port of the plain HTTP listener. |
| `WEBVPN_OWN_ADDRESSES` | none | A list of the relay's own public addresses. See [own addresses](#own-addresses). |
| `WEBVPN_WATCH_OWN_IPV6` | `false` | Reads the relay's own global IPv6 addresses from the system at start and every second after, and treats each as an own address. Linux only. |

### Certificate

| Setting | Default | What it does |
| --- | --- | --- |
| `WEBVPN_CERT` | none | The path of a PEM certificate chain. |
| `WEBVPN_KEY` | none | The path of its private key. |

Set both or neither. With neither, the relay serves a [self-signed certificate](#the-certificate).

### What clients may do

| Setting | Default | What it does |
| --- | --- | --- |
| `WEBVPN_LISTEN` | `true` | Lets clients listen for inbound TCP connections. |
| `WEBVPN_DNS_UPSTREAM` | none | The DNS over HTTPS endpoint (RFC 8484) that answers the clients' name lookups. Unset, the relay looks up no names, for a lookup or for a connection to a name. |
| `WEBVPN_ALLOW_PRIVATE_TARGETS` | `false` | Lets clients reach private, local and reserved addresses. |
| `WEBVPN_MIN_BIND_PORT` | `1024` | The lowest port a client may bind a UDP socket or listen on. Port `0`, any free port, always passes. |

### Limits

| Setting | Default | What it does |
| --- | --- | --- |
| `WEBVPN_MAX_SESSIONS` | `1024` | Sessions the relay holds at once. |
| `WEBVPN_MAX_SOCKETS` | `65536` | Sockets the relay holds at once, across sessions. |
| `WEBVPN_MAX_SOCKETS_PER_SESSION` | `4096` | Sockets one session holds at once. |

Every socket a client holds is an open file. The program raises its open-files limit as far as the system allows, and says so in its log when the limit stays under `WEBVPN_MAX_SOCKETS`.

Two limits have no setting. The relay holds 256 sessions in setup at once, and a client that arrives while 256 are in setup is turned away at once. A session has 15 seconds from its client's arrival to the client's hello, and is closed past that.

### Credentials

| Setting | Default | What it does |
| --- | --- | --- |
| `WEBVPN_CREDENTIALS` | none | A list of credentials. When set, a client presents one of them before it opens a socket or looks a name up. |

Each credential in the list is trimmed, so none can hold a comma or begin or end with white space. An empty item stops the program at start.

### Stopping

| Setting | Default | What it does |
| --- | --- | --- |
| `WEBVPN_DRAIN_SECONDS` | `5` | How long open sessions keep their sockets once the relay is stopping. |

## What the default rules allow

`webvpnd` runs `Basic`, the library's [default policy](/docs/embedding/#basic), with `WEBVPN_CREDENTIALS` on top of it.

- **Public addresses only.** A client reaches addresses on the public internet, as IANA's special-purpose address registries define them, and no private, loopback, link-local, shared, documentation, multicast or reserved address. An IPv6 address that spells an IPv4 one, such as `::ffff:10.0.0.1`, counts as that IPv4 address. The rule applies to every TCP connection, after its name is looked up, to the destination of every UDP datagram, and to every multicast group a socket joins.
- **No port under 1024.** A client binds a UDP socket or listens on port 1024 or above, or on port `0` for any free port.
- **Ceilings.** The relay holds 1024 sessions, 65536 sockets across sessions, and 4096 sockets in one session. A session over the ceiling is told `SESSION_LIMIT` in a `Bye` and closed. A socket over a ceiling is refused with `CAPACITY`, and the same request may pass later.
- **No pacing and no count per client.** The rules do not limit how fast a client moves bytes, or how many. To pace or meter, [embed the relay](/docs/embedding/) with a policy of your own.
- **Open to every client.** Any client that reaches the relay may open sockets.

`WEBVPN_ALLOW_PRIVATE_TARGETS=true` lifts the first rule: clients also reach private, local and reserved addresses, such as the other machines on the relay's network. It is for a relay on a network you trust.

`WEBVPN_CREDENTIALS` lifts the last rule. The relay's hello tells each client that a credential is required. Until the client presents one from the list, the relay answers its socket requests and its lookups with `AUTH_REQUIRED`. A credential not on the list is answered `AUTH_FAILED`, and the session stays as it was. The other rules still apply.

### Own addresses

The relay decides about its own addresses itself, before the rules above. A connection or a datagram to an address in `WEBVPN_OWN_ADDRESSES` reaches the client socket bound on the relay at that port, or is refused. With `WEBVPN_WATCH_OWN_IPV6`, the relay also refuses the other addresses on the links of its own IPv6 addresses.

Set `WEBVPN_OWN_ADDRESSES` to every public address of the relay's host. An address left out of it is a public address like any other, and a client that connects to it reaches whatever listens on that host.

## IP tunnels

A relay can also carry whole IP packets, for a client that brings its own network stack, such as a virtual machine. Each tunnel is given an address, and its packets go out through the relay's host as through a router. IP tunnels are Linux only, and off unless `WEBVPN_IP_DEVICE` is set: without it, the relay's hello does not offer them.

They come in two halves:

- **The setup step, with privilege.** Run as root once, before the relay starts, it makes a TUN device owned by the relay's user, gives it its network, turns forwarding on and loads the host's rules for it. `crates/webvpnd/ip-tunnel-setup.sh` does all of it.
- **The relay, with none.** It only opens the device that exists and belongs to its user, and needs no capability. A device that is missing, belongs to another user, has an MTU under 1280, or does not hold the first host address of `WEBVPN_IP_POOL` with its prefix length, stops the program at start, with a message that says what to check.

### Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `WEBVPN_IP_DEVICE` | none | The TUN device's name. Unset, the relay carries no tunnels. |
| `WEBVPN_IP_POOL` | none | The device's IPv4 network, such as `198.18.0.0/28`, with a prefix length of 8 to 30. Required with the device, refused without it. The device holds the first host address, and each tunnel is given one of the others. |
| `WEBVPN_MAX_TUNNEL_PACKETS_PER_SECOND` | `20000` | The packets one tunnel takes from its client each second, past which they are dropped. `0` lifts the ceiling. |
| `WEBVPN_MAX_TUNNELS_PER_SESSION` | `1` | The tunnels one session holds at once, at least 1, past which one more is refused with `CAPACITY`. A page's network stack or a virtual machine needs one. |
| `WEBVPN_IP_PORTS` | none | The tunnels' [public ports](#public-ports), a range written `first-last`, such as `20000-29999`. Unset, tunnels have none. |
| `WEBVPN_IP_PORTS_PER_TUNNEL` | `8` | How many public ports each tunnel address holds. |

On another system than Linux, any of these stops the program at start, with a message that says IP tunnels need Linux. A tunnel is one of the session's sockets: it counts toward `WEBVPN_MAX_SOCKETS` and `WEBVPN_MAX_SOCKETS_PER_SESSION`, and `WEBVPN_CREDENTIALS` applies to it. `WEBVPN_MAX_TUNNELS_PER_SESSION` bounds one session only: a bound on the tunnels one client holds across its sessions is for a [policy of your own](/docs/embedding/) to give. The relay checks the destination of every packet against [the default rules](#what-the-default-rules-allow), as for a socket's: public addresses only, unless `WEBVPN_ALLOW_PRIVATE_TARGETS` is set. A tunnel's address is given again only once every other address of the network was given, so that a freed address stays unused as long as possible.

### The setup script

```sh
WEBVPN_IP_DEVICE=webvpn0 WEBVPN_IP_POOL=198.18.0.0/28 WEBVPN_IP_USER=webvpnd sh ip-tunnel-setup.sh up
```

It takes `WEBVPN_IP_DEVICE` (`webvpn0` by default), `WEBVPN_IP_POOL`, `WEBVPN_IP_PORTS` and `WEBVPN_IP_PORTS_PER_TUNNEL` as the relay does, `WEBVPN_IP_USER`, the user the relay runs as, which is required (a device with no owner is open to every local user), `WEBVPN_IP_MTU` (`1500` by default), and `WEBVPN_IP_FLOWS_PER_ADDRESS`, the open connections the kernel tracks that one tunnel address opens, and apart from those, to its public ports (`4096` by default, a little above the 3584 flows the relay keeps for a tunnel, so that the relay's own bound acts first). `up` prints nothing unless something fails. Running it again with the same values changes nothing: it keeps the table it loaded, and with it what the ceilings count and the timeouts of the connections the kernel tracks. With other values it loads the table again, which counts from nothing and puts the connections open at that moment back on the host's timeouts. To change a setting, run `down`, then `up`, with the relay stopped. It:

1. makes the device for its user, gives it the network's first host address, as its only IPv4 address, sets its MTU and brings it up;
2. turns IPv4 forwarding on, when it is off;
3. loads one nftables table of its own, named after the device, with:
   - packets from the device to the device dropped, so that no tunnel reaches another;
   - IPv6 packets from the device dropped, until tunnels have IPv6 addresses;
   - packets from the device to private, loopback, link-local, shared, multicast and reserved addresses dropped, the same list as the relay's own rule, as a second layer under it;
   - a ceiling on the connections the kernel tracks that one tunnel address opens, `WEBVPN_IP_FLOWS_PER_ADDRESS`, past which a new one is dropped. It counts the address's connections the kernel still tracks until they close, an earlier tunnel's at that address too: an established TCP connection until 2 hours 4 minutes after its last packet (below), and any connection for as long as its peer keeps sending on it. Clearing them when an address is freed would take `conntrack -D` and the right to change the network, which the relay does not have. A closed TCP connection does not count, though the kernel keeps it for 2 minutes (`nf_conntrack_tcp_timeout_time_wait`), as it does every closed connection on the host;
   - packets from the device that connection tracking calls invalid dropped, such as a TCP segment outside its connection's window: no address translation applies to them, and they would leave with the network's own address as their source;
   - every other packet from the device accepted;
   - packets toward the device accepted only when they belong to, or relate to, a connection that began from the device, or with `WEBVPN_IP_PORTS`, a new connection to a public port that the rule below sent there, which counts toward a ceiling of `WEBVPN_IP_FLOWS_PER_ADDRESS` for each tunnel address apart from the tunnel's own connections, so that what others send to its ports does not stop them; every other packet toward the device dropped;
   - the tunnels' established TCP connections, those to public ports included, forgotten 2 hours 4 minutes (7440 seconds) after their last packet, as the relay forgets them, where the host's default is 5 days; their other states keep the host's timeouts;
   - with `WEBVPN_IP_PORTS`, a TCP or UDP packet that does not come from the device, to one of the host's own addresses on a public port, sent to the tunnel address that holds the port, on the same port;
   - nothing from the device accepted for the host itself;
   - the network's addresses translated to the host's where packets leave by any other interface.

`down` removes that table and the device. When IPv4 forwarding is off, `up` turns it on for the whole host, which then routes between all of its interfaces and not only the device's, and `down` leaves it on, since other things on the host may need it. Run `down` only with the relay stopped: a relay whose device is removed ends its tunnels, logs `the TUN device failed`, and refuses new ones until it restarts, even once `up` made the device again. `up` refuses a pool whose prefix length is not 8 to 30, as the relay does, a range of public ports that overlaps the host's local port range (`/proc/sys/net/ipv4/ip_local_port_range`), and a pool too large for the host's connection table (below), and then changes nothing. The table needs a kernel with connection tracking timeout policies (`CONFIG_NF_CONNTRACK_TIMEOUT`): without them `up` stops and says so, before it loads the table. Its comment, which tells a second `up` whether the table holds the same rules, needs kernel 5.10 and nft 0.9.7 or later.

The connections the kernel tracks for a tunnel address outlast its tunnel, so `up` refuses a pool whose tunnel addresses times `WEBVPN_IP_FLOWS_PER_ADDRESS`, plus the addresses that hold public ports times it again, take more than half of the host's connection table (`/proc/sys/net/netfilter/nf_conntrack_max`), which every program on the host shares. That bound is on open connections. Closed TCP connections stay in the table for the host's TIME_WAIT timeout outside the ceiling, as those of every program on the host do. A tunnel that opens and closes connections fast holds more, and so does anyone who opens and closes connections to the host's own ports, such as the WebSocket port. With 262144, the kernel's default on a 64-bit host with more than 4 GiB of memory, and the default ceiling, the largest pool is a `/27`, for 29 tunnels at once, or a `/28`, for 13, when each address holds public ports. With 65536, its default on a host with more than 1 GiB and at most 4 GiB, it is a `/29`, for 5, or a `/30`, for 1, and a host with less memory has a smaller table still. A lower ceiling allows a larger pool. For more tunnels at the same ceiling, raise `nf_conntrack_max` on the host.

The script needs the right to change the network (`CAP_NET_ADMIN`) and `/dev/net/tun`, and to turn forwarding on, the right to write the system's settings. On a host whose forwarding is already on, as on a Kubernetes node, a container with `CAP_NET_ADMIN` alone and `/dev/net/tun` mounted can run it. The relay's own container then needs only `/dev/net/tun` mounted and no capability.

The table does not assume it is the only firewall on the host. Another table that drops forwarded packets, such as a firewall manager's, still drops the tunnels' packets: let packets from and toward the device through there too.

### Public ports

With `WEBVPN_IP_PORTS`, a client's own network stack can listen. The relay tells each tunnel its public address, the first IPv4 address of `WEBVPN_OWN_ADDRESSES` (which the setting needs), and its ports. A TCP or UDP packet that anyone outside the relay sends to the host on one of those ports reaches the tunnel's own address on the same port, and the tunnel's answers leave from the host's address and that port.

The ports are split into fixed blocks, one for each tunnel address, which the relay and the setup script both follow, so the host's rules never change while the relay runs. The k-th tunnel address, counting from 0 at the network's second host address (the device holds the first), holds the ports from `first + k * size` to `first + (k + 1) * size - 1`, where `size` is `WEBVPN_IP_PORTS_PER_TUNNEL`. The relay at start and `up` both refuse a pool with more tunnel addresses than the range has blocks, so every address holds one. With `198.18.0.0/28`, `20000-20103` and 8, `198.18.0.2` holds 20000 to 20007, `198.18.0.3` holds 20008 to 20015, and so on up to `198.18.0.14`, which holds 20096 to 20103.

- **Keep the range clear of every port something on the host uses.** A new connection or datagram to the host on a port of the range goes to a tunnel, whatever listens there: the relay's carriers, its HTTP listener, or any other program. A range that holds `WEBVPN_WEBTRANSPORT_PORT`, `WEBVPN_WEBSOCKET_PORT` or `WEBVPN_HTTP_PORT` stops the program at start, with a message that names the setting; the relay cannot see the ports of other programs. `up` refuses a range that overlaps the host's local port range, where the system takes the ports of its own connections, and the relay refuses to bind a client's UDP socket or listener on a port of the range (`ADDRESS_IN_USE`).
- **The policy decides.** A tunnel is given its ports only when the policy lets the session bind every one of them, in TCP and in UDP, as for a listener, and otherwise opens with no public port. Under the default rules that means ports of `WEBVPN_MIN_BIND_PORT` and above, and a range that starts under it stops the program at start.
- **A client of the relay does not reach a tunnel's public port.** No client socket can be bound there, so a socket's connection to one of the [own addresses](#own-addresses) on such a port is refused (`REFUSED`) and its datagram is dropped. The relay drops a tunnel's packet to its own addresses, and the host drops one to its other addresses.
- **Fragments.** A datagram in fragments to a public port passes when its first fragment comes first, as the host's connection tracking sends it.
- **IPv4 only.** Tunnels have no IPv6 address yet, so they have no IPv6 public address either.

### In a container

The device lives in the host's network, so the relay's container shares it, and needs the device node `/dev/net/tun`, which a plain container does not have. Run the setup step on the host with the user the container runs as, then:

```sh
docker run --rm --network host --device /dev/net/tun --user 1000:1000 \
  -e WEBVPN_IP_DEVICE=webvpn0 -e WEBVPN_IP_POOL=198.18.0.0/28 webvpnd
```

With `--network host`, the relay binds its ports on the host itself, so no `-p` is needed.

### What a client can expect

- **Its address is private, and translated.** It is one of the network's addresses, and the host translates it to its own where packets leave. It lasts as long as the tunnel does.
- **A tunnel takes only answers.** A packet reaches the client only when it answers a flow the client sent on, or is an ICMP error about a packet it sent, or comes to one of its [public ports](#public-ports). Nothing else reaches a tunnel unasked, and nothing that answers the address's earlier holder.
- **Flows are bounded and forgotten when silent.** The relay keeps at most 3584 flows a tunnel, and forgets a flow silent for 2 minutes, 5 for UDP, and 2 hours 4 minutes for an open TCP connection. A client that needs a quiet flow kept sends on it more often than that.
- **Packets may be dropped.** A tunnel is a link that may drop, when a queue is full or a packet is refused, and nothing is sent again.

`webvpn_ip_packets_total` counts the tunnels' packets by direction, and `webvpn_ip_dropped_total` the relay's drops by reason.

## Health, readiness and metrics

The HTTP listener speaks plain HTTP, on `127.0.0.1:8080` by default. It starts after both carriers, so it answers once they serve.

| Request | Answer |
| --- | --- |
| `GET /health` | `200` and `OK`. |
| `GET /ready` | `200` and `Ready`, or `503` and `Draining` once the relay is stopping. |
| `GET /metrics` | The relay's counters in the Prometheus text format. |
| `GET /cert-hash` | The SHA-256 of the certificate in use, as a JSON array of 32 numbers, with `access-control-allow-origin: *`. |

```sh
curl http://127.0.0.1:8080/health
```

The metrics include `webvpn_active_connections_total`, the open sessions, `webvpn_active_sockets`, `webvpn_bandwidth_bytes_total` by direction, and `webvpn_handshakes_total`. No series carries a label about a client, an address or a destination.

## The load probe

The WebSocket port answers `GET /load` with the open sessions, `WEBVPN_MAX_SESSIONS` and the relay's version, as JSON:

```json
{"sessions":0,"maxSessions":1024,"version":"0.1.0"}
```

Any origin may read the answer, and nothing may cache it. The relay ignores the query string. The request takes the same TCP and TLS path as a session, so a client that times it measures the round trip its session would have. Every other request that is not a WebSocket upgrade is answered `404`.

```sh
curl -k https://127.0.0.1:8443/load
```

`-k` lets curl take the self-signed certificate.

## Stopping

On SIGTERM or SIGINT, the relay:

1. takes no new session: WebTransport refuses each arrival, the WebSocket port closes, and `/ready` answers `503`;
2. sends each open session `Draining` once, and the session keeps its sockets;
3. after `WEBVPN_DRAIN_SECONDS`, sends each session still open a `Bye` with `RESTARTING` and the reason `the relay is stopping`, then closes it with the same, which a WebSocket client also reads as close code `4004`;
4. exits with code `0`, as soon as every session has ended and at most 4 seconds after the grace. Its last log line counts the sessions it closed when the grace ran out.

## On macOS

`webvpnd` builds and runs on macOS as on Linux. A client can see these differences there:

- A UDP socket bound to one address, and not to `0.0.0.0` or `::`, ends when it disconnects from a peer, or connects while it already has one, if macOS moved it to another address. The relay answers the request first, then sends `Closed` with `ADDRESS_NOT_AVAILABLE`.
- A UDP connect that fails on a socket that already has a peer leaves the socket with no peer. On Linux the socket keeps the peer it had.
- A TTL of 0 is accepted. Linux refuses it.
- `WEBVPN_WATCH_OWN_IPV6` does nothing.
- [IP tunnels](#ip-tunnels) are not available, and their settings stop the program at start.
