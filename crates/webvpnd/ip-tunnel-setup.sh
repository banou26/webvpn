#!/bin/sh
# Sets a Linux node up for webvpnd's IP tunnels, or takes that setup down. Run it as root, before the relay starts:
# the relay itself needs no privilege, it only opens the device this makes for its user. When IPv4 forwarding is off,
# up turns it on for the whole host, which then routes between all of its interfaces and not only the device's, and
# down leaves it on. Where forwarding is on already, the right to change the network (CAP_NET_ADMIN) and /dev/net/tun
# are all the script needs.
#
#   ip-tunnel-setup.sh up      makes the device and its rules
#   ip-tunnel-setup.sh down    removes them
#
# Both are safe to run again. up again with the same values keeps the table, what it counts and the timeouts of the
# connections the kernel tracks. With other values it loads the table again, which counts from nothing and puts the
# connections open at that moment back on the node's timeouts. To change a setting, run down, then up, with the relay
# stopped. Run down only with the relay stopped: a relay whose device went away refuses every new tunnel until it
# restarts, even once up made the device again. Set with variables:
#
#   WEBVPN_IP_DEVICE   the TUN device's name, as the relay is given it. Default: webvpn0
#   WEBVPN_IP_POOL     the device's IPv4 network, as the relay is given it, such as 198.18.0.0/28. Required for up.
#                      The device takes its first host address; the relay gives the others to tunnels.
#   WEBVPN_IP_USER     the user the relay runs as, a name or a number, which owns the device. Required for up: a
#                      device with no owner is open to every local user.
#   WEBVPN_IP_MTU      the device's MTU, at least 1280. Default: 1500
#   WEBVPN_IP_FLOWS_PER_ADDRESS
#                      the open connections the kernel tracks that one tunnel address opens, past which a new one is
#                      dropped, and apart from those, the connections to its public ports. Default: 4096. The relay
#                      keeps at most 3584 flows a tunnel and forgets flows past that, so an answer on a forgotten
#                      flow never reaches the client anyway: the default sits a little above, so that the relay's own
#                      bound acts first. Those connections outlast their tunnel, so the pool's tunnel addresses times
#                      this, plus the addresses that hold public ports times it, is what the tunnels' open connections
#                      can take of the kernel's table, which every program on the node shares: up refuses more than
#                      half of nf_conntrack_max. It counts only its own pool: on a host with several setups, size their
#                      pools and ceilings so that together they stay under half. A TCP connection stops counting once
#                      it closes. The kernel keeps it for the node's TIME_WAIT timeout
#                      (nf_conntrack_tcp_timeout_time_wait, 2 minutes by default), as it keeps every closed connection
#                      on the node. So an address that opens and closes connections fast holds more.
#   WEBVPN_IP_PORTS    the tunnels' public ports, as the relay is given them: a range written first-last, such as
#                      20000-29999. Unset, tunnels have none. The pool's k-th tunnel address, from 0 at the pool's
#                      second host address, holds the ports first + k * size to first + (k + 1) * size - 1, and up
#                      refuses, as the relay does, a pool with more tunnel addresses than blocks. A TCP or UDP packet
#                      to one of the node's own addresses on one of those ports goes to the address that holds it, on
#                      the same port. Those connections count toward a ceiling of WEBVPN_IP_FLOWS_PER_ADDRESS of their
#                      own, apart from the tunnel's own. up refuses a range that overlaps the node's local port range:
#                      keep it clear of every port something on the node uses.
#   WEBVPN_IP_PORTS_PER_TUNNEL
#                      the size of a block, as the relay is given it. Default: 8
#
# up loads one nftables table of its own, named after the device, which needs a kernel with connection tracking timeout
# policies (CONFIG_NF_CONNTRACK_TIMEOUT). The table's comment needs kernel 5.10 and nft 0.9.7 or later. It does not
# assume it is the only firewall on the host: another table that drops forwarded packets still drops the tunnels'
# packets, and has to let them through.

set -eu

device=${WEBVPN_IP_DEVICE:-webvpn0}
table=webvpn_$(printf %s "$device" | tr -c 'A-Za-z0-9_' '_')

fail() {
	echo "ip-tunnel-setup: $*" >&2
	exit 1
}

up() {
	pool=${WEBVPN_IP_POOL:?WEBVPN_IP_POOL is required, such as 198.18.0.0/28}
	user=${WEBVPN_IP_USER:?WEBVPN_IP_USER is required: the user the relay runs as}
	mtu=${WEBVPN_IP_MTU:-1500}
	flows=${WEBVPN_IP_FLOWS_PER_ADDRESS:-4096}
	case $flows in
	'' | *[!0-9]*) fail "WEBVPN_IP_FLOWS_PER_ADDRESS is not a number" ;;
	esac
	case $pool in
	*.*.*.*/*) ;;
	*) fail "WEBVPN_IP_POOL is not an IPv4 network written with its prefix length" ;;
	esac
	network=${pool%/*}
	prefix=${pool#*/}
	case $prefix in
	[89] | [12][0-9] | 30) ;;
	*) fail "WEBVPN_IP_POOL's prefix length is not 8 to 30" ;;
	esac
	last=${network##*.}
	address=${network%.*}.$((last + 1))
	# every address of the network but its own, the device's and the broadcast one
	addresses=$(((1 << (32 - prefix)) - 3))
	public_ports

	# without connection tracking timeout policies the kernel refuses the whole table, and nft would not say why. The
	# probe loads connection tracking too, whose size is read next.
	nft -f - <<EOF || fail "nft could not load a connection tracking timeout policy: run up as root, with nftables \
installed, on a kernel with CONFIG_NF_CONNTRACK_TIMEOUT"
table inet ${table}_probe { ct timeout probe { protocol tcp; l3proto ip; }; }
delete table inet ${table}_probe
EOF
	# The kernel keeps a tunnel's connections past the tunnel, so each address may hold its ceiling of open ones, and
	# each address that holds public ports that many again: that is what the tunnels can take of a table every program
	# on the node shares, and half of it stays for the others when this is the host's only setup.
	max=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
	[ $(((addresses + holders) * flows)) -le $((max / 2)) ] ||
		fail "the pool's $addresses tunnel addresses, plus the $holders that hold public ports, times \
WEBVPN_IP_FLOWS_PER_ADDRESS, $flows, is more than half of the node's nf_conntrack_max, $max: take a smaller pool, \
a lower ceiling or no public ports, or raise nf_conntrack_max"

	ip link show dev "$device" >/dev/null 2>&1 || ip tuntap add dev "$device" mode tun user "$user"
	ip address replace "$address/$prefix" dev "$device"
	# an earlier up's other pool goes: the relay reads only the device's first IPv4 address
	ip -4 -o address show dev "$device" | while read -r _ _ _ held _; do
		[ "$held" = "$address/$prefix" ] || ip address delete "$held" dev "$device"
	done
	ip link set dev "$device" mtu "$mtu" up
	# only when it is off: where it is on already, the step then needs no more than the right to change the network
	[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || echo 1 >/proc/sys/net/ipv4/ip_forward

	# The reserved destinations are the relay's own egress rule (crates/webvpn-server/src/egress.rs), held again here
	# so that a relay set to reach them still does not reach them through a tunnel.
	rules=$(cat <<EOF
	set reserved {
		type ipv4_addr
		flags interval
		elements = {
			0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24,
			192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
			224.0.0.0/4, 240.0.0.0/4
		}
	}

	# room for two elements a key: an element whose count fell to 0 takes room until the kernel frees it, and a full set
	# lets a new connection pass uncounted
	set flows {
		type ipv4_addr
		size $((2 * addresses))
		flags dynamic
	}

	# as long as the relay keeps a quiet open TCP flow (TCP_OPEN_LIFE in crates/webvpn-server/src/flow.rs), where the
	# node's default is 5 days: a closed tunnel's connections count toward the ceilings of the next tunnel at its
	# address. The other states keep the node's timeouts, time_wait above all: the masquerade picks a port only clear
	# of the tracked connections, so a shorter one lets it reuse a 4-tuple that a server still holds in TIME_WAIT.
	ct timeout tunnel {
		protocol tcp
		l3proto ip
		policy = { established: 7440 }
	}

$public_map
	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname "$device" oifname "$device" drop
		# until tunnels have IPv6 addresses. The relay sends no IPv6 packet until then, so no test reaches this rule
		iifname "$device" meta nfproto ipv6 drop
		iifname "$device" ip daddr @reserved drop
		iifname "$device" ct state new add @flows { ip saddr ct count over $flows } drop
		# the masquerade below translates no packet connection tracking calls invalid: it would leave with the pool's
		# address as its source
		iifname "$device" ct state invalid drop
		# the kernel takes a connection's timeout policy from its first packet only
		iifname "$device" ct timeout set "tunnel" accept
		oifname "$device" ct state established,related accept
$public_forward
		oifname "$device" drop
	}

	chain input {
		type filter hook input priority filter; policy accept;
		iifname "$device" drop
	}

$public_prerouting
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr $pool oifname != "$device" masquerade
	}
EOF
	)
	# A table loaded again counts the ceilings from nothing, and the kernel takes the old one's timeout policy off every
	# connection that holds it, which then gets the node's timeout, 5 days by default, at its next packet: a table
	# that holds the same rules stays, and its comment says which they are.
	sum=$(printf %s "$rules" | cksum)
	nft list table inet "$table" 2>/dev/null | grep -qF "comment \"$sum\"" && return 0
	nft -f - <<EOF
table inet $table {}
delete table inet $table
table inet $table {
	comment "$sum"
$rules
}
EOF
}

# Sets public_map, public_forward and public_prerouting to the rules of WEBVPN_IP_PORTS, empty when it is unset, and
# holders to the tunnel addresses that hold ports.
public_ports() {
	public_map= public_forward= public_prerouting= holders=0
	range=${WEBVPN_IP_PORTS:-}
	[ -n "$range" ] || return 0
	size=${WEBVPN_IP_PORTS_PER_TUNNEL:-8}
	first=${range%-*}
	end=${range#*-}
	case $range:$size in
	[1-9]*-[1-9]*:[1-9]*) ;;
	*) fail "WEBVPN_IP_PORTS is not written first-last, or WEBVPN_IP_PORTS_PER_TUNNEL is not a number above 0" ;;
	esac
	case $first$end$size in
	*[!0-9]*) fail "WEBVPN_IP_PORTS is not written first-last, or WEBVPN_IP_PORTS_PER_TUNNEL is not a number above 0" ;;
	esac
	[ "$first" -le "$end" ] && [ "$end" -le 65535 ] || fail "WEBVPN_IP_PORTS is not a range of ports from 1 to 65535"
	[ "$size" -le $((end - first + 1)) ] || fail "WEBVPN_IP_PORTS_PER_TUNNEL is more than the ports of WEBVPN_IP_PORTS"
	# the relay refuses the same: it gives every address in turn, so one past the last block would get no port
	blocks=$(((end - first + 1) / size))
	[ "$blocks" -ge "$addresses" ] ||
		fail "WEBVPN_IP_POOL holds $addresses tunnel addresses and WEBVPN_IP_PORTS only $blocks blocks: make the \
pool smaller or the range larger, so that every address holds a block"
	# through cat: dash reads a file a byte at a time, and a sysctl file gives a read past its start nothing
	local_ports=$(cat /proc/sys/net/ipv4/ip_local_port_range)
	low=${local_ports%%[!0-9]*}
	high=${local_ports##*[!0-9]}
	# a datagram nobody asked for, to a socket the node bound there, would reach a tunnel
	[ "$first" -gt "$high" ] || [ "$end" -lt "$low" ] ||
		fail "WEBVPN_IP_PORTS overlaps the node's local port range, $low-$high: move it clear of that range"

	saved=$IFS
	IFS=.
	# shellcheck disable=SC2086
	set -- $network
	IFS=$saved
	base=$((($1 << 24) + ($2 << 16) + ($3 << 8) + $4))
	elements=
	k=0
	while [ "$k" -lt "$addresses" ]; do
		n=$((base + 2 + k))
		from=$((first + k * size))
		owner=$((n >> 24 & 255)).$((n >> 16 & 255)).$((n >> 8 & 255)).$((n & 255))
		elements="$elements $from-$((from + size - 1)) : $owner,"
		k=$((k + 1))
	done
	holders=$k

	public_map="	map public {
		type inet_service : ipv4_addr
		flags interval
		elements = {${elements%,} }
	}

	# as flows: twice the keys
	set inbound {
		type ipv4_addr
		size $((2 * holders))
		flags dynamic
	}
"
	# a count of their own: anyone can open these, and in the tunnel's count they would stop its own connections
	public_forward="
		oifname \"$device\" ct status dnat ct state new add @inbound { ip daddr ct count over $flows } drop
		oifname \"$device\" ct status dnat ct state new ct timeout set \"tunnel\" accept"
	public_prerouting="	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname != \"$device\" fib daddr type local ip protocol { tcp, udp } dnat ip to th dport map @public
	}
"
}

# Forwarding stays on: other things on the host may need it.
down() {
	if nft list table inet "$table" >/dev/null 2>&1; then
		nft delete table inet "$table"
	fi
	if ip link show dev "$device" >/dev/null 2>&1; then
		ip link delete dev "$device"
	fi
}

case ${1:-} in
up) up ;;
down) down ;;
*) fail "usage: $0 up|down" ;;
esac
