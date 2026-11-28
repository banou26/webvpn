#!/bin/sh
# Sets a Linux node up for webvpnd's IP tunnels, or takes that setup down. Run it as root, before the relay starts:
# the relay itself needs no privilege, it only opens the device this makes for its user.
#
#   ip-tunnel-setup.sh up      makes the device and its rules
#   ip-tunnel-setup.sh down    removes them
#
# Both are safe to run again. Set with variables:
#
#   WEBVPN_IP_DEVICE   the TUN device's name, as the relay is given it. Default: webvpn0
#   WEBVPN_IP_POOL     the device's IPv4 network, as the relay is given it, such as 198.18.0.0/16. Required for up.
#                      The device takes its first host address; the relay gives the others to tunnels.
#   WEBVPN_IP_USER     the user the relay runs as, a name or a number, which owns the device. Required for up: a
#                      device with no owner is open to every local user.
#   WEBVPN_IP_MTU      the device's MTU, at least 1280. Default: 1500
#   WEBVPN_IP_FLOWS_PER_ADDRESS
#                      the connections the kernel tracks for one tunnel address, past which a new one is dropped.
#                      Default: 4096. The relay keeps at most 3584 flows a tunnel and forgets the oldest past that, so
#                      an answer on a forgotten flow never reaches the client anyway: the default sits a little above,
#                      so that the relay's own bound acts first and this one only keeps the kernel's table bounded.
#   WEBVPN_IP_PORTS    the tunnels' public ports, as the relay is given them: a range written first-last, such as
#                      30000-39999. Unset, tunnels have none. The pool's k-th tunnel address, from 0 at the pool's
#                      second host address, holds the ports first + k * size to first + (k + 1) * size - 1, and an
#                      address whose block would pass last holds none. A TCP or UDP packet to one of the node's own
#                      addresses on one of those ports goes to the address that holds it, on the same port, and counts
#                      toward WEBVPN_IP_FLOWS_PER_ADDRESS as the tunnel's own connections do. up refuses a range that
#                      overlaps the node's local port range: keep it clear of every port something on the node uses.
#   WEBVPN_IP_PORTS_PER_TUNNEL
#                      the size of a block, as the relay is given it. Default: 8
#
# up loads one nftables table of its own, named after the device. It does not assume it is the only firewall on the
# host: another table that drops forwarded packets still drops the tunnels' packets, and has to let them through.

set -eu

device=${WEBVPN_IP_DEVICE:-webvpn0}
table=webvpn_$(printf %s "$device" | tr -c 'A-Za-z0-9_' '_')

fail() {
	echo "ip-tunnel-setup: $*" >&2
	exit 1
}

up() {
	pool=${WEBVPN_IP_POOL:?WEBVPN_IP_POOL is required, such as 198.18.0.0/16}
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
	last=${network##*.}
	address=${network%.*}.$((last + 1))
	public_ports


	ip link show dev "$device" >/dev/null 2>&1 || ip tuntap add dev "$device" mode tun user "$user"
	ip address replace "$address/$prefix" dev "$device"
	ip link set dev "$device" mtu "$mtu" up
	echo 1 >/proc/sys/net/ipv4/ip_forward

	# The reserved destinations are the relay's own egress rule (crates/webvpn-server/src/egress.rs), held again here
	# so that a relay set to reach them still does not reach them through a tunnel.
	nft -f - <<EOF
table inet $table {}
delete table inet $table
table inet $table {
	set reserved {
		type ipv4_addr
		flags interval
		elements = {
			0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24,
			192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
			224.0.0.0/4, 240.0.0.0/4
		}
	}

	set flows {
		type ipv4_addr
		size 65536
		flags dynamic
	}

$public_map
	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname "$device" oifname "$device" drop
		# until tunnels have IPv6 addresses. The relay sends no IPv6 packet until then, so no test reaches this rule
		iifname "$device" meta nfproto ipv6 drop
		iifname "$device" ip daddr @reserved drop
		iifname "$device" ct state new add @flows { ip saddr ct count over $flows } drop
		iifname "$device" accept
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
}
EOF
}

# Sets public_map, public_forward and public_prerouting to the rules of WEBVPN_IP_PORTS, empty when it is unset.
public_ports() {
	public_map= public_forward= public_prerouting=
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
	hosts=$(((1 << (32 - prefix)) - 4))
	elements=
	k=0
	while [ "$k" -le "$hosts" ] && [ $((first + (k + 1) * size - 1)) -le "$end" ]; do
		n=$((base + 2 + k))
		from=$((first + k * size))
		owner=$((n >> 24 & 255)).$((n >> 16 & 255)).$((n >> 8 & 255)).$((n & 255))
		elements="$elements $from-$((from + size - 1)) : $owner,"
		k=$((k + 1))
	done

	public_map="	map public {
		type inet_service : ipv4_addr
		flags interval
		elements = {${elements%,} }
	}
"
	public_forward="		oifname \"$device\" ct status dnat ct state new add @flows { ip daddr ct count over $flows } drop
		oifname \"$device\" ct status dnat ct state new accept"
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
