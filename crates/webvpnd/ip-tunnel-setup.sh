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
#   WEBVPN_IP_OUT      the interface tunnels' packets leave by, translated to its address. Default: the interface of
#                      the default IPv4 route.
#
# up loads one nftables table of its own, named after the device. It does not assume it is the only firewall on the
# host: another table that drops forwarded packets still drops the tunnels' packets, and has to let them through.

set -eu

# The connections the kernel tracks for one tunnel address. The relay keeps at most 3584 flows a tunnel and forgets
# the oldest past that, so an answer on a forgotten flow never reaches the client anyway: this sits a little above,
# so that the relay's own bound acts first and this one only keeps the kernel's table bounded.
FLOWS_PER_ADDRESS=4096

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
	out=${WEBVPN_IP_OUT:-$(ip -4 route show default | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')}
	[ -n "$out" ] || fail "no default IPv4 route: set WEBVPN_IP_OUT"
	case $pool in
	*.*.*.*/*) ;;
	*) fail "WEBVPN_IP_POOL is not an IPv4 network written with its prefix length" ;;
	esac
	network=${pool%/*}
	prefix=${pool#*/}
	last=${network##*.}
	address=${network%.*}.$((last + 1))

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

	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname "$device" oifname "$device" drop
		iifname "$device" ip daddr @reserved drop
		iifname "$device" ct state new add @flows { ip saddr ct count over $FLOWS_PER_ADDRESS } drop
		iifname "$device" accept
		oifname "$device" ct state established,related accept
		oifname "$device" drop
	}

	chain input {
		type filter hook input priority filter; policy accept;
		iifname "$device" drop
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr $pool oifname "$out" masquerade
	}
}
EOF
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
