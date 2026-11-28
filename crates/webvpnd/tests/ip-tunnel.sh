#!/bin/sh
# Runs webvpnd's IP tunnels over a real TUN device and a real network, with no change to the host: everything runs in
# a user, network, mount and process namespace of its own (`unshare`), where the script is root for that namespace
# only. The relay's host and "the internet" are two network namespaces joined by a veth pair. When the script ends,
# however it ends, the namespaces and every process in them go, and its files under target/ are removed.
#
# Needs: unshare (with entries in /etc/subuid and /etc/subgid for the calling user, so the namespace has a user other
# than root to run the relay as), nsenter, setpriv, ip, nft and socat, and a kernel with nftables, connection tracking
# and NAT. From the repository's root:
#
#   sh crates/webvpnd/tests/ip-tunnel.sh
#
# When a check fails, the script prints the relay's log and counters, the connections the kernel tracks (with
# conntrack, when it is installed), the rules with their counters, the neighbours and the peer's sockets. With
# WEBVPN_TEST_CAPTURE set to a directory, it also captures, with tcpdump, every interface the tunnels' packets cross,
# into one file each there:
#
#   WEBVPN_TEST_CAPTURE=target/ip-tunnel-capture sh crates/webvpnd/tests/ip-tunnel.sh

set -eu

root=$(cd "$(dirname "$0")/../../.." && pwd)
work=$root/target/ip-tunnel-test
setup=$root/crates/webvpnd/ip-tunnel-setup.sh

if [ "${WEBVPN_TEST_INSIDE:-}" != 1 ]; then
	for tool in unshare nsenter setpriv ip nft socat; do
		command -v "$tool" >/dev/null || { echo "ip-tunnel.sh needs $tool" >&2; exit 1; }
	done
	cd "$root"
	cargo build -q -p webvpnd --bin webvpnd
	test=$(cargo test -q -p webvpnd --test ip_tunnel --no-run --message-format=json | grep '"name":"ip_tunnel"' |
		sed -n 's/.*"executable":"\([^"]*\)".*/\1/p')
	[ -x "$test" ] || { echo "the ip_tunnel test did not build" >&2; exit 1; }
	rm -rf "$work"
	mkdir -p "$work"
	if [ -n "${WEBVPN_TEST_CAPTURE:-}" ]; then
		command -v tcpdump >/dev/null || { echo "a capture needs tcpdump" >&2; exit 1; }
		mkdir -p "$WEBVPN_TEST_CAPTURE"
		WEBVPN_TEST_CAPTURE=$(cd "$WEBVPN_TEST_CAPTURE" && pwd)
		export WEBVPN_TEST_CAPTURE
	fi
	status=0
	WEBVPN_TEST_INSIDE=1 WEBVPN_TEST_BINARY=$test unshare --map-auto --map-root-user --net --mount --pid --fork \
		--mount-proc --kill-child sh "$0" || status=$?
	rm -rf "$work"
	exit "$status"
fi

peer=
relay=
captures=
# What the host held when a check failed: the relay's log and counters, the connections the kernel tracks, the rules
# with their counters, the neighbours and the peer's sockets.
evidence() {
	echo "--- the relay's log"
	cat "$work/relay.log" 2>/dev/null || true
	echo "--- the relay's counters"
	# the sleep keeps the request's side open: the relay drops a connection whose client closed its half
	{ printf 'GET /metrics HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n' && sleep 1; } |
		socat - TCP:127.0.0.1:8080 2>&1 | grep '^webvpn_' || true
	echo "--- the connections the host tracks"
	conntrack -L 2>&1 || true
	echo "--- the host's rules"
	nft list ruleset 2>&1 || true
	echo "--- the neighbours of the host, then of the peer"
	ip neigh 2>&1 || true
	[ -z "$peer" ] || on_peer ip neigh 2>&1 || true
	echo "--- the peer's sockets"
	[ -z "$peer" ] || on_peer ss -uatn 2>&1 || true
}
finish() {
	status=$?
	[ "$status" = 0 ] || evidence >&2
	[ -z "$captures" ] || kill $captures 2>/dev/null || true
	[ -z "$captures" ] || wait $captures 2>/dev/null || true
	[ -z "$relay" ] || kill "$relay" 2>/dev/null || true
	sh "$setup" down || status=1
	if ip link show dev webvpn0 >/dev/null 2>&1 || nft list table inet webvpn_webvpn0 >/dev/null 2>&1; then
		echo "the setup's down left something behind" >&2
		status=1
	fi
	[ -z "$peer" ] || kill "$peer" 2>/dev/null || true
	exit "$status"
}
trap finish EXIT
trap 'exit 1' INT TERM

ip link set lo up

# "The internet": a network namespace held open by a process, with the peer at 11.0.0.2 behind the default route and at
# 12.0.0.2 behind a second interface. Its addresses are public ones so that the setup's rules, which drop reserved
# destinations, let them through; nothing leaves the namespaces.
unshare --net sleep 1000000 &
peer=$!
sleep 0.2
on_peer() {
	nsenter --net=/proc/$peer/ns/net "$@"
}
ip link add out0 type veth peer name peer0
ip link set peer0 netns "$peer"
ip address add 11.0.0.1/24 dev out0
ip link set out0 up
ip route add default via 11.0.0.2 dev out0
on_peer ip link set lo up
on_peer ip address add 11.0.0.2/24 dev peer0
on_peer ip link set peer0 up
ip link add out1 type veth peer name peer1
ip link set peer1 netns "$peer"
ip address add 12.0.0.1/24 dev out1
ip link set out1 up
on_peer ip address add 12.0.0.2/24 dev peer1
on_peer ip link set peer1 up
# so that the peer can send to a tunnel's address straight, which the setup's rules must drop
on_peer ip route add 198.18.0.0/29 via 11.0.0.1
# a private address the peer answers on, which only the setup's reserved destinations keep tunnels from
on_peer ip address add 10.0.0.2/32 dev lo

: >"$work/sink"
on_peer socat -u UDP-RECV:7002 OPEN:"$work/sink",append 2>/dev/null &
on_peer socat TCP-LISTEN:7003,fork,reuseaddr SYSTEM:true 2>/dev/null &

# The relay runs as user 1 of the namespace, which owns the device. Its binary is copied to a directory that user
# can read, on a file system of this namespace only.
# A range of public ports in the node's local port range is refused, and nothing is made.
if WEBVPN_IP_POOL=198.18.0.0/29 WEBVPN_IP_USER=1 WEBVPN_IP_PORTS=40000-40031 sh "$setup" up 2>"$work/refused"; then
	echo "the setup took public ports in the local port range" >&2
	exit 1
fi
grep -q "overlaps the node's local port range" "$work/refused" || { cat "$work/refused" >&2; exit 1; }
! ip link show dev webvpn0 >/dev/null 2>&1 || { echo "the refused setup made the device" >&2; exit 1; }
echo "ok: public ports in the local port range are refused"

# Four tunnel addresses hold 8 public ports each, 198.18.0.2 from 30000 on, and the fifth, 198.18.0.6, none.
WEBVPN_IP_DEVICE=webvpn0 WEBVPN_IP_POOL=198.18.0.0/29 WEBVPN_IP_USER=1 WEBVPN_IP_FLOWS_PER_ADDRESS=8 \
	WEBVPN_IP_PORTS=30000-30031 sh "$setup" up

if [ -n "${WEBVPN_TEST_CAPTURE:-}" ]; then
	for at in host:webvpn0 host:out0 host:out1 peer:peer0 peer:peer1; do
		device=${at#*:}
		log=$work/$device.capture
		if [ "${at%:*}" = peer ]; then
			on_peer tcpdump -Z root -U -n -i "$device" -w "$WEBVPN_TEST_CAPTURE/$device.pcap" 2>"$log" &
		else
			tcpdump -Z root -U -n -i "$device" -w "$WEBVPN_TEST_CAPTURE/$device.pcap" 2>"$log" &
		fi
		captures="$captures $!"
		tries=0
		until grep -q listening "$log" 2>/dev/null; do
			tries=$((tries + 1))
			[ "$tries" -lt 50 ] || { echo "the capture on $device did not start" >&2; exit 1; }
			sleep 0.1
		done
	done
fi

mkdir -p "$work/run"
mount -t tmpfs tmpfs "$work/run"
cp "$root/target/debug/webvpnd" "$work/run/webvpnd"
chmod 755 "$work/run" "$work/run/webvpnd"
if setpriv --reuid=1 --regid=1 --clear-groups --inh-caps=-all --bounding-set=-all true 2>/dev/null; then
	set -- "$(command -v setpriv)" --reuid=1 --regid=1 --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs
	echo "webvpnd runs as user 1 of the namespace, with no capability"
else
	set --
	echo "webvpnd runs as root of the namespace: this system gives the namespace no other user"
fi
# A relay given another network than the device's, or the same one with another prefix length, does not start.
for pool in 198.18.0.8/29 198.18.0.0/28; do
	timeout 5 env -i WEBVPN_ADDRESS=127.0.0.1 WEBVPN_IP_DEVICE=webvpn0 WEBVPN_IP_POOL=$pool "$@" "$work/run/webvpnd" \
		>"$work/refused" 2>&1 || true
	grep -q "does not hold the relay's network" "$work/refused" || { cat "$work/refused" >&2; exit 1; }
	! grep -q "198\.18" "$work/refused" || { echo "the refusal names an address" >&2; exit 1; }
done
echo "ok: a relay given another pool than the device's does not start"

# The test's one session holds all five tunnel addresses at once.
env -i RUST_LOG=error WEBVPN_ADDRESS=127.0.0.1 WEBVPN_IP_DEVICE=webvpn0 WEBVPN_IP_POOL=198.18.0.0/29 \
	WEBVPN_IP_PORTS=30000-30031 WEBVPN_OWN_ADDRESSES=11.0.0.1 WEBVPN_ALLOW_PRIVATE_TARGETS=true \
	WEBVPN_MAX_TUNNELS_PER_SESSION=5 "$@" "$work/run/webvpnd" >"$work/relay.log" 2>&1 &
relay=$!

tries=0
until socat -u OPEN:/dev/null TCP:127.0.0.1:8080 2>/dev/null; do
	tries=$((tries + 1))
	[ "$tries" -lt 50 ] || { echo "webvpnd did not start" >&2; exit 1; }
	kill -0 "$relay" 2>/dev/null || { echo "webvpnd stopped" >&2; exit 1; }
	sleep 0.1
done

WEBVPN_TEST_PEER_NETNS=/proc/$peer/ns/net WEBVPN_TEST_SINK=$work/sink "$WEBVPN_TEST_BINARY" --ignored --nocapture \
	--test-threads=1 2>&1

# The device removed while the relay runs: the relay says so, since it refuses tunnels from then on, and serves on.
sh "$setup" down
tries=0
until grep -q "the TUN device failed" "$work/relay.log"; do
	tries=$((tries + 1))
	[ "$tries" -lt 30 ] || { echo "the relay did not log the device's loss" >&2; exit 1; }
	sleep 0.1
done
kill -0 "$relay" 2>/dev/null || { echo "webvpnd stopped with its device" >&2; exit 1; }
echo "ok: a device removed while the relay runs is logged"
