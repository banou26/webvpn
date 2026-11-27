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
	status=0
	WEBVPN_TEST_INSIDE=1 WEBVPN_TEST_BINARY=$test unshare --map-auto --map-root-user --net --mount --pid --fork \
		--mount-proc --kill-child sh "$0" || status=$?
	rm -rf "$work"
	exit "$status"
fi

peer=
relay=
finish() {
	status=$?
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

# "The internet": a network namespace held open by a process, with the peer at 11.0.0.2. Its address is a public one
# so that the setup's rules, which drop reserved destinations, let it through; nothing leaves the namespaces.
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
# so that the peer can send to a tunnel's address straight, which the setup's rules must drop
on_peer ip route add 198.18.0.0/29 via 11.0.0.1

: >"$work/sink"
# shellcheck disable=SC2016
on_peer socat UDP-RECVFROM:7001,fork SYSTEM:'printf %s "$SOCAT_PEERADDR"' 2>/dev/null &
on_peer socat -u UDP-RECV:7002 OPEN:"$work/sink",append 2>/dev/null &
on_peer socat TCP-LISTEN:7003,fork,reuseaddr SYSTEM:true 2>/dev/null &

# The relay runs as user 1 of the namespace, which owns the device. Its binary is copied to a directory that user
# can read, on a file system of this namespace only.
WEBVPN_IP_DEVICE=webvpn0 WEBVPN_IP_POOL=198.18.0.0/29 WEBVPN_IP_USER=1 sh "$setup" up
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
env -i RUST_LOG=error WEBVPN_ADDRESS=127.0.0.1 WEBVPN_IP_DEVICE=webvpn0 WEBVPN_IP_POOL=198.18.0.0/29 \
	WEBVPN_ALLOW_PRIVATE_TARGETS=true "$@" "$work/run/webvpnd" &
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
