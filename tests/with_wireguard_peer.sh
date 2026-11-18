#!/usr/bin/env bash
set -euo pipefail
umask 077

work=$(mktemp -d)
peer_ns="runman-wg-$$"
host_link="rwg$$"
peer_created=0
link_created=0
http_pid=
cleanup() {
    if [ -n "$http_pid" ]; then kill "$http_pid" 2>/dev/null || true; fi
    if [ "$link_created" = 1 ]; then ip link del "$host_link" 2>/dev/null || true; fi
    if [ "$peer_created" = 1 ]; then ip netns del "$peer_ns" 2>/dev/null || true; fi
    rm -rf "$work"
}
trap cleanup EXIT

wg genkey >"$work/server.key"
wg genkey >"$work/client.key"
server_public=$(wg pubkey <"$work/server.key")
client_public=$(wg pubkey <"$work/client.key")

ip netns add "$peer_ns"
peer_created=1
ip link add "$host_link" type veth peer name underlay netns "$peer_ns"
link_created=1
ip addr add 198.18.97.1/30 dev "$host_link"
ip link set "$host_link" up
ip -n "$peer_ns" addr add 198.18.97.2/30 dev underlay
ip -n "$peer_ns" link set underlay up
ip -n "$peer_ns" link set lo up
ip -n "$peer_ns" link add tunnel type wireguard
ip netns exec "$peer_ns" wg set tunnel private-key "$work/server.key" listen-port 51820 \
    peer "$client_public" allowed-ips 198.19.97.2/32
ip -n "$peer_ns" addr add 198.19.97.1/32 dev tunnel
ip -n "$peer_ns" link set tunnel up
ip -n "$peer_ns" route add 198.19.97.2/32 dev tunnel

ip netns exec "$peer_ns" python3 - <<'PY' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class SpeedFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(10_000_000))
        self.end_headers()
        self.wfile.write(b"x" * 10_000_000)

    def do_POST(self):
        remaining = int(self.headers["Content-Length"])
        while remaining:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                return
            remaining -= len(chunk)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

ThreadingHTTPServer(("198.18.97.2", 18080), SpeedFixture).serve_forever()
PY
http_pid=$!

cat >"$work/client.conf" <<EOF
[Interface]
PrivateKey = $(cat "$work/client.key")
Address = 198.19.97.2/32
[Peer]
PublicKey = $server_public
Endpoint = 198.18.97.2:51820
AllowedIPs = 198.19.97.1/32
PersistentKeepalive = 1
EOF
RUNMAN_TEST_LOCAL_WG_CONF="$work/client.conf" RUNMAN_TEST_LOCAL_WG_NS="$peer_ns" \
    RUNMAN_TEST_SPEED_BASE=http://198.18.97.2:18080 "$@"
