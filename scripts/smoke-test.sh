#!/bin/bash
# Run as root on the dedicated VPN host. Creates and cleans a temporary namespace/peer.
# Verifies encrypted handshake -> forwarding/NAT -> internet without exposing keys.
set -euo pipefail
umask 077
if [ "$(id -u)" -ne 0 ]; then echo 'Run as root' >&2; exit 1; fi
NS=vpn-smoke
if ip netns list | grep -q "^$NS\b"; then echo 'Smoke namespace already exists' >&2; exit 1; fi
DIR=$(mktemp -d /run/vpn-smoke.XXXXXX)
PUBLIC=''
cleanup() {
  if [ -n "$PUBLIC" ]; then wg set wg0 peer "$PUBLIC" remove; fi
  ip netns del "$NS" 2>/dev/null || true
  ip link del vpn-smoke-host 2>/dev/null || true
  rm -rf -- "$DIR"
}
trap cleanup EXIT
if wg show wg0 allowed-ips | grep -q '10.66.66.254/32'; then
  echo 'Slot 254 in use; revoke or change smoke test slot before running' >&2
  exit 1
fi
wg genkey > "$DIR/client.key"
PUBLIC=$(wg pubkey < "$DIR/client.key")
SERVER=$(wg show wg0 public-key)
wg set wg0 peer "$PUBLIC" allowed-ips 10.66.66.254/32,fd42:66:66::fe/128
ip netns add "$NS"
ip link add vpn-smoke-host type veth peer name vpn-smoke-peer
ip link set vpn-smoke-peer netns "$NS"
ip addr add 192.0.2.1/30 dev vpn-smoke-host
ip link set vpn-smoke-host up
ip -n "$NS" addr add 192.0.2.2/30 dev vpn-smoke-peer
ip -n "$NS" link set vpn-smoke-peer up
ip -n "$NS" link set lo up
ip -n "$NS" link add wgtest type wireguard
ip netns exec "$NS" wg set wgtest private-key "$DIR/client.key" peer "$SERVER" endpoint 192.0.2.1:51820 allowed-ips 0.0.0.0/0,::/0
ip -n "$NS" addr add 10.66.66.254/32 dev wgtest
ip -n "$NS" -6 addr add fd42:66:66::fe/128 dev wgtest
ip -n "$NS" link set wgtest mtu 1280 up
ip -n "$NS" route add default dev wgtest
ip -n "$NS" -6 route add default dev wgtest
TARGET=$(getent ahostsv4 checkip.amazonaws.com | awk 'NR==1 {print $1}')
EXPECTED=$(curl --fail --silent --show-error --max-time 15 -4 https://checkip.amazonaws.com)
ACTUAL=$(ip netns exec "$NS" curl --fail --silent --show-error --max-time 20 -4 --resolve "checkip.amazonaws.com:443:$TARGET" https://checkip.amazonaws.com)
test "$ACTUAL" = "$EXPECTED"
echo "PASS: encrypted client internet egress = $ACTUAL"
ip netns exec "$NS" python3 - <<'PY'
import random
import socket
import struct
transaction = random.randrange(65536)
question = b'\x07example\x03com\x00' + struct.pack('!HH', 1, 1)
packet = struct.pack('!6H', transaction, 0x100, 1, 0, 0, 0) + question
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(10)
    sock.sendto(packet, ('1.1.1.1', 53))
    response = sock.recv(4096)
    assert struct.unpack('!H', response[:2])[0] == transaction
    assert response[3] & 15 == 0
print('PASS: DNS through encrypted tunnel')
PY
if ip netns exec "$NS" curl --silent --output /dev/null --max-time 3 http://169.254.169.254/latest/meta-data/; then
  echo 'FAIL: metadata reachable' >&2; exit 1
fi
if ip netns exec "$NS" curl --silent --output /dev/null --max-time 3 -g 'http://[2606:4700:4700::1111]/'; then
  echo 'FAIL: IPv6 unexpectedly routed' >&2; exit 1
fi
echo 'PASS: metadata access and IPv6 forwarding blocked'
