#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" -eq 0
helper=${1:?usage: macos-backend.sh HELPER}
dir=$(mktemp -d /tmp/peerimeter-wg.XXXXXX)
chmod 700 "$dir"
cp "$helper" "$dir/pmprobe"
cd "$dir"
wg --version
wireguard-go --version
wgpid=
refpid=
iface=
stop_tunnel() {
  if [ -n "$iface" ]; then route -n delete -host 10.203.0.2 >/dev/null 2>&1 || true; fi
  if [ -n "$wgpid" ]; then kill "$wgpid" 2>/dev/null || true; wait "$wgpid" 2>/dev/null || true; wgpid=; fi
}
cleanup() {
  result=$?
  if [ "$result" -ne 0 ]; then
    tail -n 20 "$dir/reference.log" "$dir/wireguard.log" 2>/dev/null || true
  fi
  stop_tunnel
  if [ -n "$refpid" ]; then kill "$refpid" 2>/dev/null || true; wait "$refpid" 2>/dev/null || true; fi
  rm -f "$dir/native.key" "$dir/native.pub" "$dir/reference.key" "$dir/reference.pub" "$dir/pmprobe.conf" "$dir/name"
  rm -f "$dir/pmprobe" "$dir/reference.log" "$dir/wireguard.log"
  rmdir "$dir"
}
trap cleanup EXIT
./pmprobe keygen "$dir"
./pmprobe reference "$dir" >reference.log 2>&1 &
refpid=$!
setup_tunnel() {
  rm -f "$dir/name"
  WG_TUN_NAME_FILE="$dir/name" wireguard-go -f utun >wireguard.log 2>&1 &
  wgpid=$!
  for i in {1..30}; do [ -s "$dir/name" ] && break; sleep 1; done
  iface=$(cat "$dir/name")
  wg set "$iface" private-key "$dir/native.key" listen-port 51820 peer "$(cat "$dir/reference.pub")" allowed-ips 10.203.0.2/32 endpoint 127.0.0.1:51821
  ifconfig "$iface" inet 10.203.0.1 10.203.0.1 netmask 255.255.255.255 up
  route -n add -host 10.203.0.2 -interface "$iface"
  route -n get 10.203.0.2 | awk '/interface:/ {print; found=1} END {exit !found}'
  echo "Native tunnel: $iface"
}
verify() {
  local before
  before=$(grep -c '^PASS reference' reference.log || true)
  ./pmprobe host "$dir"
  test "$(grep -c '^PASS reference' reference.log)" -gt "$before"
  wg show "$iface" latest-handshakes | awk '$2 > 0 {ok=1} END {exit !ok}'
  wg show "$iface" transfer | awk '$2 > 0 && $3 > 0 {ok=1} END {exit !ok}'
  wg show "$iface" latest-handshakes
  wg show "$iface" transfer
  tail -n 8 reference.log
}
setup_tunnel
verify
echo 'PASS: macOS native utun, route, handshake, TCP initiated in both directions'
stop_tunnel
setup_tunnel
verify
echo 'PASS: native tunnel restart and renewed traffic'
oldiface=$iface
cleanup
trap - EXIT
cd /
if ifconfig "$oldiface" >/dev/null 2>&1; then echo 'FAIL: tunnel survived cleanup'; exit 1; fi
if route -n get 10.203.0.2 | grep -q "interface: $oldiface"; then exit 1; fi
echo 'PASS: macOS cleanup'
