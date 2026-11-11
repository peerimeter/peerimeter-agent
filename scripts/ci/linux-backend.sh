#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" -eq 0
command -v wg >/dev/null
command -v ip >/dev/null
left=pmprobe-l
right=pmprobe-r
# Never clean up resources belonging to a different run.
if ip netns list | awk '{print $1}' | grep -Eq '^pmprobe-(l|r)$'; then
  echo "Refusing to reuse existing probe namespaces" >&2
  exit 1
fi
left_created=false
right_created=false
keydir=$(mktemp -d /tmp/pmprobe.XXXXXX)
chmod 700 "$keydir"
cleanup() {
  if "$left_created"; then ip netns del "$left"; left_created=false; fi
  if "$right_created"; then ip netns del "$right"; right_created=false; fi
  rm -f "$keydir/left" "$keydir/right"
  rmdir "$keydir"
}
trap cleanup EXIT
uname -a
wg --version
ip netns add "$left"
left_created=true
ip netns add "$right"
right_created=true
ip link add pml type veth peer name pmr
ip link set pml netns "$left"
ip link set pmr netns "$right"
ip -n "$left" address add 192.0.2.1/30 dev pml
ip -n "$right" address add 192.0.2.2/30 dev pmr
ip -n "$left" link set pml up
ip -n "$right" link set pmr up
ip -n "$left" link set lo up
ip -n "$right" link set lo up
umask 077
wg genkey > "$keydir/left"
wg genkey > "$keydir/right"
leftpub=$(wg pubkey < "$keydir/left")
rightpub=$(wg pubkey < "$keydir/right")
setup_left() {
  ip -n "$left" link add pm-test type wireguard
  ip netns exec "$left" wg set pm-test private-key "$keydir/left" listen-port 51820 peer "$rightpub" allowed-ips 10.203.0.2/32 endpoint 192.0.2.2:51820
  ip -n "$left" address add 10.203.0.1/32 dev pm-test
  ip -n "$left" link set pm-test up
  ip -n "$left" route add 10.203.0.2/32 dev pm-test
}
setup_left
ip -n "$right" link add pm-test type wireguard
ip netns exec "$right" wg set pm-test private-key "$keydir/right" listen-port 51820 peer "$leftpub" allowed-ips 10.203.0.1/32 endpoint 192.0.2.1:51820
ip -n "$right" address add 10.203.0.2/32 dev pm-test
ip -n "$right" link set pm-test up
ip -n "$right" route add 10.203.0.1/32 dev pm-test
verify() {
  ip netns exec "$left" ping -n -c 3 -W 3 10.203.0.2
  ip netns exec "$right" ping -n -c 3 -W 3 10.203.0.1
  for ns in "$left" "$right"; do
    ip netns exec "$ns" wg show pm-test latest-handshakes | awk '$2 > 0 {ok=1} END {exit !ok}'
    ip netns exec "$ns" wg show pm-test transfer | awk '$2 > 0 && $3 > 0 {ok=1} END {exit !ok}'
    ip netns exec "$ns" wg show pm-test latest-handshakes
    ip netns exec "$ns" wg show pm-test transfer
  done
}
verify
echo 'PASS: native interfaces, routes, handshake, bidirectional packets'
ip -n "$left" link del pm-test
setup_left
verify
echo 'PASS: interface restart and renewed traffic'
cleanup
trap - EXIT
if ip netns list | awk '{print $1}' | grep -Eq '^pmprobe-(l|r)$'; then exit 1; fi
echo 'PASS: cleanup'
