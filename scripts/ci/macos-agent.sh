#!/usr/bin/env bash
# Exercise the actual agent, its embedded utun backend, protected IPC and launchd.
set -euo pipefail
test "$(id -u)" -eq 0
agent_source=${1:?usage: macos-agent.sh AGENT HELPER}
helper_source=${2:?usage: macos-agent.sh AGENT HELPER}
test ! -e /Library/LaunchDaemons/com.peerimeter.agent.plist
dir=$(mktemp -d /tmp/pmagent.XXXXXX)
chmod 700 "$dir"
install -m 0755 "$agent_source" "$dir/peerimeter-agent"
install -m 0755 "$helper_source" "$dir/pmprobe"
agent=$dir/peerimeter-agent
helper=$dir/pmprobe
config=$dir/agent.json
state=$dir/state
fgpid=
refpid=
service_installed=false
cleanup() {
  result=$?
  if "$service_installed"; then "$agent" service uninstall >/dev/null 2>&1 || true; fi
  if [ -n "$fgpid" ]; then kill "$fgpid" 2>/dev/null || true; wait "$fgpid" 2>/dev/null || true; fi
  if [ -n "$refpid" ]; then kill "$refpid" 2>/dev/null || true; wait "$refpid" 2>/dev/null || true; fi
  if [ "$result" -ne 0 ]; then
    tail -n 30 "$dir/agent.log" "$dir/reference.log" 2>/dev/null || true
  fi
  # This unique directory contains only this run's temporary credentials/state.
  rm -rf "$dir"
}
trap cleanup EXIT
"$helper" keygen "$dir"
python3 - "$dir" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
config = {
    'version': 1, 'mode': 'static',
    'network': {'id': 'native-agent-macos', 'name': 'native-agent-macos'},
    'interface': {'private_key_file': str(root / 'native.key'), 'address': ['10.203.0.1/32'], 'listen_port': 51820},
    'peers': [{'public_key': (root / 'reference.pub').read_text().strip(), 'allowed_ips': ['10.203.0.2/32'], 'endpoint': '127.0.0.1:51821', 'persistent_keepalive_seconds': 25}],
}
path = root / 'agent.json'
path.write_text(json.dumps(config))
path.chmod(0o600)
PY
"$helper" reference "$dir" >"$dir/reference.log" 2>&1 &
refpid=$!
wait_status() {
  local attempt
  for attempt in {1..30}; do
    if "$agent" status --state-dir "$state" >"$dir/status.json" 2>/dev/null; then
      if python3 - "$dir/status.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s['state'] == 'running' and s['interface_name'].startswith('utun')
PY
      then return 0; fi
    fi
    if [ -n "$fgpid" ] && ! kill -0 "$fgpid" 2>/dev/null; then
      echo 'FAIL: foreground agent exited before IPC became available' >&2
      return 1
    fi
    sleep 1
  done
  echo 'FAIL: agent local IPC did not become available' >&2
  return 1
}
interface_name() {
  "$agent" status --state-dir "$state" >"$dir/status.json"
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["interface_name"])' "$dir/status.json"
}
verify_traffic() {
  local before after iface
  before=$(grep -c '^PASS reference' "$dir/reference.log" || true)
  "$helper" host "$dir"
  after=$(grep -c '^PASS reference' "$dir/reference.log" || true)
  test "$after" -gt "$before"
  "$agent" peers --state-dir "$state" >"$dir/peers.json"
  python3 - "$dir/peers.json" <<'PY'
import calendar, json, sys, time
peers = json.load(open(sys.argv[1]))
assert len(peers) == 1
p = peers[0]
stamp = calendar.timegm(time.strptime(p['last_handshake'][:19], '%Y-%m-%dT%H:%M:%S'))
assert abs(time.time() - stamp) < 120, 'missing fresh authenticated handshake'
assert p['received_bytes'] > 0 and p['sent_bytes'] > 0, 'missing real tunnel traffic'
print('PASS: actual agent reports fresh handshake and received/sent encrypted traffic')
PY
  iface=$(interface_name)
  /sbin/route -n get -host 10.203.0.2 | awk -v expected="$iface" '/interface:/ {if ($2 == expected) found=1} END {exit !found}'
  if /sbin/ifconfig | grep -Eq 'inet 10\.203\.0\.2([[:space:]]|$)'; then
    echo 'FAIL: reference tunnel IP was assigned to the host network stack' >&2
    return 1
  fi
}
verify_unchanged() {
  "$agent" status --state-dir "$state" >"$dir/status-after.json"
  python3 - "$dir/status-before.json" "$dir/status-after.json" <<'PY'
import json, sys
before, after = [json.load(open(p)) for p in sys.argv[1:]]
assert after['interface_name'] == before['interface_name'], 'interface recreated during peer reconciliation'
a, b = after['peers'][0], before['peers'][0]
assert a['last_handshake'] == b['last_handshake'], 'unchanged peer session reset during reconciliation'
assert a['received_bytes'] >= b['received_bytes'] and a['sent_bytes'] >= b['sent_bytes'], 'peer counters reset'
PY
}
verify_removed() {
  local old=$1 attempt
  for attempt in {1..30}; do
    if ! /sbin/ifconfig "$old" >/dev/null 2>&1; then break; fi
    sleep 1
  done
  if /sbin/ifconfig "$old" >/dev/null 2>&1; then echo 'FAIL: native utun survived shutdown' >&2; return 1; fi
  if /sbin/route -n get -host 10.203.0.2 2>/dev/null | awk -v expected="$old" '/interface:/ {if ($2 == expected) found=1} END {exit !found}'; then
    echo 'FAIL: owned route survived shutdown' >&2
    return 1
  fi
}
start_foreground() {
  "$agent" run --config "$config" --state-dir "$state" >"$dir/agent.log" 2>&1 &
  fgpid=$!
  wait_status
}
stop_foreground() {
  local iface attempt
  iface=$(interface_name)
  "$agent" stop --state-dir "$state"
  for attempt in {1..30}; do
    if ! kill -0 "$fgpid" 2>/dev/null; then break; fi
    sleep 1
  done
  if kill -0 "$fgpid" 2>/dev/null; then echo 'FAIL: foreground agent did not stop' >&2; return 1; fi
  wait "$fgpid"
  fgpid=
  verify_removed "$iface"
}
start_foreground
verify_traffic
"$agent" status --state-dir "$state" >"$dir/status-before.json"
"$agent" sync --state-dir "$state"
verify_unchanged
echo 'PASS: unchanged config reconciliation preserves actual utun and peer session'
cp "$config" "$dir/good.json"
printf '{"version":' >"$config"
if "$agent" sync --state-dir "$state" >"$dir/rejected.json" 2>/dev/null; then
  echo 'FAIL: malformed config was accepted during reload' >&2
  exit 1
fi
cp "$dir/good.json" "$config"
verify_unchanged
verify_traffic
echo 'PASS: malformed reload preserves working tunnel'
stop_foreground
start_foreground
verify_traffic
stop_foreground
echo 'PASS: actual agent foreground restart and utun/route cleanup'

# Verify system-service boot registration plus two real launchd startup cycles.
state=$dir/service-state
"$agent" service install --config "$config" --state-dir "$state"
service_installed=true
/usr/bin/plutil -lint /Library/LaunchDaemons/com.peerimeter.agent.plist
"$agent" service start
wait_status
verify_traffic
iface=$(interface_name)
"$agent" service stop
verify_removed "$iface"
"$agent" service start
wait_status
verify_traffic
iface=$(interface_name)
"$agent" service uninstall
service_installed=false
verify_removed "$iface"
test ! -e /Library/LaunchDaemons/com.peerimeter.agent.plist
test -f "$state/service.json"
test -f "$state/service.key"
if /bin/launchctl print system/com.peerimeter.agent >/dev/null 2>&1; then echo 'FAIL: launchd registration survived uninstall' >&2; exit 1; fi
echo 'PASS: launchd install/start/stop/restart/uninstall, protected configuration preserved'
echo 'PASS: macOS actual agent native tunnel, IPC, reload validation and service lifecycle'
