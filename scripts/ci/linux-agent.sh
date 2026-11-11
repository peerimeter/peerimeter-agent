#!/usr/bin/env bash
# Native Linux Phase 1 verification: two actual agents, no reference WG tools.
set -Eeuo pipefail
umask 077
[[ $(id -u) -eq 0 ]] || { echo 'Run the Linux integration test as root.' >&2; exit 1; }
AGENT=$(realpath "${AGENT:-${1:-./peerimeter-agent}}")
[[ -x "$AGENT" ]] || { echo 'AGENT must name the built executable.' >&2; exit 1; }
for dependency in ip ping python3 timeout systemctl; do command -v "$dependency" >/dev/null; done
work=$(mktemp -d /tmp/peerimeter-agent-linux.XXXXXXXX)
left="pm-left-$BASHPID"
right="pm-right-$BASHPID"
vleft="pml$BASHPID"
vright="pmr$BASHPID"
left_pid=''
right_pid=''
service_installed=false

terminate() {
  local pid=${1:-}
  [[ -n "$pid" ]] || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for _ in {1..25}; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
cleanup() {
  local outcome=$?
  trap - EXIT INT TERM
  set +e
  if (( outcome != 0 )); then
    for log in "$work"/*.log; do
      [[ -f "$log" ]] || continue
      echo "Diagnostic: $(basename "$log")" >&2
      cat "$log" >&2
    done
  fi
  if [[ "$service_installed" == true ]]; then
    "$AGENT" service stop --state-dir "$work/service-state" >/dev/null 2>&1
    "$AGENT" service uninstall --state-dir "$work/service-state" >/dev/null 2>&1
    if [[ -e /etc/systemd/system/peerimeter-agent.service ]] || ip link show dev pm-service >/dev/null 2>&1; then
      echo 'Cleanup failed: the temporary systemd unit or its adapter remains.' >&2
      outcome=1
    fi
  fi
  terminate "$left_pid"
  terminate "$right_pid"
  ip netns del "$left" 2>/dev/null
  ip netns del "$right" 2>/dev/null
  ip link del "$vleft" 2>/dev/null
  ip link del "$vright" 2>/dev/null
  rm -rf -- "$work"
  if ip netns list | awk '{print $1}' | grep -Fxq "$left" || ip netns list | awk '{print $1}' | grep -Fxq "$right" || [[ -e "$work" ]]; then
    echo 'Cleanup failed: a test namespace or credential directory remains.' >&2
    outcome=1
  fi
  echo 'Linux integration temporary namespace/key cleanup completed.'
  exit "$outcome"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Service executables must live under root-owned, non-writable ancestors. The
# Actions build directory belongs to runner, so stage this run's private copy.
install -m 0755 "$AGENT" "$work/peerimeter-agent"
AGENT="$work/peerimeter-agent"

control() {
  local namespace=$1 state=$2 operation=$3
  if [[ -n "$namespace" ]]; then
    timeout 12s ip netns exec "$namespace" "$AGENT" "$operation" --state-dir "$state"
  else
    timeout 12s "$AGENT" "$operation" --state-dir "$state"
  fi
}
wait_running() {
  local namespace=$1 state=$2 output=$3
  local deadline=$((SECONDS + 40))
  until control "$namespace" "$state" status >"$output" 2>/dev/null; do
    (( SECONDS < deadline )) || { echo "Agent did not start in $namespace." >&2; return 1; }
    sleep 0.3
  done
  python3 - "$output" <<'PY'
import json, sys
s=json.load(open(sys.argv[1]))
assert s['state']=='running' and len(s['peers'])==1, 'Unexpected native agent status'
PY
}
wait_process() {
  local pid=$1 deadline=$((SECONDS + 20))
  while kill -0 "$pid" 2>/dev/null; do
    (( SECONDS < deadline )) || { echo 'Agent did not shut down gracefully.' >&2; return 1; }
    sleep 0.2
  done
  wait "$pid"
}
ping_both() {
  timeout 15s ip netns exec "$left" ping -n -q -c 3 -W 2 10.80.0.2
  timeout 15s ip netns exec "$right" ping -n -q -c 3 -W 2 10.80.0.1
}
check_handshake() {
  local namespace=$1 state=$2 output=$3
  control "$namespace" "$state" status >"$output"
  control "$namespace" "$state" peers >"$output.peers"
  python3 - "$output" "$output.peers" <<'PY'
import datetime, json, sys
s=json.load(open(sys.argv[1])); peers=json.load(open(sys.argv[2]))
assert s['state']=='running' and s['peers']==peers and len(peers)==1
p=peers[0]
t=datetime.datetime.fromisoformat(p['last_handshake'].replace('Z','+00:00'))
assert (datetime.datetime.now(datetime.timezone.utc)-t).total_seconds()<120, 'No fresh authenticated handshake'
assert p['received_bytes']>0 and p['sent_bytes']>0, 'No bidirectional encrypted traffic counters'
PY
}
index_of() { ip -n "$1" -j link show dev "$2" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["ifindex"])'; }
assert_removed() {
  local namespace=$1 interface=$2
  if ip -n "$namespace" link show dev "$interface" >/dev/null 2>&1; then
    echo "Owned interface $interface remains after stop." >&2; return 1
  fi
  ip -n "$namespace" -j route show | python3 -c 'import json,sys; assert not any(r.get("dst") in ("10.80.0.1","10.80.0.1/32","10.80.0.2","10.80.0.2/32","10.81.0.2","10.81.0.2/32") for r in json.load(sys.stdin)), "A peer route remains after stop"'
}

"$AGENT" generate-example --directory "$work/config"
python3 - "$work/config" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
for label, endpoint in [('a','192.0.2.2:51821'),('b','192.0.2.1:51820')]:
    path=root/f'peer-{label}.json'; c=json.loads(path.read_text())
    c['network']['name']='probe'
    c['peers'][0]['endpoint']=endpoint
    path.write_text(json.dumps(c)+'\n')
PY
ip netns add "$left"
ip netns add "$right"
ip link add "$vleft" type veth peer name "$vright"
ip link set "$vleft" netns "$left"
ip link set "$vright" netns "$right"
ip -n "$left" address add 192.0.2.1/30 dev "$vleft"
ip -n "$right" address add 192.0.2.2/30 dev "$vright"
ip -n "$left" link set lo up
ip -n "$right" link set lo up
ip -n "$left" link set "$vleft" up
ip -n "$right" link set "$vright" up

# Refuse to adopt or remove an unrelated interface, even with the desired name.
ip -n "$left" link add pm-probe type dummy
if timeout 10s ip netns exec "$left" "$AGENT" run --config "$work/config/peer-a.json" --state-dir "$work/left-state" >"$work/refuse-existing.log" 2>&1; then
  echo 'Agent incorrectly accepted an existing unrelated interface.' >&2; exit 1
fi
ip -n "$left" -j -d link show dev pm-probe | python3 -c 'import json,sys; assert json.load(sys.stdin)[0]["linkinfo"]["info_kind"]=="dummy"'
ip -n "$left" link del pm-probe

ip netns exec "$left" "$AGENT" run --config "$work/config/peer-a.json" --state-dir "$work/left-state" >"$work/left.log" 2>&1 &
left_pid=$!
ip netns exec "$right" "$AGENT" run --config "$work/config/peer-b.json" --interface pm-custom --state-dir "$work/right-state" >"$work/right.log" 2>&1 &
right_pid=$!
wait_running "$left" "$work/left-state" "$work/left-status.json"
wait_running "$right" "$work/right-state" "$work/right-status.json"
left_index=$(index_of "$left" pm-probe)
right_index=$(index_of "$right" pm-custom)
ping_both
check_handshake "$left" "$work/left-state" "$work/left-before.json"
check_handshake "$right" "$work/right-state" "$work/right-before.json"
echo 'Passed: two real agents, Linux kernel interfaces, authenticated handshake, bidirectional traffic.'

control "$left" "$work/left-state" sync
control "$right" "$work/right-state" sync
check_handshake "$left" "$work/left-state" "$work/left-unchanged.json"
check_handshake "$right" "$work/right-state" "$work/right-unchanged.json"
python3 - "$work" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
for peer in ('left','right'):
    before=json.loads((root/f'{peer}-before.json').read_text())
    after=json.loads((root/f'{peer}-unchanged.json').read_text())
    assert before['peers'][0]['last_handshake']==after['peers'][0]['last_handshake'], 'Unchanged sync reset a peer'
PY
[[ $(index_of "$left" pm-probe) == "$left_index" ]]
[[ $(index_of "$right" pm-custom) == "$right_index" ]]

# Add an address and matching AllowedIP/route without resetting either device.
python3 - "$work/config" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1]); a=root/'peer-a.json'; b=root/'peer-b.json'
c=json.loads(a.read_text()); c['peers'][0]['allowed_ips'].append('10.81.0.2/32'); c['peers'][0]['persistent_keepalive_seconds']=7; a.write_text(json.dumps(c)+'\n')
c=json.loads(b.read_text()); c['interface']['address'].append('10.81.0.2/32'); b.write_text(json.dumps(c)+'\n')
PY
control "$right" "$work/right-state" sync
control "$left" "$work/left-state" sync
timeout 15s ip netns exec "$left" ping -n -q -c 3 -W 2 10.81.0.2
timeout 15s ip netns exec "$right" ping -n -q -c 3 -W 2 -I 10.81.0.2 10.80.0.1
check_handshake "$left" "$work/left-state" "$work/left-diff.json"
check_handshake "$right" "$work/right-state" "$work/right-diff.json"
python3 - "$work" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
for peer in ('left','right'):
    before=json.loads((root/f'{peer}-before.json').read_text())
    after=json.loads((root/f'{peer}-diff.json').read_text())
    assert before['peers'][0]['last_handshake']==after['peers'][0]['last_handshake'], 'Normal diff reset a peer handshake'
PY
[[ $(index_of "$left" pm-probe) == "$left_index" ]]
[[ $(index_of "$right" pm-custom) == "$right_index" ]]
echo 'Passed: unchanged sync and live peer/address/route changes preserve interfaces and handshakes.'

python3 - "$work/config/peer-a.json" <<'PY'
import json, pathlib, sys
p=pathlib.Path(sys.argv[1]); c=json.loads(p.read_text()); c['version']=999; p.write_text(json.dumps(c)+'\n')
PY
if control "$left" "$work/left-state" sync >"$work/invalid-sync.log" 2>&1; then
  echo 'Invalid config was accepted by sync.' >&2; exit 1
fi
ping_both
python3 - "$work/config/peer-a.json" <<'PY'
import json, pathlib, sys
p=pathlib.Path(sys.argv[1]); c=json.loads(p.read_text()); c['version']=1; c['network']['name']='renamed network'; p.write_text(json.dumps(c)+'\n')
PY
control "$left" "$work/left-state" stop
wait_process "$left_pid"
left_pid=''
assert_removed "$left" pm-probe
ip netns exec "$left" "$AGENT" run --config "$work/config/peer-a.json" --state-dir "$work/left-state" >"$work/left-restarted.log" 2>&1 &
left_pid=$!
wait_running "$left" "$work/left-state" "$work/left-restarted.json"
python3 - "$work/left-restarted.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))['interface_name']=='pm-probe', 'Persisted interface name changed after display rename'
PY
ping_both
check_handshake "$left" "$work/left-state" "$work/left-after-restart.json"
check_handshake "$right" "$work/right-state" "$work/right-after-restart.json"
# Simulate an ungraceful process death. Kernel interface/routes survive SIGKILL;
# the persisted random ownership token allows safe recovery by this same state.
kill -KILL "$left_pid"
wait "$left_pid" 2>/dev/null || true
left_pid=''
ip -n "$left" link show dev pm-probe >/dev/null
ip netns exec "$left" "$AGENT" run --config "$work/config/peer-a.json" --state-dir "$work/left-state" >"$work/left-crash-recovered.log" 2>&1 &
left_pid=$!
wait_running "$left" "$work/left-state" "$work/left-crash-recovered.json"
ping_both
check_handshake "$left" "$work/left-state" "$work/left-after-crash.json"
check_handshake "$right" "$work/right-state" "$work/right-after-crash.json"
echo 'Passed: SIGKILL recovery reclaims only the interface matching protected persistent ownership state.'
control "$left" "$work/left-state" stop
control "$right" "$work/right-state" stop
wait_process "$left_pid"; left_pid=''
wait_process "$right_pid"; right_pid=''
assert_removed "$left" pm-probe
assert_removed "$right" pm-custom
echo 'Passed: invalid reload preserves traffic, graceful restart preserves local name, owned interfaces/routes are removed.'

# Separate systemd lifecycle probe. Handshake evidence comes from the agents
# above; a running supervisor alone never counts as tunnel traffic verification.
[[ ! -e /etc/systemd/system/peerimeter-agent.service && ! -L /etc/systemd/system/peerimeter-agent.service ]]
"$AGENT" generate-example --directory "$work/service-config"
python3 - "$work/service-config/peer-a.json" <<'PY'
import json, pathlib, sys
p=pathlib.Path(sys.argv[1]); c=json.loads(p.read_text())
c['interface'].update(name='pm-service',address=['10.254.254.1/32'],listen_port=51790)
c['peers'][0].update(allowed_ips=['10.254.254.2/32'],endpoint='127.0.0.1:51791')
p.write_text(json.dumps(c)+'\n')
PY
"$AGENT" service install --config "$work/service-config/peer-a.json" --state-dir "$work/service-state"
service_installed=true
systemctl is-enabled peerimeter-agent.service
"$AGENT" service start --state-dir "$work/service-state"
wait_running '' "$work/service-state" "$work/service-status.json"
"$AGENT" service stop --state-dir "$work/service-state"
if ip link show dev pm-service >/dev/null 2>&1; then echo 'systemd stop left its interface behind.' >&2; exit 1; fi
"$AGENT" service start --state-dir "$work/service-state"
wait_running '' "$work/service-state" "$work/service-restarted.json"
"$AGENT" service stop --state-dir "$work/service-state"
"$AGENT" service uninstall --state-dir "$work/service-state"
service_installed=false
[[ ! -e /etc/systemd/system/peerimeter-agent.service ]]
[[ -f "$work/service-state/service.json" && -f "$work/service-state/service.key" ]]
if ip link show dev pm-service >/dev/null 2>&1; then echo 'systemd uninstall left its interface behind.' >&2; exit 1; fi
echo 'Passed: systemd install, boot enable, start, stop, second start and uninstall; protected keys/config preserved until test cleanup.'
