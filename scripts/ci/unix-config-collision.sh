#!/usr/bin/env bash
# A failed service install must not adopt another installation's config/keys,
# overwrite its supervisor registration, or delete them during full removal.
set -euo pipefail
agent=${1:?CURRENT_AGENT}
source_config=${2:?SOURCE_CONFIG}
config_dir=${3:?RUNNING_A_CONFIG_DIRECTORY}
runtime_dir=${4:?RUNNING_A_RUNTIME_DIRECTORY}
parent=${5:?PRIVATE_TEST_PARENT}
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d "$parent/config-collision.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
program="$work/installation B"
bash "$repo/scripts/ci/unix-install-native.sh" "$agent" "$program"
other="$program/peerimeter-agent"
case $(uname -s) in Linux) unit=/etc/systemd/system/peerimeter-agent.service;; Darwin) unit=/Library/LaunchDaemons/com.peerimeter.agent.plist;; *) exit 1;; esac
snapshot() {
 python3 - "$config_dir" "$unit" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);paths=[root/'service.json',root/'service.key',root/'.peerimeter-agent.config',pathlib.Path(sys.argv[2])];out={}
for p in paths:
 s=p.stat();out[str(p)]=[s.st_mode,s.st_uid,s.st_gid,s.st_mtime_ns,hashlib.sha256(p.read_bytes()).hexdigest()]
print(json.dumps(out,sort_keys=True))
PY
}
snapshot >"$work/before.json"
if "$other" service install --config "$source_config" --config-dir "$config_dir" --state-dir "$work/state B" --runtime-dir "$work/runtime B" >"$work/rejected.log" 2>&1; then
 echo 'Installation B adopted installation A protected configuration directory.' >&2; exit 1
fi
snapshot >"$work/after-rejection.json"
cmp "$work/before.json" "$work/after-rejection.json"
"$other" uninstall --install-dir "$program" >"$work/removed.json"
python3 - "$work/removed.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['state']=='removed'
PY
snapshot >"$work/after-uninstall.json"
cmp "$work/before.json" "$work/after-uninstall.json"
"$agent" status --runtime-dir "$runtime_dir" >"$work/A-status.json"
python3 - "$work/A-status.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['state']=='running'
PY
echo 'PASS: rejected configuration-directory adoption and B full uninstall preserve A private snapshots, ownership marker, supervisor and live native manager.'
