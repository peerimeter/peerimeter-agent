#!/usr/bin/env bash
# Real native installation, separate directories, live legacy migration and full
# removal. Run only on an isolated CI runner: it exercises machine-wide defaults.
set -Eeuo pipefail
umask 077
[[ $(id -u) -eq 0 ]]
agent_source=${1:?usage: unix-layout-uninstall.sh CURRENT_AGENT LEGACY_AGENT}
legacy_source=${2:?usage: unix-layout-uninstall.sh CURRENT_AGENT LEGACY_AGENT}
repo=$(cd "$(dirname "$0")/../.." && pwd)
base=$(mktemp -d /tmp/pm-layout.XXXXXXXX)
chmod 0711 "$base"
active=''
default_sentinel="/usr/local/bin/.peerimeter-ci-unrelated-$$"
case $(uname -s) in
 Linux)
  defaults_config=/etc/peerimeter
  defaults_state=/var/lib/peerimeter-agent
  defaults_runtime=/run/peerimeter-agent
  service_file=/etc/systemd/system/peerimeter-agent.service
  operator=nobody
  ;;
 Darwin)
  defaults_config=/etc/peerimeter
  defaults_state='/Library/Application Support/Peerimeter'
  defaults_runtime=/var/run/peerimeter-agent
  service_file=/Library/LaunchDaemons/com.peerimeter.agent.plist
  operator=${SUDO_USER:-runner}
  ;;
 *) exit 1;;
esac
[[ $(id -u "$operator") -ne 0 ]]
cleanup() {
 result=$?
 trap - EXIT INT TERM
 set +e
 if [[ -n "$active" && -x "$active" ]]; then "$active" service uninstall >/dev/null 2>&1; fi
 if (( result != 0 )); then
  for log in "$base"/*.log; do [[ ! -f "$log" ]] || { echo "Diagnostic: $(basename "$log")" >&2; tail -n 30 "$log" >&2; }; done
 fi
 # Only this freshly created test tree is recursively removed. Product removal
 # below must preserve unrelated files in every shared managed parent.
 rm -f "$default_sentinel"
 if [[ -f "$base/default-parent-permissions.json" ]]; then
  if ! python3 - "$base/default-parent-permissions.json" <<'PYRESTORE'
import json,os,stat,sys
for item in reversed(json.load(open(sys.argv[1]))):
 current=os.lstat(item['path'])
 if (current.st_uid,current.st_gid)!=(item['uid'],item['gid']):os.chown(item['path'],item['uid'],item['gid'])
 current=os.lstat(item['path'])
 if stat.S_IMODE(current.st_mode)!=item['mode']:os.chmod(item['path'],item['mode'])
PYRESTORE
  then
   echo 'CI default-prefix permission restoration failed.' >&2
   result=1
  fi
 fi
 rm -rf "$base"
 exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
[[ ! -e "$service_file" ]]
for path in "$defaults_config" "$defaults_state" "$defaults_runtime"; do
 [[ ! -e "$path" ]] || { echo "Default test destination is already occupied: $path" >&2; exit 1; }
done
install -m 0755 "$agent_source" "$base/source-agent"
source_cli="$base/source-agent"
mkdir -m 0755 "$base/package"
install -m 0755 "$agent_source" "$base/package/peerimeter-agent"
printf 'Native integration archive fixture; release packages carry full dependency notices.\n' >"$base/package/peerimeter-agent.NOTICES.txt"
tar -czf "$base/package.tar.gz" -C "$base/package" peerimeter-agent peerimeter-agent.NOTICES.txt
if command -v sha256sum >/dev/null; then digest=$(sha256sum "$base/package.tar.gz" | awk '{print $1}'); else digest=$(shasum -a 256 "$base/package.tar.gz" | awk '{print $1}'); fi
install_program() {
 sh "$repo/install.sh" --archive "$base/package.tar.gz" --sha256 "$digest" --install-dir "$1"
 [[ -f "$1/.peerimeter-agent.install.json" ]]
 chmod 0755 "$(dirname "$1")" "$1"
}
as_operator() {
 if [[ $(uname -s) == Linux ]]; then runuser -u "$operator" -- "$@"; else sudo -u "$operator" -- "$@"; fi
}
wait_status() {
 local executable=$1 runtime=${2:-} output=$3 attempt
 for attempt in {1..40}; do
  if [[ -n "$runtime" ]]; then
   if "$executable" status --runtime-dir "$runtime" >"$output" 2>/dev/null; then return 0; fi
  else
   if "$executable" status >"$output" 2>/dev/null; then return 0; fi
  fi
  sleep 0.3
 done
 echo 'Installed service did not publish local status.' >&2
 return 1
}
wait_interface_gone() {
 local interface=$1 attempt
 for attempt in {1..40}; do
  if [[ $(uname -s) == Linux ]]; then
   if ! ip link show dev "$interface" >/dev/null 2>&1; then return 0; fi
  else
   if ! /sbin/ifconfig "$interface" >/dev/null 2>&1; then return 0; fi
  fi
  sleep 0.2
 done
 echo 'Owned native interface survived service shutdown.' >&2; return 1
}
check_layout() {
 local cfg=$1 state=$2 runtime=$3
 [[ -f "$cfg/service.json" && -f "$cfg/service.key" ]]
 [[ -f "$state/ownership" ]]
 [[ ! -e "$state/service.key" && ! -e "$state/service.json" && ! -e "$state/control.sock" && ! -e "$state/agent.lock" ]]
 [[ -S "$runtime/control.sock" && -f "$runtime/.peerimeter-agent.runtime" ]]
 [[ ! -e "$runtime/service.key" && ! -e "$runtime/ownership" && ! -e "$runtime/network.json" ]]
 python3 - "$cfg" <<'PYLAYOUT'
import json,os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]);c=json.loads((root/'service.json').read_text())
assert os.path.realpath(c['interface']['private_key_file'])==str((root/'service.key').resolve()),'installed config still depends on the original/legacy private key'
for name in ('service.json','service.key'):
 s=(root/name).stat();assert s.st_uid==0 and stat.S_IMODE(s.st_mode)&0o077==0,'installed secret snapshot permissions are too broad'
PYLAYOUT
 if as_operator test -r "$cfg/service.key" || as_operator test -w "$state/ownership"; then
  echo 'Operator gained private key or persistent identity write access.' >&2; return 1
 fi
}
# Snapshot file names, modes, ownership, sizes and contents, but not access time:
# reading a file may update atime while remaining a read-only operation.
snapshot() {
 python3 - "$@" <<'PY'
import hashlib,json,os,pathlib,stat,sys
out={}
for root in map(pathlib.Path,sys.argv[1:]):
 paths=[root]
 if root.is_dir(): paths+=list(root.rglob('*'))
 for p in sorted(paths):
  try:s=p.lstat()
  except FileNotFoundError:continue
  value=[stat.S_IFMT(s.st_mode),stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid]
  if p.is_file():value += [s.st_size,s.st_mtime_ns,hashlib.sha256(p.read_bytes()).hexdigest()]
  elif p.is_symlink():value += [os.readlink(p)]
  out[str(p)]=value
print(json.dumps(out,sort_keys=True))
PY
}
check_state() { python3 - "$1" "$2" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['state']==sys.argv[2]
PY
}

# The original source lives outside every managed directory and must survive.
"$source_cli" generate-example --directory "$base/original credentials"
source_config="$base/original credentials/peer-a.json"
python3 - "$source_config" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);c=json.loads(p.read_text())
c['network']['name']='layout-probe';c['interface']['address']=['10.244.244.1/32'];c['interface']['listen_port']=51970
c['peers'][0].update(allowed_ips=['10.244.244.2/32'],endpoint='127.0.0.1:51971')
p.write_text(json.dumps(c)+'\n')
PY
snapshot "$base/original credentials" >"$base/original-before.json"

program_default=/usr/local/bin
# Hosted images deliberately permit runner/convenience-group writes to
# /usr/local. A system-service executable requires trusted ancestors. Prepare
# only this fixed prefix on the disposable VM and restore its original metadata
# on exit; no product permission checks are weakened by the fixture.
python3 - "$program_default" "$base/default-parent-permissions.json" <<'PYTRUST'
import json,os,pathlib,stat,sys
p=pathlib.Path(sys.argv[1]);records=[]
for directory in [p]+list(p.parents):
 s=directory.lstat()
 print('CI default program ancestor:',directory,'uid='+str(s.st_uid),'mode='+oct(stat.S_IMODE(s.st_mode)))
 assert stat.S_ISDIR(s.st_mode),'default install ancestor must be an existing real directory'
 assert s.st_uid==0 or str(directory) in ('/usr/local','/usr/local/bin'),'unexpected ownership outside the disposable test prefix'
 records.append(dict(path=str(directory),uid=s.st_uid,gid=s.st_gid,mode=stat.S_IMODE(s.st_mode)))
with open(sys.argv[2],'w') as f:json.dump(records,f)
for item in records:
 if item['uid']!=0:os.chown(item['path'],0,item['gid'])
 if item['mode']&0o022:os.chmod(item['path'],item['mode']&~0o022)
PYTRUST
for member in peerimeter-agent peerimeter-agent.NOTICES.txt .peerimeter-agent.install.json .peerimeter-agent.install.lock; do
 [[ ! -e "$program_default/$member" && ! -L "$program_default/$member" ]] || { echo 'Default program install destination is already occupied.' >&2; exit 1; }
done
# Omit --install-dir to verify the actual Unix installer destination default.
sh "$repo/install.sh" --archive "$base/package.tar.gz" --sha256 "$digest"
[[ -f "$program_default/.peerimeter-agent.install.json" ]]
printf 'unrelated shared-bin resource\n' >"$default_sentinel"
agent="$program_default/peerimeter-agent"
active="$agent"
"$agent" service install --config "$source_config" --operator "$operator"
"$agent" service start
wait_status "$agent" '' "$base/default-status.json"
check_layout "$defaults_config" "$defaults_state" "$defaults_runtime"
as_operator "$agent" status >"$base/default-operator.json"
as_operator "$agent" peers --json >"$base/default-operator-peers.json"
as_operator "$agent" sync
bash "$repo/scripts/ci/unix-config-collision.sh" "$agent" "$source_config" "$defaults_config" "$defaults_runtime" "$base"
snapshot "$defaults_config" "$defaults_state" >"$base/default-durable.json"
"$agent" service stop
wait_interface_gone "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["interface_name"])' "$base/default-status.json")"
[[ ! -e "$defaults_runtime/control.sock" ]]
rm -rf "$defaults_runtime"
"$agent" service start
wait_status "$agent" '' "$base/default-restarted.json"
check_layout "$defaults_config" "$defaults_state" "$defaults_runtime"
snapshot "$defaults_config" "$defaults_state" >"$base/default-durable-after.json"
cmp "$base/default-durable.json" "$base/default-durable-after.json"
"$agent" service uninstall
wait_interface_gone "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["interface_name"])' "$base/default-restarted.json")"
active=''
[[ ! -e "$service_file" && ! -e "$defaults_runtime/control.sock" ]]
[[ -f "$defaults_config/service.key" && -f "$defaults_state/ownership" ]]
echo 'PASS: native Unix defaults separate credentials/state/runtime, operator IPC and reboot-style runtime recreation preserve durable identity.'

# A loaded executable blocked before its startup inventory capture must not
# reinterpret a removed installation as an untracked source build afterward.
queued_program="$base/queued program/bin"
install_program "$queued_program"
python3 - "$queued_program/peerimeter-agent" "$queued_program" "$source_config" "$base" <<'PYQUEUED'
import errno,json,os,pathlib,subprocess,sys,time
agent,program,source,base=sys.argv[1:];root=pathlib.Path(base)
fifo=root/'queued configuration.json';os.mkfifo(fifo,0o600)
state=root/'queued persistent state';runtime=root/'queued runtime';configdir=root/'queued installed configuration'
config=json.loads(pathlib.Path(source).read_text());config['interface']['private_key_file']=str((pathlib.Path(source).parent/config['interface']['private_key_file']).resolve())
with (root/'queued-process.log').open('w') as log:
 process=subprocess.Popen([agent,'run','--config',str(fifo),'--config-dir',str(configdir),'--state-dir',str(state),'--runtime-dir',str(runtime)],stdout=log,stderr=subprocess.STDOUT)
 fd=None
 try:
  deadline=time.monotonic()+8
  while fd is None:
   try:fd=os.open(fifo,os.O_WRONLY|os.O_NONBLOCK)
   except OSError as e:
    if e.errno!=errno.ENXIO or time.monotonic()>deadline:raise
    if process.poll() is not None:raise AssertionError('queued process exited before the blocking configuration read')
    time.sleep(.05)
  # A FIFO reader proves the native image has executed, rather than merely
  # being forked but not yet loaded when the installed path is deleted.
  removed=subprocess.run([agent,'uninstall','--install-dir',program],capture_output=True,text=True,timeout=30,check=True)
  assert json.loads(removed.stdout)['state']=='removed'
  os.write(fd,json.dumps(config).encode());os.close(fd);fd=None
  assert process.wait(timeout=10)!=0,'deleted installed image restarted as an untracked manager'
  assert not state.exists() and not runtime.exists(),'late startup created managed state after complete removal'
 finally:
  if fd is not None:os.close(fd)
  if process.poll() is None:process.terminate();process.wait(timeout=10)
  fifo.unlink(missing_ok=True)
PYQUEUED
echo 'PASS: a loaded pre-start Unix process cannot recreate manager state after its installation is completely removed.'

# A second real installation will migrate an already-running old combined
# service. The supervisor path remains identical while its executable inode is
# atomically upgraded, exactly as an operator upgrade behaves on Unix.
program="$base/migration program/bin"
install_program "$program"
agent="$program/peerimeter-agent"
legacy="$base/legacy combined state"
new_config="$base/migrated configuration"
new_runtime="$base/migrated runtime files"
install -m 0755 "$legacy_source" "$program/legacy.new"
mv -f "$program/legacy.new" "$agent"
active="$agent"
"$agent" service install --config "$source_config" --state-dir "$legacy" --operator "$operator"
"$agent" service start
for attempt in {1..40}; do
 if "$agent" status --state-dir "$legacy" >"$base/legacy-status.json" 2>/dev/null; then break; fi
 sleep 0.3
done
[[ -S "$legacy/control.sock" ]]
cp "$legacy/ownership" "$base/old-ownership"
if [[ -f "$legacy/network.json" ]]; then cp "$legacy/network.json" "$base/old-network.json"; fi
cp "$legacy/service.key" "$base/old-service.key"
install -m 0755 "$source_cli" "$program/current.new"
mv -f "$program/current.new" "$agent"
mkdir -m 0700 "$new_config"
printf 'conflicting protected destination\n' >"$new_config/service.key"
cp "$new_config/service.key" "$base/conflict.original"
if "$agent" service migrate --state-dir "$legacy" --config-dir "$new_config" --runtime-dir "$new_runtime" --operator "$operator" >"$base/migration-conflict.log" 2>&1; then
 echo 'Migration overwrote a conflicting destination.' >&2; exit 1
fi
cmp "$new_config/service.key" "$base/conflict.original"
cmp "$legacy/service.key" "$base/old-service.key"
cmp "$legacy/ownership" "$base/old-ownership"
"$agent" status --runtime-dir "$legacy" >"$base/legacy-after-conflict.json"
rm "$new_config/service.key"
"$agent" service migrate --state-dir "$legacy" --config-dir "$new_config" --runtime-dir "$new_runtime" --operator "$operator"
[[ ! -e "$legacy/service.json" && ! -e "$legacy/service.key" && ! -e "$legacy/control.sock" ]]
cmp "$new_config/service.key" "$base/old-service.key"
cmp "$legacy/ownership" "$base/old-ownership"
if [[ -f "$base/old-network.json" ]]; then cmp "$legacy/network.json" "$base/old-network.json"; fi
"$agent" service start
wait_status "$agent" "$new_runtime" "$base/migrated-status.json"
check_layout "$new_config" "$legacy" "$new_runtime"
as_operator "$agent" status --runtime-dir "$new_runtime" >"$base/migrated-operator.json"
as_operator "$agent" peers --json --runtime-dir "$new_runtime" >"$base/migrated-operator-peers.json"
as_operator "$agent" sync --runtime-dir "$new_runtime"
echo 'PASS: live old combined service migration rejects conflicts, preserves keys/interface identity and starts with spaced separate directories.'

for directory in "$program" "$new_config" "$legacy" "$new_runtime"; do printf 'unrelated operator file\n' >"$directory/unrelated.txt"; done
snapshot "$program" "$new_config" "$legacy" "$new_runtime" "$service_file" >"$base/before-dry-run.json"
"$agent" uninstall --install-dir "$program" --dry-run >"$base/dry-run.json"
check_state "$base/dry-run.json" dry_run
snapshot "$program" "$new_config" "$legacy" "$new_runtime" "$service_file" >"$base/after-dry-run.json"
cmp "$base/before-dry-run.json" "$base/after-dry-run.json"
"$agent" status --runtime-dir "$new_runtime" >"$base/still-running-after-dry-run.json"
# Refuse hash-changed owned program resources without stopping the working
# service. Restoring and then omitting a previously removed member exercises retry
# from a partial inventory cleanup, without adding production-only fault hooks.
cp "$program/peerimeter-agent.NOTICES.txt" "$base/notices.original"
printf 'operator changed tracked notice\n' >>"$program/peerimeter-agent.NOTICES.txt"
if "$agent" uninstall --install-dir "$program" >"$base/changed-file.log" 2>&1; then echo 'Uninstall ignored changed owned-file hash.' >&2; exit 1; fi
[[ -f "$new_config/service.key" && -f "$program/.peerimeter-agent.install.json" ]]
"$agent" status --runtime-dir "$new_runtime" >"$base/still-running-after-rejection.json"
cp "$base/notices.original" "$program/peerimeter-agent.NOTICES.txt"
rm "$program/peerimeter-agent.NOTICES.txt"
"$agent" uninstall --install-dir "$program" >"$base/removed.json"
check_state "$base/removed.json" removed
wait_interface_gone "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["interface_name"])' "$base/migrated-status.json")"
active=''
[[ ! -e "$service_file" && ! -e "$new_runtime/control.sock" ]]
for path in "$program/peerimeter-agent" "$program/.peerimeter-agent.install.json" "$program/.peerimeter-agent.install.lock" "$new_config/service.json" "$new_config/service.key" "$legacy/ownership" "$legacy/network.json" "$legacy/agent.lock" "$legacy/.peerimeter-agent.profile"; do [[ ! -e "$path" ]] || { echo "Managed resource survived uninstall: $path" >&2; exit 1; }; done
for directory in "$program" "$new_config" "$legacy" "$new_runtime"; do [[ $(cat "$directory/unrelated.txt") == 'unrelated operator file' ]]; done
"$source_cli" uninstall --install-dir "$program" >"$base/already-absent.json"
check_state "$base/already-absent.json" already_absent
"$program_default/peerimeter-agent" uninstall --install-dir "$program_default" >"$base/default-removed.json"
check_state "$base/default-removed.json" removed
[[ $(cat "$default_sentinel") == 'unrelated shared-bin resource' ]]
for member in peerimeter-agent peerimeter-agent.NOTICES.txt .peerimeter-agent.install.json .peerimeter-agent.install.lock; do [[ ! -e "$program_default/$member" ]]; done
for path in "$defaults_config/service.json" "$defaults_config/service.key" "$defaults_state/ownership" "$defaults_state/network.json" "$defaults_state/.peerimeter-agent.profile" "$defaults_runtime/control.sock"; do [[ ! -e "$path" ]] || { echo "Default managed resource survived uninstall: $path" >&2; exit 1; }; done
snapshot "$base/original credentials" >"$base/original-after.json"
cmp "$base/original-before.json" "$base/original-after.json"
echo 'PASS: actual installer inventory, read-only dry-run, live full uninstall, changed-file refusal, partial-state retry, idempotency and unrelated/source-file preservation.'
