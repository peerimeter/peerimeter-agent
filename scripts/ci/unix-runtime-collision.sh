#!/usr/bin/env bash
# A failed instance must never claim or remove another installation's runtime.
set -euo pipefail
agent=${1:?CURRENT_AGENT}
config=${2:?SOURCE_CONFIG}
runtime=${3:?RUNNING_A_RUNTIME}
parent=${4:?PRIVATE_TEST_PARENT}
namespace=${5:-}
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d "$parent/collision.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
other="$work/installation B"
bash "$repo/scripts/ci/unix-install-native.sh" "$agent" "$other"
other_agent="$other/peerimeter-agent"
cp "$runtime/.peerimeter-agent.runtime" "$work/runtime-marker.before"
python3 - "$other_agent" "$config" "$work/state B" "$work/config B" "$runtime" "$namespace" "$work/start.log" <<'PY'
import subprocess,sys
agent,config,state,configdir,runtime,ns,log=sys.argv[1:]
command=[agent,'run','--config',config,'--config-dir',configdir,'--state-dir',state,'--runtime-dir',runtime]
if ns:command=['ip','netns','exec',ns]+command
with open(log,'w') as output:p=subprocess.run(command,stdout=output,stderr=subprocess.STDOUT,timeout=8)
assert p.returncode!=0,'installation B accepted installation A runtime'
PY
python3 - "$other/.peerimeter-agent.install.json" "$runtime" <<'PY'
import json,os,sys
inv=json.load(open(sys.argv[1])); profiles=inv['profiles']
assert len(profiles)==1,'failed startup must retain its planned profile for safe cleanup'
p=profiles[0]
assert os.path.realpath(p['runtime_dir'])==os.path.realpath(sys.argv[2])
assert not p.get('runtime_owned',False),'failed installation claimed another installation runtime'
PY
"$other_agent" uninstall --json --install-dir "$other" >"$work/removal.json"
python3 - "$work/removal.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['state']=='removed'
PY
[[ -S "$runtime/control.sock" ]]
cmp "$runtime/.peerimeter-agent.runtime" "$work/runtime-marker.before"
"$agent" status --json --runtime-dir "$runtime" >"$work/A-still-running.json"
python3 - "$work/A-still-running.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['state']=='running'
PY
echo 'PASS: installation B failed shared-runtime startup and full uninstall preserved installation A socket, runtime identity and live manager.'

# Also protect a runtime that an installation genuinely owned in the past and
# that another installation has since reused. A persisted historical ownership
# bit is not proof that the current socket belongs to the old installation.
python3 - "$agent" "$repo" "$work" "$namespace" <<'PYREUSE'
import json,pathlib,subprocess,sys,time
agent,repo,work,namespace=sys.argv[1:];root=pathlib.Path(work)
subprocess.run([agent,'generate-example','--directory',str(root/'reuse sources')],check=True)
config=root/'reuse sources'/'peer-a.json';c=json.loads(config.read_text())
c['network']={'id':'runtime-reuse-network','name':'runtime-reuse'}
c['interface'].update(address=['10.245.245.1/32'],listen_port=51990)
c['peers'][0].update(allowed_ips=['10.245.245.2/32'],endpoint='127.0.0.1:51991',persistent_keepalive_seconds=0)
config.write_text(json.dumps(c)+'\n')
programs=[root/'installation X',root/'installation Y']
for program in programs:subprocess.run(['bash',str(pathlib.Path(repo)/'scripts/ci/unix-install-native.sh'),agent,str(program)],check=True)
runtime=root/'historically shared runtime';processes=[]
def cli(args):return subprocess.run([agent]+args,capture_output=True,text=True,timeout=12,check=True)
def start(index):
 program=programs[index];state=root/f'reuse state {index}'
 command=[str(program/'peerimeter-agent'),'run','--config',str(config),'--config-dir',str(root/f'reuse config {index}'),'--state-dir',str(state),'--runtime-dir',str(runtime)]
 if namespace:command=['ip','netns','exec',namespace]+command
 log=(root/f'reuse-{index}.log').open('w')
 process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT);processes.append(process)
 for attempt in range(40):
  if process.poll() is not None:raise AssertionError('native historical-reuse agent exited before control readiness')
  try:
   status=json.loads(cli(['status','--json','--runtime-dir',str(runtime)]).stdout)
   if status['state']=='running':return process,status
  except (subprocess.SubprocessError,json.JSONDecodeError):pass
  time.sleep(.2)
 raise AssertionError('native historical-reuse agent did not become ready')
try:
 first,before=start(0)
 marker_before=(runtime/'.peerimeter-agent.runtime').read_bytes()
 cli(['stop','--runtime-dir',str(runtime)]);assert first.wait(timeout=15)==0
 for attempt in range(40):
  if sys.platform=='darwin':check=['/sbin/ifconfig',before['interface_name']]
  else:
   check=['ip','link','show','dev',before['interface_name']]
   if namespace:check=['ip','netns','exec',namespace]+check
  if subprocess.run(check,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0:break
  time.sleep(.2)
 else:raise AssertionError('stopped historical-owner tunnel did not detach')
 second,before_second=start(1)
 marker_second=(runtime/'.peerimeter-agent.runtime').read_bytes()
 assert marker_second!=marker_before,'runtime profile identity did not change when reused'
 result=subprocess.run([str(programs[0]/'peerimeter-agent'),'uninstall','--json','--install-dir',str(programs[0])],capture_output=True,text=True,timeout=30,check=True)
 assert json.loads(result.stdout)['state']=='removed'
 assert (runtime/'.peerimeter-agent.runtime').read_bytes()==marker_second,'historical owner removed or replaced the new runtime identity'
 after=json.loads(cli(['status','--json','--runtime-dir',str(runtime)]).stdout)
 assert after['state']=='running' and after['interface_name']==before_second['interface_name'],'historical owner stopped or recreated the new manager/tunnel'
 cli(['stop','--runtime-dir',str(runtime)]);assert second.wait(timeout=15)==0
 result=subprocess.run([str(programs[1]/'peerimeter-agent'),'uninstall','--json','--install-dir',str(programs[1])],capture_output=True,text=True,timeout=30,check=True)
 assert json.loads(result.stdout)['state']=='removed'
finally:
 for process in processes:
  if process.poll() is None:
   process.terminate()
   try:process.wait(timeout=15)
   except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
PYREUSE
echo 'PASS: a historical runtime owner full uninstall preserves the newer installation runtime marker, live manager and native tunnel.'
