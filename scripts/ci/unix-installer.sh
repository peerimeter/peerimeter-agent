#!/usr/bin/env bash
# Portable Linux/macOS installer tests, requiring no published GitHub release.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
installer=$repo/docs/install.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
case "$(uname -s)" in Linux) native_os=linux;; Darwin) native_os=darwin;; *) exit 1;; esac
case "$(uname -m)" in x86_64|amd64) native_arch=amd64;; arm64|aarch64) native_arch=arm64;; *) exit 1;; esac
case "$native_arch" in amd64) asset_arch=x86_64;; arm64) asset_arch=aarch64;; esac
if [[ $# -gt 0 ]]; then
 native_binary=$1
 native_notices=$2
else
 native_binaries=("$repo"/dist/peerimeter-agent-"${native_os}-${asset_arch}")
 [[ ${#native_binaries[@]} -eq 1 && -f "${native_binaries[0]}" ]] || { echo 'Supply one actual native release binary for installer inventory tests.' >&2; exit 1; }
 native_binary=${native_binaries[0]}
 native_notices=${native_binary}.NOTICES.txt
fi
mkdir -p "$work/mock-bin" "$work/custom install/bin"
cp "$native_binary" "$work/peerimeter-agent"
cp "$native_notices" "$work/peerimeter-agent.NOTICES.txt"
hash=$(sha256 "$work/peerimeter-agent")
notices_hash=$(sha256 "$work/peerimeter-agent.NOTICES.txt")
destination=$work/custom\ install/bin
printf 'operator config stays\n' >"$destination/operator.config"
printf 'operator key stays\n' >"$destination/operator.key"
cp "$destination/operator.config" "$work/original.config"
cp "$destination/operator.key" "$work/original.key"
sh "$installer" --binary "$work/peerimeter-agent" --sha256 "$hash" --notices "$work/peerimeter-agent.NOTICES.txt" --notices-sha256 "$notices_hash" --install-dir "$destination"
cmp "$work/peerimeter-agent" "$destination/peerimeter-agent"
cmp "$work/peerimeter-agent.NOTICES.txt" "$destination/peerimeter-agent.NOTICES.txt"
"$destination/peerimeter-agent" version --json >"$work/version.json"
python3 - "$work/version.json" "$native_os" <<'PYVERSION'
import json,sys
v=json.load(open(sys.argv[1]));assert v['os']==sys.argv[2] and v['go_version']=='go1.27.4'
PYVERSION
[[ -f "$destination/.peerimeter-agent.install.json" ]]
cp "$destination/peerimeter-agent" "$work/original.agent"
cp "$destination/peerimeter-agent.NOTICES.txt" "$work/original.notices"
cp "$destination/.peerimeter-agent.install.json" "$work/original.inventory"
expect_failure() {
  local pattern=$1
  shift
  if "$@" >"$work/failure.log" 2>&1; then
    echo "FAIL: command succeeded while expecting: $pattern" >&2
    exit 1
  fi
  if ! grep -Fq "$pattern" "$work/failure.log"; then cat "$work/failure.log" >&2; exit 1; fi
  cmp "$work/original.agent" "$destination/peerimeter-agent"
  cmp "$work/original.notices" "$destination/peerimeter-agent.NOTICES.txt"
  cmp "$work/original.inventory" "$destination/.peerimeter-agent.install.json"
}
expect_failure 'Binary checksum verification failed' sh "$installer" --binary "$work/peerimeter-agent" --sha256 "$(printf '%064d' 0)" --notices "$work/peerimeter-agent.NOTICES.txt" --notices-sha256 "$notices_hash" --install-dir "$destination"
expect_failure 'SHA-256 digest' sh "$installer" --binary "$work/peerimeter-agent" --sha256 "$hash
$hash" --notices "$work/peerimeter-agent.NOTICES.txt" --notices-sha256 "$notices_hash" --install-dir "$destination"
echo 'PASS: offline checksum verification, spaced destination and existing binary preservation'

# Existing destination links are rejected before package members are replaced.
printf 'outside installer test directory\n' >"$work/victim"
rm -f "$destination/peerimeter-agent.NOTICES.txt"
ln -s "$work/victim" "$destination/peerimeter-agent.NOTICES.txt"
if sh "$installer" --binary "$work/peerimeter-agent" --sha256 "$hash" --notices "$work/peerimeter-agent.NOTICES.txt" --notices-sha256 "$notices_hash" --install-dir "$destination" >"$work/failure.log" 2>&1; then
  echo 'FAIL: existing destination symlink was accepted' >&2
  exit 1
fi
grep -Fq 'must not be symbolic links' "$work/failure.log"
test -L "$destination/peerimeter-agent.NOTICES.txt"
cmp "$work/original.agent" "$destination/peerimeter-agent"
cmp "$work/original.inventory" "$destination/.peerimeter-agent.install.json"
rm "$destination/peerimeter-agent.NOTICES.txt"
cp "$work/original.notices" "$destination/peerimeter-agent.NOTICES.txt"
echo 'PASS: existing destination symlink rejected without changing its target or installed binary'

# This fake curl is a deterministic fixture transport. The installer still uses
# its real fixed HTTPS URLs; there is no untrusted HTTP/base-URL bypass in it.
cat >"$work/mock-bin/curl" <<'SH'
#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
 case "$1" in
  -o|--output) output=$2; shift 2;;
  -w|--write-out|--proto|--proto-redir|--max-time) shift 2;;
  --tlsv1.2|-fsSL) shift;;
  https://*) url=$1; shift;;
  *) echo 'Unexpected mock curl argument' >&2; exit 97;;
 esac
done
printf '%s\n' "$url" >>"$FIXTURE_CURL_LOG"
repo=https://github.com/peerimeter/peerimeter-agent
if [ "$url" = "$repo/releases/latest" ]; then
 printf '%s/releases/tag/v0.4.2' "$repo"
 exit 0
fi
case "$url" in "$repo/releases/download/v99.0.0/"*) exit 22;; esac
case "$url" in "$repo/releases/download/v0.4.2/"*) tag=v0.4.2;; "$repo/releases/download/v0.3.1/"*) tag=v0.3.1;; *) exit 98;; esac
asset=peerimeter-agent-${FIXTURE_OS}-${FIXTURE_ASSET_ARCH}
notices=$asset.NOTICES.txt
case "$url" in
 "$repo/releases/download/$tag/$asset") cp "$FIXTURE_BINARY" "$output";;
 "$repo/releases/download/$tag/$notices") cp "$FIXTURE_NOTICES" "$output";;
 "$repo/releases/download/$tag/SHA256SUMS") printf '%s  %s\n%s  %s\n' "$FIXTURE_HASH" "$asset" "$FIXTURE_NOTICES_HASH" "$notices" >"$output";;
 *) exit 99;;
esac
SH
chmod 755 "$work/mock-bin/curl"
case "$(uname -s)" in Linux) FIXTURE_OS=linux;; Darwin) FIXTURE_OS=darwin;; *) exit 1;; esac
case "$(uname -m)" in x86_64|amd64) FIXTURE_ARCH=amd64;; arm64|aarch64) FIXTURE_ARCH=arm64;; *) exit 1;; esac
case "$FIXTURE_ARCH" in amd64) FIXTURE_ASSET_ARCH=x86_64;; arm64) FIXTURE_ASSET_ARCH=aarch64;; esac
export FIXTURE_OS FIXTURE_ARCH FIXTURE_ASSET_ARCH
export FIXTURE_BINARY=$work/peerimeter-agent FIXTURE_NOTICES=$work/peerimeter-agent.NOTICES.txt FIXTURE_HASH=$hash FIXTURE_NOTICES_HASH=$notices_hash FIXTURE_CURL_LOG=$work/curl.log
export PATH=$work/mock-bin:$PATH
: >"$FIXTURE_CURL_LOG"
sh "$installer" --install-dir "$destination"
python3 - "$FIXTURE_CURL_LOG" "$FIXTURE_OS" "$FIXTURE_ASSET_ARCH" <<'PY'
import pathlib, sys
log, os, arch = sys.argv[1:]
base = 'https://github.com/peerimeter/peerimeter-agent/releases'
asset=f'peerimeter-agent-{os}-{arch}'
assert pathlib.Path(log).read_text().splitlines() == [base + '/latest', base + f'/download/v0.4.2/{asset}', base + f'/download/v0.4.2/{asset}.NOTICES.txt', base + '/download/v0.4.2/SHA256SUMS']
PY
: >"$FIXTURE_CURL_LOG"
sh "$installer" --version 0.3.1 --install-dir "$destination"
python3 - "$FIXTURE_CURL_LOG" "$FIXTURE_OS" "$FIXTURE_ASSET_ARCH" <<'PY'
import pathlib, sys
log, os, arch = sys.argv[1:]
base = 'https://github.com/peerimeter/peerimeter-agent/releases/download/v0.3.1'
asset=f'peerimeter-agent-{os}-{arch}'
assert pathlib.Path(log).read_text().splitlines() == [base + f'/{asset}', base + f'/{asset}.NOTICES.txt', base + '/SHA256SUMS']
PY
: >"$FIXTURE_CURL_LOG"
expect_failure 'Invalid release version' sh "$installer" --version '../unsafe' --install-dir "$destination"
test ! -s "$FIXTURE_CURL_LOG"
expect_failure 'Cannot download release v99.0.0' sh "$installer" --version v99.0.0 --install-dir "$destination"
cmp "$work/original.config" "$destination/operator.config"
cmp "$work/original.key" "$destination/operator.key"
echo 'PASS: latest resolves once, pinned tag and native OS/architecture match, unsupported releases fail clearly'

# Exercise full removal of a real installed native binary under the ordinary
# package-test account, without requiring machine-wide service privileges.
cp "$destination/peerimeter-agent" "$work/uninstall-verifier"
python3 - "$destination" >"$work/before-dry-run.json" <<'PY'
import hashlib,json,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]);out={}
for p in sorted(root.iterdir()):
 s=p.lstat();out[p.name]=[s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,hashlib.sha256(p.read_bytes()).hexdigest()]
print(json.dumps(out,sort_keys=True))
PY
"$destination/peerimeter-agent" uninstall --install-dir "$destination" --dry-run >"$work/removal-dry-run.json"
python3 - "$destination" "$work/before-dry-run.json" "$work/removal-dry-run.json" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);out={}
for p in sorted(root.iterdir()):
 s=p.lstat();out[p.name]=[s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,hashlib.sha256(p.read_bytes()).hexdigest()]
assert out==json.load(open(sys.argv[2])),'dry-run changed installed resources'
assert json.load(open(sys.argv[3]))['state']=='dry_run'
PY
"$destination/peerimeter-agent" uninstall --install-dir "$destination" >"$work/removal.json"
python3 - "$work/removal.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['state']=='removed'
PY
for member in peerimeter-agent peerimeter-agent.NOTICES.txt .peerimeter-agent.install.json .peerimeter-agent.install.lock; do test ! -e "$destination/$member"; done
cmp "$work/original.config" "$destination/operator.config"
cmp "$work/original.key" "$destination/operator.key"
"$work/uninstall-verifier" uninstall --install-dir "$destination" >"$work/repeated-removal.json"
python3 - "$work/repeated-removal.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['state']=='already_absent'
PY
echo 'PASS: real native installer inventory, read-only full-removal dry-run, self-uninstall, idempotence and unrelated-file preservation'
