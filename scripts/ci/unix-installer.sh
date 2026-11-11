#!/usr/bin/env bash
# Portable Linux/macOS installer tests, requiring no published GitHub release.
set -euo pipefail
installer=$(cd "$(dirname "$0")/../.." && pwd)/install.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
mkdir -p "$work/package" "$work/mock-bin" "$work/custom install/bin"
printf '#!/bin/sh\nprintf "fixture agent\\n"\n' >"$work/package/peerimeter-agent"
chmod 755 "$work/package/peerimeter-agent"
printf 'Fixture third-party notices\n' >"$work/package/peerimeter-agent.NOTICES.txt"
tar -czf "$work/package.tar.gz" -C "$work/package" peerimeter-agent peerimeter-agent.NOTICES.txt
hash=$(sha256 "$work/package.tar.gz")
destination=$work/custom\ install/bin
printf 'operator config stays\n' >"$destination/operator.config"
printf 'operator key stays\n' >"$destination/operator.key"
cp "$destination/operator.config" "$work/original.config"
cp "$destination/operator.key" "$work/original.key"
sh "$installer" --archive "$work/package.tar.gz" --sha256 "$hash" --install-dir "$destination"
cmp "$work/package/peerimeter-agent" "$destination/peerimeter-agent"
cmp "$work/package/peerimeter-agent.NOTICES.txt" "$destination/peerimeter-agent.NOTICES.txt"
test "$("$destination/peerimeter-agent")" = 'fixture agent'
cp "$destination/peerimeter-agent" "$work/original.agent"
cp "$destination/peerimeter-agent.NOTICES.txt" "$work/original.notices"
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
}
expect_failure 'Package checksum verification failed' sh "$installer" --archive "$work/package.tar.gz" --sha256 "$(printf '%064d' 0)" --install-dir "$destination"
expect_failure 'single SHA-256 digest' sh "$installer" --archive "$work/package.tar.gz" --sha256 "$hash
$hash" --install-dir "$destination"
echo 'PASS: offline checksum verification, spaced destination and existing binary preservation'

# Build malicious archives with valid checksums: validation must reject archive
# structure before any extraction can follow a link or overwrite another file.
printf 'outside archive extraction directory\n' >"$work/victim"
python3 - "$work" <<'PY'
import io, pathlib, sys, tarfile
root = pathlib.Path(sys.argv[1])
for kind in ('symlink', 'hardlink', 'duplicate', 'traversal'):
    with tarfile.open(root / (kind + '.tar.gz'), 'w:gz') as archive:
        binary = tarfile.TarInfo('peerimeter-agent')
        if kind in ('symlink', 'duplicate'):
            binary.type, binary.linkname = tarfile.SYMTYPE, str(root / 'victim')
            archive.addfile(binary)
        elif kind == 'hardlink':
            binary.type, binary.linkname = tarfile.LNKTYPE, str(root / 'victim')
            archive.addfile(binary)
        else:
            binary.size = 3
            archive.addfile(binary, io.BytesIO(b'new'))
        if kind == 'duplicate':
            binary = tarfile.TarInfo('peerimeter-agent')
            binary.size = 3
            archive.addfile(binary, io.BytesIO(b'new'))
        notices = tarfile.TarInfo('peerimeter-agent.NOTICES.txt')
        notices.size = 7
        archive.addfile(notices, io.BytesIO(b'notices'))
        if kind == 'traversal':
            other = tarfile.TarInfo('../outside')
            other.size = 3
            archive.addfile(other, io.BytesIO(b'bad'))
PY
for kind in symlink hardlink; do
  expect_failure 'must be regular files' sh "$installer" --archive "$work/$kind.tar.gz" --sha256 "$(sha256 "$work/$kind.tar.gz")" --install-dir "$destination"
done
expect_failure 'exactly one binary' sh "$installer" --archive "$work/duplicate.tar.gz" --sha256 "$(sha256 "$work/duplicate.tar.gz")" --install-dir "$destination"
expect_failure 'Unexpected package member' sh "$installer" --archive "$work/traversal.tar.gz" --sha256 "$(sha256 "$work/traversal.tar.gz")" --install-dir "$destination"
test "$(cat "$work/victim")" = 'outside archive extraction directory'
echo 'PASS: symlink, hardlink, duplicate and traversal packages rejected before installation'
# Existing destination links are replaced as directory entries, never followed.
rm -f "$destination/peerimeter-agent.NOTICES.txt"
ln -s "$work/victim" "$destination/peerimeter-agent.NOTICES.txt"
sh "$installer" --archive "$work/package.tar.gz" --sha256 "$hash" --install-dir "$destination"
test ! -L "$destination/peerimeter-agent.NOTICES.txt"
test "$(cat "$work/victim")" = 'outside archive extraction directory'
cmp "$work/original.notices" "$destination/peerimeter-agent.NOTICES.txt"
echo 'PASS: existing destination notice symlink replaced without following it'

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
asset=peerimeter-agent_${tag}_${FIXTURE_OS}_${FIXTURE_ARCH}.tar.gz
case "$url" in
 "$repo/releases/download/$tag/$asset") cp "$FIXTURE_ARCHIVE" "$output";;
 "$repo/releases/download/$tag/SHA256SUMS") printf '%s  %s\n' "$FIXTURE_HASH" "$asset" >"$output";;
 *) exit 99;;
esac
SH
chmod 755 "$work/mock-bin/curl"
case "$(uname -s)" in Linux) FIXTURE_OS=linux;; Darwin) FIXTURE_OS=darwin;; *) exit 1;; esac
case "$(uname -m)" in x86_64|amd64) FIXTURE_ARCH=amd64;; arm64|aarch64) FIXTURE_ARCH=arm64;; *) exit 1;; esac
export FIXTURE_OS FIXTURE_ARCH
export FIXTURE_ARCHIVE=$work/package.tar.gz FIXTURE_HASH=$hash FIXTURE_CURL_LOG=$work/curl.log
export PATH=$work/mock-bin:$PATH
: >"$FIXTURE_CURL_LOG"
sh "$installer" --install-dir "$destination"
python3 - "$FIXTURE_CURL_LOG" "$FIXTURE_OS" "$FIXTURE_ARCH" <<'PY'
import pathlib, sys
log, os, arch = sys.argv[1:]
base = 'https://github.com/peerimeter/peerimeter-agent/releases'
assert pathlib.Path(log).read_text().splitlines() == [base + '/latest', base + f'/download/v0.4.2/peerimeter-agent_v0.4.2_{os}_{arch}.tar.gz', base + '/download/v0.4.2/SHA256SUMS']
PY
: >"$FIXTURE_CURL_LOG"
sh "$installer" --version 0.3.1 --install-dir "$destination"
python3 - "$FIXTURE_CURL_LOG" "$FIXTURE_OS" "$FIXTURE_ARCH" <<'PY'
import pathlib, sys
log, os, arch = sys.argv[1:]
base = 'https://github.com/peerimeter/peerimeter-agent/releases/download/v0.3.1'
assert pathlib.Path(log).read_text().splitlines() == [base + f'/peerimeter-agent_v0.3.1_{os}_{arch}.tar.gz', base + '/SHA256SUMS']
PY
: >"$FIXTURE_CURL_LOG"
expect_failure 'Invalid release version' sh "$installer" --version '../unsafe' --install-dir "$destination"
test ! -s "$FIXTURE_CURL_LOG"
expect_failure 'Cannot download release v99.0.0' sh "$installer" --version v99.0.0 --install-dir "$destination"
cmp "$work/original.config" "$destination/operator.config"
cmp "$work/original.key" "$destination/operator.key"
echo 'PASS: latest resolves once, pinned tag and native OS/architecture match, unsupported releases fail clearly'
