#!/bin/sh
# Operator-invoked installer. Does not enroll, start services or change config.
set -eu
version=latest
install_dir=/usr/local/bin
archive=
expected=
usage() { echo 'Usage: install.sh [--version <tag|latest>] [--install-dir <path>] [--archive <local.tar.gz> --sha256 <digest>]' >&2; exit 1; }
while [ "$#" -gt 0 ]; do
 case "$1" in
  --version) [ "$#" -ge 2 ] || usage; version=$2; shift 2;;
  --install-dir) [ "$#" -ge 2 ] || usage; install_dir=$2; shift 2;;
  --archive) [ "$#" -ge 2 ] || usage; archive=$2; shift 2;;
  --sha256) [ "$#" -ge 2 ] || usage; expected=$2; shift 2;;
  *) usage;;
 esac
done
case "$install_dir" in /*) ;; *) echo 'Installation directory must be absolute.' >&2; exit 1;; esac
case "$(uname -s)" in Linux) os=linux;; Darwin) os=darwin;; *) echo 'Unsupported OS; use install.ps1 on Windows.' >&2; exit 1;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Unsupported CPU architecture.' >&2; exit 1;; esac
work=$(mktemp -d)
staged=
staged_notice=
cleanup() {
 rm -rf "$work"
 if [ -n "$staged" ]; then rm -f "$staged"; fi
 if [ -n "$staged_notice" ]; then rm -f "$staged_notice"; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
if [ -z "$archive" ]; then
 command -v curl >/dev/null 2>&1 || { echo 'curl is required for release downloads.' >&2; exit 1; }
 repo=https://github.com/peerimeter/peerimeter-agent
 if [ "$version" = latest ]; then
  resolved=$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --max-time 60 -o /dev/null -w '%{url_effective}' "$repo/releases/latest") || { echo 'Cannot resolve the latest release; check connectivity and whether a release has been published.' >&2; exit 1; }
  version=${resolved##*/}
 fi
 case "$version" in v*) ;; *) version=v$version;; esac
 # Only release tags; reject traversal, option injection and ambiguous paths.
 printf '%s\n' "$version" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$' || { echo 'Invalid release version.' >&2; exit 1; }
 asset=peerimeter-agent_${version}_${os}_${arch}.tar.gz
 curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --max-time 120 "$repo/releases/download/$version/$asset" -o "$work/package.tar.gz" || { echo "Cannot download release $version for $os/$arch; check the release tag and available assets." >&2; exit 1; }
 curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --max-time 60 "$repo/releases/download/$version/SHA256SUMS" -o "$work/SHA256SUMS" || { echo 'Cannot download release checksums.' >&2; exit 1; }
 expected=$(awk -v name="$asset" '$2==name {print $1}' "$work/SHA256SUMS")
 archive=$work/package.tar.gz
fi
case "$expected" in ''|*[!0-9a-fA-F]*) echo 'A single SHA-256 digest is required; local archives need --sha256.' >&2; exit 1;; esac
[ "${#expected}" -eq 64 ] || { echo 'A single SHA-256 digest is required; local archives need --sha256.' >&2; exit 1; }
actual=$(sha256 "$archive")
[ "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" = "$actual" ] || { echo 'Package checksum verification failed.' >&2; exit 1; }
# Only known regular files are extracted; reject links, unexpected archive names.
tar -tzf "$archive" > "$work/entries"
while IFS= read -r member; do
 case "$member" in peerimeter-agent|peerimeter-agent.NOTICES.txt) ;; *) echo 'Unexpected package member.' >&2; exit 1;; esac
done < "$work/entries"
[ "$(wc -l < "$work/entries" | tr -d ' ')" -eq 2 ] && [ "$(sort -u "$work/entries" | wc -l | tr -d ' ')" -eq 2 ] || { echo 'Package must contain exactly one binary and one notice file.' >&2; exit 1; }
# Inspect entry types before extracting anything: checking -f after extraction
# cannot distinguish a hard link from an ordinary file, or detect an earlier
# malicious duplicate member overwritten by a later one.
LC_ALL=C tar -tvzf "$archive" > "$work/types"
LC_ALL=C awk 'substr($0,1,1) != "-" || / -> | link to / {bad=1} END {exit bad}' "$work/types" || { echo 'Package members must be regular files; links are not accepted.' >&2; exit 1; }
tar -xzf "$archive" -C "$work" peerimeter-agent peerimeter-agent.NOTICES.txt
[ -f "$work/peerimeter-agent" ] && [ ! -L "$work/peerimeter-agent" ] && [ -f "$work/peerimeter-agent.NOTICES.txt" ] && [ ! -L "$work/peerimeter-agent.NOTICES.txt" ] || { echo 'Package must contain regular binary and notice files.' >&2; exit 1; }
mkdir -p "$install_dir" || { echo 'Cannot create destination; choose a writable directory or run with sudo.' >&2; exit 1; }
[ ! -d "$install_dir/peerimeter-agent" ] || { echo 'Binary destination is a directory.' >&2; exit 1; }
[ ! -d "$install_dir/peerimeter-agent.NOTICES.txt" ] || { echo 'Notice destination is a directory.' >&2; exit 1; }
staged=$(mktemp "$install_dir/.peerimeter-agent.XXXXXX")
staged_notice=$(mktemp "$install_dir/.peerimeter-notices.XXXXXX")
install -m 0755 "$work/peerimeter-agent" "$staged"
# Notices precede the atomic executable replacement; no config or keys are touched.
install -m 0644 "$work/peerimeter-agent.NOTICES.txt" "$staged_notice"
mv -f "$staged_notice" "$install_dir/peerimeter-agent.NOTICES.txt"
staged_notice=
mv -f "$staged" "$install_dir/peerimeter-agent"
staged=
printf 'Installed %s/peerimeter-agent (%s/%s). Config and services are managed separately.\n' "$install_dir" "$os" "$arch"
