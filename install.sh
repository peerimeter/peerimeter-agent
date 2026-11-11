#!/bin/sh
# Operator-invoked installer. Does not enroll, start services or change config.
set -eu
version=latest
install_dir=/usr/local/bin
binary=
notices=
expected=
notices_expected=
allow_insecure_install_dir=0
usage() { echo 'Usage: install.sh [--version <tag|latest>] [--install-dir <path>] [--allow-insecure-install-dir] [--binary <local-file> --sha256 <digest> --notices <local-file> --notices-sha256 <digest>]' >&2; exit 1; }
while [ "$#" -gt 0 ]; do
 case "$1" in
  --version) [ "$#" -ge 2 ] || usage; version=$2; shift 2;;
  --install-dir) [ "$#" -ge 2 ] || usage; install_dir=$2; shift 2;;
  --allow-insecure-install-dir) allow_insecure_install_dir=1; shift;;
  --binary) [ "$#" -ge 2 ] || usage; binary=$2; shift 2;;
  --notices) [ "$#" -ge 2 ] || usage; notices=$2; shift 2;;
  --sha256) [ "$#" -ge 2 ] || usage; expected=$2; shift 2;;
  --notices-sha256) [ "$#" -ge 2 ] || usage; notices_expected=$2; shift 2;;
  *) usage;;
 esac
done
case "$install_dir" in /*) ;; *) echo 'Installation directory must be absolute.' >&2; exit 1;; esac
case "$(uname -s)" in Linux) os=linux;; Darwin) os=darwin;; *) echo 'Unsupported OS; use install.ps1 on Windows.' >&2; exit 1;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Unsupported CPU architecture.' >&2; exit 1;; esac
work=$(mktemp -d)
staged=
staged_notice=
changed=0
completed=0
old_binary=0
old_notice=0
rollback_failed=0
rollback_file() {
 target=$1
 original=$2
 existed=$3
 if [ "$existed" -eq 1 ]; then
  restore=$(mktemp "$install_dir/.peerimeter-restore.XXXXXX") || return 1
  cp -p "$original" "$restore" && mv -f "$restore" "$target" || { rm -f "$restore"; return 1; }
 else
  rm -f "$target" || return 1
 fi
}
cleanup() {
 status=$?
 if [ "$changed" -eq 1 ] && [ "$completed" -eq 0 ]; then
  rollback_file "$install_dir/peerimeter-agent" "$work/original-agent" "$old_binary" || { echo 'Installer rollback could not restore the previous executable.' >&2; status=1; rollback_failed=1; }
  rollback_file "$install_dir/peerimeter-agent.NOTICES.txt" "$work/original-notices" "$old_notice" || { echo 'Installer rollback could not restore the previous notice file.' >&2; status=1; rollback_failed=1; }
 fi
 if [ "$rollback_failed" -eq 0 ]; then rm -rf "$work"; else printf 'Previous package backups retained for recovery: %s\n' "$work" >&2; fi
 if [ -n "$staged" ]; then rm -f "$staged"; fi
 if [ -n "$staged_notice" ]; then rm -f "$staged_notice"; fi
 trap - EXIT
 exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
if [ -z "$binary" ]; then
 command -v curl >/dev/null 2>&1 || { echo 'curl is required for release downloads.' >&2; exit 1; }
 repo=https://github.com/peerimeter/peerimeter-agent
 if [ "$version" = latest ]; then
  resolved=$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --max-time 60 -o /dev/null -w '%{url_effective}' "$repo/releases/latest") || { echo 'Cannot resolve the latest release; check connectivity and whether a release has been published.' >&2; exit 1; }
  version=${resolved##*/}
 fi
 case "$version" in v*) ;; *) version=v$version;; esac
 # Only release tags; reject traversal, option injection and ambiguous paths.
 printf '%s\n' "$version" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$' || { echo 'Invalid release version.' >&2; exit 1; }
 case "$arch" in amd64) asset_arch=x86_64;; arm64) asset_arch=aarch64;; esac
 asset=peerimeter-agent-${os}-${asset_arch}
 notices_asset=$asset.NOTICES.txt
 binary=$work/peerimeter-agent
 notices=$work/peerimeter-agent.NOTICES.txt
 curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --max-time 120 "$repo/releases/download/$version/$asset" -o "$binary" || { echo "Cannot download release $version for $os/$arch; check the release tag and available assets." >&2; exit 1; }
 curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --max-time 60 "$repo/releases/download/$version/$notices_asset" -o "$notices" || { echo 'Cannot download release notices.' >&2; exit 1; }
 curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --max-time 60 "$repo/releases/download/$version/SHA256SUMS" -o "$work/SHA256SUMS" || { echo 'Cannot download release checksums.' >&2; exit 1; }
 expected=$(awk -v name="$asset" '$2==name {print $1}' "$work/SHA256SUMS")
 notices_expected=$(awk -v name="$notices_asset" '$2==name {print $1}' "$work/SHA256SUMS")
fi
for digest in "$expected" "$notices_expected"; do
 case "$digest" in ''|*[!0-9a-fA-F]*) echo 'A SHA-256 digest is required for both binary and notices.' >&2; exit 1;; esac
 [ "${#digest}" -eq 64 ] || { echo 'A SHA-256 digest is required for both binary and notices.' >&2; exit 1; }
done
[ -f "$binary" ] && [ ! -L "$binary" ] && [ -f "$notices" ] && [ ! -L "$notices" ] || { echo 'Binary and notices must be regular files.' >&2; exit 1; }
[ "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" = "$(sha256 "$binary")" ] || { echo 'Binary checksum verification failed.' >&2; exit 1; }
[ "$(printf '%s' "$notices_expected" | tr 'A-F' 'a-f')" = "$(sha256 "$notices")" ] || { echo 'Notice checksum verification failed.' >&2; exit 1; }
mkdir -p "$install_dir" || { echo 'Cannot create destination; choose a writable directory or run with sudo.' >&2; exit 1; }
[ ! -d "$install_dir/peerimeter-agent" ] || { echo 'Binary destination is a directory.' >&2; exit 1; }
[ ! -d "$install_dir/peerimeter-agent.NOTICES.txt" ] || { echo 'Notice destination is a directory.' >&2; exit 1; }
# Preserve existing ordinary package members before any replacement. Never
# dereference a pre-existing link into another application's files.
for destination in "$install_dir/peerimeter-agent" "$install_dir/peerimeter-agent.NOTICES.txt"; do
 [ ! -L "$destination" ] || { echo 'Installed package members must not be symbolic links.' >&2; exit 1; }
 [ ! -e "$destination" ] || [ -f "$destination" ] || { echo 'Installed package member is not a regular file.' >&2; exit 1; }
done
if [ -f "$install_dir/peerimeter-agent" ]; then cp -p "$install_dir/peerimeter-agent" "$work/original-agent"; old_binary=1; fi
if [ -f "$install_dir/peerimeter-agent.NOTICES.txt" ]; then cp -p "$install_dir/peerimeter-agent.NOTICES.txt" "$work/original-notices"; old_notice=1; fi
staged=$(mktemp "$install_dir/.peerimeter-agent.XXXXXX")
staged_notice=$(mktemp "$install_dir/.peerimeter-notices.XXXXXX")
install -m 0755 "$binary" "$staged"
# Notices precede the atomic executable replacement; no config or keys are touched.
install -m 0644 "$notices" "$staged_notice"
changed=1
mv -f "$staged_notice" "$install_dir/peerimeter-agent.NOTICES.txt"
staged_notice=
mv -f "$staged" "$install_dir/peerimeter-agent"
staged=
# The installed binary writes the protected inventory using the same audited
# ownership/path rules as full uninstall. Source configs and keys are not claimed.
if [ "$allow_insecure_install_dir" -eq 1 ]; then
 "$install_dir/peerimeter-agent" register-installation --install-dir "$install_dir" --allow-insecure-install-dir >/dev/null
else
 "$install_dir/peerimeter-agent" register-installation --install-dir "$install_dir" >/dev/null
fi
[ -f "$install_dir/.peerimeter-agent.install.json" ] && [ ! -L "$install_dir/.peerimeter-agent.install.json" ] || { echo 'Installation inventory registration failed.' >&2; exit 1; }
completed=1
printf 'Installed %s/peerimeter-agent (%s/%s). Config and services are managed separately.\n' "$install_dir" "$os" "$arch"
