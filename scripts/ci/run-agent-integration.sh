#!/usr/bin/env bash
# Same real agent acceptance test locally as in native CI. Requires root/sudo.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export CGO_ENABLED=0
go build -mod=readonly -o "$work/peerimeter-agent" ./cmd/peerimeter-agent
case "$(uname -s)" in
 Linux|Darwin)
  legacy_revision=4246c6bea040bfa41a0bd506f0df501310a20367
  if ! git cat-file -e "$legacy_revision^{commit}" 2>/dev/null; then git fetch --depth=1 origin "$legacy_revision"; fi
  mkdir "$work/legacy-source"
  git archive "$legacy_revision" | tar -x -C "$work/legacy-source"
  go build -C "$work/legacy-source" -mod=readonly -o "$work/legacy-agent" ./cmd/peerimeter-agent;;
 esac
case "$(uname -s)" in
 Linux) sudo bash scripts/ci/linux-agent.sh "$work/peerimeter-agent" "$work/legacy-agent";;
 Darwin)
  go build -C tests/backendprobe -mod=readonly -o "$work/pmprobe" .
  sudo bash scripts/ci/macos-agent.sh "$work/peerimeter-agent" "$work/pmprobe" "$work/legacy-agent";;
 *) echo 'Use scripts/ci/windows-agent.ps1 with the packaged executable/DLL and reference peer on Windows.' >&2;exit 1;;
esac
