#!/usr/bin/env bash
# Same real agent acceptance test locally as in native CI. Requires root/sudo.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export CGO_ENABLED=0
go build -mod=readonly -o "$work/peerimeter-agent" ./cmd/peerimeter-agent
case "$(uname -s)" in
 Linux) sudo bash scripts/ci/linux-agent.sh "$work/peerimeter-agent";;
 Darwin)
  go build -C tests/backendprobe -mod=readonly -o "$work/pmprobe" .
  sudo bash scripts/ci/macos-agent.sh "$work/peerimeter-agent" "$work/pmprobe";;
 *) echo 'Use scripts/ci/windows-agent.ps1 with the packaged executable/DLL and reference peer on Windows.' >&2;exit 1;;
esac
