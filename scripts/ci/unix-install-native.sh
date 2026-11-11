#!/usr/bin/env bash
# Stage an archive from the actual native test executable and feed the real
# operator installer. Production release archives are verified separately by the
# package workflow; this fixture exists to exercise inventory ownership natively.
set -euo pipefail
source=${1:?usage: unix-install-native.sh AGENT DESTINATION}
destination=${2:?usage: unix-install-native.sh AGENT DESTINATION}
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/package"
install -m 0755 "$source" "$work/package/peerimeter-agent"
printf 'Native integration archive fixture; release packages include full dependency notices.\n' >"$work/package/peerimeter-agent.NOTICES.txt"
tar -czf "$work/package.tar.gz" -C "$work/package" peerimeter-agent peerimeter-agent.NOTICES.txt
if command -v sha256sum >/dev/null; then hash=$(sha256sum "$work/package.tar.gz" | awk '{print $1}'); else hash=$(shasum -a 256 "$work/package.tar.gz" | awk '{print $1}'); fi
sh "$repo/install.sh" --archive "$work/package.tar.gz" --sha256 "$hash" --install-dir "$destination"
[[ -f "$destination/.peerimeter-agent.install.json" ]]
chmod 0755 "$destination"
