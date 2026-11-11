#!/usr/bin/env bash
# Stage the actual native test executable and feed the real operator installer.
set -euo pipefail
source=${1:?usage: unix-install-native.sh AGENT DESTINATION}
destination=${2:?usage: unix-install-native.sh AGENT DESTINATION}
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/package"
install -m 0755 "$source" "$work/package/peerimeter-agent"
printf 'Native integration archive fixture; release packages include full dependency notices.\n' >"$work/package/peerimeter-agent.NOTICES.txt"
if command -v sha256sum >/dev/null; then hash=$(sha256sum "$work/package/peerimeter-agent" | awk '{print $1}'); notice_hash=$(sha256sum "$work/package/peerimeter-agent.NOTICES.txt" | awk '{print $1}'); else hash=$(shasum -a 256 "$work/package/peerimeter-agent" | awk '{print $1}'); notice_hash=$(shasum -a 256 "$work/package/peerimeter-agent.NOTICES.txt" | awk '{print $1}'); fi
sh "$repo/install.sh" --binary "$work/package/peerimeter-agent" --sha256 "$hash" --notices "$work/package/peerimeter-agent.NOTICES.txt" --notices-sha256 "$notice_hash" --install-dir "$destination"
[[ -f "$destination/.peerimeter-agent.install.json" ]]
chmod 0755 "$destination"
