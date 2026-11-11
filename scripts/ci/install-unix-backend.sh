#!/usr/bin/env bash
# Build the exact official backend tools used by the feasibility probes.
set -euo pipefail
out=${1:?usage: install-unix-backend.sh OUTPUT_DIRECTORY}
mkdir -p "$out"
source_dir=$(mktemp -d)
trap 'rm -rf "$source_dir"' EXIT
fetch_source() {
  local repo=$1 commit=$2 destination=$3
  git init -q "$destination"
  git -C "$destination" fetch -q --depth=1 "https://github.com/WireGuard/$repo.git" "$commit"
  test "$(git -C "$destination" rev-parse FETCH_HEAD)" = "$commit"
  git -C "$destination" checkout -q --detach FETCH_HEAD
}
# wireguard-tools v1.0.20260223, dereferenced signed release tag.
fetch_source wireguard-tools 49ce333da02056ae7b22ee2aeb6afe8aaed79b19 "$source_dir/tools"
make -C "$source_dir/tools/src" wg
install -m 0755 "$source_dir/tools/src/wg" "$out/wg"
if [ "$(uname -s)" = Darwin ]; then
  # wireguard-go 0.0.20250522: official macOS userspace backend.
  fetch_source wireguard-go f333402bd9cbe0f3eeb02507bd14e23d7d639280 "$source_dir/go"
  (cd "$source_dir/go" && go build -mod=readonly -o "$out/wireguard-go" .)
fi
"$out/wg" --version
