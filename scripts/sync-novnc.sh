#!/usr/bin/env bash
# Re-vendor dashboard/static/vendor/novnc/ from a pinned noVNC release
# tarball and rewrite dashboard/frontend/novnc.lock. Same idea as
# sync-theme.sh, adapted for a GitHub release tarball instead of a local git
# clone since noVNC has no equivalent of theme.css's single-file build
# output -- core/ is a whole ES module tree.
#
# Usage: scripts/sync-novnc.sh <tag> <expected-tarball-sha256>
#   The sha256 must be supplied by the caller (looked up from GitHub's own
#   release page or computed from a copy already verified out-of-band) --
#   this script does not trust an unpinned download by design, same as
#   every other third-party artifact fetch in this repo (capa-rules,
#   capa-sigs, GhidrAssist).
set -euo pipefail
export LC_ALL=C

tag="${1:?usage: scripts/sync-novnc.sh <tag> <expected-tarball-sha256>}"
expected_sha256="${2:?usage: scripts/sync-novnc.sh <tag> <expected-tarball-sha256>}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock="$root/dashboard/frontend/novnc.lock"
vendored="$root/dashboard/static/vendor/novnc"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/novnc.tar.gz" "https://github.com/novnc/noVNC/archive/refs/tags/${tag}.tar.gz"
actual_sha256="$(sha256sum "$tmp/novnc.tar.gz" | cut -d' ' -f1)"
if [ "$actual_sha256" != "$expected_sha256" ]; then
  echo "tarball checksum mismatch for noVNC@$tag" >&2
  echo "  expected $expected_sha256" >&2
  echo "  actual   $actual_sha256" >&2
  exit 1
fi

version="${tag#v}"
tar -xzf "$tmp/novnc.tar.gz" -C "$tmp" \
  "noVNC-${version}/core" \
  "noVNC-${version}/vendor/pako/lib" \
  "noVNC-${version}/vendor/pako/LICENSE" \
  "noVNC-${version}/LICENSE.txt"

rm -rf "$vendored"
mkdir -p "$vendored/vendor/pako"
cp -r "$tmp/noVNC-${version}/core" "$vendored/core"
cp -r "$tmp/noVNC-${version}/vendor/pako/lib" "$vendored/vendor/pako/lib"
cp "$tmp/noVNC-${version}/vendor/pako/LICENSE" "$vendored/vendor/pako/LICENSE"
cp "$tmp/noVNC-${version}/LICENSE.txt" "$vendored/LICENSE.txt"

tree_sha256="$(cd "$vendored" && find . -type f | sort | xargs sha256sum | sha256sum | cut -d' ' -f1)"

cat >"$lock" <<EOF
repository=https://github.com/novnc/noVNC
tag=$tag
tarball_sha256=$expected_sha256
tree_sha256=$tree_sha256
EOF

echo "vendored noVNC@$tag"
echo
echo "Next:"
echo "  1. (cd dashboard && go build ./... && go test ./...)"
echo "  2. scripts/check-vendored-novnc.sh"
echo "  3. review noVNC's changelog for rfb.js API changes before updating any code that imports it"
