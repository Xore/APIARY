#!/usr/bin/env bash
# Verify dashboard/static/vendor/novnc/ still matches the pinned release
# recorded in dashboard/frontend/novnc.lock -- same convention as
# check-vendored-theme.sh for Xore/theme, adapted for a multi-file vendor
# tree: tree_sha256 is sha256(sorted `find | xargs sha256sum` output), so
# any file added, removed, or edited inside the vendored tree changes it.
# Computed from paths relative to the vendored dir itself (cd into it
# first) -- sha256sum's own output line includes the path, so an absolute
# path would make this hash depend on where the repo happens to be checked
# out, which defeats the whole point of a reproducible pin. LC_ALL=C forces
# a fixed byte-order sort -- found live: the default locale's collation
# order sorted these filenames differently between a dev machine
# (en_US.UTF-8) and the CI runner, producing two different "correct"
# hashes for the identical file tree.
#
# Usage: scripts/check-vendored-novnc.sh
set -euo pipefail
export LC_ALL=C

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock="$root/dashboard/frontend/novnc.lock"
vendored="$root/dashboard/static/vendor/novnc"

[ -f "$lock" ] || { echo "missing $lock" >&2; exit 1; }
[ -d "$vendored" ] || { echo "missing $vendored" >&2; exit 1; }

read_pin() {
  sed -n "s/^$1=//p" "$lock" | head -n1
}

expected="$(read_pin tree_sha256)"
tag="$(read_pin tag)"
[ -n "$expected" ] || { echo "novnc.lock must define tree_sha256=" >&2; exit 1; }

actual="$(cd "$vendored" && find . -type f | sort | xargs sha256sum | sha256sum | cut -d' ' -f1)"
if [ "$actual" != "$expected" ]; then
  echo "dashboard/static/vendor/novnc/ does not match novnc.lock" >&2
  echo "  expected tree sha256 $expected (novnc/noVNC@$tag)" >&2
  echo "  actual   tree sha256 $actual" >&2
  exit 1
fi
echo "vendored noVNC matches novnc.lock ($tag)"
