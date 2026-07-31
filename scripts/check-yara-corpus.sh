#!/usr/bin/env bash
# Verify that the vendored upstream YARA corpus is still the tree recorded in
# analysis/yara/rules/upstream.lock, and that index.yar names files that exist.
#
# Offline and always runs. It answers two questions that matter for a scanner
# nobody watches:
#
#   * Was a rule file edited in place? Vendored rules are upstream's, not ours;
#     a local edit here is silently lost on the next sync.
#   * Does index.yar still name every vendored file, and only files that exist?
#     A stale include is a hard yara(1) error, and yara(1) refuses to start at
#     all rather than skipping the missing file — so a broken index disables
#     scanning completely rather than partially.
#
# Skips cleanly when nothing has been vendored yet: the sync is optional, and
# the local rules work on their own.
#
# Usage: scripts/check-yara-corpus.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rules="$root/analysis/yara/rules"
dest="$rules/upstream"
lock="$rules/upstream.lock"
index="$rules/index.yar"

if [ ! -e "$lock" ] && [ ! -d "$dest" ]; then
  echo "no upstream corpus vendored - skipping (analysis/yara/sync-yara.sh adds one)"
  exit 0
fi

[ -f "$lock" ] || { echo "$dest exists but $lock does not - run analysis/yara/sync-yara.sh" >&2; exit 1; }
[ -d "$dest" ] || { echo "$lock exists but $dest does not - run analysis/yara/sync-yara.sh" >&2; exit 1; }
[ -f "$dest/MANIFEST" ] || { echo "missing $dest/MANIFEST" >&2; exit 1; }

read_pin() { sed -n "s/^$1=//p" "$lock" | head -n1; }

commit="$(read_pin commit)"
expected="$(read_pin manifest_sha256)"
[ -n "$commit" ] && [ -n "$expected" ] || {
  echo "upstream.lock must define commit= and manifest_sha256=" >&2; exit 1; }

actual="$(sha256sum "$dest/MANIFEST" | cut -d' ' -f1)"
if [ "$actual" != "$expected" ]; then
  echo "$dest/MANIFEST does not match upstream.lock" >&2
  echo "  expected $expected" >&2
  echo "  actual   $actual" >&2
  exit 1
fi

# The manifest lists every vendored file with its hash, so this catches an edit
# to a rule file that left the manifest alone.
#
# -c, not --quiet --check: BusyBox sha256sum has no long options, and this
# script runs on the Alpine image the scanner is built from as well as in CI.
# Output is captured rather than suppressed so the failing file is named.
if ! verified="$(cd "$rules" && sha256sum -c "$dest/MANIFEST" 2>&1)"; then
  echo "a vendored rule file has been modified since the last sync" >&2
  printf '%s\n' "$verified" | grep -v ': OK$' >&2 || true
  echo "Vendored rules belong to upstream. Change them there, then re-sync." >&2
  exit 1
fi

# Every file the manifest lists must still be present, and nothing may have
# been added by hand - MANIFEST itself is the one file not in its own list.
listed="$(cut -d' ' -f3- < "$dest/MANIFEST" | sort)"
present="$(cd "$rules" && find upstream -type f ! -name MANIFEST | sort)"
if [ "$listed" != "$present" ]; then
  echo "the vendored tree does not match MANIFEST" >&2
  diff <(echo "$listed") <(echo "$present") >&2 || true
  exit 1
fi

[ -f "$index" ] || { echo "missing $index - run analysis/yara/sync-yara.sh" >&2; exit 1; }
while read -r included; do
  [ -f "$rules/$included" ] || {
    echo "index.yar includes $included, which does not exist" >&2; exit 1; }
done < <(sed -n 's/^include "\(.*\)"$/\1/p' "$index")

# And the other direction: a vendored rule file nobody includes is a rule that
# looks present in the tree but is never loaded, which is the quieter failure.
index_files="$(sed -n 's/^include "\(upstream\/.*\)"$/\1/p' "$index" | sort)"
vendored="$(cd "$rules" && find upstream -type f -name '*.yar' | sort)"
if [ "$index_files" != "$vendored" ]; then
  echo "index.yar does not include exactly the vendored rule files" >&2
  diff <(echo "$index_files") <(echo "$vendored") >&2 || true
  exit 1
fi

echo "yara corpus ok: $(grep -c . < "$dest/MANIFEST") vendored file(s) at ${commit:0:7}"
