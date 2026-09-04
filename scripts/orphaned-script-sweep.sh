#!/usr/bin/env bash
# Cross-reference every tracked shell script against anything that could invoke
# it, and report the ones nothing does.
#
# #1609 Phase 6 asked for "a real orphaned-script pass"; the first attempt at it
# timed out and was never completed. This is that pass, written down so it is
# repeatable rather than a one-off answer that goes stale the next time someone
# adds a script.
#
# Three reference channels are checked, because checking only the first produces
# a pile of false positives:
#
#   1. basename or path mentioned anywhere else in the tree
#   2. GLOB invocation of the containing directory -- e.g. quality.yml runs
#      `for t in analysis/github/tests/*.sh`, which names none of the seven
#      scripts it executes. A basename-only sweep reports all seven as orphans.
#   3. mention in any .md, which is how the operator-run diagnostics are
#      "invoked" -- by a human following a runbook.
#
# Vendored trees and cowrie's honeyfs/fakefs are excluded: those are decoy
# content for attackers to find, not code this repo calls, and every file in
# them is unreferenced by design.
#
# Exit status is 0 regardless of findings. This reports; it does not judge.
# Deleting a script because nothing greps it is how a working operator tool
# disappears -- read what each one does first.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

EXCLUDE_RE='^(sandbox/ghosts/vendor/|arcane/home/honeypot-cowrie/cowrie/honeyfs/|arcane/home/honeypot-cowrie/cowrie/fakefs/)'

mapfile -t scripts < <(git ls-files '*.sh' | grep -vE "$EXCLUDE_RE")
echo "scanned ${#scripts[@]} tracked .sh files (vendored + honeyfs decoys excluded)"

orphans=()
for f in "${scripts[@]}"; do
  base="$(basename "$f")"
  dir="$(dirname "$f")"

  # 1. referenced by name or path anywhere but itself
  if git grep -q -l -F -- "$base" -- ":!$f" 2>/dev/null; then continue; fi
  # 2. its directory invoked as a glob
  if git grep -q -lE "${dir}/\*" -- ":!$f" 2>/dev/null; then continue; fi
  # 3. named in documentation (operator-run tools live here)
  if git grep -q -l -F -- "$base" -- '*.md' 2>/dev/null; then continue; fi

  orphans+=("$f")
done

echo
if (( ${#orphans[@]} == 0 )); then
  echo "no unreferenced scripts."
  exit 0
fi

echo "${#orphans[@]} script(s) with no reference in code, glob or docs:"
echo
for f in "${orphans[@]}"; do
  desc="$(sed -n '2,6p' "$f" 2>/dev/null | grep -m1 '^#' | sed 's/^# *//' | cut -c1-90)"
  printf '  %-58s %s\n' "$f" "${desc:-<no header comment>}"
done
echo
echo "Unreferenced is not the same as dead. Before removing any of these, read"
echo "the file: an operator-run diagnostic is unreferenced by design, while a"
echo "test nothing runs is a real gap (see #2878 for that exact class)."
