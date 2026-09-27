#!/usr/bin/env bash
# scripts/merge-train.sh — batch-validate N PRs as ONE merged result, locally.
#
# WHY: waiting for each PR's CI after each sibling merge costs O(N^2) CI runs, and
# this repo's self-hosted fleet (7 CI runners) saturates on two concurrent runs —
# the second sits `queued` with no signal. This merges every train member into a
# throwaway worktree cut from the base tip, runs the local gate suite ONCE on the
# final result, and prints the evidence that authorizes `gh pr merge` per member.
#
# READ-ONLY FROM origin. It never pushes, never merges a PR, never touches another
# worktree, and never uses `git stash`. Merging stays a separate, explicit step.
#
# Usage:
#   scripts/merge-train.sh [--plan] <base-branch> <PR#> [<PR#>...]
#     --plan  print the planned work and exit 0; no worktree, no network
#
# Exit codes:
#   0  suite green, or red-but-only-inherited (see INHERITED below); evidence printed
#   1  usage error
#   2  suite red on the merged result (real regression or conflict)
#   A PR that conflicts with the accumulated result is EJECTED and reported; the
#   train continues with the rest, matching upstream behaviour.
#
# Adapted from diegosouzapw/OmniRoute scripts/release/merge-train.sh (v3.8.49
# merge queue fallback, docs/ops/MERGE_TRAIN.md). Upstream's --fast reduced-coverage
# mode is deliberately NOT ported: the doc gates are the point of the work this
# repo is merging, so parity means the full local suite.
set -uo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
PLAN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --plan) PLAN=1; shift ;;
    --*) echo "error: unknown flag '$1'" >&2; exit 1 ;;
    *) break ;;
  esac
done
[ $# -ge 2 ] || { echo "usage: $0 [--plan] <base-branch> <PR#> [<PR#>...]" >&2; exit 1; }

BASE=$1; shift
PRS=("$@")
for N in "${PRS[@]}"; do
  case "$N" in
    ''|*[!0-9]*) echo "error: PR number '$N' is not numeric" >&2; exit 1 ;;
  esac
done

echo "== merge-train plan =="
echo "base : $BASE"
echo "prs  : ${PRS[*]}"
if [ "$PLAN" = 1 ]; then
  echo "(--plan: no worktree created, no network calls)"
  exit 0
fi

command -v gh >/dev/null || { echo "error: gh not found" >&2; exit 1; }

# Resolve each PR's head branch. A closed/unknown PR is a usage error, not a skip:
# silently dropping a member would validate a batch the caller did not ask for.
BRANCHES=()
for N in "${PRS[@]}"; do
  info=$(gh pr view "$N" --repo Xore/APIARY --json state,headRefName,headRefOid,mergeable \
         --jq '"\(.state)|\(.headRefName)|\(.headRefOid)|\(.mergeable)"' 2>/dev/null) || {
    echo "error: cannot read PR #$N" >&2; exit 1; }
  IFS='|' read -r state branch oid mergeable <<<"$info"
  case "$state" in
    OPEN) ;;
    *) echo "error: PR #$N is $state, not OPEN — refusing to train it" >&2; exit 1 ;;
  esac
  echo "  #$N  $branch  ${oid:0:8}  ($mergeable)"
  BRANCHES+=("$branch")
done

git -C "$REPO_ROOT" fetch -q origin 2>/dev/null || true
BASE_SHA=$(git -C "$REPO_ROOT" rev-parse "origin/$BASE" 2>/dev/null) || {
  echo "error: no origin/$BASE" >&2; exit 1; }

WT=$(mktemp -d "${TMPDIR:-/tmp}/merge-train-XXXXXX")
# shellcheck disable=SC2064
trap "rm -rf '$WT'" EXIT
echo
echo "== throwaway worktree: $WT =="

git -C "$REPO_ROOT" worktree add -q --detach "$WT" "$BASE_SHA" || {
  echo "error: worktree add failed" >&2; exit 1; }

EJECTED=()
for i in "${!BRANCHES[@]}"; do
  b=${BRANCHES[$i]}; n=${PRS[$i]}
  if git -C "$WT" merge --no-edit -q "origin/$b" >"$WT/.merge.log" 2>&1; then
    echo "  merged  #$n  $b"
  else
    # Eject, do not abort the train: the caller decides whether to fix or drop it.
    echo "  EJECTED #$n  $b  (conflict)"
    sed -n '1,20p' "$WT/.merge.log" | sed 's/^/      /'
    EJECTED+=("$n")
    git -C "$WT" merge --abort 2>/dev/null || git -C "$WT" reset -q --hard "$BASE_SHA"
  fi
  rm -f "$WT/.merge.log"
done

# Anchor gate: the train is only meaningful if the base itself passes. A base that
# is already red is reported INHERITED and does not by itself condemn the batch.
echo
echo "== local gate suite on the merged result =="
declare -a GATES=(
  "scripts/check-doc-paths-exist.py"
  "scripts/check-docs-reachable.py"
  "scripts/check-doc-stale-paths.py"
  "scripts/check-public-leaks.py"
)
FAILED=()
for g in "${GATES[@]}"; do
  if [ ! -f "$WT/$g" ]; then
    # A named gate that is absent is a FAILURE, not a skip: silently skipping a
    # renamed gate is how a train goes green without ever having been checked.
    echo "  FAIL  $g (named gate missing at this base — parity with CI is broken)"
    FAILED+=("$g")
    continue
  fi
  if out=$(cd "$WT" && python3 "$g" 2>&1); then
    echo "  PASS  $g"
  else
    echo "  FAIL  $g"
    echo "$out" | tail -15 | sed 's/^/        /'
    FAILED+=("$g")
  fi
done

# The link + Mermaid gates are pytest rows in quality.yml, not scripts — parity
# means running the same suite CI runs, not a hand-picked subset of it.
if [ -d "$WT/tests/docs" ]; then
  if out=$(cd "$WT" && python3 -m pytest tests/docs/ -q 2>&1); then
    echo "  PASS  tests/docs/ (link, Mermaid and regression gates)"
  else
    echo "  FAIL  tests/docs/"
    echo "$out" | tail -25 | sed 's/^/        /'
    FAILED+=("tests/docs/")
  fi
else
  echo "  FAIL  tests/docs/ (missing at this base — parity with CI is broken)"
  FAILED+=("tests/docs/")
fi

echo
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "TRAIN_GREEN"
  [ ${#EJECTED[@]} -eq 0 ] || echo "EJECTED: ${EJECTED[*]} — not validated, do not merge"
  echo "Next: re-check 'state,headRefOid' per PR, then merge one at a time."
  exit 0
fi

echo "TRAIN_RED"
[ ${#EJECTED[@]} -eq 0 ] || echo "EJECTED: ${EJECTED[*]}"
echo "Failing gates: ${FAILED[*]}"
echo "A red is information. Bisect by halves; do not blanket-rerun CI."
exit 2
