#!/usr/bin/env bash
# test_rejections.sh — malformed or unresolvable requests are rejected with
# a recorded reason, never silently dropped and never treated as a pass.
set -euo pipefail

fail() { echo "FAIL: $*"; exit 1; }
pass() { echo "pass: $*"; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Pin the env-file path into the sandbox. The production scripts source
# ${GITHUB_ANALYSIS_ENV_FILE:-/etc/honeypot-github.env} whenever the file
# exists, and this suite's CI lane runs on the real homeserver runner
# (#2389), which legitimately has /etc/honeypot-github.env installed --
# sourcing it would override these hermetic exports with live host state
# (GH_PAT, GITHUB_REPO, real dirs). The old refuse-guard closed that leak
# by refusing to run on any host carrying the file, which made this test
# permanently red on the very runner it is routed to (#2461). Pointing the
# variable at an empty fixture inside $work closes the same leak
# deterministically instead: nothing host-owned can ever be sourced.
: >"$work/host-env"
export GITHUB_ANALYSIS_ENV_FILE="$work/host-env"

export GITHUB_ANALYSIS_REQUEST_DIR="$work/requests/pending"
export GITHUB_ANALYSIS_RESULTS_DIR="$work/results"
export GITHUB_ANALYSIS_PENDING_DIR="$work/pending"
export GITHUB_ANALYSIS_LOCK="$work/publish.lock"
export COWRIE_DOWNLOADS_DIR="$work/cowrie-downloads"
unset GITHUB_PUBLISH_ENABLED

install -d -m 0700 "$GITHUB_ANALYSIS_REQUEST_DIR" "$GITHUB_ANALYSIS_RESULTS_DIR" "$COWRIE_DOWNLOADS_DIR"
rejected="$work/requests/rejected"

# Case 1: malformed hash (not hex, wrong length).
: >"$GITHUB_ANALYSIS_REQUEST_DIR/not-a-hash.request"

# Case 2: well-formed hash, but no sample anywhere resolves to it.
unresolvable=$(printf '%064d' 1)
: >"$GITHUB_ANALYSIS_REQUEST_DIR/$unresolvable.request"

"$script_dir/process-github-requests.sh"

[[ -f "$rejected/not-a-hash.request" ]] || fail "malformed hash request was not moved to rejected/"
pass "malformed hash rejected"
[[ -f "$rejected/not-a-hash.request.error" ]] || fail "malformed hash rejection has no recorded reason"
pass "malformed hash rejection reason recorded"

[[ -f "$rejected/$unresolvable.request" ]] || fail "unresolvable-sample request was not moved to rejected/"
pass "unresolvable sample rejected"
[[ -f "$rejected/$unresolvable.request.error" ]] || fail "unresolvable-sample rejection has no recorded reason"
pass "unresolvable sample rejection reason recorded"

shopt -s nullglob
results=("$GITHUB_ANALYSIS_RESULTS_DIR"/*.json)
shopt -u nullglob
[[ ${#results[@]} -eq 0 ]] || fail "a rejected request produced a result record; rejections are not verdicts"
pass "no result records for rejected requests"

echo "OK: rejections are recorded, not dropped or scored"
