#!/usr/bin/env bash
# test_run_pending_stale_claims.sh (#2253) — proves run_pending.sh reconciles
# claims that never resolved, and that a live detonation failure still lands
# in the same *.request.failed state end-to-end.
#
# Mirrors #2246's fix for cape-worker.py/ghidra-worker.py, applied here to
# the shell consumer: a claim (*.request.running) left behind by a worker
# that died mid-detonation must not sit invisible to every future spool
# glob forever. No hypervisor, no network -- the orchestrator is stubbed.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "pass: $*"; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export WINDOWS_SANDBOX_REQUEST_DIR="$work/requests"
export WINDOWS_SANDBOX_RESULTS_DIR="$work/results"
export WINDOWS_SANDBOX_SAMPLES_DIR="$work/samples"
export WINDOWS_SANDBOX_LOCK="$work/worker.lock"
export WINDOWS_SANDBOX_KVM_SHARED_LOCK=""
export WINDOWS_SANDBOX_STALE_RUNNING_SECS=1800

install -d -m 0700 "$WINDOWS_SANDBOX_REQUEST_DIR" "$WINDOWS_SANDBOX_RESULTS_DIR" "$WINDOWS_SANDBOX_SAMPLES_DIR"

sha_stale=$(printf 'stale-claim-fixture' | sha256sum | cut -d' ' -f1)
sha_fresh=$(printf 'fresh-claim-fixture' | sha256sum | cut -d' ' -f1)
sha_fail=$(printf 'failing-claim-fixture' | sha256sum | cut -d' ' -f1)

# --- case 1: a claim older than the stale threshold is released -----------
stale_claim="$WINDOWS_SANDBOX_REQUEST_DIR/$sha_stale.request.running"
: >"$stale_claim"
touch -d "@$(( $(date +%s) - 3600 ))" "$stale_claim"

# --- case 2: a claim younger than the threshold is left alone -------------
fresh_claim="$WINDOWS_SANDBOX_REQUEST_DIR/$sha_fresh.request.running"
: >"$fresh_claim"
touch -d "@$(( $(date +%s) - 60 ))" "$fresh_claim"

# --- case 3: claim-on-failure path, driven end-to-end ----------------------
printf 'not a real sample' >"$WINDOWS_SANDBOX_SAMPLES_DIR/$sha_fail"
: >"$WINDOWS_SANDBOX_REQUEST_DIR/$sha_fail.request"
export WINDOWS_SANDBOX_ORCHESTRATOR="$work/fake-orchestrator.py"
cat >"$WINDOWS_SANDBOX_ORCHESTRATOR" <<'PY'
import sys
sys.exit(1)
PY

"$script_dir/run_pending.sh"

[[ ! -e $stale_claim ]] || fail "stale claim was not released"
pass "stale claim removed from *.request.running"

[[ -e "${stale_claim%.running}.failed" ]] || fail "stale claim did not land in .request.failed"
pass "stale claim reconciled to .request.failed"

[[ -e $fresh_claim ]] || fail "fresh claim was wrongly reaped"
pass "fresh claim (younger than threshold) left untouched"

[[ ! -e "$WINDOWS_SANDBOX_REQUEST_DIR/$sha_fail.request" ]] || fail "failing request was never claimed"
[[ ! -e "$WINDOWS_SANDBOX_REQUEST_DIR/$sha_fail.request.running" ]] || fail "failing request claim was never resolved"
[[ -e "$WINDOWS_SANDBOX_REQUEST_DIR/$sha_fail.request.failed" ]] || fail "failed detonation did not land in .request.failed"
pass "claim-on-failure path resolves .request -> .request.running -> .request.failed"

echo "OK: staleness reconciliation and claim-on-failure path hold"
