#!/bin/bash
# alert-notifier worker smoke: runs one baseline (mark-only) pass against
# live ES and verifies the loop starts and alert docs stay consistent.
# WRITES to dashboard-alert-state-v1 (same key/shape contract as the Go
# alertManager — safe alongside it, counts may double-increment).
#
# #2213: this used to run `timeout 30 cargo run`, charging a cold compile to
# the worker's own window — the compile ate the whole 30s budget (proven:
# `timeout 30 cargo build` exits 124 with no binary in a cold tree), and
# nothing asserted the loop had ever started, so AFTER==BEFORE compared two
# counts from a run where the worker may never have existed. The window now
# measures steady state only: compile first, run the prebuilt binary, and
# require positive evidence the notifier started (its startup log line AND a
# bound port answering healthz — bare timestamp deltas are not evidence).
source "$(dirname "$0")/lib.sh"
require_es

# --- prebuild OUTSIDE any measured window (#2213) ------------------------
echo "prebuilding apiary-backend (compile cost is not charged to the worker's budget)"
(cd "$BACKEND_DIR" && cargo build -q) || {
  echo "FATAL: backend build failed" >&2
  exit 1
}
BIN="$BACKEND_DIR/target/debug/apiary-backend"
[ -x "$BIN" ] || {
  echo "FATAL: prebuilt binary missing at $BIN" >&2
  exit 1
}

NOTIFIER_LOG="${TMPDIR:-/tmp}/port-tests-notifier.log"
BEFORE=$(curl -s "$ES_URL/dashboard-alert-state-v1/_count" | python3 -c 'import sys,json; print(json.load(sys.stdin)["count"])')
echo "alert docs before: $BEFORE"

# --- steady-state window: prebuilt binary only ---------------------------
env ELASTICSEARCH_URL="$ES_URL" LISTEN_ADDR="127.0.0.1:$BE_PORT" \
  WORKER_LOOPS=alert-notifier RUST_LOG=info APIARY_ALLOW_UNAUTH_DEV=1 \
  timeout 30 "$BIN" >"$NOTIFIER_LOG" 2>&1 &
WPID=$!

# Poll for positive startup evidence instead of sleep-and-hope (#2213): an
# instantly dead process fails fast rather than burning the full budget. No
# evidence by the end of the window is a FAIL below, never a skip.
LOG_STARTED=0
PORT_OPEN=0
for _ in $(seq 1 30); do
  grep -Eq "worker loop enabled: alert-notifier" "$NOTIFIER_LOG" && LOG_STARTED=1
  curl -sf --max-time 2 "$BE_URL/healthz" >/dev/null 2>&1 && PORT_OPEN=1
  [ "$LOG_STARTED" -eq 1 ] && [ "$PORT_OPEN" -eq 1 ] && break
  kill -0 "$WPID" 2>/dev/null || break
  sleep 1
done

if [ "$LOG_STARTED" -eq 1 ]; then
  # Give the boot-time baseline pass room to finish its ES writes before we
  # sample the after-count and tear down.
  sleep 10
fi
kill "$WPID" 2>/dev/null
wait "$WPID" 2>/dev/null
WAIT_STATUS=$?
echo "worker process exit status: $WAIT_STATUS (124 = budget exhausted, 143 = our SIGTERM)"

echo "--- notifier log (worker-loop/error lines) ---"
grep -Ei "worker loop|error" "$NOTIFIER_LOG" | head -5 || true
echo "----------------------------------------------"

check "notifier loop started within budget (startup line present)" test "$LOG_STARTED" -eq 1
check "worker bound $BE_PORT and answered healthz within budget" test "$PORT_OPEN" -eq 1
AFTER=$(curl -s "$ES_URL/dashboard-alert-state-v1/_count" | python3 -c 'import sys,json; print(json.load(sys.stdin)["count"])')
echo "alert docs after: $AFTER"
check "alert store did not shrink" test "$AFTER" -ge "$BEFORE"
check_json "newest alert has contract fields" \
  "$ES_URL/dashboard-alert-state-v1/_search?size=1&sort=LastSeen:desc" \
  "all(k in d['hits']['hits'][0]['_source'] for k in ('Key','Message','Count','Acknowledged'))"

summary
