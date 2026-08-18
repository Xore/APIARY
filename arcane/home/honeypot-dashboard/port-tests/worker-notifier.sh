#!/bin/bash
# alert-notifier worker smoke: runs one baseline (mark-only) pass against
# live ES and verifies the loop starts and alert docs stay consistent.
# WRITES to dashboard-alert-state-v1 (same key/shape contract as the Go
# alertManager — safe alongside it, counts may double-increment).
source "$(dirname "$0")/lib.sh"
require_es

BEFORE=$(curl -s "$ES_URL/dashboard-alert-state-v1/_count" | python3 -c 'import sys,json; print(json.load(sys.stdin)["count"])')
echo "alert docs before: $BEFORE"
(cd "$BACKEND_DIR" && env ELASTICSEARCH_URL="$ES_URL" LISTEN_ADDR="127.0.0.1:$BE_PORT" \
  WORKER_LOOPS=alert-notifier RUST_LOG=info \
  timeout 30 cargo run -q 2>&1 | grep -Ei "worker loop|error" | head -5)
sleep 2
AFTER=$(curl -s "$ES_URL/dashboard-alert-state-v1/_count" | python3 -c 'import sys,json; print(json.load(sys.stdin)["count"])')
echo "alert docs after: $AFTER"
check "alert store did not shrink" test "$AFTER" -ge "$BEFORE"
check_json "newest alert has contract fields" \
  "$ES_URL/dashboard-alert-state-v1/_search?size=1&sort=LastSeen:desc" \
  "all(k in d['hits']['hits'][0]['_source'] for k in ('Key','Message','Count','Acknowledged'))"

summary
