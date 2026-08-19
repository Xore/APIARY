#!/bin/bash
# reports-scheduler worker parity: proves the Rust scheduled-tick behavior
# (worker.rs's reports_scheduler_tick) matches the contract the old Go
# dashboard's reports_scheduler_test.go::TestScheduledReportLifecycle
# already established for reportScheduleLoop — the success path (one
# generated doc with origin="schedule", last_run_at set, next_run_at
# advances) and the #1340 no-hot-loop failure path (no artifact,
# last_run_at stays empty, next_run_at still advances so a permanently
# broken definition can't spin the loop forever).
#
# Neither implementation's public API can itself create an already-due
# schedule (put_definition always recomputes next_run_at into the future
# on save, same as Go's putDefinition) — so this script backdates
# next_run_at directly in the singleton dashboard-reports-definitions-v1
# document, the same thing Go's own unit test does internally via direct
# ES-doc surgery, done here from outside the process since this is a
# black-box live-ES test, not a cargo test.
#
# WRITES to dashboard-reports-definitions-v1 (two throwaway definitions,
# deleted at the end via the real DELETE API — leaves every other real
# definition in the doc untouched) and dashboard-generated-reports-v1 (one
# new doc for the success case, deleted directly since there is no DELETE
# route for a single generated report — delete_definition() does not
# cascade to it). Run against a scratch/dev ES cluster.
source "$(dirname "$0")/lib.sh"
require_es

start_backend WORKER_LOOPS=reports-scheduler

# --- create the two test definitions via the real HTTP API ---------------
SUCCESS_BODY='{"name":"port-tests parity success","template":"custom","theme":"dark","elements":["cover","metrics"],"schedule":{"enabled":true,"frequency":"daily","hour":3,"minute":30}}'
FAILURE_BODY='{"name":"port-tests parity failure","template":"sandbox","theme":"dark","scope":{"job":"no-such-job-xyz"},"schedule":{"enabled":true,"frequency":"daily","hour":3,"minute":30}}'

ID_A=$(curl -s -X POST "$BE_URL/api/v1/reports/definitions" -H 'content-type: application/json' -d "$SUCCESS_BODY" | python3 -c 'import sys,json; print(json.load(sys.stdin)["definition"]["id"])')
ID_B=$(curl -s -X POST "$BE_URL/api/v1/reports/definitions" -H 'content-type: application/json' -d "$FAILURE_BODY" | python3 -c 'import sys,json; print(json.load(sys.stdin)["definition"]["id"])')
echo "created definition A (success case): $ID_A"
echo "created definition B (#1340 failure case): $ID_B"

cleanup_definitions() {
  # delete_definition() doesn't cascade to the generated-reports doc it
  # produced — find and delete that directly against ES before dropping
  # the definitions, mirroring backend-api.sh's "restores state" discipline.
  local generated_id
  generated_id=$(curl -s "$BE_URL/api/v1/store/generated-reports?size=100" |
    python3 -c "import sys,json; d=json.load(sys.stdin); rows=[r['id'] for r in d['rows'] if r.get('definition_id') in ('$ID_A','$ID_B')]; print('\n'.join(rows))" 2>/dev/null)
  for id in $generated_id; do
    curl -s -X DELETE "$ES_URL/dashboard-generated-reports-v1/_doc/$id" >/dev/null
  done
  [ -n "${ID_A:-}" ] && curl -s -X DELETE "$BE_URL/api/v1/reports/definitions/$ID_A" >/dev/null
  [ -n "${ID_B:-}" ] && curl -s -X DELETE "$BE_URL/api/v1/reports/definitions/$ID_B" >/dev/null
}
trap 'cleanup_definitions; stop_all' EXIT

if [ -z "$ID_A" ] || [ -z "$ID_B" ]; then
  echo "FATAL: could not create test definitions" >&2
  exit 1
fi

# --- backdate both definitions' schedule.next_run_at into the past -------
# Neither create nor a subsequent PUT can itself produce a due schedule
# (both recompute next_run_at into the future on save), so this reaches
# past the API into the singleton definitions document directly, exactly
# like Go's own unit test does — touching only ID_A/ID_B, leaving every
# other real definition already in the shared cluster untouched.
python3 - "$ES_URL" "$ID_A" "$ID_B" <<'PYEOF'
import sys, json, urllib.request, datetime

es_url, id_a, id_b = sys.argv[1], sys.argv[2], sys.argv[3]
past = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

with urllib.request.urlopen(f"{es_url}/dashboard-reports-definitions-v1/_doc/definitions") as r:
    doc = json.load(r)["_source"]

touched = 0
for definition in doc["payload"]["definitions"]:
    if definition["id"] in (id_a, id_b):
        definition["schedule"]["next_run_at"] = past
        touched += 1
assert touched == 2, f"expected to backdate 2 definitions, touched {touched}"

body = json.dumps(doc).encode()
req = urllib.request.Request(f"{es_url}/dashboard-reports-definitions-v1/_doc/definitions?refresh=true", data=body, method="PUT", headers={"content-type": "application/json"})
urllib.request.urlopen(req)
print(f"backdated next_run_at to {past} for {id_a} and {id_b}")
PYEOF

# --- wait for the tick (interval is 30s; tokio fires the first tick ------
# immediately on loop start, so a schedule backdated before that first
# tick can fire almost right away — poll rather than sleep a fixed time) --
echo "waiting for the scheduler tick to pick up the backdated definitions..."
for _ in $(seq 1 45); do
  LAST_RUN=$(curl -s "$BE_URL/api/v1/reports/definitions/$ID_A" | python3 -c 'import sys,json; print(json.load(sys.stdin)["definition"].get("schedule",{}).get("last_run_at",""))')
  [ -n "$LAST_RUN" ] && break
  sleep 1
done

# --- assertions, mirroring TestScheduledReportLifecycle exactly ----------
check_json "definition A: last_run_at is set after the tick" \
  "$BE_URL/api/v1/reports/definitions/$ID_A" \
  "bool(d['definition'].get('schedule', {}).get('last_run_at'))"
check_json "definition A: next_run_at advanced past last_run_at" \
  "$BE_URL/api/v1/reports/definitions/$ID_A" \
  "d['definition']['schedule']['next_run_at'] > d['definition']['schedule']['last_run_at']"
check_json "definition A: exactly one generated-reports row with origin=schedule" \
  "$BE_URL/api/v1/store/generated-reports?size=100" \
  "sum(1 for r in d['rows'] if r.get('definition_id') == '$ID_A' and r.get('origin') == 'schedule') == 1"
check_json "definition A: the generated row has real content (size_bytes > 0)" \
  "$BE_URL/api/v1/store/generated-reports?size=100" \
  "next(r for r in d['rows'] if r.get('definition_id') == '$ID_A')['size_bytes'] > 0"

check_json "definition B (#1340): last_run_at stays empty on a render failure" \
  "$BE_URL/api/v1/reports/definitions/$ID_B" \
  "not d['definition'].get('schedule', {}).get('last_run_at')"
check_json "definition B (#1340): next_run_at still advances (no hot-loop)" \
  "$BE_URL/api/v1/reports/definitions/$ID_B" \
  "d['definition']['schedule']['next_run_at'] > ''"
check_json "definition B (#1340): no generated-reports row was written" \
  "$BE_URL/api/v1/store/generated-reports?size=100" \
  "sum(1 for r in d['rows'] if r.get('definition_id') == '$ID_B') == 0"

summary
