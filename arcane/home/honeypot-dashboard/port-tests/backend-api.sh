#!/bin/bash
# Rust service tier smoke: every /api/v1 read endpoint against live ES.
# Read-only except the ip-block round trip, which uses a TEST-NET-3
# address and restores state.
source "$(dirname "$0")/lib.sh"
require_es
start_backend

check_json "overview kpis"        "$BE_URL/api/v1/overview/kpis"       "d['total'] > 0 and d['unique_ips'] > 0"
check_json "overview dashboard"   "$BE_URL/api/v1/overview/dashboard"  "len(d['top_ips']) > 0 and len(d['heatmap']) > 0 and len(d['map_points']) > 0"
check_json "events list"          "$BE_URL/api/v1/events?size=5"       "d['total'] > 0 and len(d['rows']) == 5"
check_json "events kind filter"   "$BE_URL/api/v1/events?kind=command&size=1" "len(d['rows']) == 1"
check_json "events q search"      "$BE_URL/api/v1/events?q=telnet&size=1"     "d['total'] > 0"
check_json "sources"              "$BE_URL/api/v1/sources?size=5"      "d['total_unique'] > 0"
check_json "filter values"        "$BE_URL/api/v1/filter-values"       "len(d['sensors']) > 0 and len(d['kinds']) > 0"
check_json "source health"        "$BE_URL/api/v1/source-health"       "d['total_documents'] > 0 and len(d['sensors']) > 0"
check_json "sensors detail"       "$BE_URL/api/v1/sensors"             "'mailoney' in d and 'http_requests' in d"
check_json "search groups"        "$BE_URL/api/v1/search?q=root"       "d['total'] > 0"
check_json "campaigns"            "$BE_URL/api/v1/campaigns?size=3"    "d['total'] > 0"
check_json "clusters"             "$BE_URL/api/v1/clusters?size=3"     "'rows' in d"
check_json "attackers"            "$BE_URL/api/v1/attackers?size=3"    "d['total'] > 0"
check_json "recordings"           "$BE_URL/api/v1/recordings?size=3"   "d['total'] > 0"
check_json "alerts"               "$BE_URL/api/v1/alerts?size=3"       "d['total'] > 0"
check_json "payloads"             "$BE_URL/api/v1/payloads?size=3"     "d['total'] > 0"
check_json "config"               "$BE_URL/api/v1/config"              "'payload' in d"
check_json "users roster"         "$BE_URL/api/v1/users"               "len(d['users']) > 0"
check_json "storage stats"        "$BE_URL/api/v1/settings/storage"    "d['doc_count'] > 0"

for store in auth-events ml-anomalies agent-campaigns canarytokens problem-reports dead-letters yara sandbox-runs ghidra-runs static-analysis workbench-runs generated-reports report-definitions intelligence llm-analysis; do
  check_json "store $store" "$BE_URL/api/v1/store/$store?size=1" "'rows' in d"
done

for chart in kill-chain-sankey attck-coverage campaign-timeline ml-backlog netflow-bytes netflow-packets anomaly-trend dionaea-cves os-distribution tls-fingerprints ssh-fingerprints endlessh-held-histogram ml-anomaly-scores; do
  check_http "chart $chart" 200 "$BE_URL/api/v1/charts/$chart"
done

# Detail endpoints, keys discovered live. #2184: an empty discovery is not
# allowed to silently drop the family's coverage — each conditional site
# either runs its check or emits a counted SKIP line.
SID=$(discover_key "$BE_URL/api/v1/events?kind=command&size=1" 'd["rows"][0]["session"] if d.get("rows") else ""')
if [ -n "$SID" ]; then
  check_json "session detail" "$BE_URL/api/v1/sessions/$SID" "d['total'] > 0"
else
  skip "session detail" "command sessions"
fi
SHA=$(discover_key "$BE_URL/api/v1/recordings?size=1" 'd["rows"][0]["shasum"] if d.get("rows") else ""')
check_json "tty replay decode" "$BE_URL/api/v1/recordings/$SHA" "d['frames'] > 0 and len(d['transcript']) > 0"
HASH=$(discover_key "$BE_URL/api/v1/payloads?size=1" 'd["rows"][0]["Hash"] if d.get("rows") else ""')
check_json "payload detail" "$BE_URL/api/v1/payloads/$HASH" "len(d['hex_preview']) > 0"
IP=$(discover_key "$BE_URL/api/v1/events?size=1" 'd["rows"][0]["src_ip"] if d.get("rows") else ""')
check_json "investigate ip" "$BE_URL/api/v1/investigate/ip/$IP" "d['total'] > 0"
AID=$(discover_key "$BE_URL/api/v1/attackers?size=1" 'd["rows"][0]["id"] if d.get("rows") else ""')
check_http "attacker fusion" 200 "$BE_URL/api/v1/charts/attacker-fusion?id=$AID"
RID=$(discover_key "$BE_URL/api/v1/store/generated-reports?size=1" 'd["rows"][0]["id"] if d.get("rows") else ""')
if [ -n "$RID" ]; then
  check_http "report pdf" 200 "$BE_URL/api/v1/reports/$RID/pdf"
else
  skip "report pdf" "generated reports"
fi
GSHA=$(discover_key "$ES_URL/ghidra-report-artifacts-v1/_search?size=1" \
  'd["hits"]["hits"][0]["_source"]["sha256"] if d.get("hits", {}).get("hits") else ""')
if [ -n "$GSHA" ]; then
  check_json "ghidra artifacts" "$BE_URL/api/v1/artifacts/ghidra/$GSHA" "len(d['rows']) > 0"
else
  skip "ghidra artifacts" "ghidra report artifacts"
fi

check_json "attack vectors" "$BE_URL/api/v1/attack-vectors?sensor=cowrie" "len(d['ports']) > 0"
check_json "attackers graph" "$BE_URL/api/v1/attackers-graph?id=$AID" "len(d['nodes']) > 1 and d['nodes'][0]['kind'] == 'hub'"
JOB=$(discover_key "$ES_URL/sandbox-export-artifacts-v1/_search?size=1" \
  'd["hits"]["hits"][0]["_source"]["job"] if d.get("hits", {}).get("hits") else ""')
if [ -n "$JOB" ]; then
  check_json "sandbox run detail" "$BE_URL/api/v1/sandbox/$JOB" "'_doc_id' in d"
else
  skip "sandbox run detail" "sandbox export artifacts"
fi
if [ -n "$GSHA" ]; then
  check_json "ghidra run detail" "$BE_URL/api/v1/ghidra/$GSHA" "'ghidra' in d"
else
  skip "ghidra run detail" "ghidra report artifacts"
fi
for store in revdeck cape github-analysis; do
  check_json "store $store (absent-index tolerant)" "$BE_URL/api/v1/store/$store?size=1" "'rows' in d"
done

# ML anomaly ack round trip on a synthetic key (never a real anomaly id);
# leaves the record un-acked.
check "ml ack set" curl -sf -X POST "$BE_URL/api/v1/ml-anomalies/ack" -H 'Content-Type: application/json' -d '{"key":"port-tests-synthetic","ack":true,"actor":"port-tests"}'
sleep 1
check_json "ml acks map" "$BE_URL/api/v1/ml-anomalies/acks" "d.get('port-tests-synthetic',{}).get('Acknowledged') == True"
check "ml ack unset" curl -sf -X POST "$BE_URL/api/v1/ml-anomalies/ack" -H 'Content-Type: application/json' -d '{"key":"port-tests-synthetic","ack":false,"actor":"port-tests"}'

# SSE stream: at least one event within 15s.
check "sse live stream" bash -c "timeout 15 curl -sN $BE_URL/api/v1/live | head -c 50 | grep -q 'event:'"

# ip-block round trip on TEST-NET-3 (never a real attacker); restores state.
TESTIP="203.0.113.99"
check "ip-block set" curl -sf -X POST "$BE_URL/api/v1/ip-block" -H 'Content-Type: application/json' -d "{\"ip\":\"$TESTIP\",\"blocked\":true,\"expires_days\":1,\"actor\":\"port-tests\"}"
sleep 1
check "ip-block export contains" bash -c "curl -s $BE_URL/api/v1/ip-block-export | grep -q $TESTIP"
check "ip-block unset" curl -sf -X POST "$BE_URL/api/v1/ip-block" -H 'Content-Type: application/json' -d "{\"ip\":\"$TESTIP\",\"blocked\":false,\"actor\":\"port-tests\"}"
sleep 1
check "ip-block export clean" bash -c "! curl -s $BE_URL/api/v1/ip-block-export | grep -q $TESTIP"

summary
