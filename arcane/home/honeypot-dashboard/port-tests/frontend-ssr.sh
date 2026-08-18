#!/bin/bash
# SSR smoke: every route renders 200 with OIDC_DISABLED=1 dev identity;
# the BFF proxies (SSE, charts, exports) pass real bytes through.
# SKIP_FE_BUILD=1 reuses the last vite build.
source "$(dirname "$0")/lib.sh"
require_es
start_backend
start_frontend

for page in "" events ips campaigns clusters attackers kill-chain commands sensors recordings \
    alerts source-health history reports canarytokens payloads payload-workbench/results \
    ml-anomalies llm-analysis agent-campaigns auth-events settings problem-reports dead-letters \
    revdeck cape github-analysis "search?q=root"; do
  check_http "page /$page" 200 "$FE_URL/$page"
done
check_http "404 page" 404 "$FE_URL/this-does-not-exist"

SHA=$(curl -s "$BE_URL/api/v1/recordings?size=1" | python3 -c 'import sys,json; print(json.load(sys.stdin)["rows"][0]["shasum"])')
check_http "tty replay page" 200 "$FE_URL/tty-replay/$SHA"
IP=$(curl -s "$BE_URL/api/v1/events?size=1" | python3 -c 'import sys,json; print(json.load(sys.stdin)["rows"][0]["src_ip"])')
# -L: the router 307-normalizes some encodings (IPv6 sources) first.
check "investigate page" bash -c \
  "[ \"\$(curl -sL -o /dev/null -w '%{http_code}' --max-time 90 '$FE_URL/investigate/ip/$IP')\" = 200 ]"
SID=$(curl -s "$BE_URL/api/v1/events?kind=command&size=1" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["rows"][0]["session"] if d["rows"] else "")')
[ -n "$SID" ] && check_http "session page" 200 "$FE_URL/sessions/$SID"
HASH=$(curl -s "$BE_URL/api/v1/payloads?size=1" | python3 -c 'import sys,json; print(json.load(sys.stdin)["rows"][0]["Hash"])')
check_http "payload analysis page" 200 "$FE_URL/payload-analysis/$HASH"
JOB=$(curl -s "$ES_URL/sandbox-export-artifacts-v1/_search?size=1" | python3 -c 'import sys,json; h=json.load(sys.stdin)["hits"]["hits"]; print(h[0]["_source"]["job"] if h else "")')
[ -n "$JOB" ] && check_http "sandbox detail page" 200 "$FE_URL/sandbox/$JOB"
GSHA=$(curl -s "$ES_URL/ghidra-report-artifacts-v1/_search?size=1" | python3 -c 'import sys,json; h=json.load(sys.stdin)["hits"]["hits"]; print(h[0]["_source"]["sha256"] if h else "")')
[ -n "$GSHA" ] && check_http "ghidra detail page" 200 "$FE_URL/ghidra/$GSHA"

# BFF proxies.
check_http "chart proxy" 200 "$FE_URL/api/chart/os-distribution"
check "sse proxy streams" bash -c "timeout 15 curl -sN $FE_URL/api/live | head -c 50 | grep -q 'event:'"
check_http "blackhole export (unauthenticated)" 200 "$FE_URL/export/portbridge-manual-blackhole.txt"

summary
