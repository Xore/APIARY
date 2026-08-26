#!/bin/bash
# SSR smoke: every route renders 200 with OIDC_DISABLED=1 dev identity;
# the BFF proxies (SSE, charts, exports) pass real bytes through.
# SKIP_FE_BUILD=1 reuses the last vite build.
source "$(dirname "$0")/lib.sh"
require_es
start_backend
start_frontend

for page in "" events ips campaigns clusters attackers kill-chain commands sensors recordings \
    alerts source-health history reports canarytokens credentials payloads payload-workbench/results \
    ml-anomalies llm-analysis agent-campaigns auth-events settings problem-reports dead-letters \
    revdeck cape github-analysis "search?q=root"; do
  check_http "page /$page" 200 "$FE_URL/$page"
done
check_http "404 page" 404 "$FE_URL/this-does-not-exist"

# Detail pages, keys discovered live. #2184: an empty discovery must not
# silently drop a family's coverage — each conditional site either runs its
# check or emits a counted SKIP line.
SHA=$(discover_key "$BE_URL/api/v1/recordings?size=1" 'd["rows"][0]["shasum"] if d.get("rows") else ""')
check_http "tty replay page" 200 "$FE_URL/tty-replay/$SHA"
IP=$(discover_key "$BE_URL/api/v1/events?size=1" 'd["rows"][0]["src_ip"] if d.get("rows") else ""')
# -L: the router 307-normalizes some encodings (IPv6 sources) first.
check "investigate page" bash -c \
  "[ \"\$(curl -sL -o /dev/null -w '%{http_code}' --max-time 90 '$FE_URL/investigate/ip/$IP')\" = 200 ]"
SID=$(discover_key "$BE_URL/api/v1/events?kind=command&size=1" 'd["rows"][0]["session"] if d.get("rows") else ""')
if [ -n "$SID" ]; then
  check_http "session page" 200 "$FE_URL/sessions/$SID"
else
  skip "session page" "command sessions"
fi
HASH=$(discover_key "$BE_URL/api/v1/payloads?size=1" 'd["rows"][0]["Hash"] if d.get("rows") else ""')
check_http "payload analysis page" 200 "$FE_URL/payload-analysis/$HASH"
JOB=$(discover_key "$ES_URL/sandbox-export-artifacts-v1/_search?size=1" \
  'd["hits"]["hits"][0]["_source"]["job"] if d.get("hits", {}).get("hits") else ""')
if [ -n "$JOB" ]; then
  check_http "sandbox detail page" 200 "$FE_URL/sandbox/$JOB"
else
  skip "sandbox detail page" "sandbox export artifacts"
fi
GSHA=$(discover_key "$ES_URL/ghidra-report-artifacts-v1/_search?size=1" \
  'd["hits"]["hits"][0]["_source"]["sha256"] if d.get("hits", {}).get("hits") else ""')
if [ -n "$GSHA" ]; then
  check_http "ghidra detail page" 200 "$FE_URL/ghidra/$GSHA"
else
  skip "ghidra detail page" "ghidra report artifacts"
fi

# #2127: the cape/github-analysis/revdeck detail routes used to
# server-render their parent LIST — a component-ful layout swallowed its
# children, and a 200-only check cannot see that, because every one of
# these lists treats an empty state as normal. So each deep link below is
# checked for the detail page's header copy, which server-renders
# unconditionally (the data cards hydrate client-side via useResolved,
# so only the headers are guaranteed in SSR output).
# #2184: these were also the families most at risk of vacuous skips — an
# absent key would silently elide exactly the routes born broken in #2127.
CAPE_SHA=$(discover_key "$ES_URL/cape-analysis-v1/_search?size=1" \
  'd["hits"]["hits"][0]["_source"].get("file", {}).get("hash", {}).get("sha256", "") if d.get("hits", {}).get("hits") else ""')
if [ -n "$CAPE_SHA" ]; then
  check_http "cape detail page" 200 "$FE_URL/cape/$CAPE_SHA"
  check "cape deep link renders the run page" bash -c \
    "curl -s --max-time 90 '$FE_URL/cape/$CAPE_SHA' | grep -q 'debugger-instrumented'"
else
  skip "cape detail page" "cape analyses"
  skip "cape deep link renders the run page" "cape analyses"
fi
GHANA_SHA=$(discover_key "$ES_URL/github-analysis-v1/_search?size=1" \
  'd["hits"]["hits"][0]["_source"].get("file", {}).get("hash", {}).get("sha256", "") if d.get("hits", {}).get("hits") else ""')
if [ -n "$GHANA_SHA" ]; then
  check_http "github-analysis detail page" 200 "$FE_URL/github-analysis/$GHANA_SHA"
  check "github-analysis deep link renders the run page" bash -c \
    "curl -s --max-time 90 '$FE_URL/github-analysis/$GHANA_SHA' | grep -q 'multi-engine scanner verdict'"
else
  skip "github-analysis detail page" "github analyses"
  skip "github-analysis deep link renders the run page" "github analyses"
fi
REVDECK_SHA=$(discover_key "$ES_URL/revdeck-analysis-v1/_search?size=1" \
  '(h[0]["_source"].get("revdeck", {}).get("sha256") or h[0]["_source"].get("sha256") or "") if (h := d.get("hits", {}).get("hits")) else ""')
if [ -n "$REVDECK_SHA" ]; then
  check_http "revdeck detail page" 200 "$FE_URL/revdeck/$REVDECK_SHA"
  check "revdeck deep link renders the run page" bash -c \
    "curl -s --max-time 90 '$FE_URL/revdeck/$REVDECK_SHA' | grep -q 'reverse-engineering deck walkthrough'"
else
  skip "revdeck detail page" "revdeck analyses"
  skip "revdeck deep link renders the run page" "revdeck analyses"
fi

# BFF proxies.
check_http "chart proxy" 200 "$FE_URL/api/chart/os-distribution"
check "sse proxy streams" bash -c "timeout 15 curl -sN $FE_URL/api/live | head -c 50 | grep -q 'event:'"
check_http "blackhole export (unauthenticated)" 200 "$FE_URL/export/portbridge-manual-blackhole.txt"

summary
