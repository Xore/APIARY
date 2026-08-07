#!/usr/bin/env bash
# Tests for the geoip-honeypot ingest pipeline's conpot persona extraction
# (#567: 5 of 6 personas collapsed to the generic 'conpot' once
# ip-enrichment-worker's flat-filename output replaced the original
# directory-per-persona path).
#
# Runs a real Elasticsearch container and uses its
# _ingest/pipeline/_simulate API -- see analysis/tests/test_geoip_pipeline.sh
# (#563) for why there's no lighter-weight Painless test harness. Needs
# Docker and the ability to pull docker.elastic.co/elasticsearch; skips
# cleanly if either is unavailable, same convention as
# analysis/yara/tests/test_sync_yara.sh.
#
# Usage: analysis/tests/test_conpot_persona_pipeline.sh
set -euo pipefail

ES_IMAGE="docker.elastic.co/elasticsearch/elasticsearch:8.13.4"

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker is not installed"
  exit 0
fi
if ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker daemon is not reachable"
  exit 0
fi
if ! docker pull -q "$ES_IMAGE" >/dev/null 2>&1; then
  echo "SKIP: could not pull $ES_IMAGE (no network egress?)"
  exit 0
fi

src_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
container="es-conpot-persona-test-$$"
port=$((19000 + (RANDOM % 900)))
tmp="$(mktemp -d)"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

docker run -d --name "$container" -p "127.0.0.1:${port}:9200" \
  -e discovery.type=single-node -e xpack.security.enabled=false \
  -e ES_JAVA_OPTS="-Xms512m -Xmx512m" \
  "$ES_IMAGE" >/dev/null

es_url="http://127.0.0.1:${port}"
ready=0
for _ in $(seq 1 40); do
  if curl -fsS "$es_url/_cluster/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 3
done
[ "$ready" -eq 1 ] || fail "Elasticsearch did not become reachable at $es_url"

start_line=$(grep -n '^geoip_pipeline_body=' "$src_root/analysis/elasticsearch-setup.sh" | head -1 | cut -d: -f1)
body_start=$((start_line + 1))
end_line=$(tail -n "+$body_start" "$src_root/analysis/elasticsearch-setup.sh" | grep -n '^JSON$' | head -1 | cut -d: -f1)
body_end=$((body_start + end_line - 2))
sed -n "${body_start},${body_end}p" "$src_root/analysis/elasticsearch-setup.sh" |
  sed 's#__ES_HOME_NET_JSON__#[]#' > "$tmp/pipeline.json"

python3 -c "import json; json.load(open('$tmp/pipeline.json'))" ||
  fail "extracted pipeline body is not valid JSON -- extraction line range needs updating"

curl -fsS -X PUT "$es_url/_ingest/pipeline/geoip-honeypot" \
  -H 'Content-Type: application/json' \
  --data-binary "@$tmp/pipeline.json" >/dev/null ||
  fail "Elasticsearch rejected the pipeline definition"
pass "pipeline installs cleanly"

# All 6 personas, both path shapes: the original directory-per-persona form
# (still valid for any deploy not routed through ip-enrichment-worker) and
# the flat-filename form ip-enrichment-worker's /logs/enriched/<persona>.json
# actually produces (confirmed against ip-enrichment-worker/main.go directly:
# output: filepath.Join(outDir, name+".json")).
personas="conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup"

cat > "$tmp/docs.json" <<EOF
{"docs":[
$(for p in $personas; do echo "  {\"_source\":{\"log\":{\"file\":{\"path\":\"/logs/$p/conpot.json\"}}}},"; done)
$(for p in $personas; do echo "  {\"_source\":{\"log\":{\"file\":{\"path\":\"/logs/enriched/$p.json\"}}}},"; done | sed '$ s/,$//')
]}
EOF

result="$(curl -fsS -X POST "$es_url/_ingest/pipeline/geoip-honeypot/_simulate" \
  -H 'Content-Type: application/json' --data-binary "@$tmp/docs.json")"

check_persona() {
  # check_persona <expected-persona> <doc-index-0-based>
  local expected="$1" idx="$2"
  local got
  got="$(echo "$result" | python3 -c "
import json, sys
docs = json.load(sys.stdin)['docs']
src = docs[$idx]['doc']['_source']
print(src.get('event', {}).get('sensor', ''))
")"
  [ "$got" = "$expected" ] || fail "doc $idx: expected persona '$expected', got '$got'"
}

i=0
for p in $personas; do
  check_persona "$p" "$i"
  i=$((i + 1))
done
pass "all 6 personas resolve correctly from the original directory-per-persona path"

for p in $personas; do
  check_persona "$p" "$i"
  i=$((i + 1))
done
pass "all 6 personas resolve correctly from ip-enrichment-worker's flat-filename path -- the bug this issue fixes (each check_persona call above already asserts exact equality, so a collapse to the generic 'conpot' value would have failed there)"

# Unaffected sensors stay untouched.
cat > "$tmp/others.json" <<'EOF'
{"docs":[
  {"_source":{"honeypot":{"sensor":"cowrie"},"log":{"file":{"path":"/logs/enriched/cowrie.json"}}}},
  {"_source":{"log":{"file":{"path":"/logs/enriched/dionaea.json"}}}},
  {"_source":{"honeypot":{"sensor":"dns-honeypot"},"log":{"file":{"path":"/logs/enriched/dns-honeypot.json"}}}},
  {"_source":{"honeypot":{"sensor":"cisco-asa-honeypot"},"log":{"file":{"path":"/logs/enriched/cisco-asa-honeypot.json"}}}}
]}
EOF
others_result="$(curl -fsS -X POST "$es_url/_ingest/pipeline/geoip-honeypot/_simulate" \
  -H 'Content-Type: application/json' --data-binary "@$tmp/others.json")"
echo "$others_result" | python3 -c "
import json, sys
docs = json.load(sys.stdin)['docs']
expected = ['cowrie', 'dionaea', 'dns-honeypot', 'cisco-asa-honeypot']
for i, doc in enumerate(docs):
    got = doc['doc']['_source'].get('event', {}).get('sensor', '')
    assert got == expected[i], f'{expected[i]}: expected {expected[i]!r}, got {got!r}'
print('ok')
" || fail "an unaffected sensor's persona/sensor extraction regressed"
pass "unaffected sensors (cowrie, dionaea, dns-honeypot, cisco-asa-honeypot) are untouched"

echo
echo "all conpot persona extraction tests passed"
