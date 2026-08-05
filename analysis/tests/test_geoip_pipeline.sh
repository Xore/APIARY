#!/usr/bin/env bash
# Tests for the geoip-honeypot ingest pipeline analysis/elasticsearch-setup.sh
# installs (#563: cowrie's url field wasn't promoted to ECS url.path the way
# other sensors' path field is).
#
# Runs a real Elasticsearch container and uses its _ingest/pipeline/_simulate
# API -- there is no standalone Painless interpreter to test the pipeline's
# script processors against, and this repo has no lighter-weight fixture for
# it. Needs Docker and the ability to pull docker.elastic.co/elasticsearch;
# skips cleanly if either is unavailable, same convention as
# analysis/yara/tests/test_sync_yara.sh skipping without a real yara(1).
#
# Usage: analysis/tests/test_geoip_pipeline.sh
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
container="es-pipeline-test-$$"
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

# Extract exactly the geoip-honeypot pipeline's JSON body (between the PUT
# command's heredoc markers) rather than the whole file, so this stays in
# sync with elasticsearch-setup.sh automatically -- no copy of the pipeline
# definition to fall out of date here.
start_line=$(grep -n '_ingest/pipeline/geoip-honeypot' "$src_root/analysis/elasticsearch-setup.sh" | head -1 | cut -d: -f1)
body_start=$((start_line + 3))
end_line=$(tail -n "+$body_start" "$src_root/analysis/elasticsearch-setup.sh" | grep -n '^JSON$' | head -1 | cut -d: -f1)
body_end=$((body_start + end_line - 2))
sed -n "${body_start},${body_end}p" "$src_root/analysis/elasticsearch-setup.sh" > "$tmp/pipeline.json"

python3 -c "import json; json.load(open('$tmp/pipeline.json'))" ||
  fail "extracted pipeline body is not valid JSON -- extraction line range needs updating"

curl -fsS -X PUT "$es_url/_ingest/pipeline/geoip-honeypot" \
  -H 'Content-Type: application/json' \
  --data-binary "@$tmp/pipeline.json" >/dev/null ||
  fail "Elasticsearch rejected the pipeline definition"
pass "pipeline installs cleanly"

simulate() {
  # simulate <fixture-file> -> prints the resulting document's url.path (or empty)
  curl -fsS -X POST "$es_url/_ingest/pipeline/geoip-honeypot/_simulate" \
    -H 'Content-Type: application/json' \
    --data-binary "@$1" |
    python3 -c "
import json, sys
doc = json.load(sys.stdin)['docs'][0]['doc']['_source']
print(doc.get('url', {}).get('path', ''))
"
}

cat > "$tmp/cowrie_url_only.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"eventid":"cowrie.session.file_download","url":"http://198.51.100.10/malware.sh","src_ip":"198.51.100.10"}}}]}
EOF
result="$(simulate "$tmp/cowrie_url_only.json")"
[ "$result" = "http://198.51.100.10/malware.sh" ] ||
  fail "cowrie's url field was not promoted to url.path (got: '$result')"
pass "cowrie's url field (no path) is promoted to url.path"

cat > "$tmp/path_only.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"sensor":"http-honeypot","path":"/wp-login.php","src_ip":"198.51.100.20"}}}]}
EOF
result="$(simulate "$tmp/path_only.json")"
[ "$result" = "/wp-login.php" ] ||
  fail "an existing path-only sensor regressed (got: '$result')"
pass "an existing path-only sensor (http-honeypot) is unaffected"

cat > "$tmp/both_path_and_url.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"sensor":"dionaea","path":"/uploads/x.exe","url":"http://should-not-win.example/decoy","src_ip":"198.51.100.30"}}}]}
EOF
result="$(simulate "$tmp/both_path_and_url.json")"
[ "$result" = "/uploads/x.exe" ] ||
  fail "path did not take precedence over url when a document sets both (got: '$result')"
pass "path takes precedence over url when a document sets both"

echo
echo "all geoip-honeypot pipeline tests passed"
