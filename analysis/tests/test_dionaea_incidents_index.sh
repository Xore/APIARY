#!/usr/bin/env bash
# Tests for the dionaea-incidents-v1-* index template analysis/elasticsearch-setup.sh
# installs (#565: dionaea's log_incident records were reaching Elasticsearch
# only as an opaque `message` string).
#
# Runs a real Elasticsearch container -- the point of this test is proving
# heterogeneous data across incident origins does NOT cause a mapping
# rejection, which only a real mapping enforcement pass can confirm. Needs
# Docker and the ability to pull docker.elastic.co/elasticsearch; skips
# cleanly if either is unavailable, same convention as
# analysis/yara/tests/test_sync_yara.sh and
# analysis/tests/test_geoip_pipeline.sh.
#
# Usage: analysis/tests/test_dionaea_incidents_index.sh
set -euo pipefail

ES_IMAGE="docker.elastic.co/elasticsearch/elasticsearch:9.5.1@sha256:b70b3017fbd35310bc57e7e3f8c0ca42ca0b94df3331f747b7cdcfddae430a5a"

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
container="es-dionaea-incidents-test-$$"
port=$((19000 + (RANDOM % 900)))
index="dionaea-incidents-v1-test-$$"

cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
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

# The template references the delete-only daily-index policy -- register it
# so index creation doesn't warn/fail on a missing policy reference.
curl -fsS -X PUT "$es_url/_ilm/policy/dionaea-incidents-30d" \
  -H 'Content-Type: application/json' \
  --data-binary '{"policy":{"phases":{"hot":{"actions":{}},"delete":{"min_age":"30d","actions":{"delete":{}}}}}}' >/dev/null

# Extract exactly the dionaea-incidents template's JSON body between its PUT
# command's heredoc markers, same technique test_geoip_pipeline.sh uses --
# stays in sync with elasticsearch-setup.sh automatically.
start_line=$(grep -n '_index_template/dionaea-incidents"' "$src_root/analysis/elasticsearch-setup.sh" | head -1 | cut -d: -f1)
body_start=$((start_line + 3))
end_line=$(tail -n "+$body_start" "$src_root/analysis/elasticsearch-setup.sh" | grep -n '^JSON$' | head -1 | cut -d: -f1)
body_end=$((body_start + end_line - 2))
tmp="$(mktemp -d)"
sed -n "${body_start},${body_end}p" "$src_root/analysis/elasticsearch-setup.sh" > "$tmp/template.json"

python3 -c "import json; json.load(open('$tmp/template.json'))" ||
  fail "extracted template body is not valid JSON -- extraction line range needs updating"

curl -fsS -X PUT "$es_url/_index_template/dionaea-incidents" \
  -H 'Content-Type: application/json' \
  --data-binary "@$tmp/template.json" >/dev/null ||
  fail "Elasticsearch rejected the index template"
pass "index template installs cleanly"

policy_name=$(python3 -c "import json; print(json.load(open('$tmp/template.json'))['template']['settings']['index.lifecycle.name'])")
[ "$policy_name" = "dionaea-incidents-30d" ] ||
  fail "dionaea template uses $policy_name, want the non-rollover dionaea-incidents-30d policy"
pass "daily Dionaea indices use their dedicated non-rollover retention policy"

# #1375 migration regression: reproduce an already-existing daily index in
# the exact ERROR state from production, then exercise setup.sh's supported
# remove-then-apply policy switch. Directly overwriting index.lifecycle.name
# is deliberately not tested because Elasticsearch can retain the cached hot
# phase from the old policy in that unsupported sequence.
legacy_index="dionaea-incidents-v1-legacy-$$"
curl -fsS -X PUT "$es_url/_ilm/policy/honeypot-30d" \
  -H 'Content-Type: application/json' \
  --data-binary '{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"1d"}}},"delete":{"min_age":"30d","actions":{"delete":{}}}}}}' >/dev/null
curl -fsS -X PUT "$es_url/_cluster/settings" -H 'Content-Type: application/json' \
  --data-binary '{"transient":{"indices.lifecycle.poll_interval":"1s"}}' >/dev/null
curl -fsS -X PUT "$es_url/$legacy_index" -H 'Content-Type: application/json' \
  --data-binary '{"settings":{"index.lifecycle.name":"honeypot-30d"}}' >/dev/null

errored=0
for _ in $(seq 1 20); do
  step=$(curl -fsS "$es_url/$legacy_index/_ilm/explain" |
    python3 -c "import json,sys; print(json.load(sys.stdin)['indices']['$legacy_index'].get('step', ''))")
  if [ "$step" = "ERROR" ]; then
    errored=1
    break
  fi
  sleep 1
done
[ "$errored" -eq 1 ] || fail "legacy rollover-managed Dionaea index did not reproduce the ERROR step"
pass "legacy daily index reproduces the missing-rollover-alias ERROR"

curl -fsS -X POST "$es_url/$legacy_index/_ilm/remove" >/dev/null
curl -fsS -X PUT "$es_url/$legacy_index/_settings" \
  -H 'Content-Type: application/json' \
  -d '{"index.lifecycle.name":"dionaea-incidents-30d"}' >/dev/null

migrated=0
for _ in $(seq 1 20); do
  read -r policy step <<EOF
$(curl -fsS "$es_url/$legacy_index/_ilm/explain" | python3 -c "import json,sys; i=json.load(sys.stdin)['indices']['$legacy_index']; print(i.get('policy', ''), i.get('step', ''))")
EOF
  if [ "$policy" = "dionaea-incidents-30d" ] && [ "$step" != "ERROR" ]; then
    migrated=1
    break
  fi
  sleep 1
done
[ "$migrated" -eq 1 ] || fail "legacy Dionaea index did not leave ERROR under the delete-only policy"
pass "remove-then-apply migration clears the old ERROR and starts the delete-only policy"

# Two incidents from different origins reusing the same "port" key with
# incompatible value types (int vs string) -- exactly the scenario the
# previous raw-message design existed to avoid. Field/value shapes match
# real dionaea log_incident.py output: {timestamp, name, origin, data}.
curl -fsS -X POST "$es_url/$index/_doc" -H 'Content-Type: application/json' -d '{
  "timestamp":"2026-08-05T00:00:00","name":"dionaea","origin":"dionaea.download.complete",
  "data":{"url":"http://198.51.100.5/x.exe","shasum":"deadbeef","port":445}
}' >/dev/null || fail "indexing the first (int port) incident was rejected"

curl -fsS -X POST "$es_url/$index/_doc" -H 'Content-Type: application/json' -d '{
  "timestamp":"2026-08-05T00:01:00","name":"dionaea","origin":"dionaea.connection.link",
  "data":{"port":"not-a-number","connection":{"protocol":"smbd","remote_ip":"198.51.100.5"}}
}' >/dev/null || fail "indexing the second (string port) incident was rejected -- mapping conflict"
pass "two incidents with an incompatible-typed shared key (data.port: int vs string) both index without a mapping rejection"

curl -fsS -X POST "$es_url/$index/_refresh" >/dev/null

search() {
  curl -fsS -X GET "$es_url/$index/_search" -H 'Content-Type: application/json' --data-binary "$1" |
    python3 -c "import json,sys; print(json.load(sys.stdin)['hits']['total']['value'])"
}

[ "$(search '{"query":{"exists":{"field":"data.url"}}}')" = "1" ] ||
  fail "data.url is not queryable through the flattened field"
pass "data.url is queryable"

[ "$(search '{"query":{"term":{"data.shasum":"deadbeef"}}}')" = "1" ] ||
  fail "data.shasum term query did not match"
pass "data.shasum is queryable"

[ "$(search '{"query":{"term":{"origin":"dionaea.connection.link"}}}')" = "1" ] ||
  fail "origin keyword filter did not match"
pass "origin is a filterable typed field"

echo
echo "all dionaea-incidents index tests passed"
