#!/usr/bin/env bash
# Tests for the honeypot-30d ILM policy analysis/elasticsearch-setup.sh
# installs (#585: without an explicit rollover action, ILM cannot delete a
# data stream's write index -- the delete phase gets permanently stuck at
# "wait-for-shard-history-leases" and the single backing index grows
# unbounded forever, so the stated 30-day retention did nothing at all).
#
# Runs a real Elasticsearch container and forces ILM's own periodic poll
# down to a few seconds so the full rollover-then-delete lifecycle can be
# observed end to end in well under a minute, with no manual _rollover call
# standing in for what ILM does automatically in production. Needs Docker
# and the ability to pull docker.elastic.co/elasticsearch; skips cleanly if
# either is unavailable, same convention as
# analysis/yara/tests/test_sync_yara.sh.
#
# Usage: analysis/tests/test_honeypot_ilm_rollover.sh
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
container="es-ilm-rollover-test-$$"
port=$((19000 + (RANDOM % 900)))

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

# ILM's default poll interval is 10 minutes -- far too slow for a test.
# Shortening it is the only way to observe a real, automatic (not manually
# forced) rollover-then-delete cycle in a reasonable test runtime.
curl -fsS -X PUT "$es_url/_cluster/settings" -H 'Content-Type: application/json' \
  --data-binary '{"transient":{"indices.lifecycle.poll_interval":"3s"}}' >/dev/null

# Extract the exact honeypot-30d policy body from elasticsearch-setup.sh,
# then substitute in fast rollover/delete ages for this test only -- stays
# in sync with the real policy's *shape* (still has a rollover action in
# the hot phase) automatically, without waiting real days for it to fire.
# Quote-style agnostic since #2193 moved the body to the loop's
# escaped-double-quote idiom (the single-quoted literal was itself the
# bug: it silently blocked ${retention_days} expansion).
setup="$src_root/arcane/home/honeypot-init/analysis/elasticsearch-setup.sh"
policy_line=$(grep -n '_ilm/policy/honeypot-30d"' "$setup" | head -1 | cut -d: -f1)
[ -n "$policy_line" ] || fail "cannot locate the honeypot-30d PUT in elasticsearch-setup.sh"
policy_body=$(sed -n "$((policy_line + 2))p" "$setup" |
  sed -e 's/^ *--data-binary //' -e 's/ *>\/dev\/null$//' \
      -e 's/^"\(.*\)"$/\1/' -e 's/\\"/"/g')

case "$(printf '%s' "$policy_body" | grep -cF '${retention_days}')" in
  1)
    pass "honeypot-30d delete.min_age is wired to \${retention_days}, not hardcoded (#2193)"
    ;;
  *)
    fail "honeypot-30d min_age no longer derives from retention_days -- the #2193 hardcode crept back"
    ;;
esac

# Exercise the derivation without booting a second Elasticsearch: expand
# the knob textually through the REAL source line and check the resulting
# JSON deletes at the expected age both ways (unset default stays 30d --
# byte-equivalent to the pre-#2193 literal -- and a lowered knob shrinks
# the dominant stream along with everything else).
age_for() {
  printf '%s' "$policy_body" |
    awk -v repl="$1" '{ gsub(/\$\{retention_days\}/, repl); printf "%s", $0 }' |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["policy"]["phases"]["delete"]["min_age"])'
}
[ "$(age_for 30)" = "30d" ] || fail "default run must keep deleting at 30d (got $(age_for 30))"
pass "unset HONEYPOT_RETENTION_DAYS preserves today's exact 30d behavior"
[ "$(age_for 7)" = "7d" ] || fail "HONEYPOT_RETENTION_DAYS=7 must yield delete.min_age 7d (got $(age_for 7))"
pass "HONEYPOT_RETENTION_DAYS=7 propagates to honeypot-30d delete.min_age"

echo "$policy_body" | grep -q '"rollover"' ||
  fail "honeypot-30d policy has no rollover action -- this is exactly the #585 bug, still present"
pass "honeypot-30d policy's hot phase has a rollover action"

fast_body=$(echo "$policy_body" | python3 -c "
import json, sys
p = json.load(sys.stdin)
p['policy']['phases']['hot']['actions']['rollover'] = {'max_age': '5s'}
p['policy']['phases']['delete']['min_age'] = '5s'
print(json.dumps(p))
")
curl -fsS -X PUT "$es_url/_ilm/policy/honeypot-30d" -H 'Content-Type: application/json' \
  --data-binary "$fast_body" >/dev/null ||
  fail "Elasticsearch rejected the (fast-tuned) honeypot-30d policy"
pass "policy installs cleanly"

curl -fsS -X PUT "$es_url/_index_template/honeypot-events-v2" -H 'Content-Type: application/json' \
  --data-binary '{"index_patterns":["honeypot-v2-*"],"priority":500,"data_stream":{},"template":{"settings":{"index.lifecycle.name":"honeypot-30d","index.number_of_replicas":0}}}' >/dev/null ||
  fail "Elasticsearch rejected the honeypot-events-v2 data stream template"

resp="$(curl -fsS -X POST "$es_url/honeypot-v2-test/_doc" -H 'Content-Type: application/json' \
  -d '{"@timestamp":"2026-08-05T00:00:00Z","msg":"doc1"}')"
first_index="$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin)['_index'])")"
pass "data stream created, first write landed in $first_index"

# Let ILM's own automatic poll do everything from here -- no manual
# _rollover call. This is the actual thing #585 found broken: without a
# rollover action, this loop would run forever with the index stuck at
# wait-for-shard-history-leases and never disappearing.
deleted=0
for _ in $(seq 1 20); do
  sleep 3
  if ! curl -fsS -o /dev/null "$es_url/$first_index" 2>/dev/null; then
    deleted=1
    break
  fi
done
[ "$deleted" -eq 1 ] ||
  fail "the original backing index ($first_index) was never deleted -- ILM's delete phase is still stuck, the #585 bug is not fixed"
pass "the original backing index was automatically rolled over and then deleted by ILM's own poll cycle -- no manual intervention"

status="$(curl -fsS "$es_url/_data_stream/honeypot-v2-test" | python3 -c "import json,sys; print(json.load(sys.stdin)['data_streams'][0]['status'])")"
[ "$status" = "GREEN" ] || fail "data stream status is $status after the delete, expected GREEN"
pass "data stream remains healthy (GREEN) after its original backing index was deleted"

curl -fsS -X POST "$es_url/honeypot-v2-test/_doc" -H 'Content-Type: application/json' \
  -d '{"@timestamp":"2026-08-05T00:10:00Z","msg":"still writable"}' >/dev/null ||
  fail "data stream stopped accepting writes after the delete"
pass "data stream still accepts writes after the delete"

echo
echo "all honeypot-30d ILM rollover tests passed"
