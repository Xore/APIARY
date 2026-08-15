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

ES_IMAGE="docker.elastic.co/elasticsearch/elasticsearch:8.19.20@sha256:e4797708584bd0df7c746b33a6640d243018a0ae8c8b088391c6f4675a3bef52"

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

# Extract exactly the geoip-honeypot pipeline's JSON body (the
# geoip_pipeline_body heredoc) rather than the whole file, so this stays in
# sync with elasticsearch-setup.sh automatically -- no copy of the pipeline
# definition to fall out of date here. Located by the heredoc's own open/
# close markers, not the PUT command -- #827 moved the actual curl call to
# after the heredoc (the body needs a placeholder substituted first, see
# below), so it's no longer adjacent to "<<'JSON'" the way earlier versions
# of this pipeline's install code had it.
start_line=$(grep -n "cat <<'JSON'" "$src_root/analysis/elasticsearch-setup.sh" | head -1 | cut -d: -f1)
body_start=$((start_line + 1))
end_line=$(tail -n "+$body_start" "$src_root/analysis/elasticsearch-setup.sh" | grep -n '^JSON$' | head -1 | cut -d: -f1)
body_end=$((body_start + end_line - 2))
sed -n "${body_start},${body_end}p" "$src_root/analysis/elasticsearch-setup.sh" > "$tmp/pipeline.json.tmpl"

# #827: the extracted body still has the literal __ES_HOME_NET_JSON__
# placeholder elasticsearch-setup.sh's own sed substitutes at install time --
# same real TEST-NET-2 convention as the rest of this file's fixtures below,
# not a real address, so this test's own "home_net" IS the address the
# simulate fixtures below deliberately trigger the swap against.
sed 's#__ES_HOME_NET_JSON__#["198.51.100.1"]#' "$tmp/pipeline.json.tmpl" > "$tmp/pipeline.json"

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

# #827: Suricata netflow logs both directions of one flow as separate
# records, source/destination reflecting literal packet direction not
# attacker/victim -- for the "reflected" direction (our own service
# answering back), source.ip is this host's own address, not the remote
# attacker's. This pipeline is installed above with home_net=198.51.100.1
# (this test's own fixture-only address, matching the TEST-NET-2 convention
# every other fixture here already uses).
simulate_flow() {
  # simulate_flow <fixture-file> -> prints "source.ip destination.ip destination.port"
  curl -fsS -X POST "$es_url/_ingest/pipeline/geoip-honeypot/_simulate" \
    -H 'Content-Type: application/json' \
    --data-binary "@$1" |
    python3 -c "
import json, sys
doc = json.load(sys.stdin)['docs'][0]['doc']['_source']
src = doc.get('source', {}).get('ip', '')
dst = doc.get('destination', {})
print(f\"{src} {dst.get('ip', '')} {dst.get('port', '')}\")
"
}

# Normal direction: a real remote attacker (198.51.100.77) hitting our VNC
# honeypot (port 5900) -- source is already the remote party, nothing to
# swap. Confirms the fix doesn't disturb the overwhelming majority case.
cat > "$tmp/netflow_normal.json" <<'EOF'
{"docs":[{"_source":{"suricata":{"eve":{"event_type":"netflow","src_ip":"198.51.100.77","src_port":51234,"dest_ip":"198.51.100.1","dest_port":5900,"proto":"TCP"}}}}]}
EOF
result="$(simulate_flow "$tmp/netflow_normal.json")"
[ "$result" = "198.51.100.77 198.51.100.1 5900" ] ||
  fail "normal-direction netflow regressed (got: '$result')"
pass "normal-direction netflow (remote -> us) is unaffected"

# Reflected direction: the same conversation's return leg, as Suricata
# actually logs it -- src_ip/src_port are OUR OWN service (5900), dest_ip/
# dest_port are the real remote attacker's ephemeral port. Without the
# #827 fix, source.ip would be our own address here -- exactly what showed
# up as the #1 "attack source" in the real dashboard before this fix.
cat > "$tmp/netflow_reflected.json" <<'EOF'
{"docs":[{"_source":{"suricata":{"eve":{"event_type":"netflow","src_ip":"198.51.100.1","src_port":5900,"dest_ip":"198.51.100.77","dest_port":51234,"proto":"TCP"}}}}]}
EOF
result="$(simulate_flow "$tmp/netflow_reflected.json")"
[ "$result" = "198.51.100.77 198.51.100.1 5900" ] ||
  fail "reflected-direction netflow was not corrected (got: '$result', want the same real-attacker/our-own-service pair as the normal-direction case above)"
pass "reflected-direction netflow (us -> remote) is corrected to the real remote party"

# Neither side is home_net -- e.g. Suricata observing unrelated third-party
# traffic, or the swap condition genuinely doesn't apply. Falls back to
# positional (source, destination), same as every event type without this
# fix -- no false-positive swap.
cat > "$tmp/netflow_neither_homenet.json" <<'EOF'
{"docs":[{"_source":{"suricata":{"eve":{"event_type":"netflow","src_ip":"203.0.113.5","src_port":443,"dest_ip":"198.51.100.77","dest_port":51234,"proto":"TCP"}}}}]}
EOF
result="$(simulate_flow "$tmp/netflow_neither_homenet.json")"
[ "$result" = "203.0.113.5 198.51.100.77 51234" ] ||
  fail "a flow with neither side in home_net was swapped when it shouldn't be (got: '$result')"
pass "a flow with neither side in home_net falls back to positional (no false-positive swap)"

simulate_hash() {
  # simulate_hash <fixture-file> -> prints file.hash.sha256 (or empty)
  curl -fsS -X POST "$es_url/_ingest/pipeline/geoip-honeypot/_simulate" \
    -H 'Content-Type: application/json' \
    --data-binary "@$1" |
    python3 -c "
import json, sys
doc = json.load(sys.stdin)['docs'][0]['doc']['_source']
print(doc.get('file', {}).get('hash', {}).get('sha256', ''))
"
}

# #1240: cowrie.session.file_download's honeypot.shasum is a genuine
# captured-payload hash and must still reach file.hash.sha256 -- confirms
# the fix below doesn't regress the legitimate case.
cat > "$tmp/file_download_shasum.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"eventid":"cowrie.session.file_download","shasum":"deadbeefcafef00d0000000000000000000000000000000000000000000000","src_ip":"198.51.100.40"}}}]}
EOF
result="$(simulate_hash "$tmp/file_download_shasum.json")"
[ "$result" = "deadbeefcafef00d0000000000000000000000000000000000000000000000" ] ||
  fail "cowrie.session.file_download's shasum was not promoted to file.hash.sha256 (got: '$result')"
pass "cowrie.session.file_download's shasum is promoted to file.hash.sha256"

# #1240: cowrie.log.closed's honeypot.shasum is the TTY recording's own
# filename-derived session ID, not a captured file's hash -- confirmed live
# against real production data (51k+ documents carried a bogus
# file.hash.sha256 from this event type alone, vs. 2.9k genuine
# file_download hashes) that corrupted every payload-hash-keyed feature
# reading it (attacker-identity entity panels, correlation, dedup) with
# stale references that 404 when clicked.
cat > "$tmp/log_closed_shasum.json" <<'EOF'
{"docs":[{"_source":{"honeypot":{"eventid":"cowrie.log.closed","shasum":"1b160c2a72b76aa2b1e8cf1e2a2bca6dd2bd9d2de5df20f94577c138d6cc85b9","ttylog":"var/lib/cowrie/tty/1b160c2a72b76aa2b1e8cf1e2a2bca6dd2bd9d2de5df20f94577c138d6cc85b9","src_ip":"198.51.100.41"}}}]}
EOF
result="$(simulate_hash "$tmp/log_closed_shasum.json")"
[ -z "$result" ] ||
  fail "cowrie.log.closed's ttylog-derived shasum leaked into file.hash.sha256 (got: '$result', want empty)"
pass "cowrie.log.closed's shasum is not mistaken for a real payload hash"

echo
echo "all geoip-honeypot pipeline tests passed"
