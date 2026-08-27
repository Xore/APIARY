#!/usr/bin/env bash
# probe-real-session-fetch.sh -- stage 0 of the real-data qualitative check.
#
# Pulls raw real cowrie command activity from this honeypot's own
# Elasticsearch store (read-only _search query, nothing written) and
# writes it as plain JSON for probe-real-session.py's stage 1 to sanitize
# and build the real production prompt from. Runs from the analysis host
# itself over the honeynet Docker network -- does not touch hp-llm-worker,
# which cannot resolve `elasticsearch` while LLM_ENABLED stays false (see
# probe-real-session.py's module docstring).
#
# Usage:
#   probe-real-session-fetch.sh [lookback] [max-sessions]
#   probe-real-session-fetch.sh 7d 5 > /tmp/real-sessions.json

set -euo pipefail

lookback="${1:-7d}"
max_sessions="${2:-5}"

query=$(jq -n --arg lookback "$lookback" '{
  size: 2000,
  query: {
    bool: {
      filter: [
        {range: {"@timestamp": {gte: ("now-" + $lookback)}}},
        {terms: {"honeypot.eventid": ["cowrie.command.input", "cowrie.command.failed"]}}
      ]
    }
  },
  sort: [{"@timestamp": {order: "desc"}}],
  _source: ["honeypot.session", "honeypot.input", "@timestamp"]
}')

hits=$(docker run --rm --network honeynet curlimages/curl:8.21.0@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13 -s \
  -H 'Content-Type: application/json' \
  "http://elasticsearch:9200/honeypot-v2-*/_search" -d "$query" \
  | jq '.hits.hits')

echo "$hits" | jq --argjson max_sessions "$max_sessions" '
  ([.[] | select(._source.honeypot.session and ._source.honeypot.input)]
   | group_by(._source.honeypot.session)
   | map({
       session_id: .[0]._source.honeypot.session,
       commands: [.[]._source.honeypot.input],
       last_seen: (map(._source["@timestamp"]) | max)
     })
   | sort_by(.commands | length)
   | reverse
   | .[0:$max_sessions]) as $sessions
  | if ($sessions | length) == 0
    then {warning: "no real cowrie command activity in this lookback window -- this is itself a valid finding, not a script failure", sessions: []}
    else {sessions: $sessions}
    end
'
