#!/usr/bin/env bash
# probe-real-session-fetch.sh -- stage 0 of the real-data qualitative check.
#
# Pulls raw real cowrie session activity from this honeypot's own
# Elasticsearch store (read-only _search queries, nothing written) and
# writes it as plain JSON for probe-real-session.py's stage 1 to sanitize
# and build the real production prompt from. Runs from the analysis host
# itself over the honeynet Docker network -- does not touch hp-llm-worker,
# which cannot resolve `elasticsearch` while LLM_ENABLED stays false (see
# probe-real-session.py's module docstring).
#
# Two queries, both bound by the same lookback window:
#   1. Command events (as always) select the sessions themselves, ranked by
#      how many real commands they carry.
#   2. A follow-up query correlates the per-session auth-outcome and close
#      evidence (#2387) for exactly those selected sessions: cowrie.login.success /
#      cowrie.login.failed decide auth_success the way llm-worker's
#      SessionAccumulator does (worker.py sets it true only on a login.success),
#      and cowrie.session.closed supplies honeypot.duration the same way
#      production fills duration_seconds. Keeping this second query separate
#      keeps credential-guessing noise (thousands of login.failed events from
#      unrelated scanner sessions) out of the command-selection budget.
#
# Usage:
#   PROBE_REAL_SESSION_ES_HOST=http://elasticsearch:9200 (the honeynet alias, default)
#   probe-real-session-fetch.sh [lookback] [max-sessions]
#   probe-real-session-fetch.sh 7d 5 > /tmp/real-sessions.json
#
# Output schema (one object per selected session; anything stage 0 cannot
# resolve for a session is null here plus an entry in metadata_gaps --
# deliberately NOT defaulted downstream, so stage 1 can refuse to dress an
# unknown up as production reality):
#   session_id        -- the cowrie session token
#   commands          -- captured command strings
#   first_seen        -- earliest timestamp of any correlated session event (or null)
#   last_seen         -- latest command timestamp (as before)
#   auth_success      -- true when cowrie.login.success was observed; false when only
#                        cowrie.login.failed was; null when neither appeared in the window
#   closed            -- whether cowrie.session.closed was observed
#   duration_seconds  -- honeypot.duration from the latest close event, else null
#   metadata_gaps     -- explicit list of the fields above that stayed unresolvable
#                        for this session inside the lookback window (empty when none)

set -euo pipefail

lookback="${1:-7d}"
max_sessions="${2:-5}"
es_host="${PROBE_REAL_SESSION_ES_HOST:-http://elasticsearch:9200}"

fetch_hits() { # $1: ES query body -- read-only _search, nothing written
  docker run --rm --network honeynet curlimages/curl:8.21.0@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13 -s \
    -H 'Content-Type: application/json' \
    "$es_host/honeypot-v2-*/_search" -d "$1" \
    | jq '.hits.hits'
}

command_query=$(jq -n --arg lookback "$lookback" '{
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

sessions=$(fetch_hits "$command_query" | jq --argjson max_sessions "$max_sessions" '
  [.[] | select(._source.honeypot.session and ._source.honeypot.input)]
  | group_by(._source.honeypot.session)
  | map({
      session_id: .[0]._source.honeypot.session,
      commands: [.[]._source.honeypot.input],
      last_seen: (map(._source["@timestamp"]) | max)
    })
  | sort_by(.commands | length)
  | reverse
  | .[0:$max_sessions]
')

if [ "$(jq 'length' <<<"$sessions")" -eq 0 ]; then
  jq -n '{warning: "no real cowrie command activity in this lookback window -- this is itself a valid finding, not a script failure", sessions: []}'
  exit 0
fi

session_ids=$(jq '[.[].session_id]' <<<"$sessions")

auth_query=$(jq -n --arg lookback "$lookback" --argjson ids "$session_ids" '{
  size: 4000,
  query: {
    bool: {
      filter: [
        {range: {"@timestamp": {gte: ("now-" + $lookback)}}},
        {terms: {"honeypot.session": $ids}},
        {terms: {"honeypot.eventid": ["cowrie.login.success", "cowrie.login.failed", "cowrie.session.closed"]}}
      ]
    }
  },
  sort: [{"@timestamp": {order: "asc"}}],
  _source: ["honeypot.session", "honeypot.eventid", "@timestamp"]
}')

metadata=$(fetch_hits "$auth_query")

printf '%s' "$sessions" | jq --argjson meta "$metadata" '
  def normalize_duration:
    if type == "number" then . else ((tonumber?) // null) end;
  map(. as $sess
    | [($meta // [])[] | select(._source.honeypot.session == $sess.session_id)] as $events
    | [$events[]."_source".honeypot.eventid] as $eventids
    | if ($events | length) == 0 then
        $sess + {
          first_seen: null,
          auth_success: null,
          closed: false,
          duration_seconds: null,
          metadata_gaps: ["no login-outcome or session-close evidence for this session inside the lookback window"]
        }
      else
        (if any($eventids[]; . == "cowrie.login.success") then true
         elif any($eventids[]; . == "cowrie.login.failed") then false
         else null end) as $auth
        | ([$events[]
            | select(._source.honeypot.eventid == "cowrie.session.closed")
            | select(._source.honeypot.duration != null)]
           | sort_by(._source["@timestamp"])
           | last
           | ._source.honeypot.duration
           | normalize_duration
          ) as $duration
        # Production semantics for reference: llm-worker keeps auth_success=False
        # until a login.success arrives and reads duration only from the close
        # event -- but where this probe cannot observe either, it emits null
        # and names the gap instead of borrowing that default silently here.
        | ($sess
          + {
              first_seen: ([($events[] | ._source["@timestamp"])] | min),
              auth_success: $auth,
              closed: (any($eventids[]; . == "cowrie.session.closed")),
              duration_seconds: $duration
            }
          + {metadata_gaps: (
               (if $auth == null then
                  ["auth_success: no cowrie.login.success/cowrie.login.failed event found for this session inside the lookback window"]
                else [] end)
               + (if $duration == null then
                    (if any($eventids[]; . == "cowrie.session.closed") then
                       ["duration_seconds: cowrie.session.closed observed but carried no usable honeypot.duration"]
                     else
                       ["duration_seconds: no cowrie.session.closed event found for this session inside the lookback window"]
                     end)
                  else [] end)
             )}
        )
      end
)'
