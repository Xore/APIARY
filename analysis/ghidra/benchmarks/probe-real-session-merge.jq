# probe-real-session-merge.jq -- stage 0's correlate-and-fill step, extracted
# verbatim from probe-real-session-fetch.sh so it can run hermetically (#2426).
#
# Contract (identical to the live probe's invocation):
#   stdin : the selected-sessions array produced by the command query
#   --argjson meta <json>: `.hits.hits` from the follow-up auth/close query,
#                          an empty array when that response carried nothing
#
# Correlates per-session auth outcome and close evidence the way llm-worker's
# SessionAccumulator reads them (worker.py sets auth_success=true only on a
# cowrie.login.success; duration_seconds comes from the LATEST
# cowrie.session.closed event carrying a usable honeypot.duration -- strings
# included, since ES mints them both ways). Anything a session cannot resolve
# becomes null plus an explicit entry in metadata_gaps: deliberately NOT
# defaulted here, so stage 1 can refuse to dress an unknown up as production
# reality.
#
# Hermetic fixture suite: tests/fixtures/probe-real-session-merge/, exercised
# by tests/test_probe_real_session.py::StageZeroMergeFixturesTest (skips with
# an explanation where the jq binary itself is unavailable).

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
)
