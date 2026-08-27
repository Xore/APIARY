#!/usr/bin/env python3
"""Real-data qualitative check for the sessions slot (#568, formalized under #637).

Builds the production prompt (llm-worker/contracts.py's real
sanitize_commands()/session_prompt() -- not a reimplementation) from real
session activity pulled live from this honeypot's own Elasticsearch store,
then sends it to a specified model and prints the raw response for a human
(or an agent) to read and judge -- correctness and groundedness against the
real captured commands, not exact-wording matched against a fixed answer.
This is deliberately NOT an automated pass/fail: real captured data has no
fixed expected answer, unlike evaluate-models.py's synthetic corpus.

Prompt-input fidelity (#2387): every session_prompt() input except the
sanitized transcript itself comes from stage 0's correlated per-session
evidence, not from constants. auth_success mirrors llm-worker's
SessionAccumulator (set true only when a cowrie.login.success event is
observed) and duration_seconds is the honeypot.duration the
cowrie.session.closed event carried. Sessions whose evidence does not reach
the lookback window are listed in "skipped_sessions" with the missing field
named -- they are NOT prompted with synthesized stand-in values. Residual,
documented difference from production: production accumulates continuously
from its own persistent checkpoint and may hold evidence outside this
probe's point-in-time window (a login that precedes it, or a close event
that lands after stage 0 ran); such sessions surface here as skipped rather
than as fabricated metadata.

Three stages, not one script, because hp-llm-worker's compose file joins
only an internal synthetic-only network while LLM_ENABLED stays false --
confirmed live: it cannot resolve `elasticsearch` or `ollama` in that mode,
by design (see worker.py's module docstring: "production input requires a
separate Compose override plus three explicit gates"). Routing around that
isolation just to make this diagnostic tool more convenient would defeat
its purpose, so this stays split instead:

  Stage 0 (probe-real-session-fetch.sh, alongside this file): pulls real
  command text plus the auth-outcome/close evidence for the selected
  sessions from Elasticsearch from wherever the host already has ES access
  (this analysis host, over the honeynet Docker network), writes it as
  plain JSON. No llm-worker involvement, no contracts.py needed yet. Its
  header documents the per-session schema, including which fields can be
  null because no evidence was found in-window (#2387).

  Stage 1 (this file, run via `docker exec -i hp-llm-worker python3 -`,
  reading stage 0's JSON on stdin): has llm-worker's actual dependencies
  (pydantic) and contracts.py already on its path. Builds the real
  production prompt from the already-fetched data -- no network call of
  its own, so hp-llm-worker's isolation is never touched. Prints prompt
  JSON to stdout.

  Stage 2 (probe-real-session-run.sh): posts stage 1's prompt to a live
  Ollama server from wherever that's reachable (typically the analysis
  host), prints the raw model reply.

Usage (hp-llm-worker's root filesystem is read-only, so `docker cp` into it
fails -- pass this script's own source as `python3 -c` instead, which
leaves stdin free for stage 0's data):
  analysis/ghidra/benchmarks/probe-real-session-fetch.sh 7d 5 \
    > /tmp/real-sessions.json
  sudo docker exec -i hp-llm-worker python3 -c \
    "$(cat analysis/ghidra/benchmarks/probe-real-session.py)" \
    < /tmp/real-sessions.json \
    > /tmp/real-session-prompts.json
  analysis/ghidra/benchmarks/probe-real-session-run.sh \
    /tmp/real-session-prompts.json qwen3:14b

Safety: stage 0 is read-only against Elasticsearch (_search queries,
nothing written). Real captured attacker command text is not synthetic --
treat the output the same as any other captured evidence (do not execute
anything in it, review the JSON before sharing it outside the operator's
own systems).
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, "/app")
from contracts import SYSTEM_PROMPT, sanitize_commands, session_prompt  # noqa: E402


def _unresolvable_fields(session: dict) -> list[str]:
    """Names the prompt inputs stage 0 could not resolve for this session.

    auth_success must be a literal bool (JSON true/false; null means no
    login outcome was observed). duration_seconds must be numeric but not
    bool (bool is an int subclass in Python, so True would silently count
    as 1.0s otherwise). Anything else stays unresolved -- stage 0's nulls
    are honest evidence gaps and are never defaulted downstream.
    """
    missing = []
    if not isinstance(session.get("auth_success"), bool):
        missing.append("auth_success")
    duration = session.get("duration_seconds")
    if isinstance(duration, bool) or not isinstance(duration, (int, float)):
        missing.append("duration_seconds")
    return missing


def main() -> int:
    max_content_chars = int(os.getenv("MAX_CONTENT_CHARS", "12000"))
    raw = json.load(sys.stdin)
    sessions = raw.get("sessions", [])

    if not sessions:
        print(json.dumps({
            "warning": raw.get("warning", "no sessions in stage 0 input -- this is itself "
                       "a valid finding, not a script failure"),
            "prompts": [],
        }, indent=2))
        return 0

    prompts: list[dict] = []
    skipped: list[dict] = []

    for session in sessions:
        transcript, original_count = sanitize_commands(
            session["commands"], max_content_chars
        )
        missing = _unresolvable_fields(session)
        if missing:
            # #2387: refusing to pin auth_success=False / duration=0.0 means
            # admitting these two sessions' worth of metadata simply did not
            # make it into the probe window. Say which fields, keep the
            # transcript count visible, and skip -- no synthetic framing of
            # what was actually a successful authenticated intrusion.
            skipped.append({
                "session_id": session["session_id"],
                "command_count_seen": original_count,
                "last_seen": session.get("last_seen"),
                "unresolvable_fields": missing,
                "note": "; ".join(session.get("metadata_gaps") or []),
            })
            continue

        gap_notes = session.get("metadata_gaps") or []
        prompt_record = {
            "session_id": session["session_id"],
            "real_command_count": original_count,
            "first_seen": session.get("first_seen"),
            "last_seen": session.get("last_seen"),
            "transcript_truncated": transcript.truncated,
            "system_prompt": SYSTEM_PROMPT,
            # Both metadata inputs are resolved-from-evidence values: a
            # cowrie.login.success/failed observation decides auth_success,
            # and duration_seconds is the close event's honeypot.duration.
            "user_prompt": session_prompt(
                transcript,
                float(session["duration_seconds"]),
                original_count,
                session["auth_success"],
            ),
        }
        if gap_notes:
            prompt_record["metadata_gaps"] = gap_notes
        prompts.append(prompt_record)

    output = {
        "generated_from": (
            "real Elasticsearch data, this honeypot's own store "
            "(auth outcomes and durations correlated per session, #2387)"
        ),
        "prompts": prompts,
    }
    if skipped:
        output["skipped_sessions"] = skipped
        output["skipped_note"] = (
            "these sessions were NOT prompted with synthesized metadata -- "
            "stage 0 could not resolve the named fields inside the lookback "
            "window, so building 'production' prompts from them would have "
            "required inventing inputs"
        )
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
