#!/usr/bin/env python3
"""Real-data qualitative check for the sessions slot (#568, formalized under #637).

Builds the EXACT production prompt (llm-worker/contracts.py's real
sanitize_commands()/session_prompt() -- not a reimplementation) from real
session activity pulled live from this honeypot's own Elasticsearch store,
then sends it to a specified model and prints the raw response for a human
(or an agent) to read and judge -- correctness and groundedness against the
real captured commands, not exact-wording matched against a fixed answer.
This is deliberately NOT an automated pass/fail: real captured data has no
fixed expected answer, unlike evaluate-models.py's synthetic corpus.

Three stages, not one script, because hp-llm-worker's compose file joins
only an internal synthetic-only network while LLM_ENABLED stays false --
confirmed live: it cannot resolve `elasticsearch` or `ollama` in that mode,
by design (see worker.py's module docstring: "production input requires a
separate Compose override plus three explicit gates"). Routing around that
isolation just to make this diagnostic tool more convenient would defeat
its purpose, so this stays split instead:

  Stage 0 (probe-real-session-fetch.sh, alongside this file): pulls raw
  real command text from Elasticsearch from wherever the host already has
  ES access (this analysis host, over the honeynet Docker network), writes
  it as plain JSON. No llm-worker involvement, no contracts.py needed yet.

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

Safety: stage 0 is read-only against Elasticsearch (a _search query,
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

    prompts = []
    for session in sessions:
        transcript, original_count = sanitize_commands(session["commands"], max_content_chars)
        prompts.append({
            "session_id": session["session_id"],
            "real_command_count": original_count,
            "last_seen": session.get("last_seen"),
            "transcript_truncated": transcript.truncated,
            "system_prompt": SYSTEM_PROMPT,
            "user_prompt": session_prompt(transcript, duration_seconds=0.0, command_count=original_count, auth_success=False),
        })

    print(json.dumps({"generated_from": "real Elasticsearch data, this honeypot's own store", "prompts": prompts}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
