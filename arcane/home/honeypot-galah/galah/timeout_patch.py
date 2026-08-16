#!/usr/bin/env python3
"""Raise galah's hardcoded 10s response deadline (#1513).

internal/server/server.go's SetupServer() builds every listener with
WriteTimeout: 10 * time.Second, not exposed via any CLI flag or `env:`
binding in internal/app/args.go -- confirmed directly against the vendored
source, not assumed. Go's net/http.Server.WriteTimeout forcibly closes the
connection once exceeded, covering the entire request handler including the
LLM call chain (internal/server/server.go's handler -> pkg/llm.
GenerateLLMResponse -> galah-llm-broker -> Ollama), regardless of what
galah-llm-broker's own UPSTREAM_TIMEOUT_SECONDS allows.

Confirmed live the actual failure mode this causes: Ollama's default
keep_alive unloads an idle model after 5 minutes, and a cold reload of
qwen2.5:7b-instruct-q4_K_M measured 15.1s of load_duration alone (19.28s
total for a trivial "hi" prompt) in one live sample -- comfortably past
both this 10s WriteTimeout and galah-llm-broker's own 8s default
UPSTREAM_TIMEOUT_SECONDS (raised alongside this patch, see compose.yml).
Any request arriving after 5 minutes of quiet -- the normal case for a
honeypot, not an edge case -- hit this ceiling and errored, which is why
galah has been returning HTTP 500 for real traffic instead of its intended
LLM-generated decoy response (#1513).

A second live sample under real GPU contention from this host's other
Ollama consumers (llm-worker, ml-worker, rex86-eval) measured over 40s and
still didn't finish -- the cold-load cost is genuinely variable, not a
fixed ~19s, so this is deliberately set well above either single
observation rather than just past the first sample. 100s gives real margin
for a worse-contention case without either of these two samples being
treated as the ceiling. ReadTimeout is untouched, this sensor receives
small requests, not large uploads, so read time was never the bottleneck.
A slower response is an acceptable, even fitting, tradeoff for a decoy
service -- HellPot/endlessh already lean on wasted attacker time as a
deliberate design goal elsewhere in this stack.

Same shape as hellpot/router_patch.py: exact-match string replacement with
a marker for idempotency, applied at Docker build time.
"""
from pathlib import Path

MARKER = "honeypot-stack: raised WriteTimeout for cold Ollama loads (#1513)"
TARGET = Path("/build/internal/server/server.go")

OLD = """		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
}"""

NEW = """		ReadTimeout: 10 * time.Second,
		// MARKER_PLACEHOLDER
		WriteTimeout: 100 * time.Second,
	}
}""".replace("MARKER_PLACEHOLDER", MARKER)


def main():
    text = TARGET.read_text()
    if MARKER in text:
        return  # already patched
    count = text.count(OLD)
    if count != 1:
        raise SystemExit(
            "timeout_patch.py: expected exactly 1 match for SetupServer()'s "
            "timeouts, found {}".format(count)
        )
    TARGET.write_text(text.replace(OLD, NEW, 1))


if __name__ == "__main__":
    main()
