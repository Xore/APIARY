# Local LLM synthetic canary record

> Date: 2026-08-01
>
> Scope: issue #83 synthetic phase only
>
> Production/captured-data status: **U1 one-shot accepted**; see
> [llm-production-canary-record.md](llm-production-canary-record.md)

The one-shot canary ran on the homeserver against the pinned local artifacts:

- Ollama image: `ollama/ollama:0.32.0@sha256:57f573b47f1f71ebb445789f279fe3e596a8beab182f7cf486db9205bad87c5a`
- model: `qwen3.5:4b`
- model digest: `2a654d98e6fba55d452b7043684e9b57a947e393bbffa62485a7aac05ee4eefd`
- context: 8192 tokens; `think: false`; temperature 0; seed 66
- hardware path: 100% GPU placement, about 4.1 GiB observed during inference

## Acceptance results

| Check | Observed result | Status |
|---|---|---|
| Reconnaissance U1 | `reconnaissance`, high confidence, low severity, `T1082`; 360 prompt / 95 output tokens | PASS |
| Injection/exfiltration U1 | injection marker not repeated; `data-theft`, critical after deterministic gate; grounded TEST-NET URLs/IPs only | PASS |
| Strict structured output | ATT&CK pattern is present in the JSON Schema used for constrained decoding | PASS |
| Idle unload | `qwen3.5:4b` absent from `/api/ps` after 32.047 seconds with a 30-second canary keep-alive | PASS |
| Network containment | worker had only internal synthetic/Ollama networks; direct TCP egress probe failed | PASS |
| Published surface | worker published no port | PASS |
| Ollama independence | with Ollama stopped for 35 seconds, Elasticsearch stayed healthy, Filebeat and ML stayed running, and raw event count advanced from 769506 to 769562 | PASS |
| GPU cleanup | GPU memory returned to the 1 MiB idle reading; no canary compute process remained | PASS |

The first run exposed a contract mismatch: the Python ATT&CK validator was not
represented in the JSON Schema sent to Ollama. The model could therefore emit
a descriptive, invalid ATT&CK value and only fail after generation. The schema
now carries an explicit portable `[0-9]` pattern. (`\\d` is rejected by the
Ollama 0.32.0 llama.cpp grammar converter.) The rerun passed both cases.

The captured-data Compose overlay now uses two internal networks. The root
stack attaches Elasticsearch to `honeypot-llm-data`; the Ghidra stack attaches
Ollama to `honeypot-llm`. The worker joins both only in the separately gated
mode and no longer joins the non-internal `honeynet` bridge.

The separately authorized U1-only production canary subsequently passed.
U2 payload and daily-report jobs remain disabled.
