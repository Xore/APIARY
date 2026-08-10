# Rev·Deck Integration

Source: [biniamf/ai-reverse-engineering](https://github.com/biniamf/ai-reverse-engineering)

Rev·Deck is a local AI-assisted reverse engineering workstation that pairs
the Ghidra headless REST service with an LLM copilot.

**Current build (2026-08-10, #1165):** the deployed build tracks upstream
`main` (the real "Rev·Deck" rebrand -- tokens/layout/components theme,
Mermaid diagrams, citations, a much richer Ghidra REST client), not the
fork's PR #1 rewrite this banner used to describe -- that PoC was evaluated
and abandoned (#1164) because its rewrite expected a Ghidra REST contract
(`/analyze_b64`, `/jobs`, `/tools/{endpoint}`) this project doesn't
implement. PR #1's one genuinely exclusive feature (symbol/type/class
recovery, the Analysis workbench's Recovery subtab) was re-ported onto
upstream `main` instead of adopting the rest of the fork. Rollback to the
last known-good pre-#1165 image, if ever needed:

```bash
cd analysis/ghidra
docker tag ghidra-revdeck:backup-pre-pr1-20260810 ghidra-revdeck:latest
docker compose -f docker-compose.ghidra.yml --profile revdeck up -d --no-build revdeck
```

**CORS/403 fix (2026-08-11, #1156-adjacent):** the deployed build's own
same-origin guard (`webui/app.py`'s `_reject_cross_origin`) rejected every
state-changing route (upload, chat, cancel, ...) with 403 `"cross-origin
request is not allowed"` when reached through Traefik's TLS-terminating
edge -- confirmed live against the deployed container's own request log.
Root cause and fix: `revdeck-proxyfix/wsgi_proxyfix.py`'s own doc comment.
No change to the vendored `webui/` tree itself; the fix is a bind-mounted
shim plus a `command:` override in `docker-compose.ghidra.yml`, so a future
re-clone of upstream `main` doesn't silently lose it.

## Setup

```bash
# Clone Rev·Deck into this folder
git clone https://github.com/biniamf/ai-reverse-engineering \
    analysis/ghidra/revdeck/ai-reverse-engineering

# Copy and configure .env
cp ai-reverse-engineering/.env.example ai-reverse-engineering/.env
# Edit: set API_BASE, MODEL_NAME, API_KEY
```

## Recommended LLM Configs

```dotenv
# Option 1: Local Ollama (free, private)
API_BASE=http://127.0.0.1:11434/v1
API_KEY=not-used
MODEL_NAME=qwen2.5-coder:7b-instruct-q4_K_M

# Option 2: OpenRouter (hosted)
API_BASE=https://openrouter.ai/api/v1
API_KEY=<your-key>
MODEL_NAME=anthropic/claude-opus-4.8
```

## Start the full stack

```bash
cd analysis/ghidra
docker compose -f docker-compose.ghidra.yml --profile revdeck up -d

# Pull the independently selected interactive model into the shared Ollama
# volume (the analysis-host installer only guarantees the Ghidra model).
docker compose -f docker-compose.ghidra.yml exec ollama \
    ollama pull qwen2.5-coder:7b-instruct-q4_K_M
```

Open http://127.0.0.1:19500 — the compose file maps host port `19500` to
the container's internal `5000` (`${HP_BIND:-127.0.0.1}:19500:5000`).
Loopback-only when `HP_BIND` is unset, like the rest of this file, but on a
different mechanism than `ghidra`/`ollama`/`statictools`: those three bind
`127.0.0.1` unconditionally, since nothing about them is meant to be reached
off-host; `revdeck`'s binding is `HP_BIND`-controlled because it is the one
service here meant to be reachable remotely (see below).

### Reaching it remotely (Traefik + Keycloak/oauth2-proxy SSO)

Set `HP_BIND` in this directory's `.env` (copy from `.env.example`) to the
same WireGuard address `APIARY`'s own `HP_BIND` uses, then redeploy
this stack — `revdeck`'s port publish reads it, everything else in this file
stays loopback-only regardless. The VPS side (`socat-hp-revdeck` in
`vps/docker-compose.yml`, the `honeypot-revdeck` router in
`vps/traefik/dynamic.yml`) is already wired to a `rev.<domain>` route
behind the same shared Keycloak/oauth2-proxy SSO gateway every other
gateway-fronted investigation UI (Kibana, Arkime, ...) uses — register the DNS record and it's
reachable at `https://rev.<your-domain>`. No new auth pattern; this is
the existing one extended to one more service.

## Automated Triage (#78)

`worker/ghidra-worker.py` now drives Rev·Deck automatically as one more
fail-soft enrichment inside `analyse_one()`, alongside the worker's own local
`triage()` — a second, independent AI aid, not a replacement for it. It runs:

```
POST /upload           multipart "file" (+ "analyze_as_raw": "true")
                       -> {"job_id": ..., "status": "queued"|"done", ...}
GET  /status/{job_id}  -> {"status": "queued|running|done|failed|
                            cancelled|interrupted", ...}
POST /chat             JSON {"message", "job_id", "mode": "autonomous",
                              "workflow": "program_triage"}
                       -> text/event-stream, one "data: {json}\n\n" line per
                          event (activity_start, token, tool_call,
                          tool_result, warning, citations, error, done)
```

This is the **verified** contract — read against a real clone of this
project's `webui/app.py`, `ghidra_assistant.py`, `workflows.py`,
`ghidra_client.py` and `file_preflight.py` on 2026-08-01, not from a plan
document. It replaces the old, never-run `/api/upload`/`/api/chat` shape a
prior version of `ghidra_analyze.py` guessed at, which was deleted alongside
the disproven Ghidra REST contract
[#101](https://github.com/Xore/APIARY/issues/101) under
[#107](https://github.com/Xore/APIARY/issues/107) without ever having
run against a live container. See the comment block above `REVDECK_API_BASE`
in [`worker/ghidra-worker.py`](../../../../analysis/ghidra/worker/ghidra-worker.py) for the full
contract, including why `analyze_as_raw=true` is always sent.

**Off by default.** Set `REVDECK_API_BASE` (e.g.
`http://127.0.0.1:19500`, the published host port, not the container's
internal `5000`) on the worker host to turn it on — same convention
as `STATICTOOLS_API_BASE`/`GHIDRA_TRIAGE_API_BASE`, except empty is the
default here rather than a loopback address, since this stack has never
shipped running before now. `endpoint_is_local()` refuses anything that
is not this host or its network before the sample itself is uploaded (#103,
applied harder here than for text-only triage). The result lands in the
`revdeck` field of `{sha256}_ghidra.json`, distinct from the worker's own
`ai_triage` field, and is rendered in both the HTML report
(`report/generate_report.py`) and the dashboard's Ghidra detail page.

Only one autonomous workflow runs per analysis, chosen by
`REVDECK_WORKFLOW` (default `program_triage`, the whole-program summary that
most directly parallels the worker's own local triage). `suspicious_behavior`
is the other no-analyst-target workflow worth trying; swap it in per
deployment rather than running both and doubling the cost of every analysis
on a shared GPU. `attack_surface_triage` and `vulnerability_hypothesis`
require an analyst-selected function address and are not run by this
pipeline — they stay interactive-only, same as before.

A `"max_turns"` finish — the step budget ran out before the model reached its
own conclusion — is kept as a best-effort partial answer rather than
discarded; only an `"error"` status or an empty answer is thrown away. See
`_revdeck_chat()` in the worker for the reasoning.

**Bring the container up, then opt in on the worker:**

```bash
cd analysis/ghidra
docker compose -f docker-compose.ghidra.yml --profile revdeck up -d
# on the worker host:
export REVDECK_API_BASE=http://127.0.0.1:19500
```

The interactive UI at http://127.0.0.1:19500 keeps working exactly as before —
turning on automation does not remove the ability to drive Rev·Deck by hand
for `attack_surface_triage`, `vulnerability_hypothesis`, or any deeper dive a
particular sample warrants.

The local default comes from the task-specific
[model evaluation](../../../local-llm-model-evaluation.md): it tied for
the highest Rev·Deck score, passed the x86 intent case, and does not depend on
the thinking-control field that the current upstream Rev·Deck client does not
send.

## Evidence Grounding

Rev·Deck citations use `[function:0xADDR]`, `[string:0xADDR]`, `[import:name]`
format and are verified against retrieved evidence. Unverified claims are
explicitly marked. This prevents hallucination on specific binary facts.
