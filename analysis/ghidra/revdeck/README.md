# Rev·Deck Integration

Source: [biniamf/ai-reverse-engineering](https://github.com/biniamf/ai-reverse-engineering)

Rev·Deck is a local AI-assisted reverse engineering workstation that pairs
the Ghidra headless REST service with an LLM copilot.

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
MODEL_NAME=qwen3:8b

# Option 2: OpenRouter (hosted)
API_BASE=https://openrouter.ai/api/v1
API_KEY=<your-key>
MODEL_NAME=anthropic/claude-opus-4.8
```

## Start the full stack

```bash
cd analysis/ghidra
docker compose -f docker-compose.ghidra.yml --profile revdeck up -d
```

Open http://127.0.0.1:5000 — loopback-only by default, same as `ghidra`/
`ollama`/`statictools` in this compose file.

### Reaching it remotely (Traefik + forward-auth SSO)

Set `HP_BIND` in this directory's `.env` (copy from `.env.example`) to the
same WireGuard address `honeypot-stack`'s own `HP_BIND` uses, then redeploy
this stack — `revdeck`'s port publish reads it, everything else in this file
stays loopback-only regardless. The VPS side (`socat-hp-revdeck` in
`vps/docker-compose.yml`, the `honeypot-revdeck` router in
`vps/traefik/dynamic.yml`) is already wired to a `revdeck.<domain>` route
behind the same shared forward-auth SSO middleware every other investigation
UI (dashboard, Kibana, Arkime, ...) uses — register the DNS record and it's
reachable at `https://revdeck.<your-domain>`. No new auth pattern; this is
the existing one extended to one more service.

## Automated Workflows Used

| Workflow | Purpose |
|----------|---------|
| `program_triage` | Summarize binary purpose, family, risk |
| `suspicious_behavior` | IOC-grounded behavior detection |
| `attack_surface_triage` | Top dangerous functions, scored |
| `vulnerability_hypothesis` | CVE-style analysis for high-value targets |

Nothing in this repository automates Rev·Deck yet. The earlier
`revdeck_triage()` function in `ghidra_analyze.py` called this stack's
`/api/upload`/`/api/chat` endpoints, but the `revdeck` container in
`docker-compose.ghidra.yml` has never been deployed or run, so that contract
was as unverified as the disproven Ghidra REST contract
[#101](https://github.com/Xore/honeypot-stack/issues/101) found broken —
both were deleted together under
[#107](https://github.com/Xore/honeypot-stack/issues/107). Automating Rev·Deck
triage against a verified contract, and turning its output into a report, is
tracked by [#78](https://github.com/Xore/honeypot-stack/issues/78). Until
then, this stack is interactive-only: bring it up with `docker compose` and
use the UI at http://127.0.0.1:5000 by hand.

## Evidence Grounding

Rev·Deck citations use `[function:0xADDR]`, `[string:0xADDR]`, `[import:name]`
format and are verified against retrieved evidence. Unverified claims are
explicitly marked. This prevents hallucination on specific binary facts.
