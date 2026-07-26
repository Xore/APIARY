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
docker compose -f docker-compose.ghidra.yml up
```

Open http://127.0.0.1:5000

## Automated Workflows Used

| Workflow | Purpose |
|----------|---------|
| `program_triage` | Summarize binary purpose, family, risk |
| `suspicious_behavior` | IOC-grounded behavior detection |
| `attack_surface_triage` | Top dangerous functions, scored |
| `vulnerability_hypothesis` | CVE-style analysis for high-value targets |

All outputs are saved to `reports/ghidra/<sha256>/revdeck_triage.json`
and embedded in the final PDF report.

## Evidence Grounding

Rev·Deck citations use `[function:0xADDR]`, `[string:0xADDR]`, `[import:name]`
format and are verified against retrieved evidence. Unverified claims are
explicitly marked. This prevents hallucination on specific binary facts.
