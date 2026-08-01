# Guarded local LLM worker

This is the offline-first implementation of
[#66](https://github.com/Xore/honeypot-stack/issues/66). It produces advisory,
schema-validated session, text-payload, and daily-report documents for the
`llm-analysis` Elasticsearch index. It never executes captured content,
generates live honeypot responses, blocks traffic, or calls a hosted model.

## Safe default

The base Compose file runs only built-in synthetic contract checks. Its Docker
network is internal and has no route to Elasticsearch, Ollama, capture volumes,
or the Internet:

```bash
cp llm-worker/.env.example llm-worker/.env
docker compose -f llm-worker/docker-compose.yml up -d --build
docker exec hp-llm-worker python worker.py --selftest
docker port hp-llm-worker  # empty
```

`LLM_DRY_RUN=true` is not the only guard. Captured-data mode also requires
`LLM_ENABLED=true`, `LLM_ALLOW_CAPTURED_DATA=true`, at least one job flag, and
the separate `docker-compose.captured-data.yml` network/volume grant. Setting
an environment variable in the base stack cannot create a network path it does
not have.

## Captured-data canary

Do not enable this as part of #66. Issue
[#83](https://github.com/Xore/honeypot-stack/issues/83) owns the explicit
authorization, synthetic-to-production transition, output review, and
rollback:

```bash
docker compose \
  -f llm-worker/docker-compose.yml \
  -f llm-worker/docker-compose.captured-data.yml \
  config --quiet
```

The override attaches the worker to `honeynet` for Elasticsearch and to the
internal `honeypot-llm` network for the one Ollama instance already measured
and pinned by #144. Ollama is not placed on `honeynet`, and the worker publishes
no port. The override mounts only Cowrie downloads and retained inline scripts
read-only. Version 1 accepts regular text files no larger than 1 MiB, refuses
symlinks and NUL-containing/binary data, and hashes content itself instead of
trusting a filename.

## Guardrails

- strict pydantic schemas reject extra keys, invalid enums, malformed ATT&CK
  IDs, and oversized fields;
- control characters and prompt delimiters are neutralized, secrets in common
  assignment/URL forms are redacted, and transcripts are capped;
- model-proposed IOCs are discarded and replaced with bounded indicators
  extracted literally from sanitized evidence;
- a deterministic credential-access + encoding/chunking + outbound-transfer
  combination is forced to critical even if the model says high/low;
- Ollama requests use structured output, temperature zero, `think: false`, an
  8192 context cap, a bounded response, no redirects, and no environment proxy;
- Elasticsearch and Ollama URLs must be uncredentialed local/internal HTTP
  endpoints;
- checkpoint/session state is bounded and writes only sanitized commands;
- after bounded retries, an error annotation is written while raw ingestion
  remains unaffected.

The cross-sensor decoder/correlation expansion remains tracked by
[#154](https://github.com/Xore/honeypot-stack/issues/154). Dashboard delivery
is #150, and the customizable analyzer workbench is explicitly tracked by
[#155](https://github.com/Xore/honeypot-stack/issues/155).

## Tests

```bash
python -m pip install -r llm-worker/requirements.txt
python -m unittest discover -s llm-worker/tests -v
python llm-worker/worker.py --selftest
```

Fixtures are synthetic and use TEST-NET addresses. Tests cover delimiter and
secret neutralization, exact schemas, local endpoints, disabled proxies and
redirects, thinking control, IOC grounding, deterministic criticality,
idempotent session accumulation, and safe text-payload scanning.

## Result contract

Every `llm-analysis` document records its type, stable source identifier,
model and digest, worker/schema/prompt versions, sanitized-input hash,
confidence, model severity, final severity, deterministic flags, truncation,
token counts, and timing. Raw prompts and captured content are not copied into
the result index. #150/#155 must HTML-escape and visibly label all narrative
fields as AI-generated.
