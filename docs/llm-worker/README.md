# Guarded local LLM worker

This is the offline-first implementation of
[#66](https://github.com/Xore/APIARY/issues/66). It produces advisory,
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

## Synthetic real-model canary

Issue #83's first phase is a one-shot test of the pinned local model. It joins
only the internal `honeypot-llm` network and has no Elasticsearch route or
capture mount:

```bash
docker compose \
  -f llm-worker/docker-compose.yml \
  -f llm-worker/docker-compose.synthetic-canary.yml \
  up --build --abort-on-container-exit --exit-code-from llm-worker
```

The command runs reconnaissance and injection/exfiltration sessions made
entirely from TEST-NET fixtures. It fails closed on schema, factuality,
injection-marker, grounded-IOC, deterministic-severity, model-digest, or
idle-unload errors. The 30-second canary keep-alive is deliberately short;
normal worker requests retain the bounded 10-minute default.

The current session default is the #158-qualified
`qwen3.5:9b@6488c96fa5faab64bb65cbd30d4289e20e6130ef535a93ef9a49f42eda893ea7`.
Its tag, digest, generated-schema hash, `session-v5` prompt hash, request
settings, host/runtime record, and per-case gates are controlled by
[`../analysis/ghidra/models/approved-models.json`](../../analysis/ghidra/models/approved-models.json).

## Captured-data canary

Issue [#83](https://github.com/Xore/APIARY/issues/83) uses a narrower
one-shot override for its authorized production U1 acceptance. It permits
Elasticsearch and Ollama access, mounts no captured-payload directory, forces
U2 and reports off, writes at most one session result, and exits:

```bash
docker compose \
  -f llm-worker/docker-compose.yml \
  -f llm-worker/docker-compose.production-session-canary.yml \
  up --build --abort-on-container-exit --exit-code-from llm-worker
```

The override uses a 30-second keep-alive so idle unload is observable during
acceptance. The production record is
[`docs/llm-production-canary-record.md`](../llm-production-canary-record.md).
The broader captured-data override remains a separately reviewed grant for
later U2 work:

```bash
docker compose \
  -f llm-worker/docker-compose.yml \
  -f llm-worker/docker-compose.captured-data.yml \
  config --quiet
```

The override attaches the worker to the internal `honeypot-llm-data` network
for Elasticsearch and the internal `honeypot-llm` network for the one Ollama
instance measured by #144 and requalified/pinned by #158. The root stack owns the former
and attaches only Elasticsearch; the Ghidra stack owns the latter and attaches
Ollama. The worker never joins the Internet-routable `honeynet` bridge and
publishes no port. The override mounts only Cowrie downloads and retained
inline scripts read-only. Version 1 accepts regular text files no larger than
1 MiB, refuses symlinks and NUL-containing/binary data, and hashes content
itself instead of trusting a filename.

## Guardrails

- strict pydantic schemas reject extra keys, invalid enums, malformed ATT&CK
  IDs, and oversized fields;
- control characters and prompt delimiters are neutralized, secrets in common
  assignment/URL/`chpasswd` forms are redacted, and transcripts are capped;
- model-proposed IOCs are discarded and replaced with bounded indicators
  extracted literally from sanitized evidence;
- SSH authorized-key and account-credential changes receive a deterministic
  persistence classification, high severity floor, and grounded ATT&CK IDs;
- unsupported password-cracking claims and platform-incompatible ATT&CK
  mappings are corrected or removed before persistence;
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
[#154](https://github.com/Xore/APIARY/issues/154). Dashboard delivery
is #150, and the customizable analyzer workbench is explicitly tracked by
[#155](https://github.com/Xore/APIARY/issues/155).

## Tests

```bash
python -m pip install -r llm-worker/requirements.txt
python -m unittest discover -s llm-worker/tests -v
python llm-worker/worker.py --selftest
```

Fixtures are synthetic and use TEST-NET addresses. Tests cover delimiter and
secret neutralization, exact schemas, local endpoints, disabled proxies and
redirects, thinking control, constrained ATT&CK IDs, IOC grounding,
deterministic criticality, idempotent session accumulation, and safe
text-payload scanning.

## Result contract

Every `llm-analysis` document records its type, stable source identifier,
model and digest, worker/schema/prompt versions, sanitized-input hash,
confidence, model severity, final severity, deterministic flags, truncation,
token counts, and timing. Raw prompts and captured content are not copied into
the result index. #150/#155 must HTML-escape and visibly label all narrative
fields as AI-generated.
