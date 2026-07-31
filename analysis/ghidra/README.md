# Ghidra analysis host

Static reverse engineering for captured payloads: headless Ghidra behind a REST
service, a host-side worker that drains a spool, and a local language model that
produces a first-pass triage opinion.

Design and phase history live in
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) (the Ghidra pipeline) and
[`DASHBOARD_INTEGRATION_PLAN.md`](DASHBOARD_INTEGRATION_PLAN.md) (how it reaches
the dashboard). This file is the operator's copy: how to install it, how to
configure it, and how to read what it produces.

---

## What runs where

```
dashboard container            host (root)                    containers (loopback)
┌──────────────────┐   .request  ┌───────────────────┐  HTTP   ┌──────────────────┐
│ POST /ghidra/    │ ──────────► │ honeypot-ghidra-  │ ──────► │ ghidra           │
│   submit         │             │ worker.path/.svc  │  :9090  │ headless REST    │
│                  │             │                   │         └──────────────────┘
│ GET /ghidra/{sha}│ ◄────────── │ ghidra-worker.py  │ ──────► ┌──────────────────┐
└──────────────────┘  _ghidra.json└───────────────────┘ :11434 │ ollama           │
                                                                │ local model      │
                                                                └──────────────────┘
```

The dashboard never talks to either container, or to Docker. It writes a
`{sha256}.request` marker into one directory and reads `{sha256}_ghidra.json`
out of another — the same spool pattern the KVM sandbox already uses. Both
container ports are published on `127.0.0.1` only: between them they hold
captured malware and every string extracted from it.

The worker is **stdlib-only Python 3** on purpose. A worker that needs
`pip install` before it can drain a queue is a worker that will be broken after
the next OS upgrade.

---

## Install

```bash
git clone https://github.com/Xore/honeypot-stack.git
sudo honeypot-stack/analysis/ghidra/install-analysis-host.sh
```

That does both halves. They can be run separately, which is what a host where
only the operator is in the `docker` group needs:

```bash
analysis/ghidra/install-analysis-host.sh --containers-only   # no root needed
sudo analysis/ghidra/install-analysis-host.sh                # the worker half
```

| Flag | Effect |
|---|---|
| `--containers-only` | Bring up/refresh the containers and stop |
| `--model NAME` | Model to pull. Defaults to `GHIDRA_TRIAGE_MODEL` from `/etc/default/honeypot-ghidra` if that file exists, else `qwen3:8b` |
| `--no-gpu` | Run the model on CPU even if an NVIDIA runtime is present |
| `--skip-pull` | Do not pull the model |
| `--stack-dir PATH` | Where to deploy the compose file. `""` runs it in place |

The script is idempotent — safe to re-run after an image bump, a model change,
or a reboot — and an existing `/etc/default/honeypot-ghidra` is never
overwritten.

One optional host package, deliberately not installed by the script because
package managers are the one thing that differs on every host:

```bash
sudo apt install graphviz
```

Without `dot` the call graph is still recovered and written as DOT; only the
rendered SVG is missing, and the worker says so (`[.] graphviz 'dot' not
installed`) rather than failing.

### Where the stack lives

On a host running Dockge (`/opt/stacks` exists) the compose file is deployed to
`/opt/stacks/ghidra/compose.yml`, which is what makes Dockge treat it as a stack
it owns rather than containers it can see but not start, stop, or read logs
from. **That copy is a deployment artifact**: edit
`docker-compose.ghidra.yml` here and re-run the script, because the next run
overwrites it.

The directory name is the compose project name and therefore the prefix on the
volumes — `ghidra_ollama_models` holds several GB of weights. Renaming it pulls
the model again into a new volume and orphans the old one.

GPU settings arrive as `compose.override.yml`, the one extra file `docker
compose` loads without being told to, because Dockge runs compose with no `-f`
of its own.

Containers created from somewhere else keep the compose labels they were born
with, and `up -d` leaves them alone because nothing about the service changed.
Once, after moving an already-running stack:

```bash
cd /opt/stacks/ghidra && docker compose up -d --force-recreate
```

Named volumes are keyed on the project name, so the weights survive that.

**The containers half** pulls both images, brings up `ghidra` and `ollama`,
polls until each actually answers (`up -d` returns when a container has
started, not when the service inside it is serving; Ghidra unpacks its own
installation on first boot and takes minutes), then pulls the model.

**The worker half** installs `ghidra-worker.py` to `/opt/honeypot-ghidra/`,
creates the spools `0700 root:root`, installs and enables
`honeypot-ghidra-worker.path`, and finishes by running `--selftest` against the
services it just started — a real binary through `/analyze`, plus a report on
whether the model endpoint is reachable, local, and serving the configured
model.

### GPU

Auto-detected from `docker info` and opted into with a compose overlay:

```bash
docker compose -f analysis/ghidra/docker-compose.ghidra.yml \
  -f analysis/ghidra/docker-compose.ghidra.gpu.yml up -d ollama
```

The overlay is separate because a device reservation the host cannot satisfy is
a hard `could not select device driver` on `up`. The base file works everywhere;
on CPU the model is slower and the worker cannot tell the difference.

### The dashboard side

`deploy.yml` excludes `.env` by design, so this part is yours:

```
GHIDRA_REQUEST_DIR=/ghidra-requests
GHIDRA_RESULTS_DIR=/ghidra-results
```

Those are the in-container paths; `docker-compose.yml` mounts the host spools
onto them. Without both, the dashboard hides the Ghidra queue entirely.

---

## Configuration

Everything lives in `/etc/default/honeypot-ghidra`, installed from
[`worker/honeypot-ghidra.default.example`](worker/honeypot-ghidra.default.example),
which documents each setting inline. The ones worth knowing:

| Variable | Default | Notes |
|---|---|---|
| `GHIDRA_API_BASE` | `http://127.0.0.1:9090` | The headless REST service |
| `GHIDRA_ANALYSIS_TIMEOUT` | `4200` | Per binary. Deliberately longer than the container's own `ANALYSIS_TIMEOUT` |
| `GHIDRA_TRIAGE_API_BASE` | `http://127.0.0.1:11434/v1` | Empty switches triage off |
| `GHIDRA_TRIAGE_MODEL` | `qwen3:8b` | Recorded in every result |
| `GHIDRA_TRIAGE_TIMEOUT` | `300` | Per workflow call; two calls run per sample |
| `GHIDRA_TRIAGE_MAX_STRINGS` / `_IMPORTS` / `_FUNCTIONS` | `200` / `150` / `100` | How much of the binary the model is shown. Around 8000 tokens together — see [the context window](#the-context-window-is-part-of-the-configuration) before raising them |

Spool paths are also set here, and must agree with `ReadWritePaths=` in
`honeypot-ghidra-worker.service`: systemd cannot expand these values, so moving
a spool means editing both files.

Alerting is configured on the **dashboard** side, not here:
`GHIDRA_ALERT_RISK_LEVELS` (default `high,critical`) and
`GHIDRA_ALERT_ON_CRYPTO` (default `false`).

---

## AI triage, and the local-only rule

After collection the worker runs two workflows against the model —
`program_triage` and `suspicious_behavior` — and writes the answer to
`ai_triage` on the result.

The endpoint is OpenAI-compatible (`/v1/chat/completions`), the dialect that
Ollama, llama.cpp's server, vLLM and LM Studio all serve, so the backend is
swappable. What is not swappable is that it must be **local**.

The prompts carry strings, imports and function names lifted straight out of a
captured sample. Sending that to a hosted API is not a smaller version of this
feature; it is a data-exfiltration path out of the analysis environment. So the
rule is enforced in code — `endpoint_is_local()` in
[`worker/ghidra-worker.py`](worker/ghidra-worker.py) — and **there is no
override flag**:

- IP literals must be loopback, RFC1918/ULA, or link-local.
- A bare name with no dot is accepted; so is one ending `.local`, `.internal`,
  `.lan`, `.localdomain`, `.home.arpa`.
- Everything else is refused, before any request is made.

The judgement is syntactic, not a DNS lookup, because a resolver answer can be
moved by whoever controls the zone — and the failure actually being guarded
against is an operator pasting an `api.openai.com` or `openrouter.ai` URL into
config.

### The context window is part of the configuration

The evidence block for a real binary is around 8000 tokens. Ollama's default
window is 4096 whatever the model can do — `qwen3:8b` advertises 40960 — and an
overlong prompt is **truncated, not refused**. There is no error, no HTTP
status, and the model answers from whichever fragment survived.

Measured here on `/usr/bin/wget`: at the default the reply described a command
line with hardcoded credentials that appears nowhere in the sample; at 16384
the same prompt returns `{"family_guess": "wget", "risk_level": "low"}`.

So the compose file sets `OLLAMA_CONTEXT_LENGTH=16384`. It has to be set on the
server, because `/v1/chat/completions` has no field for context length — only
Ollama's native API and that variable can reach it. Budget about 1.8 GB of KV
cache on top of the weights; `qwen3:8b` Q4_K_M then reports 7.8 GB and just
fits an 8 GB card. On a smaller card lower it rather than let it spill to CPU,
and lower the evidence budgets to match.

The worker does not trust the setting. Every reply is checked against the token
count the server reports about itself, and an answer whose prompt was truncated
is discarded with the reason logged. A window that is too small therefore shows
up as **missing** triage, never as invented findings. `--selftest` probes for it
directly, so it is visible at install time rather than in a malware report.

Triage fails soft, in every direction. No endpoint configured, an endpoint that
is refused, one that is unreachable, a model error, an answer that will not
parse — each leaves `ai_triage` null with the rest of the analysis complete and
the result written. Triage never fails an analysis.

### Reading the result

```json
"ai_triage": {
  "workflow": "program_triage+suspicious_behavior",
  "family_guess": "Mirai variant",
  "risk_level": "high",
  "behaviors": ["connects to a hardcoded C2 address", "kills competing processes"],
  "model": "qwen3:8b",
  "evidence_shown": "150/312 imports, 200/11482 strings (longest first, deduplicated, >=6 chars), 100/847 functions (largest first)"
}
```

- **`risk_level`** is normalised to `low` / `medium` / `high` / `critical`, or
  left empty. Models return "Highly Suspicious" and "Moderate" given the chance,
  and the dashboard's alert config matches exact strings — an un-normalised
  level would silently never alert.
- **`model`** is always recorded. The detail page and the alert text both name
  it, because "the model said" is only useful if you know which model.
- **`evidence_shown`** is the one to read first. A real sample overflows any
  context window, so the assessment is formed from a subset; a claim the model
  did **not** make may simply be something it was never shown.
- **`behaviors`** carry no per-claim evidence links. The workflows do not
  return that mapping, and inventing one would make a guess look like a
  citation.

`findcrypt` results are deliberately kept out of the prompt. Crypto constants
carry their own caveat — presence does not show malicious use — and feeding
them to a model invites exactly the over-reading the dashboard warns about.

Every claim is a language model's reading of decompiled code. The detail page
says so in an orange banner above the section, and the alert text carries
`UNVERIFIED`, because a webhook is read where that banner is not visible.

### Prompt injection

The evidence is attacker-authored: it is text out of a sample that may well
contain instructions aimed at whatever reads it. It is fenced in
`=== EVIDENCE ===` markers, the system prompt names it as data rather than
instructions, the answer is structurally constrained, and everything is
re-normalised on the way out. That is containment, not immunity — which is why
the banner stays.

---

## Operations

```bash
# Is any of this working?
python3 /opt/honeypot-ghidra/worker/ghidra-worker.py --selftest
```

It prints the endpoints, whether the spools exist, a `TRIAGE` line (disabled /
refused / unreachable / model not pulled / OK), and runs a real binary through
`/analyze` end to end:

```
API_BASE      : http://127.0.0.1:9090
/v1/health    : OK
REQUEST_DIR   : /var/lib/honeypot-ghidra/requests/pending (exists=True)
RESULTS_DIR   : /var/lib/honeypot-ghidra/results (exists=True)
SAMPLES_DIR   : /var/lib/honeypot-sandbox/inbox/samples (exists=True)
TRIAGE        : http://127.0.0.1:11434/v1 OK, model qwen3:8b available, context fits a full evidence block (7972 tokens read)

round trip on /bin/true ...
  job            : 4761e1f6b74841db9f744c552cc94240
  analyzer       : ghidra-11.3.2 (artifacts 2.1)
  functions      : 96
  strings        : 180
  imports        : 38

contract OK
```

```bash
# Worker logs
journalctl -u honeypot-ghidra-worker.service -f
```

```bash
# Swap the model
analysis/ghidra/install-analysis-host.sh --containers-only --model qwen3:14b
```

Then set `GHIDRA_TRIAGE_MODEL` to match and
`systemctl restart honeypot-ghidra-worker.path`. Pulling a model the worker is
not configured for leaves several GB on disk and triage still not working.

```bash
# What is loaded, what is on disk
docker compose -f /opt/stacks/ghidra/compose.yml exec ollama ollama ps
docker compose -f /opt/stacks/ghidra/compose.yml exec ollama ollama list
```

`ollama ps` has a `CONTEXT` column and a `PROCESSOR` column. Those are the two
that decide whether triage works and how long it takes:

```
NAME      ID            SIZE     PROCESSOR    CONTEXT
qwen3:8b  500a1f067a9f  7.8 GB   100% GPU     16384
```

`4096` there means the window setting is not reaching the container. Anything
other than `100% GPU` means part of the model is on CPU, which on this host is
the difference between a minute and a quarter of an hour per sample.

### Rev·Deck

The `revdeck` service is behind a `revdeck` profile and is not started by
default. Its build context is not vendored, and triage does not go through it —
the worker calls the model directly, so the local-only rule lives in code rather
than in an operator's `.env`. See [`revdeck/README.md`](revdeck/README.md).

---

## Tests

```bash
python3 analysis/ghidra/worker/test_ghidra_worker.py
```

Stdlib only, both sides stubbed, runs in seconds, and runs in CI on every
change. It covers spool discipline, the endpoint contract, risk normalisation,
the evidence budget, `<think>` stripping — and that a non-local endpoint is
refused, which is a rule worth only as much as the thing that checks it.
