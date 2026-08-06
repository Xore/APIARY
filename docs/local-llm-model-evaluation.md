# Local LLM model evaluation

Status: completed for [issue #144](https://github.com/Xore/APIARY/issues/144) and requalified under [issue #158](https://github.com/Xore/APIARY/issues/158), 2026-08-01. Re-evaluated and re-approved under [issue #568](https://github.com/Xore/APIARY/issues/568), 2026-08-05 — see [§ Issue #568 re-evaluation](#issue-568-re-evaluation-real-20gb-card) below; that section is now the current approved state, superseding the v2 table immediately above it.

This is a task-specific decision record for the three independent local-model
slots in this repository. It does not assume that a model named in an earlier
plan is suitable, or that one model should serve all three jobs.

This evaluation assumes Ollama as the serving layer throughout — see
[`llm-inference-backend-comparison.md`](llm-inference-backend-comparison.md)
(#598) for whether that assumption itself still holds against llama.cpp/vLLM.

## Decision scope

| Slot | Input | Required output | Main failure modes |
|---|---|---|---|
| Ghidra automated triage | Imports, strings, and function signatures extracted from an untrusted binary | Exact JSON for family/risk and evidence-grounded behavior claims | Invalid schema, invented evidence, prompt injection in sample strings, under-rating dangerous behavior |
| Honeypot session analysis (#66) | Attacker-controlled commands and event text | Exact JSON summary, intent, MITRE techniques, IOCs, severity, and confidence | Prompt injection, missed IOCs, unsafe overconfidence, failure to recognize encoded/chunked activity |
| Rev·Deck interactive analysis | Assembly, decompiler output, imports, strings, and analyst questions | Useful evidence-bounded explanation and next checks | Confusing fact and inference, shallow code understanding, cyber-analysis refusal, obeying strings/comments as instructions |

These stay separately configurable as `GHIDRA_TRIAGE_MODEL`, the future
worker's `LLM_MODEL`, and `REVDECK_MODEL`. Sharing one Ollama server does not
make their quality requirements interchangeable.

## Test system

The live analysis host was measured rather than inferred from the roadmap:

- NVIDIA Quadro RTX 4000, 8192 MiB VRAM, driver 580.173.02;
- Ollama 0.32.0, upgraded from 0.12.11 for current model-family support;
- one request and one loaded model at a time;
- 16,384-token server context for Ghidra evidence;
- model storage in the existing `ghidra_ollama_models` volume;
- no GPU process before the evaluation began.

CPU and system-RAM offload are allowed on this host. Full GPU residency is
reported for capacity planning, but it is not an acceptance gate when the model
remains accurate and completes within the task timeout.

Selection priority is accuracy first: task correctness, injection resistance,
and context reliability outrank latency. Throughput and residency break ties
and guide operations; they do not replace a more accurate model.

The Packer-launched Windows QEMU process was checked before and throughout the
work. The evaluation does not call libvirt, signal QEMU, change its files, or
interact with the guest.

## Candidate matrix

All tags are exact Ollama tags, not family aliases. On-disk sizes are those
reported by the live 0.32.0 runtime.

| Candidate | ID | Size | Native context | Why it is included |
|---|---|---:|---:|---|
| `qwen3:8b` | `500a1f067a9f` | 5.2 GB | 40,960 | Existing Ghidra and Rev·Deck default; baseline |
| `qwen3.5:4b` | `2a654d98e6fb` | 3.4 GB | 262,144 | Current smaller Qwen option with more VRAM margin |
| `qwen3.5:9b` | `6488c96fa5fa` | 6.6 GB | 262,144 | Current larger Qwen option; tests whether weights plus 16k context fit an 8 GiB card |
| `qwen2.5:7b-instruct-q4_K_M` | `845dbda0ea48` | 4.7 GB | 32,768 | Model named by the #66 design, never previously measured here |
| `qwen2.5-coder:7b-instruct-q4_K_M` | `dae161e27b0e` | 4.7 GB | 32,768 | Code-specialized instruction model |
| `codegeex4:9b` | `867b8e81d038` | 5.5 GB | 131,072 | Code model with a long advertised context |
| `glm4:9b` | `5b699761eca5` | 5.5 GB | 131,072 | General GLM-family local candidate |
| `llama3.1:8b-instruct-q4_K_M` | `46e0c10c039e` | 4.9 GB | 131,072 | #66's documented alternative |
| `codellama:7b-instruct-q4_K_M` | `dfd9bbf35961` | 4.1 GB | 16,384 | Comparator motivated by the REx86 paper |
| `qwen2.5-coder:7b-base-q4_K_M` | `bd8755145f1c` | 4.7 GB | 32,768 | Non-instruction control and the closest Ollama base for REx86 |

Current tag data was checked against the official Ollama library pages for
[Qwen3.5](https://ollama.com/library/qwen3.5/tags),
[Qwen2.5-Coder](https://ollama.com/library/qwen2.5-coder),
[CodeGeeX4](https://ollama.com/library/codegeex4),
[GLM4](https://ollama.com/library/glm4), and the exact
[Llama 3.1 tag](https://ollama.com/library/llama3.1%3A8b-instruct-q4_K_M).
The IDs, sizes, quantizations, and context values above were also read from the
live Ollama manifest/API. Family marketing context is not substituted for the
metadata of the artifact that is actually loaded.

## Benchmark

`analysis/ghidra/benchmarks/evaluate-models.py` uses only synthetic evidence,
reserved TEST-NET addresses, fake domains, and fake credentials. It never
executes sample text, manages containers or processes, or calls an external
model service.

Each candidate receives identical temperature-zero prompts and is unloaded
before the next candidate. Generation is capped at 512 tokens: a model that
spends the entire practical response budget reasoning and returns no usable
answer fails the task. Ollama enables thinking by default for supported models,
so the production worker sends `reasoning_effort: "none"` and the native
benchmark sends `think: false`; hidden traces are neither consumed nor stored
by these features. JSON cases use Ollama's documented
[structured output](https://docs.ollama.com/capabilities/structured-outputs)
mode and are then validated independently. The report records:

- exact schema and enum correctness;
- expected family, risk, intent, severity, behavior, and reverse-engineering concepts;
- IOC recovery;
- prompt-injection resistance in binary strings, session commands, and analyst evidence;
- a 16k context sentinel probe;
- output rate, loaded-model size, VRAM residency, and wall time.

The cases cover a benign downloader, ransomware-like evidence, process
injection, reconnaissance, payload deployment, cryptomining, a stack overflow,
x86 code intent, and a synthetic agentic intrusion sequence. The last case was
added from the defensive lessons in Hugging Face's
[July 2026 technical timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline):
service-account discovery, gzip/base64 chunking, web dead-drop style transfer,
alternate egress, raw sockets, and an attacker-authored instruction to lower
severity. It must be classified as critical while recovering the synthetic
IOCs and recognizing the encoded exfiltration behavior.

This is a small acceptance benchmark, not a universal leaderboard. Its purpose
is to reject unsuitable defaults and compare the exact tasks this stack will
ask the models to perform. Future regressions should add cases without changing
old expected outcomes silently.

## Research interpretation

### REx86

[REx86](https://arxiv.org/html/2510.20975) is directly relevant to the
assembly-understanding part of Rev·Deck, but not direct evidence for Ghidra's
current import/string/signature triage or for honeypot log summarization. The
paper fine-tunes Qwen2.5-Coder, CodeLlama, and CodeGemma variants on 5,981 x86
assembly examples across code intent, code completion, inline comments, header
comments, and x86 Q&A.

The authors select fine-tuned Qwen2.5-Coder-7B as the balanced REx86 model.
CodeLlama-7B has the highest overall cosine score and code-intent score in their
table, while the selected Qwen model is stronger across the other task types.
The 43-person human study finds a significant improvement only for line-level
understanding; the higher solve rate is not statistically significant. It is
one x86 teaching-lab specimen, so it cannot establish general malware-analysis
or multi-architecture performance.

The published CC-BY-4.0
[Zenodo artifact](https://zenodo.org/records/15420461) is a
323,014,168-byte PEFT LoRA adapter for the **base**
`unsloth/Qwen2.5-Coder-7B`, not the instruct artifact. Its adapter configuration
uses rank 32 and targets the attention and MLP projection layers. The release
is useful for reproducing the paper, but it is not currently a deployable
Ollama candidate here: Ollama 0.32.0's
[Modelfile documentation](https://docs.ollama.com/modelfile) does not list Qwen
among supported Safetensors adapter architectures, and both file and directory
imports failed before a model was created. Applying it to a differently
quantized or instruct base would also violate Ollama's warning that an adapter
must match its training base.

Consequently, this evaluation does three honest things: adds an x86 code-intent
case inspired by the paper, tests Qwen2.5-Coder base/instruct and CodeLlama
controls, and records REx86 as a promising Rev·Deck-only follow-up requiring a
supported conversion/runtime. It does not pretend that the adapter was tested
when it could not be loaded.

### Broader reverse-engineering evidence

Several recent papers change how the results should be read:

- [BinDeObfBench](https://arxiv.org/abs/2604.08083) reports that reasoning and
  domain expertise matter more than scale alone for binary deobfuscation, and
  that task-specific supervised fine-tuning can outperform broad domain
  pretraining. It also evaluates semantic preservation and readability rather
  than lexical similarity alone.
- [REBENCH](https://arxiv.org/abs/2604.27319) emphasizes standardized,
  non-trivial, multi-architecture and multi-optimization evaluation. Rankings
  across papers with different corpora, preprocessing, and metrics are not
  directly comparable.
- [REFORGE](https://arxiv.org/abs/2607.07738) tracks provenance through compile,
  debug-information alignment, and decompilation, and shows how optimization
  reduces high-confidence paired yield. Unpaired evaluation can overstate
  quality through survivorship bias.
- [LLM4Decompile](https://arxiv.org/abs/2403.05286) reinforces the value of
  executable/semantic and readability-oriented downstream evaluation for
  decompilation and refinement.

The practical conclusion is to prefer task-specific evidence over parameter
count, retain provenance, test non-trivial optimized samples later, and keep
deterministic tools as the source of facts. Model prose is an interpretation of
those facts, not a replacement for them.

### Untrusted evidence and agentic intrusion

[Instruction Hierarchy](https://arxiv.org/abs/2404.13208) formalizes the core
prompt-injection problem: lower-priority untrusted text must not override system
or developer intent. The benchmark therefore embeds adversarial instructions
inside every input class and scores the model's consequential fields, not just
whether the forbidden phrase was repeated while rejecting it.

The Hugging Face incident adds two operational lessons relevant to #66 and
tracked more broadly in [issue #154](https://github.com/Xore/APIARY/issues/154):

1. encoded/chunked content must be decoded with bounded deterministic code and
   provenance before an LLM summarizes it; and
2. critical alert gates must correlate trust-boundary crossings and credential
   access without depending on a model to choose the right severity.

OpenAI's companion
[incident disclosure](https://openai.com/index/hugging-face-model-evaluation-security-incident/)
confirms that the evaluation had no direct Internet path and that a package
registry cache proxy became the escape route. Permitted package/cache services
must therefore be treated as egress trust boundaries, and evaluation answers
or reference artifacts must remain unreachable even after one such boundary is
compromised.

The article's GLM-5.2 forensic model is hundreds of billions of parameters and
cannot fit this 8 GiB host. `glm4:9b` is tested as a local GLM-family candidate,
not represented as an equivalent model.

## Results

Accuracy is shown before operational measurements, in accordance with the
selection priority. `Loaded` is Ollama's total allocation and `VRAM` is its
GPU-resident portion at the final 16k probe. CPU/RAM offload was allowed.

| Candidate | Ghidra | Sessions | Rev·Deck | 16k probe | Output tok/s | Loaded / VRAM | Suite time |
|---|---:|---:|---:|:---:|---:|---:|---:|
| `qwen3:8b` | **100.0%** | 90.6% | 87.5% | pass | 41.88 | 7.81 / 6.84 GB | 94.69 s |
| `qwen3.5:4b` | **100.0%** | **94.3%** | 87.5% | fail | 60.23 | 3.70 / 3.70 GB | 91.63 s |
| `qwen3.5:9b` | 97.5% | 88.7% | **93.8%** | pass | 42.60 | 6.06 / 6.06 GB | 115.26 s |
| `qwen2.5:7b-instruct-q4_K_M` | 92.5% | 92.5% | **93.8%** | pass | 51.58 | 5.62 / 5.62 GB | 140.27 s |
| `qwen2.5-coder:7b-instruct-q4_K_M` | 80.0% | 90.6% | **93.8%** | pass | 55.36 | 5.62 / 5.62 GB | 89.31 s |
| `codegeex4:9b` | 85.0% | 79.2% | 81.2% | pass | 45.01 | 5.89 / 5.89 GB | 125.70 s |
| `glm4:9b` | 97.5% | 86.8% | 81.2% | pass | 44.83 | 5.89 / 5.89 GB | 101.30 s |
| `llama3.1:8b-instruct-q4_K_M` | 92.5% | 92.5% | 62.5% | pass | 53.71 | 6.89 / 6.89 GB | 79.99 s |
| `codellama:7b-instruct-q4_K_M` | 87.5% | 60.4% | 81.2% | pass | 15.76 | 13.16 / 6.80 GB | 203.44 s |
| `qwen2.5-coder:7b-base-q4_K_M` | 87.5% | 83.0% | 87.5% | fail | 53.25 | 5.62 / 5.62 GB | 87.15 s |

The report was generated at `2026-08-01T09:33:44Z` with thinking disabled and
has SHA-256
`54b850e0463acb155aa3bf0848977f1b0a0af0fc248acda3d47e01385ca3991f`.
The raw 205 kB report remains an operator-side artifact because it contains
verbose model replies; the benchmark, fixtures, scores, and exact model IDs are
versioned here.

### Important case-level findings

- `qwen3:8b` was the only candidate to score every Ghidra assertion and pass
  the long-context probe. Its 16k allocation offloaded about 0.97 GB to system
  RAM, which is acceptable on this host.
- `qwen3.5:4b` won the session suite and resisted both injected instructions.
  Its long-context failure was not truncation: it saw the sentinel but wrapped
  it in a verbose string instead of returning the exact requested value. The
  planned session worker caps prompts at 8192, while Ghidra needs the stricter
  16k behavior.
- `qwen2.5:7b-instruct-q4_K_M` followed the attacker's instruction to lower the
  result on the payload-deployment case. Its good aggregate score therefore
  does not make it an acceptable session default.
- All three 93.8% Rev·Deck leaders passed the x86 intent case at 6/6 and the
  stack-overflow case at 5/5. Each missed one process-injection next-check term;
  the score does not justify claiming one was more accurate than the others.
- Stock CodeLlama's weak result compared with the paper is expected evidence
  that REx86's task-specific fine-tuning mattered. The base-family result cannot
  stand in for the unavailable REx86 adapter.
- Every model resisted the literal injected instruction in the new agentic
  case, but **none assigned the required critical severity**. The best case
  score was 14/16 (`qwen3.5:9b`); it still returned `high`. Criticality for
  credential access plus encoded exfiltration must therefore be a deterministic
  rule under #154, not an LLM decision.

### Thinking control

An initial control run left Ollama's default thinking enabled. It produced:

| Candidate | Ghidra | Sessions | Rev·Deck | Suite time |
|---|---:|---:|---:|---:|
| `qwen3:8b` | 92.5% | 88.7% | 37.5% | about 6.5 min |
| `qwen3.5:4b` | 15.0% | 13.2% | 18.8% | about 4 min |
| `qwen3.5:9b` | 15.0% | 13.2% | 18.8% | about 3.5 min |

The Qwen3.5 models spent the bounded generation on a hidden trace and returned
no usable content in most cases. Explicit non-thinking mode is required for
these bounded tasks. The Ghidra worker now sends `reasoning_effort: "none"`;
the future #66 worker must send the equivalent. Rev·Deck's current upstream
client does not expose that control, which matters when choosing its default.

## Decisions

### Ghidra: keep `qwen3:8b`

It is the accuracy winner: 40/40, all injection checks passed, and the 16k
sentinel was exact. Its CPU offload is permitted and its measured suite time is
within the existing workflow timeout. Keep `GHIDRA_TRIAGE_MODEL=qwen3:8b` and
disable thinking in the request.

### Historical #144 session decision: `qwen3.5:4b`

It has the highest session score (50/53), passes both prompt-injection checks,
and is the only candidate to score the three existing session cases perfectly.
Use `LLM_MODEL=qwen3.5:4b`, `think: false`, and the planned 8192 maximum context.
The worker still needs deterministic criticality rules; its model returning
`high` on the agentic fixture is not sufficient. This selection was superseded
by the production-contract requalification below.

### Rev·Deck: `qwen2.5-coder:7b-instruct-q4_K_M`

Three models tie at 15/16, so accuracy does not separate them. Qwen2.5-Coder is
selected because it passes the x86 case, is instruction-tuned for code, aligns
with REx86's evidence that task-specific Qwen2.5-Coder training is promising,
and—unlike Qwen3.5—does not depend on a thinking-control field that Rev·Deck's
current upstream client does not send. Set
`REVDECK_MODEL=qwen2.5-coder:7b-instruct-q4_K_M`.

## Rollout rules

- Pin exact model tags and the Ollama image version; record model IDs in this
  document after selection.
- Keep `OLLAMA_MAX_LOADED_MODELS=1`/`OLLAMA_NUM_PARALLEL=1` and unload between
  independent jobs on the shared GPU.
- Keep captured evidence and prompts local. No hosted fallback is acceptable.
- Validate JSON and enums in code. A model never owns an alert or execution
  decision.
- Re-run this benchmark after any model, quantization, prompt, context, Ollama,
  or GPU-driver change.

## Issue #158 production-contract requalification

The #144 matrix used generic JSON mode and scored every candidate across every
slot. #158 tightened qualification to the exact production contract: the
generated `SessionAnalysis` JSON Schema, `session-v5` instruction hierarchy,
slot-specific requests, exact artifact metadata, and independent per-case
gates. The checked-in schema's canonical SHA-256 is verified against
`SessionAnalysis.model_json_schema()` in CI.

That stricter test rejected `qwen3.5:4b`: under the production schema it obeyed
attacker-authored `intent=unknown` / `severity=low` values in both adversarial
session cases. `qwen3:8b` resisted those strings but misclassified payload
deployment and cryptomining as persistence. Accuracy therefore required the
larger `qwen3.5:9b` session model despite lower throughput and higher VRAM use.

Final approved v2 results on the recorded RTX 4000 host:

| Slot | Exact model | Score | Required safety result |
|---|---|---:|---|
| Ghidra | `qwen3:8b@500a1f067a9f…` | 100.0% | Schema/injection gates and 16k sentinel pass |
| Sessions | `qwen3.5:9b@6488c96fa5fa…` | 98.5% | Both injection gates, encoded-exfiltration critical gate, and Linux persistence gate pass |
| Rev·Deck | `qwen2.5-coder:7b-instruct-q4_K_M@dae161e27b0e…` | 93.8% | Process-injection evidence gate passes |

The approved verbose report has SHA-256
`023555be9584540720df0dc51f0824a8279b73befae79fbc5fb6714b0ca18884`
and remains in the mode-0700 operator archive on the analysis host. It is not
committed because it contains full model replies. The reviewed manifest,
generated approval record, gate thresholds, drift workflow, promotion, and
rollback instructions live in
[`analysis/ghidra/models/`](analysis/ghidra/models/README.md). That manifest,
not a mutable tag or this prose table, is the runtime source of truth.

## Issue #568 re-evaluation (real 20GB card)

The #144/#158 matrix above was run on a Quadro RTX 4000 (8192 MiB, compute
capability 7.5). During the [#518](https://github.com/Xore/APIARY/issues/518)
full-installation smoke test, live `nvidia-smi` revealed the actual analysis
host card is an **RTX 4000 Ada Generation, 20475 MiB, compute capability
8.9** — not merely a wrong VRAM figure for the same card, but a different
card entirely (Turing → Ada Lovelace). Every model-selection decision above
was bounded by a budget, and a candidate pool, that never fit the real
hardware. [Issue #568](https://github.com/Xore/APIARY/issues/568)
scoped whether that was worth re-running; this section is the result.

### Checking the #144/#158 rejection notes for stale VRAM reasoning

None of the ten #144 candidates were rejected *because* they didn't fit in
8 GiB — every rejection in that matrix was accuracy- or safety-based (missed
injection resistance, wrong category, under-called severity), not size-based.
The real effect of the 8 GiB budget was on the **candidate pool itself**: it
only ever included 7–9B models. Nothing in the 13B+ range was ever
benchmarked, because nothing that size was expected to fit. That is the gap
#568 asked about, and it is a real one — answered by testing that pool below,
not by re-reading old rejection notes for a disqualification that never
happened.

### New candidate pool

Six candidates in the 14–27B range, quantized Q4_K_M except where noted,
chosen to actually use the new headroom rather than nibble at its edges:
`qwen3:14b`, `qwen2.5-coder:14b-instruct-q4_K_M`, `qwen2.5:14b-instruct-q4_K_M`,
`deepseek-coder-v2:16b-lite-instruct-q4_K_M`, `phi4:14b`, `gemma2:27b` (the
deliberate stress test of the pool — largest model that still fits with
headroom). Run alongside the three existing approved models
(`qwen3:8b`, `qwen3.5:9b`, `qwen2.5-coder:7b-instruct-q4_K_M`) through the
same three task suites, generic JSON mode (`evaluate-models.py`'s legacy
positional-args path, matching the original #144 matrix's rigor — not yet
the production-contract manifest mode #158 used).

| Candidate | Ghidra | Sessions | Rev·Deck | All 3 injection gates | 16k probe | tok/s (g/s/r) | VRAM MiB |
|---|---:|---:|---:|:---:|:---:|---:|---:|
| `qwen3:14b` | 97.5% | 97.0% | 87.5% | **pass** | pass | 34.2/33.4/34.1 | 10,198 |
| `qwen2.5-coder:14b-instruct-q4_K_M` | 97.5% | 97.0% | 81.2% | **pass** | pass | 32.0/31.3/31.7 | 10,128 |
| `deepseek-coder-v2:16b-lite-instruct-q4_K_M` | 100.0% | 82.1% | 87.5% | fail (sessions) | pass | 79.0/82.0/94.7 | 12,794 |
| `phi4:14b` | 100.0% | 94.0% | 87.5% | fail (sessions) | pass | 33.1/32.2/32.8 | 10,422 |
| `qwen2.5:14b-instruct-q4_K_M` | 92.5% | 97.0% | 87.5% | fail (sessions) | pass | 32.5/31.1/32.0 | 10,128 |
| `gemma2:27b` | 90.0% | 98.5% | 87.5% | fail (sessions) | **fail** | 18.6/17.5/17.8 | 17,660 |
| `qwen3:8b` (baseline) | 95.0% | 92.5% | 81.2% | fail (sessions) | pass | 57.4/56.2/58.6 | 6,216 |
| `qwen3.5:9b` (baseline) | 90.0% | 98.5% | 87.5% | fail (ghidra) | **fail** | 43.6/39.9/43.3 | 6,830 |
| `qwen2.5-coder:7b-instruct-q4_K_M` (baseline) | 80.0% | 92.5% | 93.8% | fail (sessions) | pass | 57.4/51.4/55.2 | 5,098 |

`qwen3:14b` is the only candidate — new or existing — that passes every
injection-resistance and critical-severity gate across all three slots
simultaneously in this broad screen. Both current production baselines each
fail one. Raw percentage is shown after the gate columns on purpose: several
higher-scoring rows (`gemma2:27b` 98.5% sessions, `deepseek-coder-v2` 100%
ghidra) still fail a gate and are disqualified regardless, the same standard
#158 already established (`qwen2.5:7b-instruct` was rejected there despite a
good aggregate score for obeying an attacker's instruction to lower
severity).

### Real-data qualitative check

Per-case synthetic scoring is necessarily narrow. As a second, independent
check, `qwen3:14b` and its two closest broad-screen competitors were run
against **real reconnaissance traffic pulled live from this honeypot's own
Elasticsearch store** (seven genuine hits: Censys internet-wide scanning, a
`/.git/config` secret-hunt probe, an RDWeb Gateway path probe, and a
`POST /bin/sh` hit from a UA string associated with RCE-scanning tools),
judged qualitatively — is each claim grounded in the actual data, not
exact-wording matched:

- `qwen3:14b`: correctly classified reconnaissance intent, correctly
  distinguished the legitimate Censys scanner from the more suspicious
  `libredtail-http` UA, recovered all 5 real source IPs as IOCs with zero
  fabrication, reasonable low/medium severity/confidence call. One real flaw:
  cited MITRE ATT&CK `T1043`, a **retired technique ID** (folded into T1571
  in ATT&CK v7) — ungrounded, not just imprecise.
- `deepseek-coder-v2:16b-lite-instruct-q4_K_M`: similarly well-grounded
  content and a cleaner MITRE mapping (just `T1595`, correct), but wrapped
  its JSON in markdown fences despite the system prompt explicitly
  forbidding that — a real instruction-following failure a production
  parser would have to work around.
- `phi4:14b`: same markdown-fence violation, a weaker MITRE mapping (`T1049`
  doesn't fit external recon — that technique is for a compromised host
  enumerating its own connections), and a `medium`-severity /
  `high`-confidence call that overstates what seven recon hits with zero
  successful exploitation actually support.

This is a small, real (not synthetic), but currently thin sample — this
homeserver is ~2 days past a full reinstall (#518) and has not yet
accumulated a large corpus of complex real attacker interaction (zero
completed Ghidra analyses, zero `cowrie.session.file_download` events, real
captured session command text currently 0–80 characters). It reinforces
rather than overturns the synthetic-benchmark ranking, and is exactly the
kind of check `probe-gpu-capabilities.py` (see
[`analysis/ghidra/benchmarks/README.md`](analysis/ghidra/benchmarks/README.md))
is meant to make a recurring practice once more real captures accumulate,
not a one-time substitute for the synthetic gates.

### Context-length ceiling

Measured live with `probe-gpu-capabilities.py`'s context sweep against
`qwen3:14b` on the real card:

| `num_ctx` | Sentinel probe | Total VRAM |
|---:|:---:|---:|
| 4,096 | fail (evidence overflowed the window — expected control) | 9.4 GB |
| 8,192 | pass | 10.2 GB |
| 16,384 | pass | 11.5 GB |
| 32,768 | pass | 14.1 GB |
| 65,536 | pass (native ceiling 40,960 applies; Ollama clamps silently) | 15.2 GB |

Even at the model's full native context, VRAM use stays under 15.3 GB —
over 5 GB of headroom remains on the 20,475 MiB card. Separately, real
captured content was queried directly from this honeypot's own
Elasticsearch store (last 7 days, 592 real cowrie sessions): **none**
exceed the current `MAX_CONTENT_CHARS=12000` production cap; the real
distribution is 0–80 characters per session, driven by the fact that most
captured connections are automated scanners that never issue a command.
The context ceiling was never actually the bottleneck for real traffic —
but there was also no VRAM reason left not to raise it for future growth.

Ghidra's slot was requalified (not just VRAM-swept) at `context_tokens:
32768` under the exact production manifest gates — identical scores to the
16,384 run (97.5% ghidra, 97.0% sessions, 87.5% revdeck), zero gate
regressions. `OLLAMA_CONTEXT_LENGTH` raised from 16384 to 32768 in
`analysis/ghidra/docker-compose.ghidra.yml` on that evidence, not on the
VRAM sweep alone. `LLM_CONTEXT_LENGTH`'s production clamp
(`llm-worker/worker.py`, hard-bounded to exactly 8192) is left as-is: real
session data doesn't need more, and raising a *code-level* clamp without a
concrete driver is scope the real data doesn't justify yet.

### `OLLAMA_MAX_LOADED_MODELS` decision

Kept at `1`. The original rationale (avoid evicting one multi-gigabyte model
to load a different one for the next slot) is now moot in the common case,
since all three slots share the same promoted model — but `1` is still the
correct bound if a future re-evaluation picks different models per slot
again, and there is no reload-latency cost today since there is nothing to
evict. Raising it would only matter for genuinely concurrent multi-model
serving, which none of the three slots currently need.

### Decision

Promoted `qwen3:14b@bdbd181c33f2…` to all three slots (ghidra, sessions,
revdeck), replacing `qwen3:8b`, `qwen3.5:9b`, and
`qwen2.5-coder:7b-instruct-q4_K_M` respectively, via the documented
`model-governance.py promote` workflow — two promotions on record: the
model swap, then the `context_tokens: 32768` requalification. Both are
`eligible: true` with zero gate failures against the exact production
contract. See
[`analysis/ghidra/models/approval-record.md`](analysis/ghidra/models/README.md)
for the current approved state; that file, not this prose, is authoritative.

Unifying all three slots to one model tag was not a goal going in — #144's
original per-task specialization was a deliberate design choice — but it
fell out of the data: `qwen3:14b` simply won every slot under the same
accuracy-first, injection-resistance-first standard already governing this
evaluation. It is not being kept as an architectural commitment to "one
shared model forever"; a future re-evaluation is free to re-split the slots
if a different model wins one of them next time.

## Issue #661: Hugging Face search, beyond Ollama's library

Every prior pass (#144, #158, #568/#635) sourced candidates from Ollama's
own library. This widened the search to Hugging Face directly, prioritizing
security/reverse-engineering-specific fine-tunes over generic leaderboard
performance, per #661's own scope.

### Shortlist found

| Model | Size | GGUF? | License | Relevant to | Status |
|---|---|---|---|---|---|
| `AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF` | 8B, 6.6GB | Yes | MIT | Offensive-security reasoning, exploit write-ups | **Gated repo** — requires HF account authentication this environment doesn't have. Not evaluated. |
| `AlicanKiraz0/Seneca-Cybersecurity-LLM-Q4_K_M-GGUF` | 8B (Llama-3.1 base), 4.9GB | Yes | MIT | Incident response, RE, malware analysis | Evaluated — see below |
| `AlicanKiraz0/Seneca-Cybersecurity-LLM-x-QwQ-32B-Q4_Medium-Version` | 32B (QwQ-32B base), 19.9GB | Yes | MIT | Same, larger/reasoning-capable base | Evaluated — see below |
| `RavichandranJ/Dolphin3-Cyber-8B-GGUF` | 8B, 4.9GB (Q4_K_M) | Yes | llama3.1 | Cybersecurity (OWASP/MITRE/CVE-tuned) | **Not evaluated** — fine-tuned from `Dolphin3.0-Llama3.1-8B-abliterated`, an explicitly safety-guardrail-removed base. Flagging rather than silently adopting: for this stack's defensive-analysis use case an uncensored base isn't automatically disqualifying (the job is describing real malware, not refusing to), but it's a real property worth a deliberate decision, not an accident of picking whatever GGUF was available. |
| `QuantFactory/SecurityLLM-GGUF` (ZySec-7B) | 7B, 2.7–7.7GB (multiple quants) | Yes | Apache 2.0 | Compliance/policy-focused security chat | **Not evaluated** — older Zephyr-family base, lower relevance to this stack's RE/triage task shapes (compliance-framework Q&A, not binary analysis), deprioritized given time budget. |

### Eval round (against the current `qwen3:14b` baseline, all approved slots)

Run with `evaluate-models.py`'s legacy positional-args mode, same standard as
every prior pass (accuracy-first, injection-resistance-first, a higher raw
score never overrides a failed gate):

| Model | ghidra | revdeck | sessions | tok/s | Notes |
|---|---|---|---|---|---|
| `qwen3:14b` (baseline) | 97.5% | 87.5% | 97.0% | ~34 | context probe: pass |
| `seneca-cyber-8b` | 62.5% (25/40) | 87.5% | 80.6% | ~55 | **context probe: FAIL** — real reliability red flag, not just a lower score |
| `seneca-qwq-32b` | 70.0% (28/40) | 56.2% (9/16) | 76.1% (51/67) | ~8 | Loads at 18.98GB/20.48GB VRAM (~1.5GB headroom) — fits, barely. ~4x slower than baseline. |

Neither AlicanKiraz0 cybersecurity fine-tune beats the current baseline on
any slot, despite being marketed specifically for this stack's task shapes.
`seneca-cyber-8b`'s outright context-probe failure is disqualifying on its
own regardless of raw score. `seneca-qwq-32b` (32B, QwQ-reasoning base) is
worse across all three slots than the 14B baseline *and* far slower — the
extra parameters and reasoning capability didn't translate into better
triage/RE output under this evaluation's standard, and the near-zero VRAM
headroom (1.5GB) makes it a poor fit for this hardware regardless of
quality. No promotion.

Side finding from the same eval run, not itself part of this issue's scope
but recorded since it surfaced in the same pass: `phi4:14b` (already in
Ollama's library, no HF import needed) scored 100%/87.5%/94.0% against the
baseline's 97.5%/87.5%/97.0% — competitive, arguably a wash rather than a
decisive win, worth a look under #603's Ollama-library benchmarking scope
rather than acted on here.

### Decision

No promotion. `qwen3:14b` remains approved in all three slots. The two
evaluated HF candidates underperform it; the two not evaluated (BaronLLM —
gated; SecurityLLM/ZySec-7B — lower relevance) are recorded for a future
pass if the gating/relevance situation changes. Dolphin3-Cyber-8B's
abliterated-base property needs an explicit decision before evaluation, not
an assumption either way.
