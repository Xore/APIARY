# #2646 — warm-slot reproducibility on the production triage path

## 0. What this session could and could not do

State this first so nothing below is read as stronger than it is.

The dispatch assumed shell access to the homeserver. In this session `ssh`,
`gh`, `gate.sh` and running Python scripts were all refused by the permission
layer, so **no live run against `ghidra-revdeck-1` or the Ollama container was
performed here.** Nothing in this file is a fresh measurement.

What is here instead:

- **Section 1** — a code-level finding on the production path, read out of
  `analysis/ghidra/worker/ghidra-worker.py` and
  `analysis/ghidra/docker-compose.ghidra.yml`. This is verifiable by reading
  those two files and does not depend on a live run.
- **Section 2** — the two experiments, written as exact commands so they run
  as-is on the homeserver and produce a comparable record.
- **Section 3** — the recommendation, and which parts of it Section 1 already
  supports versus which wait on Section 2.

Section 2's results are **not filled in**. The verdict on numerical versus
content-dependent drift is therefore **open**, and the PR says so.

## 1. Reading the producer

### 1.1 The production request omits the parameters that pin the instance

`_ask_model()` in `analysis/ghidra/worker/ghidra-worker.py` is the only place
production triage talks to the model. Its request body carries `model`,
`messages`, `temperature: 0`, `max_tokens`, `seed`, `stream`,
`reasoning_effort` and `response_format`.

It does **not** carry `num_ctx`, and it does **not** carry `keep_alive`.

Every other Ollama consumer in this repo does send them:

| caller | sends |
| --- | --- |
| `benchmarks/evaluate-models.py:533` | `keep_alive`, `num_ctx`, `seed`, `temperature` |
| `benchmarks/claims.py:533` | `num_ctx`, `seed`, `temperature` |
| `benchmarks/probe-real-session-run.sh:58` | `num_ctx`, `seed`, `temperature` |
| `benchmarks/probe-gpu-capabilities.py:144` | `keep_alive` |
| `llm-worker/worker.py:237` | `keep_alive` (`LLM_KEEP_ALIVE`) |
| **`ghidra/worker/ghidra-worker.py` `_ask_model()`** | **neither** |

`probe-real-session-run.sh:23` already writes the consequence down in a
comment: *"Without an explicit num_ctx, the request falls back to whatever the
[resident instance was loaded with]."* PR #2644 fixed exactly this on
`record_baseline.py`. The production worker has the same defect and was not
covered by that fix.

### 1.2 Why that matters here specifically

`docker-compose.ghidra.yml` sets `OLLAMA_MAX_LOADED_MODELS: '1'` and its own
comment (the `#568` block) records that **all three slots — ghidra, sessions,
revdeck — share one model, `qwen3:14b`**, and that Ollama "just keeps reusing
the one already-resident model across slots". The `revdeck` service points at
the same endpoint (`API_BASE: 'http://ollama:11434/v1'`).

So the resident instance the ghidra worker's triage lands on may have been
loaded by a different consumer, at that consumer's context length. Since
`_ask_model()` names no `num_ctx`, it does not reload to its own parameters —
it answers under theirs. `GHIDRA_TRIAGE_ESTIMATED_VRAM_MIB`'s comment assumes
context 32768; a slot another consumer loaded at 8192 or 16384 serves triage
at that instead, silently.

**This is a deployment-level content-dependence, and it is real regardless of
what Section 2 finds.** It is not per-prompt coupling inside one resident
instance — it is "which request arrived first decided the parameters every
later request runs under". It is consistent with the issue's 1/14 warm figure
without explaining it, and the two mechanisms are independent: fixing this one
does not make a warm slot reproducible.

The truncation guard at `_ask_model()`'s `_prompt_was_truncated()` catches the
extreme case (a window so small the prompt was cut), so this does not silently
produce answers about a fragment. It does leave answers produced under an
unrecorded context, which is exactly what makes two stored assessments
incomparable.

### 1.3 What a stored assessment currently claims

`run_triage_workflows()` stamps `model`, `workflow` and `evidence_shown`. Two
results carrying `"model": "qwen3:14b"` read as comparable. Given the issue's
own measurement (1/14 byte-identical warm) they are not. Nothing in the stored
document distinguishes them.

## 2. The experiments, as runnable commands

Run from the homeserver. `$OLLAMA` is the Ollama container name, `$REVDECK` is
`ghidra-revdeck-1`. Save every raw response — not just a hash — per
`feedback_save_full_run_transcripts`.

### 2.1 Experiment A — production-path reproduction, warm

Two identical calls, warm slot, byte-diffed.

```sh
mkdir -p /mnt-1/benchmarks/2646 && cd /mnt-1/benchmarks/2646
SHA=<a sha256 already in the ghidra results dir>
ADDR=<a function address from that sample's result>

# Confirm the slot is warm, and record which instance it is.
docker exec "$OLLAMA" curl -sS http://127.0.0.1:11434/api/ps > ps.before.json

for i in 1 2; do
  docker exec "$REVDECK" curl -sS -X POST \
    http://127.0.0.1:8080/tools/decompile_function \
    -H 'Content-Type: application/json' \
    -d "{\"address\":\"$ADDR\"}" > "A.$i.json"
done
docker exec "$OLLAMA" curl -sS http://127.0.0.1:11434/api/ps > ps.after.json

cmp A.1.json A.2.json && echo "IDENTICAL" || diff -u A.1.json A.2.json
```

Record: identical or not, and whether `ps.before.json` and `ps.after.json`
describe the same instance (same `digest`, same `context_length`, same
`size_vram`). If they differ, the run crossed a reload and proves nothing about
warm drift — repeat it.

**Result: not run in this session.**

### 2.2 Experiment B — numerical noise versus content-dependence

The discriminating experiment. Two samples, X and Y, run X → X → Y → X.

```sh
run() {  # run <sample-sha> <function-addr> <outfile>
  docker exec "$REVDECK" curl -sS -X POST \
    http://127.0.0.1:8080/tools/decompile_function \
    -H 'Content-Type: application/json' \
    -d "{\"address\":\"$2\"}" > "$3"
}

run "$X" "$XADDR" B.x1.json    # X, warm
run "$X" "$XADDR" B.x2.json    # X again, nothing in between
run "$Y" "$YADDR" B.y1.json    # a different sample
run "$X" "$XADDR" B.x3.json    # X again, after Y
```

Read it as:

| observation | verdict |
| --- | --- |
| `x1 == x2 == x3` | no warm drift on this pair; the 1/14 figure needs re-measuring |
| `x1 != x2`, and `x1 vs x2` differs about as much as `x1 vs x3` | **numerical** — slot noise, independent of what preceded |
| `x1 != x2`, but `x1 vs x3` is materially larger than `x1 vs x2` | **content-dependent** — cross-request coupling |

"Materially larger" needs a metric, not an eyeball. Use normalised edit
distance over the response text, and repeat the whole block three times: per
`reference_llm_benchmark_noise_floor` this stack is not deterministic at
temperature 0 and a single trial cannot separate ±1 noise from a real effect.

A content-dependent result is a **separate, higher-severity issue** — cross-
request coupling in a shared slot means one sample's text influenced another
sample's assessment, which is a correctness problem for stored analyses, not a
reproducibility inconvenience. It must not be folded into #2646.

**Result: not run in this session. Verdict open.**

## 3. Recommendation

Of the three options in the issue:

1. Accept the drift, document it.
2. Periodically evict, bounding drift at the cost of reload latency.
3. Pin a cold slot for analyses where reproducibility outranks latency.

**Take option 1 now, and make it real rather than a sentence in a doc — but
only because option 2 and option 3 cannot be chosen until Section 2 has run.**

Reasoning:

- Option 2 bounds drift *between* eviction windows and does nothing *within*
  one. Every analysis in a window still shares an instance, so two samples
  triaged four minutes apart are still incomparable. It buys a weaker property
  than it appears to, at 4.1 min per eviction (#2642's measured cold run).
- Option 3 is the right answer for the case that actually motivates the issue —
  a re-analysis, or an assessment an analyst may cite. But choosing where to
  apply it requires knowing whether drift is numerical or content-dependent.
  If it is content-dependent, a pinned cold slot is not an option for
  citable work, it is **mandatory for all of it**, because a shared warm slot
  would mean one sample's evidence leaking into another's assessment.
- Option 1's weakness is that "document it" usually means a paragraph nobody
  reads at the point of comparison. That is fixable: make the *result* carry
  the caveat rather than the docs.

So: **stamp the instance identity onto every stored assessment.** A reader
comparing two results can then see that they came from different resident
instances and is not relying on having read a doc. This is a prerequisite for
option 2 and option 3 either way — both need a way to tell which instance
produced a result — so it is not work that is thrown away whichever way
Section 2 lands.

Section 1.1's missing `num_ctx` is deliberately **not** fixed in the same
change. Adding `num_ctx` to `_ask_model()` forces a reload whenever the
resident instance was loaded at a different context, which changes production
latency and eviction behaviour on a shared card. That is a real change with a
real cost and it deserves its own issue and its own measurement, not a
one-line rider on a stamping change.

### What landed

`ai_triage.slot_generation`, set on every assessment
`run_triage_workflows()` returns — the live path and gpu-queue-drain's deferred
path both, since both go through that function.

Sampled from Ollama's native `/api/ps` (the `/v1` dialect does not expose it)
immediately before the first workflow call and again after the last, because a
30-minute keep-alive does not mean the slot survives one analysis: a queue
drain or another consumer of the same card can swap the instance out between
the two calls, and a stamp taken only at the start would name an instance that
did not finish the work.

Values:

- `<digest12>/ctx<n>/vram<n>mib` — a resident instance. The context length is
  in the fingerprint precisely because of Section 1.2: it is the parameter the
  request does not pin and therefore the one most likely to differ silently.
- `cold` — nothing loaded; the call cold-loaded a fresh instance. #2642
  measured that regime as reproducible.
- `unavailable` — the runtime API could not be asked. Kept distinct from
  `cold` on purpose: not knowing which instance answered must not read as
  knowing it was a fresh one.
- `a->b` — the ends disagreed. Says both rather than picking one.

Fail-soft throughout, matching the rest of triage: an unreachable `/api/ps`
costs the field, never the analysis.
