# #3077 — LLM-as-judge trust: applicability audit

Scope: does the finding in arXiv:2609.04198 (shared multi-tenant LLM serving
endpoints produce unstable rankings — same-window Spearman 0.400 vs a required
0.90; next-day byte-identical replay 0.78 vs a required 0.99) apply to
APIARY's own LLM-as-judge usage? Every claim below cites the file or config
value it is based on.

## 1. What "the judge" actually is in this codebase

There is no LLM judge in the injection gate. `injection_gate.py`'s
`classify_answer`/`paired_verdict`/`gate_points` (`analysis/ghidra/benchmarks/injection_gate.py:333-404`)
are pure lexical/regex classifiers — cue lists, sentence splitting, substring
matching. `docs/benchmarks/2026-08-30-injection-gate-recalibration.md:219`
proposes routing the injection twin's verdict through an LLM judge as
**"Layer 2 — adjudicated verdicts (optional, later)"**; it is not built.

The one LLM-as-judge mechanism that *is* live is `claims.py`'s adjudicator:
`extract_claims()` (`analysis/ghidra/benchmarks/claims.py:229-241`) calls a
`chat` callable — an Ollama `/api/chat` request — to decompose a model's
free-text analysis into atomic claims, which `forbidden_claim_adjudicator`
and `adjudicate_deterministic` (`claims.py:303-321`, `claims.py:345-`) then
score against ground truth via embeddings. `AdjudicationConfig`
(`claims.py:212-224`) enforces that the adjudicator model is never one of the
models being scored in the same round — this is the project's own defense
against a different failure mode (self-grading), not the paper's.

## 2. The paper's mechanism vs. APIARY's deployment

The paper's instability is a property of **shared multi-tenant serving**:
concurrent requests from different tenants land in the same continuous-batch
window, and floating-point non-associativity in batched matmul makes the
result depend on which other requests happen to be in the batch — an
adversarial or just noisy neighbor changes your score.

APIARY's judge does not run in that regime:

- Single Ollama instance, reached at `http://127.0.0.1:11434` by default in
  every caller (`claims.py:592`, `evaluate-models.py:1133`) — the scripts
  that invoke the judge run *on the GPU host itself*, not over a network to a
  shared endpoint.
- `analysis/ghidra/docker-compose.ghidra.yml:117-122` pins
  `OLLAMA_NUM_PARALLEL: '1'` ("One request at a time... a queue of parallel
  generations is how you get an out-of-memory unload mid-analysis") and
  `OLLAMA_MAX_LOADED_MODELS: '1'`. There is no concurrent batching to be
  unstable across, by construction — one request is served to completion
  before the next starts.
- No other tenant shares this Ollama instance's inference calls in the way
  the paper's shared provider does: it is a single docker-compose service on
  one physical GPU (RTX 4000 Ada, `docker-compose.ghidra.yml:113`), used only
  by this project's own workers and benchmark scripts.

**Verdict: the paper's specific mechanism — cross-tenant batching
non-associativity — does not apply.** There is no batch to share.

## 3. What does apply: a different, already-documented non-determinism source

APIARY has its own, independently discovered non-determinism problem in the
same judge's temperature-0 output, for a different reason. From
`docker-compose.ghidra.yml:98-108` (#2646):

> "a resident slot returns different text for an identical prompt at
> temperature 0 with a fixed seed; a freshly loaded one does not"

`EVIDENCE.md:160-222` (#2642) measured this directly: a **cold**-loaded
instance (`ollama stop` before the call) reproduces byte-identically; a
**resident** (kept-warm, `OLLAMA_KEEP_ALIVE: 30m`) instance drifts across
calls, and the within-window drift for a shared resident instance was still
"not run in this session. Verdict open" as of that writeup.
`analysis/ghidra/benchmarks/corpus/run_injection_pair.sh:5-8` codifies the
fix for models under test: `ollama stop <tag>` before every run, sequential,
N=1, because "cold cells reproduce byte-identically."

**The judge itself does not use this protocol.** `claims.py`'s `main()`
(`claims.py:592-623`) builds its `chat` closure with
`temperature: 0, seed: 144` but no `unload()`/`ollama stop` call brackets any
`extract_claims()` invocation — unlike `evaluate-models.py` and
`probe-gpu-capabilities.py`, which both call `unload()`
(`evaluate-models.py:966`, `probe-gpu-capabilities.py:130,154`) after each
model. The adjudicator runs against whatever state the shared `ollama`
docker-network alias (`docker-compose.ghidra.yml:90-92`) happens to be in —
resident from a prior triage/session/revdeck call, or cold. That is exactly
the condition #2646 says is not reproducible.

**Verdict: this part applies, but it is not the paper's finding — it is a
project-native reproducibility gap, present regardless of tenancy, that
happens to produce a similar symptom (same prompt, same params, different
output).**

## 4. Net conclusion

Mostly not applicable, and here is precisely the part that is:

- Cross-tenant batching instability (the paper's actual claim): does not
  apply — single-tenant, `OLLAMA_NUM_PARALLEL=1`, no shared batch window.
- Same-window / next-day reproducibility as a *property worth checking at
  all*: applies, but for a different, already-documented reason (#2642/#2646
  resident-vs-cold drift), and the live judge path (`claims.py`) does not
  currently take the mitigation (`unload()`/cold-slot) that the project's own
  benchmark scripts already use for models under test.

This is not a case for building anything to defend against shared-tenant
noise — there is none here. It is a case for extending the cold-slot
discipline `run_injection_pair.sh` already applies to models-under-test to
cover the adjudicator's own calls, or, short of that, for knowing that a
`claims.py` re-run against a resident (non-cold) adjudicator is not
guaranteed to reproduce and should not be read as a delta if it doesn't.
Section 5 (probe) is a first, minimal, un-run measurement of that specific
gap — not a fix.

## 5. Probe

See `analysis/ghidra/benchmarks/probe-judge-repeat-stability.py` and its
module docstring for the repeat-stability probe and how to run it once the
round-7 cold run (currently live, `OLLAMA_MAX_LOADED_MODELS=1`, must not be
disturbed — see the GPU-host sandbox constraints this stage operated under)
reports 96/96 `MODEL_DONE`. The probe was written and committed but
deliberately **not executed** in this session.
