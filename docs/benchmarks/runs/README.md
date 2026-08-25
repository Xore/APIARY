# Benchmark run transcripts

Committed transcripts from synthetic-corpus benchmark runs, written under
[issue #1805](https://github.com/Xore/APIARY/issues/1805) by
`analysis/ghidra/benchmarks/evaluate-models.py` and
`analysis/ghidra/benchmarks/corpus/record_baseline.py`.

One directory per run, named `<date>-<run_id>`:

- `transcripts.jsonl` — one record per `(run_id, slot, case, model, workflow)`
  exchange: the exact prompt as sent, the raw unparsed response, model tag and
  digest, sampling parameters, timing, and the reproducibility keys.
- `run.json` — run metadata, record count, and the transcript file's SHA-256.

## Why these are in the repo

A score is a lossy summary of an answer. Rescoring an earlier round against a
later, enlarged claim pool requires that round's original answers, and
unique-contribution ("did this model find something no other model did") is
defined against the set of models that ran, so it changes for everyone when a
model is added later. Neither is recoverable from a number, and a re-run answers
a different question because tags, quants, sampling and prompts drift.

Comparability across rounds is worth more than the small repo cost, and there is
no secret in them: these runs use only #159's provenance-controlled corpus and
the benchmark's own fixtures — TEST-NET addresses, reserved `.test`/`.invalid`
names, and fake credentials, reviewed before commit.

## What must never land here

Transcripts from runs against **real captured honeypot data**. Those contain
real attacker IPs and payloads; they belong in an operator-only path with
bounded retention, and the issue carries only the run id, hashes, a pointer and
aggregate results. `evaluate-models.py --provenance captured` refuses to write
into the repository, and `analysis/ghidra/benchmarks/tests/test_transcripts.py`
gates that on every change.

## Rules

- **Never edit a stored transcript.** A misconfigured run is superseded by a new
  run that names the old `run_id` in `supersedes`; later scores depend on the
  original text.
- **Store the failures too.** Timeouts, refusals, malformed JSON and
  decompilation failures are measurements. For a derestricted-model round, a
  refusal *is* the measurement.
- **JSONL, one record per line**, so a run appends as it goes and a diff between
  two runs stays readable.
- Issue bodies cap around 65 k characters. A full round across models, slots,
  cases and tiers does not fit and must not be attempted — the issue holds the
  summary and the pointers, these files hold the evidence.
