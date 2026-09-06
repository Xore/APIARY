# Corpus v1 (issue #3082, round-7 plan §6)

Six slices feed round 7's training legs. This issue builds the **synthetic**
half (S3-S6) plus the decontamination scan that has to show 0 hits before any
round-7 score is quoted. S1/S2 are captured honeypot/malware data and are
**not built here** -- `slices.guard_not_built_here` refuses every code path
that would touch them from this repo. They are labelled host-side on the
homeserver with a local teacher once the GPU is free (round7-1).

## Files

| file | job |
|---|---|
| `slices.py` | the six `Slice` definitions, the S1/S2 refusal guard, the 17-program name guard, the deterministic dev split |
| `schema.py` | the one JSONL `Record` shape every slice writes (`id, slice, family, source_path, prompt, completion, meta`) |
| `generate_s3.py` | >=60 template-generated C programs across 7 behaviour families (encoding loop, memory safety, dispatch table, persistence, network, benign neighbour, embedded instruction); writes `src/*.c` + `s3_manifest.jsonl` with `prompt=None` (decompilation is host-side, via `ghidra_cache.py`) |
| `generate_s4.py` | converts Zenodo 15420461 (REx86, CC-BY-4.0) entries into the schema; stamps `meta.rex86_internal_split` so #847's "check the internal split first" has something to check |
| `generate_s5.py` | builds injection-pair prompts (new phrasings, not the corpus's own) over an already-built slice, and `label_pair()` -- classifies two candidate completions into chosen/rejected using `injection_gate.classify_answer`, `polarity.forbidden_hit`, and the structured-output pydantic contracts |
| `generate_s6.py` | pools raw text from other slices into CPT shards; re-checks the S1/S2 guard itself rather than trusting the caller |
| `label_s3_openrouter.py` | S3 teacher labelling: `z-ai/glm-5.3-flash`, `reasoning: {"effort": "high"}`, key from `~/.openrouter_key` (0600, never committed), retries, one transcript JSON per call |
| `decontaminate.py` | exact-hash + shingle-Jaccard near-duplicate scan of every sample against the 17 benchmark programs' source, rubric ground truth/phrases, and the claim pool |

Every generator's `if __name__ == "__main__"` with no arguments runs a
self-contained `demo()` -- the ponytail check: run `python3 <file>.py` and it
either prints `ok` or raises.

## Dev split

`slices.dev_split(ids, seed=20260906, frac=0.1)` hashes each program/session
id with the seed and buckets on the hash -- deterministic regardless of input
order, and stable when new ids are added later. Every slice's generator
should split before writing any per-row train/dev field; **never split by
row**, since rows from the same program/session leaking across the split
would let dev "test" pretraining it has already seen.

## Decontamination

```
python3 decontaminate.py --fixture --out /tmp/fixture-report.json   # tiny synthetic proof, see below
python3 decontaminate.py s3_manifest.jsonl s5_manifest.jsonl ... --out decontamination-report.json
```

`decontamination-fixture-report.json` (committed, in this directory) is the
proof the acceptance criteria ask for: a tiny synthetic fixture -- two clean
records and one record deliberately reworded from
`analysis/ghidra/benchmarks/corpus/src/xor_decode_loop.c` -- run through the
exact same `scan_samples`/`build_report` code path production uses. It
**fails on purpose** (`"pass": false`, one hit on the contaminated record)
to prove the detector has teeth; it is not the round's real decontamination
report. The real report -- 0 hits, all six slices, generated from the actual
corpus-v1 manifests once S3 is decompiled and labelled -- is a later,
host-side run of the same script and is what plan §6.1 requires before any
round-7 score is quoted.

Two checks run per sample: exact sha256 of normalised (lowercase,
whitespace-collapsed) text, and 8-word shingle Jaccard overlap
(`--threshold`, default 0.5) against every protected document -- the 17
programs' source, their rubric `ground_truth` prose, multi-word
`required_groups`/`forbidden` phrases, and the adjudicated claim pool's claim
text. `--transcripts` additionally loads `docs/benchmarks/runs/` (off by
default -- large); `--tierb-cache <dir>` adds a host-side decompiled-variant
cache that is never committed to this repo.

## What is not in this repo

- S1/S2 sample data, or any teacher output derived from it.
- The OpenRouter API key.
- The REx86 archive itself (`generate_s4.py` converts entries handed to it;
  fetching and unzipping the Zenodo record is an operator step).
- The full corpus-v1 manifests and their decontamination report -- those are
  generated on the homeserver once S3 decompilation and labelling run
  (round7-1's GPU-free window, plan §9).
