# Model x quant-level benchmark (#847)

Standard, reproducible workflow for comparing candidate base/instruct LLMs
for the Rev·Deck promotion decision (#356), swept across multiple GGUF
quantization levels per model on the same GPU, same corpus, same scoring.
Companion to [`../engine-benchmark/`](../engine-benchmark/), which answers a
different question (llama.cpp vs. Ollama vs. vLLM, one model, one
precision) -- this directory fixes the engine to llama.cpp and instead
sweeps **which model, at which quantization**, using the exact same corpus
and scoring harness
([`../engine-benchmark/corpus_eval.py`](../engine-benchmark/corpus_eval.py)).

## The pipeline, per model

1. **Download** the HF snapshot, **convert** to an f16 GGUF
   (`llama.cpp/convert_hf_to_gguf.py`), delete the HF snapshot.
2. **Quantize** the f16 GGUF down to each requested level
   (`llama-quantize`), skip any level whose GGUF already exists.
3. **Evaluate** each quantized GGUF with `llama-server` + `corpus_eval.py`
   against the same 32-case x86_64 slice used everywhere else in this repo
   (`../corpus/manifest.json` + `../corpus/rev_cases_v2_rubric.json`), skip
   any level whose result file already exists.
4. f16 is deleted afterward unless it was itself a requested comparison
   point -- it's quantize input only, and a multi-hundred-GB file per model
   adds up fast (see `rex86_run_base_model.sh`'s tail comment for the real
   numbers that made this necessary).

Every step is resume-safe: re-running the same command after an
interruption (reboot, OOM, GPU swap) picks up exactly where it left off
instead of re-downloading or re-quantizing anything already on disk.

## Scripts

| Script | What it does |
|---|---|
| `rex86_prefetch_base_models.sh` | Bulk-downloads+converts a list of models to f16 GGUF ahead of time (useful to run overnight before the actual eval queue, since HF downloads are the slowest step and don't need the GPU). |
| `rex86_run_base_model.sh <name> <hf_repo> <TAG:NGL> [...]` | The core per-model driver -- the pipeline above, for one model, one or more quant levels. This is what you call to add a new model to the comparison. |
| `rex86_run_all_base.sh` | Orchestrates a whole queue of `rex86_run_base_model.sh` calls (one per candidate model) with proven `-ngl` values already worked out per model/quant -- see its own comments for how those envelope numbers were computed. Edit this file's `run ...` lines to add/remove models from a benchmark round. |
| `rex86_backfill_extra_quants.sh` | Fills in quant-level gaps on models that were only ever evaluated at one precision, so the comparison chart is apples-to-apples across every model. Also the reference example for requantizing from an already-quantized GGUF (`--allow-requantize`) when the f16 source has already been cleaned up, instead of re-downloading a multi-hundred-GB snapshot just to fill in one more quant level. |
| `gen_answers_md.py <result.json> <label>` | Formats one `corpus_eval.py` result file into a GitHub-comment-ready Markdown block (score table + collapsible full answers per case) for posting to #847. |

## Deployment layout

These scripts assume a `rex86-eval` Docker container with `llama.cpp`
built at `/work/llama.cpp`, model files under `/work/other-models/`, and
`corpus_eval.py` + `manifest.json` + `rev_cases_v2_rubric.json` copied to
`/work/` directly (flat, not the repo's nested `../corpus/` layout) --
deploy the current `../engine-benchmark/corpus_eval.py` there whenever it
changes upstream. A single NVIDIA GPU is shared across every script here;
`rex86_backfill_extra_quants.sh` waits for any other `rex86_*.sh` driver to
exit before it starts, and none of these scripts should ever be run
concurrently with each other.

## Reproducing a single model x quant point manually

```bash
# proven -ngl values live in rex86_run_all_base.sh -- start there before guessing
docker exec rex86-eval bash -lc \
  './llama.cpp/build/bin/llama-server -m /work/other-models/<name>-<TAG>.gguf -ngl <NGL> --port 8080 --host 0.0.0.0'
docker exec rex86-eval python3 /work/corpus_eval.py llama_cpp http://127.0.0.1:8080 \
  --manifest /work/manifest.json --rubric /work/rev_cases_v2_rubric.json \
  | tee <name>-<TAG>.corpus_eval.out
python3 gen_answers_md.py <name>-<TAG>.corpus_eval.out "<name> <TAG>" > out.md
gh issue comment 847 --repo Xore/APIARY --body-file out.md
```

## Adding a new model

```bash
bash rex86_run_base_model.sh <name> <hf_org/hf_repo> Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99
```

Start every quant's `-ngl` at `99` (full GPU offload) unless the model is
large enough that it's known not to fit 20GB VRAM at that precision (see
`rex86_run_all_base.sh`'s comments for the envelope math) --
`rex86_run_base_model.sh`'s own `run_eval()` retries at half, then a
quarter, of the requested `-ngl` on a load failure, so an over-optimistic
guess degrades gracefully rather than burning the full health-check
timeout for nothing.
