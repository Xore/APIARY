# Engine benchmark: Ollama vs. llama.cpp vs. vLLM

Follow-up to #598/#601 (research-level Ollama/llama.cpp/vLLM comparison) and
#356 (deciding how to promote the REx86 adapter into a real Rev·Deck
production path). #598/#601 established the general tradeoffs; this
directory is the actual measured comparison -- same model weights, same
GPU, same sampling parameters, run three ways -- plus the script to
reproduce or re-run it.

## Why a separate REx86 GGUF, not the production revdeck model

The REx86 LoRA adapter (#160) merged into its pinned base
(`unsloth/Qwen2.5-Coder-7B` @ `5762507e8ed2132906da60f86a2b23b54673ee81`) has
no chat template -- it's a base checkpoint, evaluated with plain
`"Q: ...\nA:"` completions, not `/api/chat`. That turns out to be an
advantage for an engine comparison: it forces every engine down its
lowest-level, least-abstracted completion path (`/completion` for
llama.cpp, `/api/generate` for Ollama, `/v1/completions` for vLLM) rather
than through each engine's own chat-templating layer, which is exactly
where behavioral differences between engines would otherwise get hidden.

See `../../models/` and issue #356 for how this ties into the actual
promotion decision. This directory's result is one input to that decision,
not the decision itself.

## Two corpora, two different questions

**1. Synthetic corpus** (`corpus_eval.py`) -- the 32-case x86_64 slice of
`../corpus/manifest.json` (8 original #144 `REV_CASES` x {gcc,clang}-x86_64
x {-O0,-O2}), scored against `../corpus/rev_cases_v2_rubric.json`'s
hand-authored ground truth. Answers: *given known-correct source, do the
engines produce the same quality of output?*

**2. Real-payload corpus** (`run_real_corpus_eval.py` +
`extract_evidence.py`) -- actual honeypot captures from this deployment's
own Dionaea/Cowrie traffic, scored by **evidence grounding**, not an
external ground truth (there isn't one for real, unlabeled captures without
importing a second tool's judgment and just moving the goalposts). The
question here is narrower and more defensible: *does the model's free-text
answer correctly cite behavior implied by the real evidence it was shown*
(specific imports, specific strings), rather than "is the malware
classification correct."

Both corpora use the same three-engine harness shape and the same
deterministic sampling (`temperature=0, seed=66, repeat_penalty=1.1,
top_k=1` where the engine's API exposes those knobs -- vLLM's
`/v1/completions` doesn't expose `repeat_penalty` in the request body used
here, left at its default).

## Real payloads are never committed here

`extract_evidence.py` writes mechanically-extracted imports/strings/section
metadata to `*.evidence.json` -- never the payload itself. Real captured
malware has no redistribution rights and this repo's own corpus-design
precedent (#159) is explicit about not committing live samples. To
reproduce the real-payload side of this benchmark on your own deployment:

```
pip install pefile
python3 extract_evidence.py /path/to/your/captured.bin ./evidence/<sha256>.evidence.json
```

then write a rubric for *your* samples' actual import/behavior shape --
`example-real-rubric.json` is the one used for the run below, documented as
an example, not a universal template. A different capture will have a
different API surface and needs its own rubric derived the same way: from
evidence you can point at, not a guess.

## How the llama.cpp side is invoked -- and a real pitfall

Use `llama-server`'s native `/completion` endpoint, **not** `llama-cli`.
`llama-cli`'s interactive/conversation scaffold activates regardless of
`--no-conversation` (that flag only toggles chat *formatting* per its own
`--help` text, not interactivity) and corrupts a raw-completion prompt on a
base model -- observed it hallucinate an entirely new, unrelated Q&A pair
instead of continuing the one given, because it treats `A:` as a chat-turn
boundary. `/completion` has no such layer.

Also worth knowing: pure greedy decoding (`top_k=1`, no repeat penalty) is
a known degenerate-loop trap on base (non-chat) models -- first attempt at
this without a repeat penalty just echoed the prompt back verbatim.
`--repeat-penalty 1.1` (matching Ollama's own default) fixed it, applied
identically across all three engines so the comparison stays fair.

Start `llama-server` with `-ngl 99` (or however many layers fit) --
verify nothing else is holding VRAM first (`nvidia-smi`). A stale vLLM or
Ollama container left running from a previous step will silently starve
the next engine's model load down to partial CPU offload, which reads as a
"slow model" rather than the actual cause (GPU memory contention from a
container you forgot to stop).

## Results (2026-08-06, RTX 4000 Ada 20GB, f16 GGUF / f16 HF weights)

### Synthetic corpus (32 cases, known ground truth)

| Engine | Score | % |
|---|---|---|
| llama.cpp (`llama-server` `/completion`) | 88/156 | 56.4% |
| Ollama 0.32.0 (same GGUF) | 88/156 | 56.4% |
| vLLM 0.26.0 (HF safetensors, no GGUF) | 84/156 | 53.8% |

llama.cpp and Ollama landed on the *identical* total and near-identical
per-slice breakdown from the same GGUF file under matched sampling --
strong confirmation that engine choice isn't introducing a quality
difference on this corpus. vLLM trailed by a small, consistent margin.

Note: these absolute scores are not directly comparable to the
Q4_K_M/Q8_0-era numbers recorded on #356 from 2026-08-02 -- that used a
different, since-lost ad hoc harness (`rev_eval.py`, wiped along with the
rest of `rex86-eval` when the homeserver's GPU was swapped) with unknown
exact prompt wording and generation length. This harness is the
newly-documented, reproducible replacement; a fresh baseline run on it is
needed before comparing across time, not just across engines within one run.

### Real-payload corpus (5 samples, evidence-grounding score)

| Engine | Score | % |
|---|---|---|
| llama.cpp | 15/20 | 75% |
| Ollama | 15/20 | 75% |
| vLLM | 6/20 | 30% |

llama.cpp and Ollama produced **byte-for-byte identical output on all 5
samples**. vLLM diverged substantially and in a consistent, specific way:
where llama.cpp/Ollama correctly grounded their answer in the real dropped
filename found in the evidence (`msg/m_chinese (simplified).wnryR9` -- a
WannaCry-family indicator, see below), vLLM's answers instead consistently
claimed the sample was "related to Microsoft Security Center Service," a
detail not supported by the evidence shown and not produced by either
other engine on the same input.

This is a real, reproducible divergence -- not noise -- and it only
surfaced on the longer, more structured real-payload prompts (~250+ tokens
of evidence), not on the shorter synthetic-corpus prompts where all three
engines agreed much more closely. **Take this as a caution, not a final
verdict**: five samples is a small n, and root-causing *why* vLLM diverges
here (default sampling nuance beyond `temperature`/`seed`, prompt handling,
something specific to longer inputs) is follow-up work, not something this
run establishes. What the run does establish: engine parity that holds on
short prompts is not guaranteed to hold on longer, more realistic ones --
worth re-checking with a larger real-payload sample before leaning on vLLM
for anything where output fidelity matters more than the throughput
difference below.

### Throughput (single prompt, 200 tokens generated, 3 runs each, RTX 4000 Ada 20GB)

| Engine | Decode tok/s |
|---|---|
| llama.cpp | ~21.4 |
| Ollama | ~21.5 |
| vLLM | ~23.1 |

Effectively tied for this model size/hardware; vLLM's edge here is small
relative to its real-payload quality divergence above.

## Side finding: vLLM's earlier GPU-detection failure was hardware-specific

#601 recorded vLLM's standard image failing to even start without a
detectable GPU. That was on this homeserver's *old* 8GB Quadro RTX 4000.
On the *new* 20GB RTX 4000 Ada Generation (confirmed via `nvidia-smi`),
`vllm/vllm-openai:latest` (v0.26.0) starts cleanly, loads a 7B model
(14.29GiB weights, 1.23GiB KV cache), completes `torch.compile` warmup
(~47s), and serves correct completions on short prompts. The rejection in
#601 doesn't hold anymore on this hardware -- doesn't change #601's other
findings (no digest/registry system, `model-governance.py`'s pipeline being
Ollama-shaped), and the real-payload divergence above is a new, separate
reason for caution.

## Settings tuning (issue #832): does configuration close the vLLM gap?

Before treating the real-payload divergence above as a verdict against
vLLM, its settings were checked for parity with llama.cpp/Ollama, then
pushed further. Tested one variable at a time against the same 5-sample
real-payload corpus (baseline: vLLM 6/20, llama.cpp/Ollama 15/20 each):

| Variant | Change | Real-payload score |
|---|---|---|
| Baseline | `temperature=0, seed=66` only | 6/20 (30%) |
| A | + `top_k=1, repetition_penalty=1.1` (matching llama.cpp/Ollama exactly) | 11/20 (55%) |
| B | + `--enforce-eager` (disables CUDA-graph capture/torch.compile) | 12/20 (60%) |
| C | + `--enable-chunked-prefill=False` | 12/20 (60%) |
| Control | + `--max-num-seqs 1` (forces effectively no batching) | 12/20 (60%), same output as C |

**Settings parity (variant A) closed about half the gap on its own** — the
original comparison genuinely wasn't apples-to-apples: `repetition_penalty`
defaulted to vLLM's `1.0` (no penalty) while llama.cpp/Ollama both used
`1.1`, and `top_k` was never set for vLLM despite a
[known vLLM bug class](https://github.com/vllm-project/vllm/issues/5404)
where `temperature=0` and `top_k=1` don't reliably produce identical output.
Variants B/C added a little more, then plateaued at 12/20.

**The `--max-num-seqs 1` control test is the important result**: forcing
effectively no batching produced the *identical* score and near-identical
output to variant C. This directly rules out vLLM's continuous-batching
architecture (floating-point non-associativity across batches, a real and
[well-documented](https://thinkingmachines.ai/blog/defeating-nondeterminism-in-llm-inference/)
source of non-determinism in vLLM generally) as the cause here — if it were
batching, forcing batch-size-1 would have changed the result. It didn't.
The remaining ~3-point/15% gap (12/20 vs 15/20) is a stable, deterministic
difference between vLLM's inference implementation and llama.cpp/Ollama's,
not a batching artifact or a settings gap. `thinking-machines-lab/batch-invariant-ops`
(1.6-2.1x slower, targets exactly the batching non-determinism this control
test ruled out) was not pursued further given this evidence.

**Confirmed against the synthetic corpus too**: the tuned config (variant
C's settings) scored **102/156 (65.4%)** on the 32-case synthetic corpus —
better than the untuned vLLM baseline (84/156) *and* better than
llama.cpp/Ollama's 88/156. So tuning is a clear net positive to adopt for
vLLM regardless of the real-payload plateau; it just doesn't fully close
that specific gap.

**Recommended vLLM config, if used**: `--enforce-eager
--enable-chunked-prefill=False`, plus explicit `top_k=1,
repetition_penalty=1.1` per request to match llama.cpp/Ollama's defaults.

### Ollama and llama.cpp tuning

Checked for completeness, not because either showed a gap to close (both
already matched exactly in the original run):

- **Ollama, `OLLAMA_FLASH_ATTENTION=1`**: byte-identical output, 15/20,
  no change. Flash attention is a performance optimization here, not a
  numerics change, as expected.
- **llama.cpp, `-fa on`** (explicit flash-attn, same default as `auto`):
  byte-identical output, 15/20, no change.
- **llama.cpp, quantized KV cache (`-ctk q8_0 -ctv q8_0`)**: **real finding
  — this degrades quality**, 15/20 → 13/20, and reproduces the exact same
  "Microsoft Security Center" hallucination seen in the vLLM divergence on
  one specific sample. This shows that hallucination isn't a vLLM-specific
  bug: it's a fragile decision boundary in the model's own interpretation
  of that sample, and *any* precision-reducing path — a different engine's
  numerics, or a quantized KV cache on the same engine — can tip it the
  wrong way. Recommend keeping the default f16 KV cache for llama.cpp/Ollama
  in production; the VRAM savings aren't worth the quality risk on this
  evidence.

## Reproducing this run

```bash
# 1. llama-server (raw GGUF)
./llama.cpp/build/bin/llama-server -m rex86-merged-f16.gguf -ngl 99 --port 8080 --host 0.0.0.0
python3 corpus_eval.py llama_cpp http://127.0.0.1:8080 \
    --manifest ../corpus/manifest.json --rubric ../corpus/rev_cases_v2_rubric.json

# 2. Ollama (same GGUF, plain-completion Modelfile, no chat wrapping)
cat > Modelfile <<'EOF'
FROM rex86-merged-f16.gguf
TEMPLATE """{{ .Prompt }}"""
PARAMETER temperature 0
PARAMETER seed 66
PARAMETER top_k 1
PARAMETER repeat_penalty 1.1
EOF
ollama create rex86raw -f Modelfile
python3 corpus_eval.py ollama http://127.0.0.1:11434 --model rex86raw \
    --manifest ../corpus/manifest.json --rubric ../corpus/rev_cases_v2_rubric.json

# 3. vLLM (HF safetensors directly, no GGUF conversion)
docker run -d --gpus all -v <merged-hf-model-dir>:/model -p 8000:8000 \
    vllm/vllm-openai:latest --model /model --dtype float16 --max-model-len 4096 \
    --gpu-memory-utilization 0.85
python3 corpus_eval.py vllm http://127.0.0.1:8000 --model /model \
    --manifest ../corpus/manifest.json --rubric ../corpus/rev_cases_v2_rubric.json

# Real-payload side, once you have your own evidence/*.evidence.json:
python3 run_real_corpus_eval.py llama_cpp http://127.0.0.1:8080 \
    --evidence-dir ./evidence --rubric example-real-rubric.json
```

Stop whichever engine you just benchmarked (`docker stop`/`docker rm`,
`pkill llama-server`) and confirm `nvidia-smi` shows the GPU free before
starting the next one -- see the VRAM-contention pitfall above.
