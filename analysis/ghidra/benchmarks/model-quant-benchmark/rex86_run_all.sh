#!/bin/bash
# rex86_run_all.sh -- drives rex86_run_one.sh across all 6 not-yet-evaluated
# REx86-paper models (#847), one at a time (single GPU). Smallest first so
# real results accumulate quickly rather than blocking everything on the
# largest download/merge first.
#
# Base-model repos below were read from each adapter's own adapter_config.json
# (not assumed) -- see the pipeline log for the exact verification. Three of
# these adapters were trained against an unsloth "-bnb-4bit" pre-quantized
# base (codellama-34B, qwen-14B, qwen-32B); this queue merges them onto the
# corresponding FULL-PRECISION base instead (standard QLoRA merge-for-
# deployment practice -- llama.cpp's GGUF converter can't consume a bnb-4bit
# tensor layout directly). codellama-34B's full-precision base is Meta's own
# official codellama/CodeLlama-34b-hf, not an unsloth repo -- unsloth's own
# unquantized 34B repos 401'd (gated/private), confirmed by checking, not
# assumed to be equivalent without noting it here.
set -uo pipefail
WORK=/var/dockge/stacks/rex86-eval/work
QUEUE_LOG="$WORK/other-models/queue.log"
cd "$WORK"
exec > >(tee -a "$QUEUE_LOG") 2>&1
echo "=== QUEUE START $(date -u +%FT%TZ) ==="

# Fail fast, not silently: found live 2026-08-07 that
# `pip install -r requirements-convert_hf_to_gguf.txt` (run once, during the
# earlier qwen-7B GGUF conversion) pulled in a CPU-only torch wheel from
# PyPI's default index over the venv's pinned cu124 build with no warning --
# every merge in this queue would otherwise fail one at a time with the same
# "Torch not compiled with CUDA enabled" error instead of stopping here with
# one clear message.
cuda_ok=$(docker exec rex86-eval bash -lc 'source /work/venv/bin/activate && python3 -c "import torch; print(torch.cuda.is_available())"' 2>&1)
if [[ "$cuda_ok" != "True" ]]; then
  echo "=== QUEUE: FATAL: torch.cuda.is_available() is not True in rex86-eval's venv ($cuda_ok) -- reinstall the pinned cu124 torch build before running this queue, don't let it silently CPU-fallback for a 7B+ merge. ==="
  exit 1
fi

run() {
  name="$1"; adapter_subdir="$2"; base_repo="$3"
  gguf="$WORK/other-models/${name}-f16.gguf"
  result="$WORK/other-models/${name}.corpus_eval.out"
  if [[ -f "$result" ]]; then
    echo "=== ${name}: already has a corpus_eval result, skipping ==="
    return 0
  fi
  echo "=== QUEUE: starting ${name} $(date -u +%FT%TZ) ==="
  if bash "$WORK/rex86_run_one.sh" "$name" "other-models/${adapter_subdir}" "$base_repo"; then
    echo "=== QUEUE: ${name} SUCCEEDED $(date -u +%FT%TZ) ==="
  else
    echo "=== QUEUE: ${name} FAILED $(date -u +%FT%TZ) -- continuing with the rest of the queue ==="
  fi
}

run qwen-3B       "qwen-3B_adapter/qwen-3B-fine-tuned"             "unsloth/Qwen2.5-Coder-3B"
run codegemma-7B  "codegemma-7B_adapter/codegemma-7B-fine-tuned"   "unsloth/codegemma-7b-it"
run codellama-7B  "codellama-7B_adapter/codellama-7B-fine-tuned"   "unsloth/codellama-7b"
run codellama-13B "codellama-13B_adapter/codellama-13B-fine-tuned" "codellama/CodeLlama-13b-hf"
run qwen-14B      "qwen-14B_adapter/qwen-14B-fine-tuned"           "unsloth/Qwen2.5-Coder-14B"
run codellama-34B "codellama-34B_adapter/codellama-34B-fine-tuned" "codellama/CodeLlama-34b-hf"
run qwen-32B      "qwen-32B_adapter/qwen-32B-fine-tuned"           "unsloth/Qwen2.5-Coder-32B"

echo "=== QUEUE DONE $(date -u +%FT%TZ) ==="
