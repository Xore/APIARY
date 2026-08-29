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
set -uo
source "$WORK/rex86_common.sh" pipefail
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
  name="$1"; adapter_subdir="$2"; base_repo="$3"; base_rev="$4"
  gguf="$WORK/other-models/${name}-f16.gguf"
  result="$WORK/other-models/${name}.corpus_eval.out"
  if [[ -f "$result" ]]; then
    echo "=== ${name}: already has a corpus_eval result, skipping ==="
    return 0
  fi
  echo "=== QUEUE: starting ${name} $(date -u +%FT%TZ) ==="
  if bash "$WORK/rex86_run_one.sh" "$name" "other-models/${adapter_subdir}" "$base_repo" "$base_rev"; then
    echo "=== QUEUE: ${name} SUCCEEDED $(date -u +%FT%TZ) ==="
  else
    echo "=== QUEUE: ${name} FAILED $(date -u +%FT%TZ) -- continuing with the rest of the queue ==="
  fi
}

# base_revision pinned per repo (resolved 2026-08-29) so a new HF commit
# landing mid-queue can't silently change the weights a result describes
# -- rex86_run_one.sh already accepts this as an optional [base_revision]
# argument (same discipline merge.py applied to the qwen-7B base), but no
# caller here was passing it (#2055 item 4).
run qwen-3B       "qwen-3B_adapter/qwen-3B-fine-tuned"             "unsloth/Qwen2.5-Coder-3B"     5860becf0623c7cd81f5467a88de66b668a46d6c
run codegemma-7B  "codegemma-7B_adapter/codegemma-7B-fine-tuned"   "unsloth/codegemma-7b-it"      f1f500be8b896ae964017b4a3016ea6e47ea09bd
run codellama-7B  "codellama-7B_adapter/codellama-7B-fine-tuned"   "unsloth/codellama-7b"         52ad3b73e63570b6c57ad1d8d46c6103b9ecfc76
run codellama-13B "codellama-13B_adapter/codellama-13B-fine-tuned" "codellama/CodeLlama-13b-hf"   8da65ff4ee20f74ecd107ca9d54f9f121b279860
run qwen-14B      "qwen-14B_adapter/qwen-14B-fine-tuned"           "unsloth/Qwen2.5-Coder-14B"    2918ea29941f20821b1ec4087d774ac0e5fa83e2
run codellama-34B "codellama-34B_adapter/codellama-34B-fine-tuned" "codellama/CodeLlama-34b-hf"   6008b9656730b71c7d19a15370c7ff6d2902f4ef
run qwen-32B      "qwen-32B_adapter/qwen-32B-fine-tuned"           "unsloth/Qwen2.5-Coder-32B"    8254c9d762e71c50966e6b0da5a0bcf72fa6fc23

echo "=== QUEUE DONE $(date -u +%FT%TZ) ==="
