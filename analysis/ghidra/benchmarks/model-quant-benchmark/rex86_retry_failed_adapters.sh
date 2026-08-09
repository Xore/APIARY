#!/bin/bash
# rex86_retry_failed_adapters.sh -- retries the 4 REx86-paper adapter
# models that failed on rex86_run_all.sh's first pass, now that
# rex86_run_one.sh has two real fixes applied (2026-08-08):
#   - codellama-13B, qwen-14B, codellama-34B: failed on the OOM boundary
#     bug (device_map="auto" with no max_memory, see rex86_run_one.sh's
#     own header) -- fixed.
#   - qwen-32B: failed on a DIFFERENT bug found after that fix (needs
#     offload_folder once model size exceeds the max_memory budget) --
#     also now fixed.
# Waits for both other GPU-bound pipelines running today (the base-model
# queue, rex86_run_all_base.sh, and the DeepSeek-Coder-V2-full pipeline
# on /mnt-1) to finish first -- this host has exactly one GPU.
set -uo pipefail
WORK=/var/dockge/stacks/rex86-eval/work
QUEUE_LOG="$WORK/other-models/queue-retry.log"
cd "$WORK"
exec > >(tee -a "$QUEUE_LOG") 2>&1
echo "=== RETRY QUEUE: waiting for base-model queue + deepseek-v2-full $(date -u +%FT%TZ) ==="

while pgrep -f 'bash .*rex86_run_all_base\.sh' >/dev/null 2>&1 || pgrep -f 'bash .*rex86_run_deepseek_v2_full\.sh' >/dev/null 2>&1; do
  sleep 30
done
echo "=== RETRY QUEUE: GPU free, starting $(date -u +%FT%TZ) ==="

retry() {
  name="$1"; adapter_dir="$2"; base_repo="$3"
  if [[ -f "$WORK/other-models/${name}.corpus_eval.out" ]]; then
    echo "=== ${name}: already has a corpus_eval result, skipping ==="
    return 0
  fi
  echo "=== RETRY: starting ${name} $(date -u +%FT%TZ) ==="
  if bash "$WORK/rex86_run_one.sh" "$name" "$adapter_dir" "$base_repo"; then
    echo "=== RETRY: ${name} SUCCEEDED $(date -u +%FT%TZ) ==="
  else
    echo "=== RETRY: ${name} FAILED AGAIN $(date -u +%FT%TZ) -- continuing with the rest ==="
  fi
}

retry codellama-13B "codellama-13B_adapter/codellama-13B-fine-tuned" "codellama/CodeLlama-13b-hf"
retry qwen-14B      "qwen-14B_adapter/qwen-14B-fine-tuned"           "unsloth/Qwen2.5-Coder-14B"
retry codellama-34B "codellama-34B_adapter/codellama-34B-fine-tuned" "codellama/CodeLlama-34b-hf"
retry qwen-32B      "qwen-32B_adapter/qwen-32B-fine-tuned"           "unsloth/Qwen2.5-Coder-32B"

echo "=== RETRY QUEUE DONE $(date -u +%FT%TZ) ==="
