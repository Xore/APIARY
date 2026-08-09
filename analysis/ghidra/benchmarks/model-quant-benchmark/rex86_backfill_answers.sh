#!/bin/bash
# Backfill full answer text (not just scores) for every already-scored
# (model, quant) pair whose corpus_eval.out predates the "cases" field fix.
# Reuses the existing idempotent scripts unchanged -- deletes only the
# stale score-only result files first so their own "already has a result,
# skipping" checks correctly redo just those.
set -uo pipefail
WORK=/var/dockge/stacks/rex86-eval/work
cd "$WORK"
LOG="$WORK/other-models/backfill-answers.log"
exec > >(tee -a "$LOG") 2>&1
echo "=== BACKFILL: START $(date -u +%FT%TZ) ==="

# --- Phase A: 3 small REx86-paper adapter models (no per-spec result check
# in rex86_run_one.sh -- it always overwrites, so no pre-delete needed) ---
bash rex86_run_one.sh qwen-3B       "qwen-3B_adapter/qwen-3B-fine-tuned"             "unsloth/Qwen2.5-Coder-3B"     || echo "=== qwen-3B backfill FAILED, continuing ==="
bash rex86_run_one.sh codegemma-7B  "codegemma-7B_adapter/codegemma-7B-fine-tuned"   "unsloth/codegemma-7b-it"      || echo "=== codegemma-7B backfill FAILED, continuing ==="
bash rex86_run_one.sh codellama-7B  "codellama-7B_adapter/codellama-7B-fine-tuned"   "unsloth/codellama-7b"         || echo "=== codellama-7B backfill FAILED, continuing ==="

# --- Phase B: 32-34B tier + mixtral, 4 quants each (delete stale results
# first so rex86_run_base_model.sh's own per-spec check redoes them) ---
for f in qwen-32b-instruct-Q6_K qwen-32b-instruct-Q5_K_M qwen-32b-instruct-Q4_K_M qwen-32b-instruct-Q3_K_M \
         deepseek-coder-33b-Q6_K deepseek-coder-33b-Q5_K_M deepseek-coder-33b-Q4_K_M deepseek-coder-33b-Q3_K_M \
         codellama-34b-instruct-Q6_K codellama-34b-instruct-Q5_K_M codellama-34b-instruct-Q4_K_M codellama-34b-instruct-Q3_K_M \
         wizardcoder-33b-Q6_K wizardcoder-33b-Q5_K_M wizardcoder-33b-Q4_K_M wizardcoder-33b-Q3_K_M \
         phind-codellama-34b-Q6_K phind-codellama-34b-Q5_K_M phind-codellama-34b-Q4_K_M phind-codellama-34b-Q3_K_M \
         mixtral-8x7b-Q6_K mixtral-8x7b-Q5_K_M mixtral-8x7b-Q4_K_M mixtral-8x7b-Q3_K_M; do
  rm -f "$WORK/other-models/${f}.corpus_eval.out"
done

bash rex86_run_base_model.sh qwen-32b-instruct "Qwen/Qwen2.5-Coder-32B-Instruct" Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99 || echo "=== qwen-32b-instruct backfill FAILED, continuing ==="
bash rex86_run_base_model.sh deepseek-coder-33b "deepseek-ai/deepseek-coder-33b-instruct" Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99 || echo "=== deepseek-coder-33b backfill FAILED, continuing ==="
bash rex86_run_base_model.sh codellama-34b-instruct "codellama/CodeLlama-34b-Instruct-hf" Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99 || echo "=== codellama-34b-instruct backfill FAILED, continuing ==="
bash rex86_run_base_model.sh wizardcoder-33b "WizardLMTeam/WizardCoder-33B-V1.1" Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99 || echo "=== wizardcoder-33b backfill FAILED, continuing ==="
bash rex86_run_base_model.sh phind-codellama-34b "Phind/Phind-CodeLlama-34B-v2" Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99 || echo "=== phind-codellama-34b backfill FAILED, continuing ==="
bash rex86_run_base_model.sh mixtral-8x7b "mistralai/Mixtral-8x7B-Instruct-v0.1" Q6_K:30 Q5_K_M:35 Q4_K_M:45 Q3_K_M:60 || echo "=== mixtral-8x7b backfill FAILED, continuing ==="

echo "=== BACKFILL: ALL DONE $(date -u +%FT%TZ) ==="
