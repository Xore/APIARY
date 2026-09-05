#!/bin/bash
# Backfill full answer text (not just scores) for every already-scored
# (model, quant) pair whose corpus_eval.out predates the "cases" field fix.
# Reuses the existing idempotent scripts unchanged -- deletes only the
# stale score-only result files first so their own "already has a result,
# skipping" checks correctly redo just those.
set -uo pipefail
WORK=/var/dockge/stacks/rex86-eval/work
source "$WORK/rex86_common.sh"
cd "$WORK"
LOG="$WORK/other-models/backfill-answers.log"
exec > >(tee -a "$LOG") 2>&1
echo "=== BACKFILL: START $(date -u +%FT%TZ) ==="

# --- Phase A: 3 small REx86-paper adapter models (no per-spec result check
# in rex86_run_one.sh -- it always overwrites, so no pre-delete needed) ---
bash rex86_run_one.sh qwen-3B       "qwen-3B_adapter/qwen-3B-fine-tuned"             "unsloth/Qwen2.5-Coder-3B"     5860becf0623c7cd81f5467a88de66b668a46d6c || echo "=== qwen-3B backfill FAILED, continuing ==="
bash rex86_run_one.sh codegemma-7B  "codegemma-7B_adapter/codegemma-7B-fine-tuned"   "unsloth/codegemma-7b-it"      f1f500be8b896ae964017b4a3016ea6e47ea09bd || echo "=== codegemma-7B backfill FAILED, continuing ==="
bash rex86_run_one.sh codellama-7B  "codellama-7B_adapter/codellama-7B-fine-tuned"   "unsloth/codellama-7b"         52ad3b73e63570b6c57ad1d8d46c6103b9ecfc76 || echo "=== codellama-7B backfill FAILED, continuing ==="

# --- Phase B: 32-34B tier + mixtral, 4 quants each. Each model's own
# stale results are deleted immediately before ITS OWN rerun, not all 24
# upfront -- a kill partway through used to invalidate every other
# model's still-good historical result along with the one in flight
# (#2055 item 1); now only the model actually being redone is at risk. ---
backfill_base_model() {
  local name="$1" hf_repo="$2"; shift 2
  local spec tag
  for spec in "$@"; do
    tag="${spec%%:*}"
    rm -f "$WORK/other-models/${name}-${tag}.corpus_eval.out"
  done
  bash rex86_run_base_model.sh "$name" "$hf_repo" "$@" || echo "=== ${name} backfill FAILED, continuing ==="
}

backfill_base_model qwen-32b-instruct "Qwen/Qwen2.5-Coder-32B-Instruct" Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99
backfill_base_model deepseek-coder-33b "deepseek-ai/deepseek-coder-33b-instruct" Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99
backfill_base_model codellama-34b-instruct "codellama/CodeLlama-34b-Instruct-hf" Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99
backfill_base_model wizardcoder-33b "WizardLMTeam/WizardCoder-33B-V1.1" Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99
backfill_base_model phind-codellama-34b "Phind/Phind-CodeLlama-34B-v2" Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99
backfill_base_model mixtral-8x7b "mistralai/Mixtral-8x7B-Instruct-v0.1" Q6_K:30 Q5_K_M:35 Q4_K_M:45 Q3_K_M:60

echo "=== BACKFILL: ALL DONE $(date -u +%FT%TZ) ==="
