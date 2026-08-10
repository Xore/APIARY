#!/bin/bash
# Direct-eval backfill: for each (model, quant) pair whose quantized GGUF
# already exists on disk, launch llama-server at the SAME -ngl that
# succeeded in the original run (avoids re-download/re-convert/re-quantize
# entirely -- the f16 intermediate was already cleaned up after the
# original run, and re-downloading a 30B+ model from HF just to regenerate
# an intermediate file nothing else needs is pure waste).
set -uo pipefail
WORK=/var/dockge/stacks/rex86-eval/work
cd "$WORK"
LOG="$WORK/other-models/backfill-direct.log"
exec > >(tee -a "$LOG") 2>&1
echo "=== DIRECT BACKFILL: START $(date -u +%FT%TZ) ==="

free_gpu() {
  docker exec rex86-eval bash -lc 'pkill -9 -f llama-server 2>/dev/null' >/dev/null 2>&1 || true
  sleep 3
}
wait_gpu_free() {
  for i in $(seq 1 30); do
    used=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits)
    if [[ "$used" -lt 500 ]]; then return 0; fi
    sleep 2
  done
}

run_direct() {
  local name="$1" tag="$2" ngl="$3"
  local gguf="/work/other-models/${name}-${tag}.gguf"
  local result="$WORK/other-models/${name}-${tag}.corpus_eval.out"
  rm -f "$result"
  free_gpu; wait_gpu_free
  echo "=== ${name} (${tag}): launching at -ngl ${ngl} (proven value from the original run) ==="
  docker exec -d rex86-eval bash -lc "cd /work && ./llama.cpp/build/bin/llama-server -m ${gguf} -ngl ${ngl} --port 8080 --host 0.0.0.0 > /tmp/${name}_${tag}_server.log 2>&1"
  local up=0
  for i in $(seq 1 60); do
    if docker exec rex86-eval curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then up=1; break; fi
    sleep 3
  done
  if [[ "$up" -ne 1 ]]; then
    echo "=== ${name} (${tag}): llama-server did not come up, check /tmp/${name}_${tag}_server.log -- skipping ==="
    docker exec rex86-eval tail -30 "/tmp/${name}_${tag}_server.log" || true
    free_gpu
    return 1
  fi
  echo "=== ${name} (${tag}): llama-server up, running #159 corpus (32 cases) $(date -u +%FT%TZ) ==="
  docker exec rex86-eval python3 /work/corpus_eval.py llama_cpp "http://127.0.0.1:8080" \
    --manifest /work/manifest.json --rubric /work/rev_cases_v2_rubric.json | tee "$result"
  free_gpu
  echo "=== ${name} (${tag}): eval done $(date -u +%FT%TZ) ==="
}

run_direct qwen-32b-instruct       Q6_K   24
run_direct qwen-32b-instruct       Q5_K_M 49
run_direct qwen-32b-instruct       Q4_K_M 99
run_direct qwen-32b-instruct       Q3_K_M 99

run_direct deepseek-coder-33b      Q6_K   24
run_direct deepseek-coder-33b      Q5_K_M 49
run_direct deepseek-coder-33b      Q4_K_M 49
run_direct deepseek-coder-33b      Q3_K_M 99

run_direct codellama-34b-instruct  Q6_K   24
run_direct codellama-34b-instruct  Q5_K_M 24
run_direct codellama-34b-instruct  Q4_K_M 24
run_direct codellama-34b-instruct  Q3_K_M 99

run_direct wizardcoder-33b         Q6_K   24
run_direct wizardcoder-33b         Q5_K_M 49
run_direct wizardcoder-33b         Q4_K_M 49
run_direct wizardcoder-33b         Q3_K_M 99

run_direct phind-codellama-34b     Q6_K   24
run_direct phind-codellama-34b     Q5_K_M 24
run_direct phind-codellama-34b     Q4_K_M 24
run_direct phind-codellama-34b     Q3_K_M 99

run_direct mixtral-8x7b            Q6_K   15
run_direct mixtral-8x7b            Q5_K_M 17
run_direct mixtral-8x7b            Q4_K_M 22
run_direct mixtral-8x7b            Q3_K_M 15

echo "=== DIRECT BACKFILL: ALL DONE $(date -u +%FT%TZ) ==="
