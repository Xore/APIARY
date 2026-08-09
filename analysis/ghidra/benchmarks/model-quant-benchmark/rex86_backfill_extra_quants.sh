#!/bin/bash
# rex86_backfill_extra_quants.sh -- fills in the quant-level gaps left by
# earlier ad hoc runs, so every model in the #847 comparison has the same
# Q6_K/Q5_K_M/Q4_K_M/Q3_K_M set and the results chart is a real 1:1
# comparison instead of some models only having one data point.
#
# codegemma-7B, codellama-7B, and qwen-3B were only ever evaluated at f16
# (their -f16.gguf is already on disk from an earlier session; not part of
# rex86_prefetch_base_models.sh's own list, so the hf_repo values below are
# best-effort/unverified -- they're only used if the f16 GGUF is ever
# deleted and needs re-fetching, which rex86_run_base_model.sh skips
# entirely while it's present).
#
# qwen-72b-instruct is the one exception that does NOT go through
# rex86_run_base_model.sh: its f16 GGUF was already deleted by that
# script's own post-run cleanup (f16 is discarded once it's served as
# quantize input and wasn't itself a requested comparison point -- see
# rex86_run_base_model.sh's tail comment). Re-fetching a 145GB HF snapshot
# just to fill in two more quant levels is wasteful when the already-quantized
# Q6_K.gguf on disk can be requantized further down instead
# (--allow-requantize) -- the standard llama.cpp practice for exactly this
# situation. ngl values are the proven ones from rex86_run_all_base.sh's
# own matrix (Q6_K:24 Q5_K_M:25 Q4_K_M:30), not guessed.
#
# Waits for any other rex86_*.sh driver to finish first -- single GPU,
# never run two of these concurrently.
set -uo pipefail
WORK=/var/dockge/stacks/rex86-eval/work
cd "$WORK"
LOG="$WORK/other-models/backfill-extra-quants.log"
exec > >(tee -a "$LOG") 2>&1
echo "=== EXTRA QUANTS BACKFILL: starting $(date -u +%FT%TZ) ==="

echo "waiting for any other rex86_*.sh driver to finish..."
while pgrep -f 'rex86_(run_all|run_one|run_base_model|backfill|prefetch)' | grep -vx "$$" | grep -q .; do
  sleep 30
done
echo "GPU clear of other rex86 drivers, starting $(date -u +%FT%TZ)"

# Swap in the updated corpus_eval.py (--manifest/--rubric flags, adds the
# per-case "cases" output) only now that nothing still running depends on
# the older positional-args interface it replaces.
if [[ -f "$WORK/corpus_eval_new.py" ]]; then
  mv "$WORK/corpus_eval_new.py" "$WORK/corpus_eval.py"
  echo "=== corpus_eval.py updated to --manifest/--rubric interface ==="
fi

bash "$WORK/rex86_run_base_model.sh" codegemma-7B "google/codegemma-7b" \
  Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99

bash "$WORK/rex86_run_base_model.sh" codellama-7B "codellama/CodeLlama-7b-hf" \
  Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99

bash "$WORK/rex86_run_base_model.sh" qwen-3B "Qwen/Qwen2.5-Coder-3B" \
  Q6_K:99 Q5_K_M:99 Q4_K_M:99 Q3_K_M:99

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
  if [[ -s "$result" ]]; then
    echo "=== ${name} (${tag}): result already exists, skipping ==="
    return 0
  fi
  free_gpu; wait_gpu_free
  echo "=== ${name} (${tag}): launching at -ngl ${ngl} ==="
  docker exec -d rex86-eval bash -lc "cd /work && ./llama.cpp/build/bin/llama-server -m ${gguf} -ngl ${ngl} --port 8080 --host 0.0.0.0 > /tmp/${name}_${tag}_extra_server.log 2>&1"
  local up=0
  for i in $(seq 1 60); do
    if docker exec rex86-eval curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then up=1; break; fi
    sleep 3
  done
  if [[ "$up" -ne 1 ]]; then
    echo "=== ${name} (${tag}): llama-server did not come up -- skipping ==="
    docker exec rex86-eval tail -30 "/tmp/${name}_${tag}_extra_server.log" || true
    free_gpu
    return 1
  fi
  echo "=== ${name} (${tag}): llama-server up, running #159 corpus (32 cases) $(date -u +%FT%TZ) ==="
  docker exec rex86-eval python3 /work/corpus_eval.py llama_cpp "http://127.0.0.1:8080" \
    --manifest /work/manifest.json --rubric /work/rev_cases_v2_rubric.json | tee "$result"
  free_gpu
  echo "=== ${name} (${tag}): eval done $(date -u +%FT%TZ) ==="
}
quantize_from() {
  local src="$1" dst="$2" type="$3"
  if [[ -f "$WORK/other-models/${dst}" ]]; then
    echo "=== ${dst}: already exists, skipping quantize ==="
    return 0
  fi
  echo "=== requantizing ${src} -> ${dst} (${type}) ==="
  docker exec rex86-eval /work/llama.cpp/build/bin/llama-quantize --allow-requantize \
    "/work/other-models/${src}" "/work/other-models/${dst}" "${type}" 16
}

run_direct qwen-72b-instruct Q6_K 24
quantize_from qwen-72b-instruct-Q6_K.gguf qwen-72b-instruct-Q5_K_M.gguf Q5_K_M
run_direct qwen-72b-instruct Q5_K_M 25
quantize_from qwen-72b-instruct-Q6_K.gguf qwen-72b-instruct-Q4_K_M.gguf Q4_K_M
run_direct qwen-72b-instruct Q4_K_M 30
# Q3_K_M for qwen-72b-instruct already exists and was already evaluated.

echo "=== EXTRA QUANTS BACKFILL: ALL DONE $(date -u +%FT%TZ) ==="
