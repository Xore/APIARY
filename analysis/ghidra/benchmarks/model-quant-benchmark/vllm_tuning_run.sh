#!/bin/bash
set -uo pipefail
WORK=/var/dockge/stacks/rex86-eval/work
RC=$WORK/real-corpus
LOG=$WORK/vllm_tuning.log
cd "$WORK"
exec > >(tee -a "$LOG") 2>&1
echo "=== VLLM TUNING RUN $(date -u +%FT%TZ) ==="

free_gpu() {
  docker stop vllm-tune >/dev/null 2>&1 || true
  docker rm -f vllm-tune >/dev/null 2>&1 || true
  sleep 3
}
wait_gpu_free() {
  for i in $(seq 1 20); do
    used=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits)
    [[ "$used" -lt 500 ]] && return 0
    sleep 2
  done
}
start_vllm() {
  local extra_flags="$1"
  free_gpu; wait_gpu_free
  # shellcheck disable=SC2086
  docker run -d --name vllm-tune --gpus all -v "$WORK/rex86-merged":/model -p 18000:8000 \
    vllm/vllm-openai:v0.26.0@sha256:ffb2d59b1c059a5bd8d781320c9f5189de8293693b7d95da54befddaa54abf52 --model /model --dtype float16 --max-model-len 4096 \
    --gpu-memory-utilization 0.85 $extra_flags
  for i in $(seq 1 40); do curl -sf http://127.0.0.1:18000/v1/models >/dev/null 2>&1 && return 0; sleep 5; done
  echo "WARNING: vllm-tune did not come up in time"
  docker logs vllm-tune 2>&1 | tail -60
  return 1
}

echo "### Variant A: top_k=1 + repetition_penalty=1.1 (settings parity with llama.cpp/Ollama) ###"
start_vllm ""
python3 "$RC/real_corpus_eval_v2.py" vllm http://127.0.0.1:18000 /model "$RC" '{"top_k": 1, "repetition_penalty": 1.1}'

echo "### Variant B: variant A settings + --enforce-eager ###"
start_vllm "--enforce-eager"
python3 "$RC/real_corpus_eval_v2.py" vllm http://127.0.0.1:18000 /model "$RC" '{"top_k": 1, "repetition_penalty": 1.1}'

echo "### Variant C: variant A settings + --enforce-eager --enable-chunked-prefill=False ###"
start_vllm "--enforce-eager --no-enable-chunked-prefill"
python3 "$RC/real_corpus_eval_v2.py" vllm http://127.0.0.1:18000 /model "$RC" '{"top_k": 1, "repetition_penalty": 1.1}'

free_gpu
echo "=== VLLM TUNING RUN DONE $(date -u +%FT%TZ) ==="
