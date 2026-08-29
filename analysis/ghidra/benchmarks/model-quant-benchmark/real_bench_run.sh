#!/bin/bash
set -uo
source "$WORK/rex86_common.sh" pipefail
WORK=/var/dockge/stacks/rex86-eval/work
RC=$WORK/real-corpus
LOG=$WORK/real_bench.log
cd "$WORK"
exec > >(tee -a "$LOG") 2>&1
echo "=== REAL CORPUS BENCH $(date -u +%FT%TZ) ==="

free_gpu() {
  docker exec rex86-eval bash -lc 'pkill -9 -f llama-server 2>/dev/null' >/dev/null 2>&1 || true
  docker stop vllm-realbench >/dev/null 2>&1 || true
  docker rm -f vllm-realbench >/dev/null 2>&1 || true
  docker stop rex86-ollama-realbench >/dev/null 2>&1 || true
  docker rm -f rex86-ollama-realbench >/dev/null 2>&1 || true
  sleep 3
}
wait_gpu_free() {
  for i in $(seq 1 20); do
    used=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits)
    [[ "$used" -lt 500 ]] && return 0
    sleep 2
  done
}

echo "### 1) llama.cpp ###"
free_gpu; wait_gpu_free
docker exec -d rex86-eval bash -lc "cd /work && ./llama.cpp/build/bin/llama-server -m /work/rex86-merged-f16.gguf -ngl 99 --port 8080 --host 0.0.0.0 > /tmp/llama_realbench.log 2>&1"
for i in $(seq 1 30); do docker exec rex86-eval curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1 && break; sleep 2; done
docker exec rex86-eval python3 /work/real-corpus/real_corpus_eval.py llama_cpp http://127.0.0.1:8080 "" /work/real-corpus
free_gpu

echo "### 2) Ollama ###"
wait_gpu_free
docker run -d --name rex86-ollama-realbench --gpus all -v "$WORK":/work -v "$WORK/ollama-data":/root/.ollama -p 18100:11434 ollama/ollama:0.32.0
sleep 6
docker exec rex86-ollama-realbench ollama list | grep -q rex86raw || {
  docker cp Modelfile rex86-ollama-realbench:/tmp/Modelfile
  docker exec rex86-ollama-realbench ollama create rex86raw -f /tmp/Modelfile
}
python3 "$RC/real_corpus_eval.py" ollama http://127.0.0.1:18100 rex86raw "$RC"
free_gpu

echo "### 3) vLLM ###"
wait_gpu_free
docker run -d --name vllm-realbench --gpus all -v "$WORK/rex86-merged":/model -p 18000:8000 \
  vllm/vllm-openai:v0.26.0@sha256:ffb2d59b1c059a5bd8d781320c9f5189de8293693b7d95da54befddaa54abf52 --model /model --dtype float16 --max-model-len 4096 --gpu-memory-utilization 0.85
for i in $(seq 1 40); do curl -sf http://127.0.0.1:18000/v1/models >/dev/null 2>&1 && break; sleep 5; done
python3 "$RC/real_corpus_eval.py" vllm http://127.0.0.1:18000 /model "$RC"
free_gpu

echo "=== REAL CORPUS BENCH DONE $(date -u +%FT%TZ) ==="
