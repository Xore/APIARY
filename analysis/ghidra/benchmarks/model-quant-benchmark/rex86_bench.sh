#!/bin/bash
set -uo pipefail
WORK=/var/dockge/stacks/rex86-eval/work
LOG=$WORK/bench.log
cd "$WORK"
exec > >(tee -a "$LOG") 2>&1
echo "=== BENCH $(date -u +%FT%TZ) ==="

PROMPT_FILE=$WORK/bench_prompt.txt
cat > "$PROMPT_FILE" <<'PEOF'
Q: Explain in detail what this x86_64 assembly function does, step by step, including register usage and control flow.

mov    eax, edi
cmp    eax, 2
ja     .default
lea    rdx, [rip+jump_table]
movsxd rax, dword ptr [rdx + rax*4]
add    rax, rdx
jmp    rax
case0: mov eax, 0x10
       ret
case1: mov eax, 0x20
       ret
case2: mov eax, 0x30
       ret
.default: mov eax, 0xFF
       ret

A:
PEOF

N_PREDICT=200
RUNS=3

free_gpu() {
  docker exec rex86-eval bash -lc 'pkill -9 -f llama-server 2>/dev/null' >/dev/null 2>&1 || true
  docker stop vllm-bench >/dev/null 2>&1 || true
  docker rm -f vllm-bench >/dev/null 2>&1 || true
  docker stop rex86-ollama-bench >/dev/null 2>&1 || true
  docker rm -f rex86-ollama-bench >/dev/null 2>&1 || true
  sleep 3
}

wait_gpu_free() {
  for i in $(seq 1 20); do
    used=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits)
    if [[ "$used" -lt 500 ]]; then return 0; fi
    sleep 2
  done
}

echo "############ 1) llama.cpp (llama-server, raw GGUF, native /completion) ############"
free_gpu; wait_gpu_free
docker exec -d rex86-eval bash -lc "cd /work && ./llama.cpp/build/bin/llama-server -m /work/rex86-merged-f16.gguf -ngl 99 --port 8080 --host 0.0.0.0 > /tmp/llama_bench_server.log 2>&1"
for i in $(seq 1 30); do docker exec rex86-eval curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1 && break; sleep 2; done
docker exec rex86-eval curl -sf http://127.0.0.1:8080/health && echo " -- llama-server up"

for r in $(seq 1 $RUNS); do
  echo "--- llama.cpp run $r ---"
  docker exec rex86-eval python3 -c "
import json, urllib.request, time
prompt = open('/work/bench_prompt.txt').read()
body = json.dumps({'prompt': prompt, 'n_predict': $N_PREDICT, 'temperature': 0, 'seed': 66, 'repeat_penalty': 1.1, 'top_k': 1}).encode()
req = urllib.request.Request('http://127.0.0.1:8080/completion', data=body, headers={'Content-Type':'application/json'})
t0=time.time()
with urllib.request.urlopen(req) as resp:
    d = json.load(resp)
t1=time.time()
timings = d.get('timings', {})
print('wall_s=%.3f prompt_tokens=%s prompt_ms=%s prompt_tps=%s predicted_tokens=%s predicted_ms=%s predicted_tps=%s' % (
    t1-t0, timings.get('prompt_n'), timings.get('prompt_ms'), timings.get('prompt_per_second'),
    timings.get('predicted_n'), timings.get('predicted_ms'), timings.get('predicted_per_second')))
"
done

echo "--- llama.cpp: full 32-case corpus ---"
docker exec rex86-eval python3 /work/corpus_eval.py llama_cpp "http://127.0.0.1:8080" \
  --manifest /work/manifest.json --rubric /work/rev_cases_v2_rubric.json
free_gpu

echo "############ 2) Ollama (same GGUF, same sampling) ############"
mkdir -p "$WORK/ollama-data"
wait_gpu_free
docker run -d --name rex86-ollama-bench --gpus all -v "$WORK":/work -v "$WORK/ollama-data":/root/.ollama -p 18100:11434 ollama/ollama:0.32.0
sleep 6
cat > Modelfile <<'MFEOF'
FROM /work/rex86-merged-f16.gguf
TEMPLATE """{{ .Prompt }}"""
PARAMETER temperature 0
PARAMETER seed 66
PARAMETER top_k 1
PARAMETER repeat_penalty 1.1
MFEOF
docker cp Modelfile rex86-ollama-bench:/tmp/Modelfile
docker exec rex86-ollama-bench ollama create rex86raw -f /tmp/Modelfile
echo "-- ollama model created, warming up (first load) --"
python3 -c "
import json, urllib.request, time
prompt = open('$PROMPT_FILE').read()
body = json.dumps({'model':'rex86raw','prompt':prompt,'stream':False,'options':{'temperature':0,'seed':66,'top_k':1,'repeat_penalty':1.1,'num_predict':10}}).encode()
req = urllib.request.Request('http://127.0.0.1:18100/api/generate', data=body, headers={'Content-Type':'application/json'})
urllib.request.urlopen(req)
print('warmup done')
"
for r in $(seq 1 $RUNS); do
  echo "--- Ollama run $r ---"
  python3 -c "
import json, urllib.request, time
prompt = open('$PROMPT_FILE').read()
body = json.dumps({'model':'rex86raw','prompt':prompt,'stream':False,'options':{'temperature':0,'seed':66,'top_k':1,'repeat_penalty':1.1,'num_predict':$N_PREDICT}}).encode()
req = urllib.request.Request('http://127.0.0.1:18100/api/generate', data=body, headers={'Content-Type':'application/json'})
t0=time.time()
with urllib.request.urlopen(req) as resp:
    d = json.load(resp)
t1=time.time()
pc = d.get('prompt_eval_count'); pd = d.get('prompt_eval_duration',0)/1e9
ec = d.get('eval_count'); ed = d.get('eval_duration',0)/1e9
print('wall_s=%.3f prompt_tokens=%s prompt_s=%.3f prompt_tps=%.1f eval_tokens=%s eval_s=%.3f eval_tps=%.1f' % (
    t1-t0, pc, pd, (pc/pd if pd else 0), ec, ed, (ec/ed if ed else 0)))
"
done

echo "--- Ollama: full 32-case corpus ---"
python3 "$WORK/corpus_eval.py" ollama "http://127.0.0.1:18100" --model rex86raw \
  --manifest "$WORK/manifest.json" --rubric "$WORK/rev_cases_v2_rubric.json"
free_gpu

echo "############ 3) vLLM (same weights, HF safetensors, OpenAI-compatible) ############"
wait_gpu_free
docker run -d --name vllm-bench --gpus all -v "$WORK/rex86-merged":/model -p 18000:8000 \
  vllm/vllm-openai:latest --model /model --dtype float16 --max-model-len 4096 --gpu-memory-utilization 0.85
for i in $(seq 1 40); do curl -sf http://127.0.0.1:18000/v1/models >/dev/null 2>&1 && break; sleep 5; done
curl -sf http://127.0.0.1:18000/v1/models >/dev/null && echo " -- vllm up"
echo "-- warmup --"
python3 -c "
import json, urllib.request
prompt = open('$PROMPT_FILE').read()
body = json.dumps({'model':'/model','prompt':prompt,'max_tokens':10,'temperature':0,'seed':66}).encode()
req = urllib.request.Request('http://127.0.0.1:18000/v1/completions', data=body, headers={'Content-Type':'application/json'})
urllib.request.urlopen(req)
print('warmup done')
"
for r in $(seq 1 $RUNS); do
  echo "--- vLLM run $r ---"
  python3 -c "
import json, urllib.request, time
prompt = open('$PROMPT_FILE').read()
body = json.dumps({'model':'/model','prompt':prompt,'max_tokens':$N_PREDICT,'temperature':0,'seed':66}).encode()
req = urllib.request.Request('http://127.0.0.1:18000/v1/completions', data=body, headers={'Content-Type':'application/json'})
t0=time.time()
with urllib.request.urlopen(req) as resp:
    d = json.load(resp)
t1=time.time()
u = d['usage']
wall = t1-t0
print('wall_s=%.3f prompt_tokens=%s completion_tokens=%s overall_tps=%.1f' % (wall, u['prompt_tokens'], u['completion_tokens'], u['completion_tokens']/wall))
"
done

echo "--- vLLM: full 32-case corpus ---"
python3 "$WORK/corpus_eval.py" vllm "http://127.0.0.1:18000" --model /model \
  --manifest "$WORK/manifest.json" --rubric "$WORK/rev_cases_v2_rubric.json"
free_gpu

echo "=== BENCH DONE $(date -u +%FT%TZ) ==="
