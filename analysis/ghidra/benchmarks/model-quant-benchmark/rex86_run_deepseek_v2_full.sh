#!/bin/bash
# rex86_run_deepseek_v2_full.sh -- deepseek-ai/DeepSeek-Coder-V2-Instruct
# (the FULL 235.74B model), stored on /mnt-1 (1.7TB free) instead of the
# main rex86-eval container's /var-backed work dir (~1TB free, and shared
# with everything else this session is doing concurrently -- the CAPE
# build, the REx86 adapter queue, and the other #847 base-model
# downloads). This one model alone needs ~470GB for its raw HF snapshot
# plus another ~470GB temporarily while convert_hf_to_gguf.py writes the
# f16 GGUF (source isn't deleted until conversion finishes) -- ~940GB
# peak, more than /var's entire free space on its own.
#
# Runs in a SEPARATE, throwaway container (rex86-eval-big) rather than
# reconfiguring the long-lived rex86-eval container mid-flight (which is
# actively running other people^Wthis session's own jobs right now, and
# recreating a running container to add a mount kills whatever docker exec
# processes are using it). Reuses rex86-eval's already-built venv and
# llama.cpp binary read-only (no reason to rebuild either), writes
# everything else to /mnt-1.
#
# Only produces the sub-3-bit quantizations established as feasible on
# #847 (IQ2_XS/IQ2_XXS/IQ1_S) -- f16/Q8_0/Q6_K/Q5_K_M/Q4_K_M/Q3_K_M/Q2_K
# all exceed the 20GB VRAM + ~60GB RAM envelope for a 235B model, computed
# and posted on #847, not guessed here.
set -euo pipefail

BIG=/mnt-1/rex86-large-models
MAIN_WORK=/var/dockge/stacks/rex86-eval/work
NAME=deepseek-coder-v2-full
HF_REPO="deepseek-ai/DeepSeek-Coder-V2-Instruct"
LOG="$BIG/${NAME}.pipeline.log"
mkdir -p "$BIG"
exec > >(tee -a "$LOG") 2>&1
echo "=== ${NAME}: START $(date -u +%FT%TZ) (on /mnt-1, separate container) ==="

df -h /mnt-1

docker rm -f rex86-eval-big >/dev/null 2>&1 || true
docker run -d --name rex86-eval-big --gpus all \
  -v "$MAIN_WORK":/work:ro \
  -v "$BIG":/workbig \
  nvidia/cuda:12.4.1-devel-ubuntu22.04 \
  sleep infinity
echo "=== ${NAME}: rex86-eval-big container up $(date -u +%FT%TZ) ==="

# Bare nvidia/cuda image has no python3 at all -- found live (2026-08-07):
# /work/venv is a symlink-based venv pointing at a system python3.10 that
# only exists in the ORIGINAL rex86-eval container, not this fresh one, so
# `source /work/venv/bin/activate` alone isn't enough here. Installing the
# matching python3 (Ubuntu 22.04's default is 3.10, same as the venv was
# built against) makes the venv's own symlinks resolve correctly again.
docker exec rex86-eval-big bash -lc "apt-get update -qq && apt-get install -y -qq python3 python3-venv curl >/dev/null"
echo "=== ${NAME}: python3 installed in rex86-eval-big $(date -u +%FT%TZ) ==="

f16_path="/workbig/${NAME}-f16.gguf"
if ! docker exec rex86-eval-big test -f "$f16_path"; then
  docker exec rex86-eval-big bash -lc "
    source /work/venv/bin/activate
    python3 -c \"
from huggingface_hub import snapshot_download
snapshot_download('${HF_REPO}', local_dir='/workbig/${NAME}-hf')
\"
  "
  echo "=== ${NAME}: download done $(date -u +%FT%TZ) ==="

  docker exec rex86-eval-big bash -lc "
    source /work/venv/bin/activate
    cd /work/llama.cpp
    python3 convert_hf_to_gguf.py /workbig/${NAME}-hf --outtype f16 --outfile ${f16_path}
  "
  docker exec rex86-eval-big sha256sum "$f16_path"
  echo "=== ${NAME}: f16 GGUF ready $(date -u +%FT%TZ) ==="
  docker exec rex86-eval-big rm -rf "/workbig/${NAME}-hf"
else
  echo "=== ${NAME}: f16 GGUF already present, skipping download+convert ==="
fi

# Download/convert above is network+CPU bound and needed the GPU idle for
# none of it, so it ran immediately regardless of the other two queues.
# Quantizing and serving DOES need the GPU, and this host has exactly one
# -- wait for both the REx86 adapter queue (rex86_run_all.sh) and the
# other #847 base-model queue (rex86_run_all_base.sh) to finish before
# touching it, same serialization rex86_run_all_base.sh already applies to
# itself relative to the adapter queue.
echo "=== ${NAME}: f16 ready, waiting for the GPU to be free of the other two queues before quantizing $(date -u +%FT%TZ) ==="
while pgrep -f 'bash .*rex86_run_all\.sh' >/dev/null 2>&1 || pgrep -f 'bash .*rex86_run_all_base\.sh' >/dev/null 2>&1; do
  sleep 30
done
echo "=== ${NAME}: other queues finished, proceeding $(date -u +%FT%TZ) ==="

free_gpu() {
  docker exec rex86-eval-big bash -lc 'pkill -9 -f llama-server 2>/dev/null' >/dev/null 2>&1 || true
  sleep 3
}
wait_gpu_free() {
  for i in $(seq 1 30); do
    used=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits)
    if [[ "$used" -lt 500 ]]; then return 0; fi
    sleep 2
  done
}

run_eval() {
  local tag="$1" ngl="$2"
  local quant_path="/workbig/${NAME}-${tag}.gguf"
  local result="$BIG/${NAME}-${tag}.corpus_eval.out"
  if [[ -f "$result" ]]; then
    echo "=== ${NAME} (${tag}): already has a corpus_eval result, skipping ==="
    return 0
  fi
  if ! docker exec rex86-eval-big test -f "$quant_path"; then
    docker exec rex86-eval-big bash -lc "/work/llama.cpp/build/bin/llama-quantize ${f16_path} ${quant_path} ${tag}"
    docker exec rex86-eval-big sha256sum "$quant_path"
    echo "=== ${NAME}: ${tag} GGUF ready $(date -u +%FT%TZ) ==="
  fi
  free_gpu; wait_gpu_free
  docker exec -d rex86-eval-big bash -lc "cd /workbig && /work/llama.cpp/build/bin/llama-server -m ${quant_path} -ngl ${ngl} --port 8081 --host 0.0.0.0 > /tmp/${NAME}_${tag}_server.log 2>&1"
  local up=0
  for i in $(seq 1 120); do
    if docker exec rex86-eval-big curl -sf http://127.0.0.1:8081/health >/dev/null 2>&1; then up=1; break; fi
    sleep 3
  done
  if [[ "$up" -ne 1 ]]; then
    echo "=== ${NAME} (${tag}): llama-server did not come up at -ngl ${ngl} ==="
    docker exec rex86-eval-big tail -60 "/tmp/${NAME}_${tag}_server.log" || true
    return 1
  fi
  echo "=== ${NAME} (${tag}): llama-server up, running #159 corpus (32 cases) $(date -u +%FT%TZ) ==="
  docker exec rex86-eval-big python3 /work/corpus_eval.py llama_cpp "http://127.0.0.1:8081" \
    --manifest /work/manifest.json --rubric /work/rev_cases_v2_rubric.json | tee "$result"
  free_gpu
  echo "=== ${NAME} (${tag}): eval done $(date -u +%FT%TZ) ==="
}

run_eval IQ2_XS 15  || echo "=== ${NAME} (IQ2_XS): FAILED, continuing ==="
run_eval IQ2_XXS 20 || echo "=== ${NAME} (IQ2_XXS): FAILED, continuing ==="
run_eval IQ1_S 30   || echo "=== ${NAME} (IQ1_S): FAILED, continuing ==="

docker rm -f rex86-eval-big >/dev/null 2>&1 || true
echo "=== ${NAME}: DONE $(date -u +%FT%TZ) ==="
