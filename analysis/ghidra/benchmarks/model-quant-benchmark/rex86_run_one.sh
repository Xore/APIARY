#!/bin/bash
# rex86_run_one.sh <name> <adapter_dir> <base_repo> [base_revision]
#
# Runs the SAME merge -> GGUF -> corpus_eval pipeline already proven on the
# qwen-7B REx86 model (see /var/dockge/stacks/rex86-eval/work/{merge.py,
# rebuild.sh,continue2.sh,rex86_bench.sh,corpus_eval.py} — this reuses those
# exact tools/versions, not a reimplementation) against the other REx86-paper
# models for issue #847.
#
# base_repo must be the FULL-PRECISION base (never a "-bnb-4bit" repo): for
# adapters whose adapter_config.json names a bnb-4bit base (codellama-34B,
# qwen-14B, qwen-32B — confirmed by reading each adapter_config.json, not
# assumed), the corresponding full-precision unsloth repo is used instead,
# following the standard QLoRA merge-for-deployment practice (train under
# 4-bit, merge onto full precision) — the bnb-4bit tensor layout itself
# isn't something llama.cpp's convert_hf_to_gguf.py can consume directly.
set -euo pipefail

name="${1:?usage: rex86_run_one.sh <name> <adapter_dir> <base_repo> [base_revision]}"
adapter_dir="${2:?adapter_dir required}"
base_repo="${3:?base_repo required}"
base_rev="${4:-main}"

WORK=/var/dockge/stacks/rex86-eval/work
LOG="$WORK/other-models/${name}.pipeline.log"
mkdir -p "$WORK/other-models"
cd "$WORK"
exec > >(tee -a "$LOG") 2>&1
echo "=== ${name}: START $(date -u +%FT%TZ) base=${base_repo}@${base_rev} adapter=${adapter_dir} ==="

merged_dir="$WORK/other-models/${name}-merged"
gguf_path="$WORK/other-models/${name}-f16.gguf"

# --- 1. Merge adapter into pinned base (same merge.py shape, parameterized) -
if [[ ! -f "$gguf_path" ]]; then
  cat > "$WORK/other-models/${name}-merge.py" <<PYEOF
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

BASE = "${base_repo}"
REV = "${base_rev}"
ADAPTER_DIR = "/work/${adapter_dir}"

print("loading base...")
# device_map="auto" (accelerate), not a hardcoded "cuda:0": found live
# (2026-08-07) that fp16-on-GPU-only OOMs outright once the base exceeds
# ~11B params on this 20GB card (codellama-13B: 13B*2 bytes = 26GB, doesn't
# fit at all) -- "auto" lets accelerate offload whatever doesn't fit onto
# system RAM instead of just failing, which is the actual point of having
# ~60GB of RAM available for this.
#
# max_memory is required, not optional: found live (2026-08-07, qwen-14B)
# that device_map="auto" WITHOUT it queries torch.cuda.mem_get_info() for
# currently-free VRAM and budgets against that with no safety margin --
# accelerate's own infer_auto_device_map greedily fills the GPU right up
# to that reported-free figure, and the load path's own transient buffers
# (dtype casting, etc.) then overflow it by a few hundred MiB, OOMing at
# the very last shard instead of leaving any headroom. Capping well under
# the card's real 20GB and leaving system RAM for everything else this
# host is doing concurrently (the base-model queue + CAPE build + prefetch)
# fixes the boundary case without disabling offload entirely.
#
# offload_folder is required for 32B+ bases: found live (2026-08-07,
# qwen-32B) that once a model's fp16 size exceeds the max_memory budget
# above (GPU 16GiB + CPU 48GiB = 64GiB, and a 32B model in fp16 is
# already ~64GB before any tokenizer/embedding/activation overhead),
# accelerate's dispatch_model refuses outright with "We need an
# offload_dir to dispatch this model" rather than silently erroring
# later -- it wants somewhere on disk to spill the remainder. Point it
# at a per-model scratch dir under the same work volume everything else
# here already uses; nothing else reads or needs this directory to
# persist after the merge finishes.
max_memory = {0: "16GiB", "cpu": "48GiB"}
base = AutoModelForCausalLM.from_pretrained(
    BASE, revision=REV, torch_dtype=torch.float16, device_map="auto",
    max_memory=max_memory,
    offload_folder="/work/other-models/${name}-offload",
)
tok = AutoTokenizer.from_pretrained(BASE, revision=REV)

print("applying adapter...")
merged = PeftModel.from_pretrained(base, ADAPTER_DIR)
merged = merged.merge_and_unload()

print("saving merged fp16 model...")
merged.save_pretrained("/work/other-models/${name}-merged", safe_serialization=True)
tok.save_pretrained("/work/other-models/${name}-merged")
print("done")
PYEOF

  docker exec rex86-eval bash -lc "
    source /work/venv/bin/activate
    python3 /work/other-models/${name}-merge.py
  "
  echo "=== ${name}: merge done $(date -u +%FT%TZ) ==="

  # --- 2. GGUF conversion, same llama.cpp checkout already built ------------
  docker exec rex86-eval bash -lc "
    source /work/venv/bin/activate
    cd /work/llama.cpp
    python3 convert_hf_to_gguf.py /work/other-models/${name}-merged --outtype f16 --outfile /work/other-models/${name}-f16.gguf
  "
  docker exec rex86-eval bash -lc "sha256sum /work/other-models/${name}-f16.gguf"
  echo "=== ${name}: GGUF ready $(date -u +%FT%TZ) ==="

  # Free disk: the merged safetensors are only needed to produce the GGUF.
  # Through the container, not the host user: these files were created as
  # root inside rex86-eval (found live -- a bare host-side `rm -rf` failed
  # with Permission denied on every file and, under set -e, silently killed
  # the rest of this pipeline including the eval step right after the
  # expensive merge+GGUF work had already succeeded).
  docker exec rex86-eval rm -rf "/work/other-models/${name}-merged" "/work/other-models/${name}-offload"
else
  echo "=== ${name}: GGUF already present, skipping merge+convert ==="
fi

# --- 3. Corpus eval via llama.cpp (same #159 corpus, same rubric/manifest) --
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

free_gpu; wait_gpu_free
# -ngl 99: full GPU offload attempted first; if the model doesn't fit in
# 20GB VRAM, llama.cpp's own allocator falls back / OOMs loudly rather than
# silently mis-offloading — see the retry-with-lower-ngl handling below.
docker exec -d rex86-eval bash -lc "cd /work && ./llama.cpp/build/bin/llama-server -m /work/other-models/${name}-f16.gguf -ngl 99 --port 8080 --host 0.0.0.0 > /tmp/${name}_server.log 2>&1"
up=0
for i in $(seq 1 60); do
  if docker exec rex86-eval curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then up=1; break; fi
  sleep 3
done
if [[ "$up" -ne 1 ]]; then
  echo "=== ${name}: llama-server did not come up at -ngl 99, check /tmp/${name}_server.log (likely VRAM OOM for this size) ==="
  docker exec rex86-eval tail -40 "/tmp/${name}_server.log" || true
  free_gpu
  # RAM-offload retry: partial GPU layers, rest on system RAM -- explicitly
  # authorized for the large models (codellama-34B, qwen-32B) that won't
  # fit fully in 20GB.
  echo "=== ${name}: retrying with partial GPU offload (-ngl 40) + system RAM ==="
  docker exec -d rex86-eval bash -lc "cd /work && ./llama.cpp/build/bin/llama-server -m /work/other-models/${name}-f16.gguf -ngl 40 --port 8080 --host 0.0.0.0 > /tmp/${name}_server.log 2>&1"
  for i in $(seq 1 60); do
    if docker exec rex86-eval curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then up=1; break; fi
    sleep 3
  done
fi
if [[ "$up" -ne 1 ]]; then
  echo "=== ${name}: FAILED to bring up llama-server even with partial offload -- see /tmp/${name}_server.log ==="
  docker exec rex86-eval tail -60 "/tmp/${name}_server.log" || true
  exit 1
fi
echo "=== ${name}: llama-server up, running #159 corpus (32 cases) $(date -u +%FT%TZ) ==="
docker exec rex86-eval python3 /work/corpus_eval.py llama_cpp "http://127.0.0.1:8080" \
  --manifest /work/manifest.json --rubric /work/rev_cases_v2_rubric.json | tee "$WORK/other-models/${name}.corpus_eval.out"
free_gpu
echo "=== ${name}: DONE $(date -u +%FT%TZ) ==="
