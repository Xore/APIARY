#!/bin/bash
# rex86_run_base_model.sh <name> <hf_repo> <spec> [<spec> ...]
#
# Same GGUF-convert -> corpus_eval leg as rex86_run_one.sh, but for a
# standalone base/instruct model with no LoRA adapter to merge -- these are
# the additional candidates researched on issue #847 (32B+ tier), not part
# of the REx86 paper's own 7 fine-tuned models. Reuses the exact same #159
# corpus (manifest.json/rev_cases_v2_rubric.json) and llama.cpp build
# already in the rex86-eval container, for a directly comparable result.
#
# Runs the corpus once per <spec>, keeping every result file -- direct
# instruction (2026-08-07): sweep multiple quantization levels per model,
# not just one, and keep every precision's numbers for comparison rather
# than quantize-and-discard.
#
# Each spec is TAG:NGL, where TAG is either the literal "f16" (the GGUF
# conversion's native, unquantized output) or an exact llama-quantize type
# name (Q8_0, Q6_K, Q5_K_M, Q4_K_M, Q3_K_M, Q2_K, IQ2_XS, IQ2_XXS, IQ1_S,
# ...). NGL is llama-server's -ngl for that specific file -- deliberately
# per-spec, not one shared value: the same model needs a far lower ngl at
# f16 (16 bits/weight) than at Q4_K_M (~4.85 bits/weight) to fit the same
# 20GB card, so a single ngl across every precision would either waste GPU
# headroom at low bit-depths or OOM at high ones.
#
# f16 GGUF and every quantized GGUF are kept on disk afterward (not
# deleted) so re-running one spec doesn't force regenerating the others.
set -euo pipefail

name="${1:?usage: rex86_run_base_model.sh <name> <hf_repo> <spec:TAG:NGL> [...]}"
hf_repo="${2:?hf_repo required}"
shift 2
specs=("$@")
if [[ ${#specs[@]} -eq 0 ]]; then
  echo "usage: rex86_run_base_model.sh <name> <hf_repo> <TAG:NGL> [<TAG:NGL> ...]" >&2
  exit 2
fi

WORK=/var/dockge/stacks/rex86-eval/work
LOG="$WORK/other-models/${name}.pipeline.log"
mkdir -p "$WORK/other-models"
cd "$WORK"
exec > >(tee -a "$LOG") 2>&1
echo "=== ${name}: START $(date -u +%FT%TZ) repo=${hf_repo} specs=${specs[*]} ==="

f16_path="$WORK/other-models/${name}-f16.gguf"
hf_dir="$WORK/other-models/${name}-hf"

if [[ ! -f "$f16_path" ]]; then
  docker exec rex86-eval bash -lc "
    source /work/venv/bin/activate
    python3 -c \"
from huggingface_hub import snapshot_download
snapshot_download('${hf_repo}', local_dir='/work/other-models/${name}-hf')
\"
  "
  echo "=== ${name}: download done $(date -u +%FT%TZ) ==="

  docker exec rex86-eval bash -lc "
    source /work/venv/bin/activate
    cd /work/llama.cpp
    python3 convert_hf_to_gguf.py /work/other-models/${name}-hf --outtype f16 --outfile /work/other-models/${name}-f16.gguf
  "
  docker exec rex86-eval bash -lc "sha256sum /work/other-models/${name}-f16.gguf"
  echo "=== ${name}: f16 GGUF ready $(date -u +%FT%TZ) ==="
  docker exec rex86-eval rm -rf "/work/other-models/${name}-hf"
else
  echo "=== ${name}: f16 GGUF already present, skipping download+convert ==="
fi

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

run_eval() {
  local tag="$1" gguf="$2" ngl="$3"
  local result="$WORK/other-models/${name}-${tag}.corpus_eval.out"
  if [[ -f "$result" ]]; then
    echo "=== ${name} (${tag}): already has a corpus_eval result, skipping ==="
    return 0
  fi
  # Retry at progressively lower -ngl on load failure: found live
  # (2026-08-08, qwen-32b-instruct Q6_K) that this tier's own ngl:99
  # entries in rex86_run_all_base.sh were sized off an estimate, not a
  # real quant size -- Q6_K for a 32B model comes out to ~25GB, which
  # does not fit this host's 20GB card at ngl=99 regardless (llama-server
  # crashed outright: "cudaMalloc failed: out of memory"), and the
  # single-attempt version of this function just burned its full 120*3s
  # health-check budget waiting for a server that had already exited.
  # Same partial-offload-on-failure pattern rex86_run_one.sh's own eval
  # step already uses for the adapter models, generalized into a loop
  # here since the exact GPU/CPU split that fits isn't known per quant
  # level ahead of time.
  # Fallback values are relative to the REQUESTED ngl (half, then a
  # quarter), not fixed absolute numbers: this tier's specs already cover
  # a wide range (99 for "offload everything" down to explicit partial
  # values like 20-35 for Mixtral/72B), and a fixed fallback higher than
  # a low requested value would just retry at MORE GPU offload than
  # already failed. Halving is also large enough to matter regardless of
  # the model's real layer count (~64 here) -- a small fixed decrement
  # off of 99 can land on a value still >= the real layer count and
  # therefore be a no-op, confirmed live for this exact model.
  local half=$(( ngl / 2 )); [[ "$half" -lt 5 ]] && half=5
  local quarter=$(( ngl / 4 )); [[ "$quarter" -lt 2 ]] && quarter=2
  local attempts=("$ngl" "$half" "$quarter")
  local up=0
  local attempt_ngl
  for attempt_ngl in "${attempts[@]}"; do
    free_gpu; wait_gpu_free
    docker exec -d rex86-eval bash -lc "cd /work && ./llama.cpp/build/bin/llama-server -m ${gguf} -ngl ${attempt_ngl} --port 8080 --host 0.0.0.0 > /tmp/${name}_${tag}_server.log 2>&1"
    up=0
    for i in $(seq 1 120); do
      if docker exec rex86-eval curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then up=1; break; fi
      sleep 3
    done
    if [[ "$up" -eq 1 ]]; then
      break
    fi
    echo "=== ${name} (${tag}): llama-server did not come up at -ngl ${attempt_ngl}, check /tmp/${name}_${tag}_server.log ==="
    docker exec rex86-eval tail -20 "/tmp/${name}_${tag}_server.log" || true
    free_gpu
    echo "=== ${name} (${tag}): retrying with a lower -ngl ==="
  done
  if [[ "$up" -ne 1 ]]; then
    echo "=== ${name} (${tag}): llama-server never came up, giving up ==="
    return 1
  fi
  echo "=== ${name} (${tag}): llama-server up at -ngl ${attempt_ngl}, running #159 corpus (32 cases) $(date -u +%FT%TZ) ==="
  docker exec rex86-eval python3 /work/corpus_eval.py llama_cpp "http://127.0.0.1:8080" \
    --manifest /work/manifest.json --rubric /work/rev_cases_v2_rubric.json | tee "$result"
  free_gpu
  echo "=== ${name} (${tag}): eval done $(date -u +%FT%TZ) ==="
}

f16_requested=0
for spec in "${specs[@]}"; do
  tag="${spec%%:*}"
  ngl="${spec##*:}"
  if [[ "$tag" == "f16" ]]; then
    f16_requested=1
    run_eval "f16" "/work/other-models/${name}-f16.gguf" "$ngl" || echo "=== ${name} (f16): eval FAILED, continuing to the next spec ==="
    continue
  fi
  quant_path="$WORK/other-models/${name}-${tag}.gguf"
  if [[ ! -f "$quant_path" ]]; then
    docker exec rex86-eval bash -lc "
      /work/llama.cpp/build/bin/llama-quantize /work/other-models/${name}-f16.gguf /work/other-models/${name}-${tag}.gguf ${tag}
    "
    docker exec rex86-eval bash -lc "sha256sum /work/other-models/${name}-${tag}.gguf"
    echo "=== ${name}: ${tag} GGUF ready $(date -u +%FT%TZ) ==="
  else
    echo "=== ${name}: ${tag} GGUF already present, skipping quantize ==="
  fi
  run_eval "$tag" "/work/other-models/${name}-${tag}.gguf" "$ngl" || echo "=== ${name} (${tag}): eval FAILED, continuing to the next spec ==="
done

# f16 was never itself a requested comparison point for this model (only
# quantize input) -- free it rather than keeping a multi-hundred-GB file
# nothing reads again. Real, not hypothetical: without this, Mixtral-8x7B
# (~93GB), Qwen2.5-72B (~145GB), and DeepSeek-Coder-V2-Instruct full
# (~470GB) alone would permanently hold ~708GB, most of this host's free
# disk, for files never used past the quantize step that already ran.
if [[ "$f16_requested" -eq 0 ]]; then
  docker exec rex86-eval rm -f "/work/other-models/${name}-f16.gguf"
  echo "=== ${name}: f16 GGUF removed (was quantize input only, not itself a requested spec) ==="
fi

echo "=== ${name}: DONE $(date -u +%FT%TZ) ==="
