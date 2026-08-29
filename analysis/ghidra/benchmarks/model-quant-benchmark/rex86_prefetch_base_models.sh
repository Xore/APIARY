#!/bin/bash
# rex86_prefetch_base_models.sh -- downloads + converts to f16 GGUF for
# every #847 base-model candidate, ahead of rex86_run_all_base.sh actually
# needing them. Download/convert is network+CPU bound, not GPU bound, so it
# can run concurrently with the still-running adapter queue (GPU) and the
# CAPE golden-image build (unrelated) without contention -- only the actual
# quantize+llama-server+corpus_eval legs need the GPU, and those stay
# serialized behind the adapter queue via rex86_run_all_base.sh itself.
#
# Deliberately only the download+f16-convert step (mirrors the first half
# of rex86_run_base_model.sh) -- quantizing here too would be wasted work
# whenever rex86_run_all_base.sh's own per-spec quantize step would
# otherwise reuse an already-converted f16 file; skips cleanly if that file
# already exists, same check that script uses.
set -uo
source "$WORK/rex86_common.sh" pipefail
WORK=/var/dockge/stacks/rex86-eval/work
LOG="$WORK/other-models/prefetch.log"
cd "$WORK"
exec > >(tee -a "$LOG") 2>&1
echo "=== PREFETCH: start $(date -u +%FT%TZ) ==="

# Safety margin, not a size lookup: the raw HF safetensors download and the
# f16 GGUF this script converts it to coexist on disk simultaneously (the
# source isn't deleted until conversion finishes) -- for a model whose
# download alone is need_gb, peak usage is closer to 2x that. Refuses to
# even start a fetch that would leave less than a further 50GB of margin
# after accounting for that, rather than risk filling /var out from under
# the CAPE build and REx86 queue that are also writing to it right now.
require_free_gb() {
  local need_gb="$1" avail_gb
  avail_gb=$(df --output=avail -BG /var | tail -1 | tr -dc '0-9')
  if (( avail_gb < need_gb * 2 + 50 )); then
    echo "=== SKIPPING: only ${avail_gb}GB free on /var, want $(( need_gb * 2 + 50 ))GB margin for a ~${need_gb}GB download (source+GGUF coexist mid-conversion) ===" >&2
    return 1
  fi
  return 0
}

fetch() {
  name="$1"; hf_repo="$2"; need_gb="${3:-70}"
  f16_path="$WORK/other-models/${name}-f16.gguf"
  if [[ -f "$f16_path" ]]; then
    echo "=== ${name}: f16 GGUF already present, skipping ==="
    return 0
  fi
  require_free_gb "$need_gb" || return 1
  echo "=== PREFETCH: ${name} ($hf_repo) starting $(date -u +%FT%TZ) ==="
  # Resolve "main" to a concrete commit SHA once and pin the download to
  # exactly that commit -- an unpinned snapshot_download means that if
  # disk is lost and the model is re-fetched later, upstream drift on the
  # "main" branch can silently swap in different weights than the ones
  # existing results describe, with nothing on disk recording which
  # commit produced them (#2055 item 4). Logged next to the GGUF's own
  # sha256sum below.
  if docker exec rex86-eval bash -lc "
    source /work/venv/bin/activate
    python3 -c \"
from huggingface_hub import snapshot_download, HfApi
rev = HfApi().model_info('${hf_repo}').sha
print('resolved_commit_sha=' + rev)
snapshot_download('${hf_repo}', revision=rev, local_dir='/work/other-models/${name}-hf')
\"
  "; then
    echo "=== ${name}: download done $(date -u +%FT%TZ) ==="
  else
    echo "=== ${name}: download FAILED $(date -u +%FT%TZ) -- continuing with the rest ==="
    return 1
  fi

  if docker exec rex86-eval bash -lc "
    source /work/venv/bin/activate
    cd /work/llama.cpp
    python3 convert_hf_to_gguf.py /work/other-models/${name}-hf --outtype f16 --outfile /work/other-models/${name}-f16.gguf
  "; then
    docker exec rex86-eval bash -lc "sha256sum /work/other-models/${name}-f16.gguf"
    echo "=== ${name}: f16 GGUF ready $(date -u +%FT%TZ) ==="
    docker exec rex86-eval rm -rf "/work/other-models/${name}-hf"
  else
    echo "=== ${name}: convert_hf_to_gguf FAILED $(date -u +%FT%TZ) -- leaving raw HF snapshot in place for inspection ==="
    return 1
  fi
}

# Smallest first, deliberately -- real results (and reclaimed disk once
# rex86_run_all_base.sh's own quantize+cleanup runs) accumulate before the
# largest, riskiest download is even attempted.
fetch qwen-32b-instruct       "Qwen/Qwen2.5-Coder-32B-Instruct"          65
fetch deepseek-coder-33b      "deepseek-ai/deepseek-coder-33b-instruct"  67
fetch codellama-34b-instruct  "codellama/CodeLlama-34b-Instruct-hf"      68
fetch wizardcoder-33b         "WizardLMTeam/WizardCoder-33B-V1.1"        67
fetch phind-codellama-34b     "Phind/Phind-CodeLlama-34B-v2"             68
fetch mixtral-8x7b            "mistralai/Mixtral-8x7B-Instruct-v0.1"     94
fetch qwen-72b-instruct       "Qwen/Qwen2.5-72B-Instruct"                146
# ~470GB alone -- by far the largest and riskiest fetch here. Only
# attempted if require_free_gb's margin genuinely clears (needs ~990GB
# free at the moment this line runs, given the 2x-plus-50GB rule above),
# which will usually mean waiting for earlier fetches' disk use to be
# reclaimed by rex86_run_all_base.sh's own downstream processing first
# rather than actually failing outright.
fetch deepseek-coder-v2-full  "deepseek-ai/DeepSeek-Coder-V2-Instruct"   470

echo "=== PREFETCH: done $(date -u +%FT%TZ) ==="
