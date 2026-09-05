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
source "$WORK/rex86_common.sh"
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
import os
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

BASE = "${base_repo}"
REV = "${base_rev}"
ADAPTER_DIR = "/work/${adapter_dir}"

print("loading base...")
# device_map={"": "cpu"}, not "auto": found live (2026-08-10, three
# separate failures on codellama-13B/qwen-14B/codellama-34B) that
# device_map="auto"'s GPU/CPU/disk offload mix puts some layers on a
# meta-device placeholder, and that meta-device state kept breaking
# unrelated later steps -- merge_and_unload()'s onload_layer step OOMing
# on the GPU well past whatever max_memory budget was set (accelerate
# doesn't seem to account its transient onload against that budget at
# all -- two different budgets, 16GiB and 14GiB, both died at the exact
# same ~19.4GiB figure), resize_token_embeddings() corrupting dispatch
# bookkeeping when shrinking, and its mean_resizing=True crashing outright
# trying to compute a covariance matrix over meta tensors. merge_and_unload
# is pure weight arithmetic (base_weight + lora_B @ lora_A * scale), not a
# forward pass -- it never needed the GPU in the first place. Loading the
# whole base straight onto CPU (this host has ~90GiB RAM, comfortably
# fits even the 34B/32B bases in fp16) sidesteps every one of those bugs
# at once instead of chasing each symptom individually. Slower than GPU,
# but the eval step right after (a fresh llama-server process against the
# GGUF this produces) is unaffected either way.
base = AutoModelForCausalLM.from_pretrained(
    BASE, revision=REV, torch_dtype=torch.float16, device_map={"": "cpu"},
)
tok = AutoTokenizer.from_pretrained(BASE, revision=REV)

# Some unsloth/CodeLlama base repos (found live 2026-08-10, codellama-7B
# and codellama-13B both) ship a tokenizer with one more token than the
# model's own embedding matrix (an added pad token that was never baked
# into config.vocab_size) -- merging the adapter and saving as-is then
# produces a GGUF whose tokenizer-derived vocab size doesn't match
# token_embd.weight's actual row count, and llama.cpp refuses to load it.
# Resizing first (a no-op when they already match) keeps the embedding
# matrix and tokenizer in sync the same way every other loader in this
# pipeline already expects.
#
# Growing only, never shrinking: found live (2026-08-10, qwen-14B) that
# Qwen2.5's base repos intentionally pad the embedding matrix LARGER than
# the tokenizer's own vocab (for tensor-core alignment) -- that's normal
# and harmless, GGUF export never needs those extra rows. Only the
# codellama direction (tokenizer bigger than embeddings) is ever a real
# problem worth fixing.
#
# mean_resizing=False: transformers' default mean_resizing=True
# initializes new embedding rows from a covariance matrix computed over
# the OLD embeddings. The new rows are unused padding tokens this eval
# never feeds real input through, so the simpler non-mean init is fine
# -- and cheaper, since a real covariance computation over a full-size
# embedding table is wasted work for tokens nothing ever reads.
if len(tok) > base.get_input_embeddings().weight.shape[0]:
    print(f"resizing embeddings {base.get_input_embeddings().weight.shape[0]} -> {len(tok)} to match tokenizer...")
    base.resize_token_embeddings(len(tok), mean_resizing=False)

print("applying adapter...")
merged = PeftModel.from_pretrained(base, ADAPTER_DIR)
merged = merged.merge_and_unload()

print("saving merged fp16 model...")
merged.save_pretrained("/work/other-models/${name}-merged", safe_serialization=True)
tok.save_pretrained("/work/other-models/${name}-merged")

# Some base repos' own tokenizers are missing files their GGUF converter
# still needs (found live 2026-08-10, codegemma-7B: unsloth/codegemma-7b-it
# never ships tokenizer.model at all, only tokenizer.json, but
# convert_hf_to_gguf.py's Gemma path requires the raw SentencePiece file).
# The Zenodo adapter release is the exact tokenizer this model was trained
# and evaluated with, so it's the right fallback source, not a guess.
import shutil
for fname in os.listdir(ADAPTER_DIR):
    if "tokenizer" in fname or fname == "special_tokens_map.json":
        dest = os.path.join("/work/other-models/${name}-merged", fname)
        if not os.path.exists(dest):
            print(f"copying {fname} from adapter dir (missing from base tokenizer)...")
            shutil.copy(os.path.join(ADAPTER_DIR, fname), dest)

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
# -ngl auto (the default -- passed explicitly to be clear this isn't an
# oversight): found live (2026-08-10, codellama-13B) that this pipeline's
# old approach -- try a hardcoded -ngl 99, on failure retry once at a
# hardcoded -ngl 40 -- actively defeated llama.cpp's own --fit mechanism
# (on by default), which auto-computes the right GPU-layer split for
# whatever VRAM is actually free, but only for args the invocation leaves
# unset. Passing an explicit -ngl value disables that outright ("failed to
# fit params to free device memory: n_gpu_layers already set by user to
# 40, abort" in the log), and the fixed 40 was never a real reduction for
# codellama-13B's own ~40 layers anyway -- it OOMed identically to -ngl 99.
# Trusting --fit (default 'on') to size this itself replaces the whole
# guess-and-retry pattern, correctly, for every model size in this queue.
docker exec -d rex86-eval bash -lc "cd /work && ./llama.cpp/build/bin/llama-server -m /work/other-models/${name}-f16.gguf -ngl auto --port 8080 --host 0.0.0.0 > /tmp/${name}_server.log 2>&1"
up=0
for i in $(seq 1 60); do
  if docker exec rex86-eval curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then up=1; break; fi
  sleep 3
done
if [[ "$up" -ne 1 ]]; then
  echo "=== ${name}: FAILED to bring up llama-server -- see /tmp/${name}_server.log ==="
  docker exec rex86-eval tail -60 "/tmp/${name}_server.log" || true
  exit 1
fi
echo "=== ${name}: llama-server up, running #159 corpus (32 cases) $(date -u +%FT%TZ) ==="
# Write to a tmp file and only replace any previous result once the eval
# pipeline has actually succeeded -- callers (rex86_run_all.sh,
# rex86_retry_failed_adapters.sh) trust this file's existence to skip
# already-done work, and an unconditional "tee" left a truncated file in
# place on a mid-eval failure that those exists-checks treated as done
# (#2055 item 2).
result="$WORK/other-models/${name}.corpus_eval.out"
tmp="${result}.tmp"
if docker exec rex86-eval python3 /work/corpus_eval.py llama_cpp "http://127.0.0.1:8080" \
  --manifest /work/manifest.json --rubric /work/rev_cases_v2_rubric.json | tee "$tmp"; then
  mv -f "$tmp" "$result"
  free_gpu
  echo "=== ${name}: DONE $(date -u +%FT%TZ) ==="
else
  rm -f "$tmp"
  free_gpu
  echo "=== ${name}: eval FAILED, no result file written -- see log above $(date -u +%FT%TZ) ==="
  exit 1
fi
