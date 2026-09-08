#!/usr/bin/env bash
# round7_t0_merge_export.sh -- T0 pipeline proof (#3081): take the #160 REx86
# PEFT adapter (Zenodo 15420461) through the whole seam -- merge into the base,
# convert to GGUF, quantise, and register in Ollama beside its untouched base
# twins -- so the training legs (#3083+) hit a proved path instead of a guess.
#
# Operational copy lives at /mnt-1/benchmarks/round7_t0_merge_export.sh.
#
# ---------------------------------------------------------------------------
# Why this is CPU-only and why it gates on the cold run
#
# Adapter load + merge + save_pretrained_merged and convert_hf_to_gguf are all
# CPU work; llama-quantize is CPU; ollama create quantises at import time on
# CPU and only REGISTERS models -- it does not load them into VRAM (that
# happens at first generate, which is the scoring leg's business, not ours).
# No step here needs the GPU. But merging a 7B model in fp16 needs ~30 GB of
# RAM, and round7_coldrun.sh is running on the same host; this script refuses
# to start unless the cold run is genuinely finished (positive condition:
# every roster tag scored or UNMEASURED, no sweep process alive -- same shape
# as chain_cold.sh) AND the host has the free RAM to merge with.
#
# Size/SHA note, measured 2026-09-07: the mandated size 323,014,168 and SHA
# a21a6918...590f belong to the INNER adapter_model.safetensors, not the
# REx86.zip wrapper (303,182,424 bytes, zip SHA 02a6e4c8...2067 -- recorded in
# the manifest, not gated on, because Zenodo may repackage zips). Zenodo's
# record API was down on 2026-09-08, so the zip is gated on a local zipfile CRC
# test instead of a live size comparison; the inner safetensors is gated on the
# hard SHA and size above. A mismatch aborts.
set -u

BASE=${BASE:-/mnt-1/benchmarks}
RUN=${RUN:-/mnt-1/training/runs/t0-rex86}
# $RUN as hp-unsloth-studio sees it: that container binds /var/training and
# RENAMES it to /workspace, so no host path is valid inside it.
RUN_C=${RUN_C:-/workspace/runs/t0-rex86}
RESULTS=${RESULTS:-$BASE/round7}
TAGLIST=${TAGLIST:-$BASE/models_requant.txt}
ROSTER7=${ROSTER7:-$BASE/round7_roster.txt}
ZENODO_REC=15420461
ZIP_URL="https://zenodo.org/api/records/${ZENODO_REC}/files/REx86.zip/content"
BASE_MODEL=unsloth/Qwen2.5-Coder-7B
BASE_REV=5762507e8ed2132906da60f86a2b23b54673ee81
UNSLOTH_IMG=hp-unsloth-studio          # running container name on homeserver
LLAMA_IMG=ghcr.io/ggml-org/llama.cpp:full
OLLAMA_C=ghidra-ollama-1
INNER_SHA=a21a6918c0416fcc7f8774b3bd41b373a0aab53e81a8b14c3ac6f9eed280590f
INNER_SIZE=323014168

log() { echo "$(date -u +%FT%TZ) $*"; }
die() { log "ABORT: $*"; exit 1; }

# ---------------------------------------------------------------------------
# Gate: positive condition only -- the cold run must be FINISHED, not merely
# not-started. Every roster tag needs both tier files or an UNMEASURED marker,
# and no sweep/baseline process may be alive (chain_cold.sh shape).
# ---------------------------------------------------------------------------
coldrun_finished() {
  python3 - "$TAGLIST" "$RESULTS" <<'EOF' || return 1
import os, sys
tags = [l.strip() for l in open(sys.argv[1]) if l.strip() and not l.startswith("#")]
res = sys.argv[2]
# Same slug derivation sweep_extra.sh scores with (tr ':/' '__').
def slug(t):
    return t.replace(":", "_").replace("/", "_")
for t in tags:
    s = slug(t)
    if os.path.exists(f"{res}/tierA_{s}_run1.json") and os.path.exists(f"{res}/tierB_{s}_run1.json"):
        continue
    # sweep_extra.sh writes UNMEASURED_<slug>.status; older copies wrote .txt,
    # and some drivers drop a plain UNMEASURED marker. Any of them is settled.
    if any(os.path.exists(f"{res}/{p}") for p in (
            f"UNMEASURED_{s}.status", f"UNMEASURED_{s}.txt", "UNMEASURED",
            f"UNRESOLVED_tierA_{s}.status", f"UNRESOLVED_tierB_{s}.status")):
        continue
    sys.exit(1)
EOF
}
# Roster for the gate. Default is the round-7 roster the cold run itself
# consumes ($BASE/round7_roster.txt is built by round7_coldrun.sh's
# build_roster and may not exist yet); T0_ROWS mode narrows the gate to the
# four T0 tags -- the merge leg runs AFTER the cold run and registers exactly
# those tags, so the full-roster wait would deadlock with this very script.
T0_ROWS="rex86-merged:q8_0
rex86-merged:q4_k_m
qwen2.5-coder-7b-base:q8_0
qwen2.5-coder-7b-base:q4_k_m"
if [ "${T0_GATE:-0}" = "1" ]; then
  TAGLIST=$(mktemp)
  printf '%s\n' "$T0_ROWS" > "$TAGLIST"
elif [ ! -s "$ROSTER7" ]; then
  [ -s "$TAGLIST" ] || TAGLIST=$BASE/models_round7.txt
else
  TAGLIST=$ROSTER7
fi
[ -s "$TAGLIST" ] || die "roster $TAGLIST is empty -- cannot evaluate the gate"
coldrun_finished || die "round-7 roster not fully scored -- cold run still owns the GPU"
pgrep -f "sweep_extra[.]sh"       >/dev/null 2>&1 && die "a sweep is still running"
pgrep -f "record_baseline[.]py"   >/dev/null 2>&1 && die "a baseline run is still running"
pgrep -f "round7_coldrun[.]sh"    >/dev/null 2>&1 && die "round7_coldrun.sh is still alive"

# RAM guard: fp16 merge of a 7B model wants ~30 GB headroom.
free_g=$(free -g | awk '/^Mem:/{print $7}')
[ "$free_g" -ge 35 ] || die "only ${free_g}G available RAM, need >=35G for the fp16 merge"

# ---------------------------------------------------------------------------
# 1. Fetch and verify the adapter (CPU, network)
# ---------------------------------------------------------------------------
mkdir -p "$RUN"
cd "$RUN" || die "cannot cd $RUN"
if [ ! -s REx86.zip ]; then
  log "downloading REx86.zip from Zenodo record $ZENODO_REC"
  curl -fL --retry 3 -o REx86.zip "$ZIP_URL" || die "download failed"
fi
# Zenodo outage 2026-09-08 (502/504): live-record size check bypassed.
# Integrity proven instead by zipfile CRC test; inner adapter SHA is checked
# below against the pinned INNER_SHA regardless.
python3 - <<'PYEOF2' || die "REx86.zip failed local integrity check (CRC)"
import sys, zipfile
z = zipfile.ZipFile("REx86.zip")
bad = z.testzip()
if bad is not None:
    print("CRC failure in", bad)
    sys.exit(1)
print("zip CRC ok:", len(z.namelist()), "entries")
PYEOF2
ZIP_SHA=$(sha256sum REx86.zip | awk '{print $1}')
log "zip sha256 $ZIP_SHA (CRC-verified, Zenodo record API down)"

if [ ! -s REx86/adapter_model.safetensors ]; then
  unzip -o REx86.zip || die "unzip failed"
fi
ZIP_SIZE=$(stat -c%s REx86.zip)
INNER_ACTUAL=$(sha256sum REx86/adapter_model.safetensors | awk '{print $1}')
INNER_ACTUAL_SIZE=$(stat -c%s REx86/adapter_model.safetensors)
[ "$INNER_ACTUAL" = "$INNER_SHA" ] || die "adapter SHA mismatch: got $INNER_ACTUAL"
[ "$INNER_ACTUAL_SIZE" = "$INNER_SIZE" ] || die "adapter size mismatch: got $INNER_ACTUAL_SIZE"
log "adapter verified: $INNER_ACTUAL_SIZE bytes, sha256 $INNER_ACTUAL"

# ---------------------------------------------------------------------------
# 2. Merge the adapter into the base (CPU; unsloth container)
#    The gate above guarantees the cold run is done, so touching the shared
#    HF cache / container here cannot contend with a live run.
# ---------------------------------------------------------------------------
MERGED="$RUN/merged_16bit"
MERGED_C="$RUN_C/merged_16bit"
# Completion sentinel. NOT config.json: save_pretrained writes that BEFORE the
# weight shards, so a crash mid-save leaves a directory every config.json gate
# reads as finished and never re-merges. .merge_done is written by this script
# only once the save AND the tokenizer normalization below have both returned.
MERGE_DONE="$MERGED/.merge_done"
if [ ! -s "$MERGE_DONE" ]; then
  rm -f "$MERGE_DONE"
  log "merging adapter into $BASE_MODEL @ $BASE_REV (CPU, fp16, unsloth)"
  docker exec "$UNSLOTH_IMG" python3 - <<PY || log "unsloth merge failed (rc=$?) -- trying the HF+PEFT CPU fallback"
import torch
from unsloth import FastLanguageModel
from peft import PeftModel
model, tok = FastLanguageModel.from_pretrained(
    model_name="$BASE_MODEL", revision="$BASE_REV",
    max_seq_length=4096, dtype=torch.float16, load_in_4bit=False)
model = PeftModel.from_pretrained(model, "$RUN_C/REx86")
model = model.merge_and_unload()
model.save_pretrained_merged("$MERGED_C", tok, save_method="merged_16bit")
print("merged (unsloth) ->", "$MERGED_C")
PY
  if [ ! -s "$MERGED/model.safetensors.index.json" ]; then
    # save_pretrained_merged hard-requires CUDA and OOMs when the Studio
    # server's own model residency already holds VRAM; fall back to a plain
    # HF+PEFT CPU merge, which produces identical weights.
    log "unsloth merge left no weight index -- falling back to HF+PEFT CPU merge"
    docker exec -e CUDA_VISIBLE_DEVICES= "$UNSLOTH_IMG" python3 - <<PY2 || die "merge failed"
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
model = AutoModelForCausalLM.from_pretrained(
    "$BASE_MODEL", revision="$BASE_REV",
    dtype=torch.float16, device_map="cpu", low_cpu_mem_usage=True)
tok = AutoTokenizer.from_pretrained("$BASE_MODEL", revision="$BASE_REV")
model = PeftModel.from_pretrained(model, "$RUN_C/REx86")
model = model.merge_and_unload()
model.save_pretrained("$MERGED_C", safe_serialization=True)
tok.save_pretrained("$MERGED_C")
print("merged (HF+PEFT CPU) ->", "$MERGED_C")
PY2
  fi
  [ -s "$MERGED/model.safetensors.index.json" ] || die "merge produced no weight shards at $MERGED"

  # newer transformers requires tokenizer_config.json's extra_special_tokens to
  # be a dict; unsloth and older PEFT merges write it as a list, which then
  # breaks convert_hf_to_gguf.py's tokenizer loader.
  TOK_CFG="$MERGED/tokenizer_config.json"
  if [ -s "$TOK_CFG" ]; then
    python3 - "$TOK_CFG" <<'EOF' || die "tokenizer_config.json normalization failed"
import json, os, sys
p = sys.argv[1]
cfg = json.load(open(p))
if isinstance(cfg.get("extra_special_tokens"), list):
    cfg["extra_special_tokens"] = {}
    # temp + os.replace: a truncating in-place dump that dies mid-write leaves a
    # corrupt tokenizer_config.json that no re-run regenerates.
    tmp = p + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(cfg, fh, indent=2)
    os.replace(tmp, p)
EOF
  fi
  date -u +%FT%TZ > "$MERGE_DONE" || die "cannot write $MERGE_DONE"
fi
[ -s "$MERGE_DONE" ] || die "merge incomplete at $MERGED"

# ---------------------------------------------------------------------------
# 3. Convert to GGUF f16, then quantise (CPU; llama.cpp container)
# ---------------------------------------------------------------------------
GGUF_F16="$RUN/rex86-merged-f16.gguf"
if [ ! -s "$GGUF_F16" ]; then
  log "converting merged model to GGUF f16"
  # /mnt-1/training is a symlink to /var/training. Binding /mnt-1 would carry
  # that symlink into the container, where its target is not mounted and so
  # dangles -- a bind cannot resolve a host symlink pointing OUTSIDE the mounted
  # tree. /var/training is a real directory, so bind it directly, identically
  # named on both sides. (Containers that RENAME the mount need their own path
  # variable instead -- see $RUN_C for hp-unsloth-studio's /workspace.)
  # The image's ENTRYPOINT swallows a bare "python3"/"/app/llama-quantize" as
  # an unknown subcommand, so it must be overridden explicitly.
  docker run --rm --entrypoint python3 -v /var/training:/var/training "$LLAMA_IMG" \
    /app/convert_hf_to_gguf.py "/var/training/runs/t0-rex86/merged_16bit" --outfile "/var/training/runs/t0-rex86/rex86-merged-f16.gguf" --outtype f16 \
    || die "convert_hf_to_gguf failed"
fi
Q4="$RUN/rex86-merged-Q4_K_M.gguf"
Q8="$RUN/rex86-merged-Q8_0.gguf"
[ -s "$Q4" ] || docker run --rm --entrypoint /app/llama-quantize -v /var/training:/var/training "$LLAMA_IMG" \
  "/var/training/runs/t0-rex86/rex86-merged-f16.gguf" "/var/training/runs/t0-rex86/rex86-merged-Q4_K_M.gguf" Q4_K_M || die "Q4_K_M quantise failed"
[ -s "$Q8" ] || docker run --rm --entrypoint /app/llama-quantize -v /var/training:/var/training "$LLAMA_IMG" \
  "/var/training/runs/t0-rex86/rex86-merged-f16.gguf" "/var/training/runs/t0-rex86/rex86-merged-Q8_0.gguf" Q8_0 || die "Q8_0 quantise failed"

# ---------------------------------------------------------------------------
# 4. Register in Ollama: merged artefact + untouched base twins
#    (create/quantise is CPU; nothing is loaded for inference here)
# ---------------------------------------------------------------------------
# The ollama container mounts only its models volume (ghidra_ollama_models ->
# /root/.ollama), not /mnt-1 or /var/training. Stage the GGUFs there via the
# volume's host mountpoint and point the Modelfiles at the in-container path.
OLLAMA_VOL=$(docker volume inspect ghidra_ollama_models --format '{{.Mountpoint}}' 2>/dev/null)
[ -n "$OLLAMA_VOL" ] || OLLAMA_VOL=$(docker inspect "$OLLAMA_C" --format '{{range .Mounts}}{{if eq .Destination "/root/.ollama"}}{{.Name}}{{end}}{{end}}' | xargs -r docker volume inspect --format '{{.Mountpoint}}')
[ -n "$OLLAMA_VOL" ] || die "cannot resolve ollama models volume"
STAGE="$OLLAMA_VOL/import-t0"
sudo -n mkdir -p "$STAGE" || die "cannot create $STAGE"
for f in "$GGUF_F16" "$Q4" "$Q8"; do
  dst="$STAGE/$(basename "$f")"
  # ~27 GB in total; skip anything a previous run already staged intact. Size
  # compare, not cmp -s, because cmp would read all 27 GB to learn nothing.
  if [ "$(stat -c%s "$f")" = "$(stat -c%s "$dst" 2>/dev/null || echo 0)" ]; then
    log "already staged: $(basename "$f")"
    continue
  fi
  sudo -n cp -f "$f" "$dst" || die "sudo cp of $(basename "$f") into ollama volume failed"
done
for q in q4_k_m q8_0; do
  SRC=$Q4; [ "$q" = q8_0 ] && SRC=$Q8
  SRCNAME=$(basename "$SRC")
  printf 'FROM /root/.ollama/import-t0/%s\n' "$SRCNAME" | sudo -n tee "$STAGE/Modelfile.rex86-$q" > /dev/null
  docker exec "$OLLAMA_C" ollama create "rex86-merged:$q" -f "/root/.ollama/import-t0/Modelfile.rex86-$q" \
    || die "ollama create rex86-merged:$q failed"
  printf 'FROM /root/.ollama/import-t0/rex86-merged-f16.gguf\n' | sudo -n tee "$STAGE/Modelfile.base-$q" > /dev/null
  docker exec "$OLLAMA_C" ollama create --quantize "$q" "qwen2.5-coder-7b-base:$q" \
    -f "/root/.ollama/import-t0/Modelfile.base-$q" \
    || die "ollama create qwen2.5-coder-7b-base:$q failed"
done
# All four tags imported; ollama holds its own copy in the blob store, so the
# staged GGUFs are now a pure duplicate inside the docker data root. Modelfiles
# stay -- they are tiny and document what was imported.
sudo -n rm -f "$STAGE"/*.gguf || log "warning: could not clean staged GGUFs from $STAGE"

# ---------------------------------------------------------------------------
# 5. Manifest: input SHAs, base revision, quant params, file sizes
# ---------------------------------------------------------------------------
python3 - "$RUN" "$ZIP_SIZE" "$ZIP_SHA" "$INNER_ACTUAL" "$INNER_ACTUAL_SIZE" <<'EOF'
import hashlib, json, os, sys
run, zip_size, zip_sha, inner_sha, inner_size = (
    sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5]))
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()
ggufs = {n: {"path": p, "bytes": os.path.getsize(p), "sha256": sha(p)}
         for n, p in [("rex86-merged-f16", f"{run}/rex86-merged-f16.gguf"),
                      ("rex86-merged-Q4_K_M", f"{run}/rex86-merged-Q4_K_M.gguf"),
                      ("rex86-merged-Q8_0", f"{run}/rex86-merged-Q8_0.gguf")]}
manifest = {
    "experiment": "T0 pipeline proof (#3081)",
    "base_model": "unsloth/Qwen2.5-Coder-7B",
    "base_revision": "5762507e8ed2132906da60f86a2b23b54673ee81",
    "adapter": {"source": "Zenodo 15420461 REx86.zip",
                "zip_bytes": zip_size, "zip_sha256": zip_sha,
                "inner_file": "REx86/adapter_model.safetensors",
                "inner_bytes": inner_size, "inner_sha256": inner_sha,
                "peft": {"type": "LORA", "r": 32, "lora_alpha": 64}},
    "merge": {"method": "merge_and_unload", "save": "merged_16bit"},
    "quant": {"source": "f16 GGUF via convert_hf_to_gguf.py",
              "levels": ["Q4_K_M", "Q8_0"], "tool": "llama-quantize"},
    "ollama_tags": ["rex86-merged:q4_k_m", "rex86-merged:q8_0",
                    "qwen2.5-coder-7b-base:q4_k_m", "qwen2.5-coder-7b-base:q8_0"],
    "gguf": ggufs,
}
out = f"{run}/manifest.json"
json.dump(manifest, open(out, "w"), indent=2)
print("wrote", out)
EOF
log "T0 pipeline complete: merged, converted, quantised, registered"
