#!/usr/bin/env bash
# export_to_ollama.sh -- the round-7 training export path (#3080, plan §5):
# merged_16bit -> GGUF f16 -> imatrix -> quantise -> ollama create, with a
# manifest.json and a mandatory Modelfile diff at every export.
#
# Operational copy lives at /mnt-1/benchmarks/round7/export_to_ollama.sh.
#
# Usage: export_to_ollama.sh <run_dir> <tag> <quant...>
#   run_dir  directory holding the merged_16bit export from train.py
#            (a HF-format checkpoint: config.json, *.safetensors, tokenizer)
#   tag      the ollama tag to create, e.g. round7-qwen3-14b-t2:latest
#   quant... one or more llama-quantize levels, e.g. Q4_K_M Q8_0
#
# Env:
#   BASE_TAG            ollama tag whose TEMPLATE/PARAMETER/SYSTEM are the
#                        production truth (required)
#   CALIB_FILE           calibration text for llama-imatrix (required)
#   ACCEPT_TEMPLATE_DIFF set to 1 to proceed despite a Modelfile mismatch
#                        (equivalent to a --accept-template-diff flag)
#   LLAMACPP_IMAGE       default ghcr.io/ggml-org/llama.cpp:full
#   OLLAMA_CONTAINER     default ghidra-ollama-1
#
# What this script does NOT do: it never merges in 4-bit
# (train.py/Unsloth's save_pretrained_merged must already have produced a
# merged_16bit run_dir) and it never calls `ollama create --quantize` --
# that path has no imatrix and is not the quality one (plan §10).
set -u

run_dir=${1:?usage: export_to_ollama.sh <run_dir> <tag> <quant...>}
tag=${2:?usage: export_to_ollama.sh <run_dir> <tag> <quant...>}
shift 2
quant_levels=("$@")
[ "${#quant_levels[@]}" -ge 1 ] || { echo "ABORT: need at least one quant level" >&2; exit 1; }

for a in "${quant_levels[@]}"; do
  [ "$a" = "--accept-template-diff" ] && ACCEPT_TEMPLATE_DIFF=1
done
quant_levels=($(printf '%s\n' "${quant_levels[@]}" | grep -v -- '--accept-template-diff'))

BASE_TAG=${BASE_TAG:?BASE_TAG env var required -- the production tag to copy TEMPLATE/PARAMETER/SYSTEM from}
CALIB_FILE=${CALIB_FILE:?CALIB_FILE env var required -- calibration text for llama-imatrix, must not touch the corpus (plan §6.1)}
ACCEPT_TEMPLATE_DIFF=${ACCEPT_TEMPLATE_DIFF:-0}
LLAMACPP_IMAGE=${LLAMACPP_IMAGE:-ghcr.io/ggml-org/llama.cpp:full}
OLLAMA_CONTAINER=${OLLAMA_CONTAINER:-ghidra-ollama-1}

log() { echo "$(date -u +%FT%TZ) $*"; }
sha256() { sha256sum "$1" | awk '{print $1}'; }
# One hash for a directory of checkpoint files (safetensors, config, tokenizer):
# sha256 of each file's own hash, sorted by relative path, then hashed again.
sha256_dir() {
  # $2 (optional): a find -prune pattern to exclude, e.g. "./export/*"
  [ -d "$1" ] || { echo ""; return; }
  ( cd "$1" && find . -type f -not -path "${2:-__none__}" -print0 | sort -z | xargs -0 sha256sum ) | sha256sum | awk '{print $1}'
}
base_model_ref() {
  # Prints "repo@revision" from adapter_config.json / config.json, else "unknown".
  python3 -c "
import json, sys
for name, key in [('adapter_config.json', 'base_model_name_or_path'), ('config.json', '_name_or_path')]:
    try:
        with open(sys.argv[1] + '/' + name) as f:
            cfg = json.load(f)
        ref = cfg.get(key)
        if ref:
            print(ref)
            sys.exit(0)
    except FileNotFoundError:
        pass
print('unknown')
" "$1"
}

[ -d "$run_dir" ] || { log "ABORT: run_dir $run_dir does not exist"; exit 1; }
[ -f "$CALIB_FILE" ] || { log "ABORT: calibration file $CALIB_FILE does not exist"; exit 1; }

work="$run_dir/export"
mkdir -p "$work"

# --- step 3: convert merged_16bit -> GGUF f16, in the llama.cpp:full image --
gguf_f16="$work/model-f16.gguf"
log "convert: $run_dir -> $gguf_f16"
docker run --rm \
  -v "$run_dir:/model:ro" -v "$work:/out" \
  "$LLAMACPP_IMAGE" \
  python3 /app/convert_hf_to_gguf.py /model --outtype f16 --outfile /out/model-f16.gguf \
  || { log "ABORT: convert_hf_to_gguf.py failed"; exit 1; }
[ -f "$gguf_f16" ] || { log "ABORT: convert produced no $gguf_f16"; exit 1; }

# --- step 4: imatrix on the calibration set, GPU -----------------------------
imatrix="$work/imatrix.dat"
log "imatrix: calibrating on $CALIB_FILE"
docker run --rm --gpus "device=GPU-18a00c7e-670a-c305-a2aa-20e3a71917a3" \
  -v "$work:/work" -v "$CALIB_FILE:/calib.txt:ro" \
  "$LLAMACPP_IMAGE" \
  llama-imatrix -m /work/model-f16.gguf -f /calib.txt -o /work/imatrix.dat \
  || { log "ABORT: llama-imatrix failed"; exit 1; }
[ -f "$imatrix" ] || { log "ABORT: imatrix produced no $imatrix"; exit 1; }

# --- step 5: quantise per level, imatrix always on --------------------------
declare -A gguf_by_level
for level in "${quant_levels[@]}"; do
  out="$work/model-$level.gguf"
  log "quantise: $level"
  docker run --rm \
    -v "$work:/work" \
    "$LLAMACPP_IMAGE" \
    llama-quantize --imatrix "/work/imatrix.dat" /work/model-f16.gguf "/work/model-$level.gguf" "$level" \
    || { log "ABORT: llama-quantize $level failed"; exit 1; }
  [ -f "$out" ] || { log "ABORT: quantise $level produced no $out"; exit 1; }
  gguf_by_level["$level"]="$out"
done

# --- step 6: Modelfile diff, then ollama create per level -------------------
base_modelfile="$work/base.Modelfile"
docker exec "$OLLAMA_CONTAINER" ollama show --modelfile "$BASE_TAG" > "$base_modelfile" \
  || { log "ABORT: ollama show --modelfile $BASE_TAG failed -- is the base tag pulled?"; exit 1; }

trained_modelfile="$run_dir/Modelfile"
[ -f "$trained_modelfile" ] || { log "ABORT: no Modelfile at $trained_modelfile -- train.py/Unsloth should write one next to the merged export"; exit 1; }

extract_directives() {
  grep -E '^(TEMPLATE|PARAMETER|SYSTEM)' "$1" | sort
}
base_directives=$(extract_directives "$base_modelfile")
trained_directives=$(extract_directives "$trained_modelfile")

if [ "$base_directives" != "$trained_directives" ]; then
  log "TEMPLATE/PARAMETER/SYSTEM diff between $BASE_TAG and $trained_modelfile:"
  diff <(echo "$base_directives") <(echo "$trained_directives") || true
  if [ "$ACCEPT_TEMPLATE_DIFF" != "1" ]; then
    log "ABORT: Modelfile diff not accepted -- rerun with --accept-template-diff if this divergence is intentional"
    exit 1
  fi
  log "diff accepted via --accept-template-diff, proceeding"
fi

manifest_created="$(date -u +%FT%TZ)"
manifest_levels="[]"
for level in "${quant_levels[@]}"; do
  gguf="${gguf_by_level[$level]}"
  level_tag="$tag-${level,,}"
  modelfile="$work/Modelfile.$level"
  {
    echo "FROM $gguf"
    echo
    echo "$base_directives"
  } > "$modelfile"

  log "ollama create: $level_tag"
  docker cp "$gguf" "$OLLAMA_CONTAINER:/tmp/$(basename "$gguf")" || { log "ABORT: docker cp $gguf failed"; exit 1; }
  docker cp "$modelfile" "$OLLAMA_CONTAINER:/tmp/Modelfile.$level" || { log "ABORT: docker cp $modelfile failed"; exit 1; }
  docker exec "$OLLAMA_CONTAINER" sh -c "cd /tmp && sed -i \"s#$gguf#/tmp/$(basename "$gguf")#\" Modelfile.$level && ollama create '$level_tag' -f Modelfile.$level" \
    || { log "ABORT: ollama create $level_tag failed"; exit 1; }

  ollama_digest=$(docker exec "$OLLAMA_CONTAINER" ollama show --modelfile "$level_tag" 2>/dev/null | grep -m1 '^FROM' | awk '{print $2}')
  manifest_levels=$(python3 -c "
import json,sys
levels = json.loads(sys.argv[1])
levels.append({
    'level': sys.argv[2],
    'tag': sys.argv[3],
    'gguf_sha256': sys.argv[4],
    'ollama_digest': sys.argv[5],
})
print(json.dumps(levels))
" "$manifest_levels" "$level" "$level_tag" "$(sha256 "$gguf")" "${ollama_digest:-unknown}")
done

manifest="$run_dir/manifest.json"
adapter_dir="$run_dir/adapter"
python3 -c "
import json,sys
manifest = {
    'source_run_dir': sys.argv[1],
    'base_model_ref': sys.argv[2],
    'base_ollama_tag': sys.argv[3],
    'adapter_sha256': sys.argv[4] or None,
    'merged_16bit_sha256': sys.argv[5],
    'gguf_f16_sha256': sys.argv[6],
    'imatrix_sha256': sys.argv[7],
    'calibration_file': sys.argv[8],
    'calibration_sha256': sys.argv[9],
    'levels': json.loads(sys.argv[10]),
    'template_diff_accepted': sys.argv[11] == '1',
    'llamacpp_image': sys.argv[12],
    'created': sys.argv[13],
}
print(json.dumps(manifest, indent=2))
" "$run_dir" "$(base_model_ref "$run_dir")" "$BASE_TAG" "$(sha256_dir "$adapter_dir")" \
  "$(sha256_dir "$run_dir" "./export/*")" "$(sha256 "$gguf_f16")" "$(sha256 "$imatrix")" \
  "$CALIB_FILE" "$(sha256 "$CALIB_FILE")" "$manifest_levels" "$ACCEPT_TEMPLATE_DIFF" \
  "$LLAMACPP_IMAGE" "$manifest_created" > "$manifest"

log "manifest written: $manifest"
