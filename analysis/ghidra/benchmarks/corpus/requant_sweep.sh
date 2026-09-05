#!/usr/bin/env bash
# requant_sweep.sh -- #1947 phase 3 / #2245: build our own quantization ladder
# from an f16 master and measure every level with the same scorer, at the same
# pin, as the as-published rows it is being compared against.
#
# Operational copy runs from /mnt-1/benchmarks/requant_sweep.sh on the
# homeserver. Committed here because the original was never committed, did not
# survive the 2026-09-03/04 rebuild, and had to be rewritten from its issue
# (#2985). Keep the two in sync by hand.
#
# ---------------------------------------------------------------------------
# What this answers, and why it is not the cheap version
#
# #2245 asks whether a base one or two size classes above the current slots,
# pushed down a quantization ladder WE control, beats the smaller models we run
# today. The cheap version -- llama-quantize --allow-requantize on a GGUF we
# already hold -- is lossy-on-lossy and, per #2245's own comment, "a fit-and-cost
# probe, not a clean quality datapoint". The operator chose the full clean f16
# ladder, so this converts from the original weights every time.
#
# Scoring is record_baseline.py at tiers A and B on the pinned harness, served
# through Ollama -- NOT corpus_eval.py via llama-server. #2245 step 4 requires a
# winner to beat the #1795/#1947 rows, and those were scored by record_baseline;
# numbers from two different scorers do not compare (rule 6 of #1947's six).
# This script therefore only BUILDS; it hands the finished tags to
# sweep_extra.sh, which already owns the cold-slot protocol, the N=2->3->5
# escalation and the UNRESOLVED marker (#3036).
#
# ---------------------------------------------------------------------------
# Per base, resume-safe at every step:
#
#   1. download the HF snapshot            (skipped if the f16 already exists)
#   2. convert_hf_to_gguf.py -> f16 GGUF   (snapshot deleted straight after)
#   3. llama-quantize down each level      (skipped per level if present)
#   4. ollama create a tag per level
#   5. hand the tags to sweep_extra.sh for scoring
#   6. delete the f16 master unless KEEP_F16=1
#
# Re-running after an interruption picks up exactly where it stopped rather than
# re-downloading or re-converting anything already on disk. That matters: an f16
# of a 27B base is ~55 GB and of a 123B base ~245 GB.
#
# ---------------------------------------------------------------------------
# Toolchain: one container, no host installs.
#
#   ghcr.io/ggml-org/llama.cpp:full  carries convert_hf_to_gguf.py, gguf-py,
#   llama-quantize and llama-gguf-split. Verified on this host 2026-09-05.
#
# There is no llama.cpp checkout on the homeserver and no rex86-eval container,
# so the layout model-quant-benchmark/README.md documents does not exist here;
# do not try to use it.
#
# HF_TOKEN is read from ~/.cache/huggingface/token. Gated repos need it, and so
# does any snapshot download at a useful rate.
#
# Usage:
#   bash requant_sweep.sh                    # work the whole plan
#   PLAN=/path/to/plan.txt bash requant_sweep.sh
#   BUILD_ONLY=1 bash requant_sweep.sh       # build the ladder, don't score
set -u

BASE=${BASE:-/mnt-1/benchmarks}
WORK=${WORK:-$BASE/f16work}
RESULTS=${RESULTS:-$BASE/1947full}
REPO=${REPO:-$BASE/APIARY}
PLAN=${PLAN:-$BASE/f16_ladder_plan.txt}
TAGLIST=${TAGLIST:-$BASE/models_requant.txt}
IMAGE=${IMAGE:-ghcr.io/ggml-org/llama.cpp:full}
OLLAMA=${OLLAMA:-ghidra-ollama-1}
KEEP_F16=${KEEP_F16:-0}
BUILD_ONLY=${BUILD_ONLY:-0}
# An f16 master plus one quant level is the peak; leave room for the largest
# base in the plan rather than discovering the ceiling mid-convert.
MIN_FREE_GB=${MIN_FREE_GB:-400}

log() { echo "$(date -u +%FT%TZ) $*"; }
die() { log "ABORT: $*"; exit 1; }

free_gb() { df --output=avail -BG "$1" | tail -1 | tr -dc '0-9'; }

# --- preconditions, asserted not assumed ------------------------------------
[ -f "$PLAN" ] || die "no plan file at $PLAN"
[ -d "$REPO" ] || die "no pinned repo at $REPO"
head=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null) || die "$REPO is not a git checkout"
[ "$head" = "a99e765" ] || die "repo head is $head, not a99e765 -- a different scoring vintage would split the matrix (#1947 rule 6)"
command -v docker >/dev/null || die "no docker"
docker ps --format '{{.Names}}' | grep -qx "$OLLAMA" || die "$OLLAMA is not running"
[ -r "$HOME/.cache/huggingface/token" ] || die "no HF token at ~/.cache/huggingface/token -- snapshot downloads need it"
docker image inspect "$IMAGE" >/dev/null 2>&1 || { log "pulling $IMAGE"; docker pull "$IMAGE" >/dev/null || die "cannot pull $IMAGE"; }

mkdir -p "$WORK" "$RESULTS"
: > "$TAGLIST"

log "REQUANT_START plan=$PLAN pin=$head free=$(free_gb "$WORK")G"

# --- helpers ----------------------------------------------------------------

# Everything heavy runs in the toolchain container with $WORK bind-mounted.
# --user keeps the outputs owned by the invoking user: a root-owned file in a
# work tree is how #3024 bricked every CI runner, and the same trap applies here.
llama() { # <args...>
  docker run --rm \
    -u "$(id -u):$(id -g)" \
    -e HOME=/work \
    -v "$WORK:/work" \
    -v "$HOME/.cache/huggingface:/work/.cache/huggingface" \
    --entrypoint "$1" "$IMAGE" "${@:2}"
}

# Some published repos ship `extra_special_tokens` as a bare LIST where
# transformers requires a dict, and the conversion dies deep inside the
# tokenizer with a bare AttributeError:
#
#   tokenization_utils_base.py: self.SPECIAL_TOKENS_ATTRIBUTES + list(special_tokens.keys())
#   AttributeError: 'list' object has no attribute 'keys'
#
# Seen on llmfan46/gemma-4-26B-A4B-it-ultra-uncensored-heretic, whose own
# sibling field `model_specific_special_tokens` IS a correctly-formed dict
# ({"audio_token": "<|audio|>", "boi_token": "<|image>", ...}), so the intended
# shape is unambiguous and the list is simply malformed upstream.
#
# The token is real -- <|video|> is in tokenizer.json's vocab -- so DELETING the
# field would silently drop a token the weights know about. Re-key it instead,
# following the sibling field's own <|x|> -> x_token convention, and log the
# rewrite: this is a deviation from the published artifact and #1947 rule 5
# requires deviations to be recorded rather than quietly applied.
normalize_snapshot() { # snapshot_dir
  python3 - "$1" <<'EOF'
import json, pathlib, re, sys
p = pathlib.Path(sys.argv[1]) / "tokenizer_config.json"
if not p.exists():
    sys.exit(0)
cfg = json.loads(p.read_text())
v = cfg.get("extra_special_tokens")
if isinstance(v, list):
    fixed = {}
    for tok in v:
        m = re.fullmatch(r"<\|(.+?)\|>", str(tok))
        key = (m.group(1) if m else re.sub(r"\W+", "_", str(tok)).strip("_")) + "_token"
        fixed[key] = tok
    cfg["extra_special_tokens"] = fixed
    p.write_text(json.dumps(cfg, indent=2))
    print(f"NORMALIZED extra_special_tokens: list {v} -> dict {fixed}")
EOF
}

snapshot_dl() { # repo dest
  local repo="$1" dest="$2"
  docker run --rm \
    -u "$(id -u):$(id -g)" \
    -e HOME=/work -e HF_HUB_ENABLE_HF_TRANSFER=0 \
    -v "$WORK:/work" \
    -v "$HOME/.cache/huggingface:/work/.cache/huggingface" \
    --entrypoint python3 "$IMAGE" -c "
import os, sys
from huggingface_hub import snapshot_download
tok = open('/work/.cache/huggingface/token').read().strip()
snapshot_download(repo_id='$repo', local_dir='$dest', token=tok,
                  allow_patterns=['*.json','*.safetensors','*.model','*.txt','*.py'])
print('snapshot ok')
"
}

# --- the plan ---------------------------------------------------------------
# One line per base:
#   <hf_repo> | <space-separated quant levels> | <ollama tag prefix>
# e.g.
#   Qwen/Qwen3-32B | Q5_K_M Q4_K_M Q3_K_M | qwen3-32b-selfquant

# Trim with bash builtins, not `xargs`: xargs treats quotes as special, so an
# apostrophe anywhere in this file's prose comments makes it error out --
# noisily and, worse, it would mangle any plan value that contained one.
trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; printf '%s' "${s%"${s##*[![:space:]]}"}"; }

while IFS='|' read -r REPO_ID LEVELS PREFIX; do
  # comment/blank check happens BEFORE any processing of the line
  case "$(trim "${REPO_ID:-}")" in \#*|'') continue;; esac
  REPO_ID=$(trim "${REPO_ID:-}"); LEVELS=$(trim "${LEVELS:-}"); PREFIX=$(trim "${PREFIX:-}")
  [ -n "$LEVELS" ] && [ -n "$PREFIX" ] || { log "SKIP malformed plan line for '$REPO_ID'"; continue; }

  name=$(echo "$REPO_ID" | tr '/' '_')
  f16="$WORK/${name}-f16.gguf"
  snap="$WORK/${name}-snapshot"

  log "=== $REPO_ID -> $PREFIX (levels: $LEVELS) ==="

  # --- 1+2. snapshot -> f16, both skipped once the f16 exists ---------------
  if [ ! -f "$f16" ]; then
    free=$(free_gb "$WORK")
    [ "$free" -ge "$MIN_FREE_GB" ] || { log "SKIP $REPO_ID: only ${free}G free, need ${MIN_FREE_GB}G"; continue; }
    if [ ! -d "$snap" ]; then
      log "downloading snapshot $REPO_ID (${free}G free)"
      snapshot_dl "$REPO_ID" "/work/${name}-snapshot" || { log "SNAPSHOT_FAILED $REPO_ID"; rm -rf "$snap"; continue; }
    else
      log "snapshot already present, reusing"
    fi
    normalize_snapshot "$snap" | while read -r l; do log "$l"; done
    log "converting to f16"
    if ! llama python3 /app/convert_hf_to_gguf.py "/work/${name}-snapshot" \
           --outfile "/work/${name}-f16.gguf" --outtype f16; then
      log "CONVERT_FAILED $REPO_ID"; rm -f "$f16"; continue
    fi
    # The snapshot is quantize input only and is the bulk of the disk cost.
    rm -rf "$snap"
    log "f16 ready: $(du -h "$f16" | cut -f1)"
  else
    log "f16 already present: $(du -h "$f16" | cut -f1)"
  fi

  # --- 3+4. ladder ----------------------------------------------------------
  for lvl in $LEVELS; do
    out="$WORK/${name}-${lvl}.gguf"
    tag="${PREFIX}:$(echo "$lvl" | tr '[:upper:]' '[:lower:]')"

    if [ ! -f "$out" ]; then
      log "quantizing -> $lvl"
      if ! llama /app/llama-quantize "/work/${name}-f16.gguf" "/work/${name}-${lvl}.gguf" "$lvl"; then
        log "QUANT_FAILED $REPO_ID $lvl"; rm -f "$out"; continue
      fi
    fi
    log "$lvl on disk: $(du -h "$out" | cut -f1)"

    if docker exec "$OLLAMA" ollama list 2>/dev/null | awk '{print $1}' | grep -qixF "$tag"; then
      log "ollama tag already present: $tag"
    else
      # ollama create needs the GGUF inside its own volume; copy, import, drop.
      vol=$(docker inspect "$OLLAMA" --format '{{range .Mounts}}{{if eq .Destination "/root/.ollama"}}{{.Source}}{{end}}{{end}}')
      [ -n "$vol" ] || { log "cannot locate the ollama volume; skipping $tag"; continue; }
      sudo -n cp "$out" "$vol/requant-import.gguf" || { log "IMPORT_COPY_FAILED $tag"; continue; }
      printf 'FROM /root/.ollama/requant-import.gguf\n' | sudo -n tee "$vol/requant-import.Modelfile" >/dev/null
      if docker exec "$OLLAMA" ollama create "$tag" -f /root/.ollama/requant-import.Modelfile >/dev/null 2>&1; then
        log "created $tag"
      else
        log "OLLAMA_CREATE_FAILED $tag"
      fi
      sudo -n rm -f "$vol/requant-import.gguf" "$vol/requant-import.Modelfile"
    fi

    docker exec "$OLLAMA" ollama list 2>/dev/null | awk '{print $1}' | grep -qixF "$tag" \
      && echo "$tag" >> "$TAGLIST"
  done

  # --- 6. drop the f16 ------------------------------------------------------
  if [ "$KEEP_F16" != "1" ]; then
    rm -f "$f16"
    log "removed f16 master for $REPO_ID (free now $(free_gb "$WORK")G)"
  fi
done < "$PLAN"

log "LADDER_BUILT tags=$(wc -l < "$TAGLIST")"
[ -s "$TAGLIST" ] || { log "REQUANT_SWEEP_COMPLETE (nothing built)"; exit 0; }

if [ "$BUILD_ONLY" = "1" ]; then
  log "BUILD_ONLY set -- not scoring. Tags in $TAGLIST"
  log "REQUANT_SWEEP_COMPLETE"
  exit 0
fi

# --- 5. score, through the reviewed driver ----------------------------------
# Not a reimplementation: sweep_extra.sh owns the cold-slot protocol, the
# N=2->3->5 escalation and the UNRESOLVED marker, and using it is what keeps
# these rows comparable to the as-published ones. Locally created tags are never
# `ollama pull`ed, so its own "already local -> will not delete" branch protects
# the ladder we just spent hours building.
log "scoring $(wc -l < "$TAGLIST") tags via sweep_extra.sh"
LIST="$TAGLIST" BASE="$RESULTS" REPO="$REPO" bash "$BASE/sweep_extra.sh"

log "REQUANT_SWEEP_COMPLETE"
