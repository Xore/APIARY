#!/usr/bin/env bash
# #2738: recover roster models Ollama's client-side hf.co name validation
# refuses to pull directly (repo-name segment > 80 chars -- see
# oversized-model-aliases.tsv's header for the full bisection). `ollama
# pull` and `ollama create ... FROM hf.co/...` both reject the reference
# before any network transfer; the only way around it is downloading the
# raw GGUF and importing it from a local file path, which never constructs
# an hf.co-shaped name Ollama has to validate.
#
# Usage:
#   scripts_dir=analysis/ghidra/benchmarks
#   $scripts_dir/recover-oversized-models.sh [--container NAME] [--cache-dir DIR] [alias ...]
#
# With no alias arguments, recovers every row in oversized-model-aliases.tsv.
# Re-running is idempotent: a model already present under its alias in
# `ollama list`, or a cache file already downloaded at the right size, is
# skipped/reused rather than redone.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mapping="$script_dir/oversized-model-aliases.tsv"
container="ghidra-ollama-1"
cache_dir="/mnt-1/benchmarks/oversized-model-cache"
only_aliases=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --container) container="$2"; shift 2 ;;
    --cache-dir) cache_dir="$2"; shift 2 ;;
    --mapping) mapping="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) only_aliases+=("$1"); shift ;;
  esac
done

[[ -f "$mapping" ]] || { echo "FATAL: mapping file not found: $mapping" >&2; exit 1; }
mkdir -p "$cache_dir"

wanted() {
  local alias="$1"
  [[ ${#only_aliases[@]} -eq 0 ]] && return 0
  local a
  for a in "${only_aliases[@]}"; do
    [[ "$a" == "$alias" ]] && return 0
  done
  return 1
}

recovered=0
skipped=0
failed=0

while IFS=$'\t' read -r alias upstream filename; do
  [[ -z "$alias" ]] && continue
  case "$alias" in \#*) continue ;; esac
  wanted "$alias" || continue

  echo "== $alias ($upstream) =="

  # -i: Ollama rewrites some quantisation-shaped tags to uppercase on write
  # (`ollama create x:q4_k_m` lands on disk as `x:Q4_K_M`; see
  # oversized-model-aliases.tsv's header for the measured set and for what
  # it does not cover), so the alias spelled in the mapping is not
  # guaranteed to be the spelling `ollama list` prints. Match
  # case-insensitively so this check can't drift out of sync with that again.
  if docker exec "$container" ollama list 2>/dev/null | awk '{print $1}' | grep -qixF "$alias"; then
    echo "already imported: $alias"
    skipped=$((skipped + 1))
    continue
  fi

  # upstream is "hf.co/<owner>/<repo>:<tag>" -- strip both to get the plain
  # HuggingFace repo id for the download URL. The tag (e.g. Q4_K_M) is not a
  # git revision on HF; it's how Ollama's own hf.co integration picks a
  # quant variant, which is exactly the resolution this script does by hand
  # via the mapping's explicit filename instead.
  hf_repo="${upstream#hf.co/}"
  hf_repo="${hf_repo%:*}"
  url="https://huggingface.co/${hf_repo}/resolve/main/${filename}"

  local_gguf="$cache_dir/${filename}"
  remote_size=$(curl -sIL "$url" | awk 'BEGIN{IGNORECASE=1} /^content-length:/{v=$2} END{gsub(/\r/,"",v); print v}')
  if [[ -z "$remote_size" || "$remote_size" -lt 1000000 ]]; then
    echo "FAIL: could not resolve a real download size for $url (got '$remote_size')" >&2
    failed=$((failed + 1))
    continue
  fi

  if [[ -f "$local_gguf" ]] && [[ "$(stat -c%s "$local_gguf" 2>/dev/null || echo 0)" == "$remote_size" ]]; then
    echo "cache hit: $local_gguf ($remote_size bytes)"
  else
    echo "downloading $filename ($remote_size bytes) ..."
    curl -fL --retry 5 --retry-delay 10 -C - -o "$local_gguf.part" "$url"
    mv "$local_gguf.part" "$local_gguf"
    actual_size=$(stat -c%s "$local_gguf")
    if [[ "$actual_size" != "$remote_size" ]]; then
      echo "FAIL: downloaded size $actual_size != expected $remote_size for $filename" >&2
      failed=$((failed + 1))
      continue
    fi
  fi

  echo "importing as $alias ..."
  docker cp "$local_gguf" "$container:/tmp/recover-${filename}"
  # $$ is this script's own PID -- only needs to be unique per invocation to
  # avoid two recoveries racing on the same Modelfile path, which they won't
  # (this script is not parallelized).
  modelfile="/tmp/recover-Modelfile-$$"
  docker exec "$container" sh -c "printf 'FROM /tmp/recover-%s\n' '$filename' > '$modelfile'"
  if ! docker exec "$container" ollama create "$alias" -f "$modelfile"; then
    echo "FAIL: ollama create $alias failed" >&2
    docker exec "$container" rm -f "/tmp/recover-${filename}" "$modelfile" 2>/dev/null || true
    failed=$((failed + 1))
    continue
  fi
  docker exec "$container" rm -f "/tmp/recover-${filename}" "$modelfile"

  if docker exec "$container" ollama list 2>/dev/null | awk '{print $1}' | grep -qixF "$alias"; then
    echo "confirmed: $alias is now in ollama list"
    recovered=$((recovered + 1))
  else
    echo "FAIL: ollama create reported success but $alias is not in ollama list" >&2
    failed=$((failed + 1))
  fi
done < "$mapping"

echo "recovered=$recovered skipped=$skipped failed=$failed"
[[ "$failed" -eq 0 ]]
