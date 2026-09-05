#!/usr/bin/env bash
# keep_and_sample.sh -- runs alongside sweep_extra.sh, changes nothing about it.
#
# Two jobs, both read-mostly:
#
# 1. RE-CREATE THE LOST SAMPLER (#2245). /mnt-1/benchmarks/vram_samples.tsv was
#    the empirical record of served size and CPU/GPU split per model -- the input
#    #2245's category-1 "which models actually spill" list was supposed to rest
#    on. It was wiped with the rest of the work area (#2971) and is in no mirror,
#    and the result JSONs record no VRAM at all, so it cannot be re-derived after
#    the fact. Sample `ollama ps` while each model is loaded or it is lost again.
#
# 2. STOP LOSING THE REQUANT INPUTS. sweep_extra.sh:153 does `ollama rm "$TAG"`
#    on every tag it pulled -- correct when /var was at 92%, wrong now that it
#    has 6.5T free, and actively destructive to #2245: all ten sources named in
#    requant_plan.txt have already been deleted this way. `ollama cp` makes a
#    second manifest over the SAME blobs (verified: cp+rm of the copy left the
#    blob count unchanged), so a keep-alias costs no disk and survives the
#    sweep's rm of the roster tag.
#
# Deliberately does NOT edit sweep_extra.sh: bash reads a running script lazily
# by byte offset, and the keep-aliases use names no roster entry can match, so
# the sweep's own "already local -> will not delete" test at line 119 is
# unaffected either way.
#
# Stop with: pkill -f keep_and_sample.sh   (leaves every alias in place)
set -u
OLLAMA=ghidra-ollama-1
SAMPLES=/mnt-1/benchmarks/vram_samples.tsv
KEPT=/mnt-1/benchmarks/kept-aliases.tsv
INTERVAL=60

oll() { docker exec "$OLLAMA" ollama "$@" 2>/dev/null; }

[ -f "$SAMPLES" ] || printf 'ts\tname\tsize\tprocessor\tcontext\n' > "$SAMPLES"
[ -f "$KEPT" ] || printf 'ts\troster_tag\tkeep_alias\n' > "$KEPT"

echo "$(date -u +%FT%TZ) KEEPSAMPLE_START interval=${INTERVAL}s"

while true; do
  ts=$(date -u +%FT%TZ)

  # --- 1. sample whatever is resident right now -------------------------------
  # `ollama ps` columns, whitespace-separated:
  #   $1 NAME  $2 ID  $3+$4 SIZE ("57 GB")  $5+$6 PROCESSOR ("65%/35% CPU/GPU")
  #   $7 CONTEXT  $8.. UNTIL
  # SIZE is the *served* footprint (weights + KV at the served context), which
  # is the number #2245 needs -- not the on-disk GGUF size. PROCESSOR is the
  # spill: anything not "100% GPU" is a category-1 requantization candidate.
  oll ps | tail -n +2 | awk -v ts="$ts" 'NF>=7 {
      printf "%s\t%s\t%s %s\t%s %s\t%s\n", ts, $1, $3, $4, $5, $6, $7
    }' >> "$SAMPLES"

  # --- 2. keep-alias anything new the sweep pulled ----------------------------
  oll list | tail -n +2 | awk '{print $1}' | while IFS= read -r tag; do
    [ -z "$tag" ] && continue
    case "$tag" in keep/*) continue;; esac
    slug=$(printf '%s' "$tag" | tr ':/' '__' | tr '[:upper:]' '[:lower:]')
    alias="keep/${slug}:src"
    if ! oll list | awk '{print $1}' | grep -qixF "$alias"; then
      if oll cp "$tag" "$alias" >/dev/null 2>&1; then
        printf '%s\t%s\t%s\n' "$ts" "$tag" "$alias" >> "$KEPT"
        echo "$ts KEPT $tag -> $alias"
      fi
    fi
  done

  sleep "$INTERVAL"
done
