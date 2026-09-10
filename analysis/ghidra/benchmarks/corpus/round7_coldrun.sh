#!/usr/bin/env bash
# round7_coldrun.sh -- the round-7 cold baseline (#3079 / #3087): the WHOLE
# #1947 roster plus the #2245 self-quant ladder, measured ONCE on the round-7
# pin -- 17 cases / 79, injection gate v3, pooled-claims-ready transcripts --
# cold slot, live workers stopped, N=2 with automatic 3/5 escalation.
#
# Operational copy lives at /var/benchmarks/round7_coldrun.sh.
#
# ---------------------------------------------------------------------------
# Why this replaced coldrun.sh's a99e765 re-run (operator decision 2026-09-06)
#
# The a99e765 cold re-run would have spent 2-4 GPU-days re-measuring ~97 tags
# on a 14-case rubric whose top is saturated -- sixteen models within one
# point at 63-64/69, and the self-quant ladder scoring 62/62/62 at Q3/Q4/Q5 --
# and round 7 needed the same tags re-scored on the 17-case pin anyway as its
# controls. One cold pass on the new pin yields the regime-uniform matrix, the
# round-7 baseline for every as-shipped row, and the injection positive control
# (strcpy_note_neutral / strcpy_note_injected / process_witness_probe) that the
# old pin could never fire. The 13 models the old-pin run finished before it
# was stopped stay in 1947cold/ (ABORTED-2026-09-06.txt); they are valid cold
# cells on the OLD pin and must not be extended.
#
# Same driver underneath: sweep_extra.sh owns the protocol (cold slot, workers
# stopped and restored by trap, N=2 -> 3 -> 5, UNRESOLVED, UNMEASURED /
# UNMEASURABLE, free-space floor). This only chooses the pin, the Tier B cache,
# the roster and the output directory -- it is not a second scorer.
#
# Preconditions it refuses to run without:
#   - the round-7 clone is detached at exactly $PIN (one vintage per table)
#   - the 17-case Tier B cache exists (round7_cache.sh) -- every Tier B run
#     fails without it, and sweep_extra would still write MODEL_DONE (#2971)
#   - no other sweep holds the card
set -u
BASE=${BASE:-/var/benchmarks}
PIN=${PIN:-32dbdeb1}
REPO=${REPO:-$BASE/APIARY-round7}
OUT=${OUT:-$BASE/round7}
ROSTER=${ROSTER:-$BASE/models_round7.txt}
GHIDRA_CACHE=${GHIDRA_CACHE:-$BASE/tierb-cache-round7}
OPERATOR=${OPERATOR:-bg-round7}
log() { echo "$(date -u +%FT%TZ) $*"; }
# --- build the combined roster ---------------------------------------------
build_roster() {
  : > "$ROSTER"
  for f in "$BASE/models_all.txt" "$BASE/models_extra_all.txt" "$BASE/models_requant.txt"; do
    [ -f "$f" ] && grep -vE '^[[:space:]]*(#|$)' "$f" >> "$ROSTER"
  done
  # de-duplicate case-insensitively: Ollama resolves names that way, and the
  # rosters spell some quant-shaped tags differently (#2738).
  awk '{ k=tolower($0); if (!(k in seen)) { seen[k]=1; print } }' "$ROSTER" > "$ROSTER.tmp" \
    && mv "$ROSTER.tmp" "$ROSTER"
}
# --- preconditions ----------------------------------------------------------
head=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null) || { log "ABORT: $REPO is not a checkout"; exit 1; }
[ "$head" = "$PIN" ] || { log "ABORT: repo head is $head, not $PIN -- wrong scoring vintage"; exit 1; }
[ -f "$GHIDRA_CACHE/index.json" ] || { log "ABORT: $GHIDRA_CACHE has no index.json -- every Tier B run would fail (#2971)"; exit 1; }
entries=$(ls "$GHIDRA_CACHE"/*.json 2>/dev/null | grep -vc index.json)
[ "$entries" -ge 17 ] || { log "ABORT: Tier B cache holds $entries entries, need 17 (one per case on this pin)"; exit 1; }
# "/coldrun.sh" with the slash: this script's own command line ends in
# "round7_coldrun.sh" and a bare "coldrun[.]sh" pattern matched itself, which
# aborted the first launch on 2026-09-06.
if pgrep -f "sweep_extra[.]sh" >/dev/null 2>&1 || pgrep -f "record_baseline[.]py" >/dev/null 2>&1 \
   || pgrep -f "/coldrun[.]sh" >/dev/null 2>&1; then
  log "ABORT: a sweep is already running -- refusing to double-book the GPU"
  exit 1
fi
mkdir -p "$OUT/logs"
build_roster
n=$(wc -l < "$ROSTER")
free=$(df --output=avail -BG /var | tail -1 | tr -dc '0-9')
log "ROUND7_START models=$n pin=$head cache=$GHIDRA_CACHE results=$OUT /var_free=${free}G"
log "protocol: cold slot, live workers stopped, N=2 with 3/5 escalation, weights kept above the floor, 17 cases / 83"
STOP_WORKERS=1 KEEP_WEIGHTS_ABOVE_GB=${KEEP_WEIGHTS_ABOVE_GB:-1000} \
  LIST="$ROSTER" BASE="$OUT" REPO="$REPO" GHIDRA_CACHE="$GHIDRA_CACHE" OPERATOR="$OPERATOR" \
  bash "$BASE/sweep_extra.sh"
log "ROUND7_COMPLETE"
