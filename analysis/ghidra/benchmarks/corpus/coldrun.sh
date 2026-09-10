#!/usr/bin/env bash
# coldrun.sh -- re-measure the WHOLE #1947 roster under one uniform regime:
# cold slot, N=2 with automatic escalation, live workers stopped.
#
# Operational copy lives at /var/benchmarks/coldrun.sh.
#
# ---------------------------------------------------------------------------
# Why this exists
#
# The matrix currently mixes two regimes and #1947 rule 2 says two vintages must
# never share a table:
#
#   phases 1+2   89 models   contended (hp-llm-worker live), N=2, escalate on
#                            disagreement                     -> 1947full/
#   phase 4       5 models   cold, workers stopped, N=3, every cell +-0
#
# The cold probe under #3023 showed contention did not move scores -- a fully
# GPU-resident control reproduced [63,63] exactly, and an escalated spilling cell
# resolved to the majority the protocol had already chosen. So this is not a
# correction of wrong numbers; it is making the regime uniform so the table is
# defensible, because the top of the field is separated by ONE point across
# sixteen models and a promotion decided on that margin cannot rest on a mixed
# protocol.
#
# N=2, not N=3. The part-4 round found "22.1 of the 37.4 model-wall hours
# re-derived identical bytes", and concluded repeats belong on the axes that are
# NOT fixed -- seed, quant, prompt phrasing. #3036 now escalates 2 -> 3 -> 5
# automatically wherever runs actually disagree, so genuine variance is still
# caught without paying a third run on every deterministic cell.
#
# ---------------------------------------------------------------------------
# Results land in a SEPARATE directory
#
# 1947cold/ rather than 1947full/. The contended numbers are not garbage and are
# not overwritten: contended-vs-cold across 89 models is itself the largest
# evidence anyone will ever have about whether the regime matters, and throwing
# it away to save disk would be the same mistake as deleting the weights.
set -u

BASE=${BASE:-/var/benchmarks}
COLD=${COLD:-$BASE/1947cold}
ROSTER=${ROSTER:-$BASE/models_cold_all.txt}
REPO=${REPO:-$BASE/APIARY}

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
[ "$head" = "a99e765" ] || { log "ABORT: repo head is $head, not a99e765 -- wrong scoring vintage"; exit 1; }
[ -d "$BASE/tierb-cache" ] || { log "ABORT: tierb-cache missing -- every Tier B run would fail (#2971)"; exit 1; }
if pgrep -f "sweep_extra.sh" >/dev/null 2>&1 || pgrep -f "record_baseline.py" >/dev/null 2>&1; then
  log "ABORT: a sweep is already running -- refusing to double-book the GPU"
  exit 1
fi

mkdir -p "$COLD/logs"
build_roster
n=$(wc -l < "$ROSTER")
free=$(df --output=avail -BG /var | tail -1 | tr -dc '0-9')
log "COLDRUN_START models=$n pin=$head results=$COLD /var_free=${free}G"
log "protocol: cold slot, live workers stopped, N=2 with 3/5 escalation, weights kept above the floor"

# sweep_extra.sh owns the protocol; this only chooses the roster, the output
# directory and the regime flags. Not a second scorer -- that is the whole point.
STOP_WORKERS=1 KEEP_WEIGHTS_ABOVE_GB=${KEEP_WEIGHTS_ABOVE_GB:-1000} \
  LIST="$ROSTER" BASE="$COLD" REPO="$REPO" bash "$BASE/sweep_extra.sh"

log "COLDRUN_COMPLETE"
