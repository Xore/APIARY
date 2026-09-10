#!/usr/bin/env bash
# round7_sweep.sh -- drive the round-7 ghidra-slot scoring for a list of tags
# through sweep_extra.sh, the ONE owner of the cold protocol (cold slot,
# STOP_WORKERS, N=2 -> 3 -> 5 escalation with UNRESOLVED, keep_and_sample.sh,
# uptime per run, KEEP_WEIGHTS_ABOVE_GB). Not a second scorer -- that is the
# whole point; this only chooses the roster, the output directory and the
# regime flags, exactly as round7_coldrun.sh does.
#
# Operational copy: /var/benchmarks/round7_sweep.sh.
#
#   LIST=/var/benchmarks/models_round7.txt RESULTS=/var/benchmarks/round7 \
#     STOP_WORKERS=1 bash round7_sweep.sh
#
# Results land beside the running cold baseline's own output when RESULTS
# points there: sweep_extra.sh is resume-safe per tag and per run (it skips
# anything already measured and writes UNMEASURED / UNRESOLVED markers), so
# rows scored as artefacts land fill in the same matrix the chain aggregates.
set -u

BASE=${BASE:-/var/benchmarks}
RESULTS=${RESULTS:-$BASE/round7}
REPO=${REPO:-$BASE/APIARY-round7}
STOP_WORKERS=${STOP_WORKERS:-1}
KEEP_WEIGHTS_ABOVE_GB=${KEEP_WEIGHTS_ABOVE_GB:-1000}
# Round-7 roster: concrete tags (see the file header). The sweep driver
# consumes LIST verbatim, so it must be set before use.
LIST=${LIST:-$BASE/models_round7.txt}

log() { echo "$(date -u +%FT%TZ) $*"; }

[ -s "$LIST" ] || { log "ABORT: LIST=$LIST is empty -- nothing to score"; exit 1; }
head=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null) || { log "ABORT: $REPO is not a checkout"; exit 1; }
[ "$head" = "${PIN:-32dbdeb1}" ] || { log "ABORT: repo head is $head, not ${PIN:-32dbdeb1} -- wrong scoring vintage"; exit 1; }
if pgrep -f "sweep_extra[.]sh" >/dev/null 2>&1 || pgrep -f "record_baseline[.]py" >/dev/null 2>&1; then
  log "ABORT: a sweep is already running -- refusing to double-book the GPU"
  exit 1
fi

mkdir -p "$RESULTS/logs"
log "ROUND7_SWEEP_START list=$LIST results=$RESULTS pin=$head"
STOP_WORKERS="$STOP_WORKERS" KEEP_WEIGHTS_ABOVE_GB="$KEEP_WEIGHTS_ABOVE_GB" \
  LIST="$LIST" BASE="$RESULTS" REPO="$REPO" GHIDRA_CACHE="${GHIDRA_CACHE:-$BASE/tierb-cache-round7}" \
  OPERATOR="${OPERATOR:-bg-round7}" \
  bash "$BASE/sweep_extra.sh"
log "ROUND7_SWEEP_COMPLETE"
