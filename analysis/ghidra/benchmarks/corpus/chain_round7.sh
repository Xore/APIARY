#!/usr/bin/env bash
# chain_round7.sh -- #3087: fire the round-7 slot sweeps once every round-7
# roster tag is measured on the ghidra slot AND the GPU work area is idle.
#
# Operational copy: /mnt-1/benchmarks/chain_round7.sh.
#
# ---------------------------------------------------------------------------
# Why the wait condition is POSITIVE, not "is the GPU idle" -- the same
# reasoning chain_cold.sh documents, applied to this round:
#
# round7_coldrun.sh is already armed and waiting for (or holding) the same
# card. A "nothing is running" trigger would fire the moment the cold run
# paused between models and double-book the GPU. So this waits on a condition
# that can only be true AFTER the cold baseline is COMPLETE:
#
#   every tag in models_round7.txt has both tier files
#   (tierA_<slug>_run1.json + tierB_<slug>_run1.json) OR an
#   UNMEASURED_slots.../UNMEASURED_<slug>.status marker in
#   /mnt-1/benchmarks/round7/
#
# ...AND no sweep_extra.sh / round7_coldrun.sh's own drivers
# (coldrun.sh) / record_baseline.py process is alive. Both must hold at once:
# a complete matrix with record_baseline.py still running is a run in flight,
# not a finished one. sweep_extra.sh carries its own "already running" guard
# as the second line of defence.
set -u

BASE=${BASE:-/mnt-1/benchmarks}
RESULTS=${RESULTS:-$BASE/round7}
TAGLIST=${TAGLIST:-$BASE/models_round7.txt}
MAX_WAIT_MIN=${MAX_WAIT_MIN:-10080}   # 7 days: the cold run alone is 2-4
KEEP_WEIGHTS_ABOVE_GB=${KEEP_WEIGHTS_ABOVE_GB:-1000}

log() { echo "$(date -u +%FT%TZ) $*"; }

# Gate: 0 only when every roster tag is measured-or-marked.
# Every tag needs both tier files OR a settled state: UNMEASURED_<slug>.status
# (sweep_extra.sh's pull-fail / giveup marker), .txt (older marker spelling),
# or a plain UNMEASURED marker file in the results dir. Also accept a
# directory-form marker and UNRESOLVED markers -- a cell the harness ran
# N=5 times with no majority has a recorded, reviewable state too.
# Same slug derivation as sweep_extra.sh's scoring loop (tr ':/' '__',
# case-preserving) -- a completion gate and the run that produces the files
# must name a cell identically or the gate never fires for it.
roster_done() {
  python3 - "$TAGLIST" "$RESULTS" <<'EOF'
import os, sys
tags = [l.strip() for l in open(sys.argv[1]) if l.strip() and not l.startswith("#")]
res = sys.argv[2]
def slug(t):
    return t.replace(":", "_").replace("/", "_")
for t in tags:
    s = slug(t)
    if os.path.exists(f"{res}/tierA_{s}_run1.json") and os.path.exists(f"{res}/tierB_{s}_run1.json"):
        continue
    settled = any(
        os.path.exists(f"{res}/{p}")
        for p in (f"UNMEASURED_{s}.status", f"UNMEASURED_{s}.txt", "UNMEASURED",
                  f"UNRESOLVED_tierA_{s}.status", f"UNRESOLVED_tierB_{s}.status")
    )
    if settled:
        continue
    print(f"pending: {t}")
    sys.exit(1)
print(f"roster complete: {len(tags)} tags measured or marked")
EOF
}

slot_idle() {
  ! pgrep -f "sweep_extra[.]sh" >/dev/null 2>&1 \
    && ! pgrep -f "/coldrun[.]sh" >/dev/null 2>&1 \
    && ! pgrep -f "record_baseline[.]py" >/dev/null 2>&1
}

[ -s "$TAGLIST" ] || { log "ABORT: $TAGLIST is empty -- nothing to wait for"; exit 1; }
log "ROUND7_CHAIN_ARMED waiting for the round-7 roster in $TAGLIST"

for _ in $(seq 1 "$MAX_WAIT_MIN"); do
  if roster_done >/dev/null; then
    if slot_idle; then
      log "roster measured and the slot is idle -- firing the slots sweeps"
      break
    fi
    log "roster measured but a run is still in flight -- waiting"
  fi
  sleep 60
done

if ! roster_done >/dev/null; then
  roster_done
  log "ABORT: round-7 roster still incomplete after ${MAX_WAIT_MIN}m"
  exit 1
fi
if ! slot_idle; then
  log "ABORT: slot still busy after the roster completed -- rerun this chain"
  exit 1
fi

# sampler first (keep_and_sample.sh is read-mostly and exits on pkill only)
pgrep -f "keep_and_sample[.]sh" >/dev/null 2>&1 || \
  { setsid nohup bash "$BASE/keep_and_sample.sh" >> "$BASE/keepsample.log" 2>&1 < /dev/null & }
cd "$BASE" || exit 1
# The corpus slot is already done (that is the wait condition); this runs the
# sessions+Rev·Deck leg, then the driver is done.
LIST="$TAGLIST" OUT="${OUT:-$BASE/round7/slots}" KEEP_WEIGHTS_ABOVE_GB="$KEEP_WEIGHTS_ABOVE_GB" \
  bash "$BASE/slots_sweep.sh"
log "ROUND7_CHAIN_COMPLETE"
