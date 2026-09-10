#!/usr/bin/env bash
# chain_phase3.sh -- run phase 3's SCORING half once phase 2 has actually
# finished with the GPU.
#
# Operational copy lives at /var/benchmarks/chain_phase3.sh. Committed here
# because the previous generation of chain scripts (chain2b.sh, chain3.sh) were
# never committed, did not survive the rebuild, and took phases 2.5/3/5 with
# them (#2985).
#
# ---------------------------------------------------------------------------
# Why this does not wait on EXTRA_COMPLETE
#
# The old chain polled for the `EXTRA_COMPLETE` marker. That marker is written
# unconditionally at the end of the roster loop no matter how many entries
# failed, and it has now produced a false completion three separate times:
# once on the pull path, once on the Tier B path (#2971), and once when 12
# models in a row died to container DNS in four minutes and the sweep declared
# itself finished anyway (#3031).
#
# So this waits on the thing that is actually true or false -- whether every
# roster entry has both tier files, or is explicitly marked UNMEASURED /
# UNMEASURABLE -- and it refuses to start if the sweep is still alive.
#
# It also declines to start on a suspicious roster: if a large share of the
# roster is unmeasured, that is an infrastructure failure to investigate, not a
# green light to spend GPU hours on the next phase.
set -u

BASE=${BASE:-/var/benchmarks}
RESULTS=${RESULTS:-$BASE/1947full}
ROSTER=${ROSTER:-$BASE/models_extra_all.txt}
TAGLIST=${TAGLIST:-$BASE/models_requant.txt}
REPO=${REPO:-$BASE/APIARY}
MAX_WAIT_MIN=${MAX_WAIT_MIN:-2880}     # 48h
MAX_UNMEASURED_PCT=${MAX_UNMEASURED_PCT:-25}

log() { echo "$(date -u +%FT%TZ) $*"; }

roster_state() { # -> "done total unmeasured"
  python3 - "$ROSTER" "$RESULTS" <<'EOF'
import os, re, sys
roster = [l.strip() for l in open(sys.argv[1]) if l.strip() and not l.startswith("#")]
res = sys.argv[2]
slug = lambda t: re.sub(r"[^A-Za-z0-9._-]", "_", t)
done = unmeasured = 0
for t in roster:
    s = slug(t)
    if os.path.exists(f"{res}/tierA_{s}_run1.json") and os.path.exists(f"{res}/tierB_{s}_run1.json"):
        done += 1
    elif os.path.exists(f"{res}/UNMEASURED_{s}.status"):
        unmeasured += 1
print(done, len(roster), unmeasured)
EOF
}

log "PHASE3_CHAIN_ARMED roster=$ROSTER taglist=$TAGLIST"

for i in $(seq 1 "$MAX_WAIT_MIN"); do
  if ! pgrep -f "sweep_extra.sh" >/dev/null 2>&1 && ! pgrep -f "record_baseline.py" >/dev/null 2>&1; then
    read -r done total unmeasured <<<"$(roster_state)"
    if [ $((done + unmeasured)) -ge "$total" ]; then
      log "phase 2 settled: $done measured, $unmeasured unmeasured, $total total"
      break
    fi
    log "sweep not running but roster incomplete ($done+$unmeasured/$total) -- waiting, it may be between models"
  fi
  sleep 60
done

read -r done total unmeasured <<<"$(roster_state)"
if [ $((done + unmeasured)) -lt "$total" ]; then
  log "ABORT: phase 2 never settled ($done+$unmeasured/$total after ${MAX_WAIT_MIN}m)"
  exit 1
fi

pct=$(( unmeasured * 100 / (total > 0 ? total : 1) ))
if [ "$pct" -gt "$MAX_UNMEASURED_PCT" ]; then
  log "ABORT: $unmeasured/$total ($pct%) of the roster is UNMEASURED, over the ${MAX_UNMEASURED_PCT}% bar."
  log "       That is an infrastructure failure to investigate (see #3031), not a"
  log "       reason to start the next phase. Not spending GPU on it."
  exit 1
fi

if [ ! -s "$TAGLIST" ]; then
  log "ABORT: $TAGLIST is empty -- the ladder was never built. Run requant_sweep.sh first."
  exit 1
fi

log "scoring $(wc -l < "$TAGLIST") self-quantized tags"
cd "$BASE" || exit 1
LIST="$TAGLIST" BASE="$RESULTS" REPO="$REPO" bash "$BASE/sweep_extra.sh"
log "PHASE3_SCORING_COMPLETE"
