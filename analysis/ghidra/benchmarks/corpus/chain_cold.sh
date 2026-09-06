#!/usr/bin/env bash
# chain_cold.sh -- start the full cold re-run once phase 3's scoring is done.
#
# Operational copy lives at /mnt-1/benchmarks/chain_cold.sh.
#
# ---------------------------------------------------------------------------
# Why the wait condition is positive, not "is the GPU idle"
#
# chain_phase3.sh is already armed and waiting for the same GPU. If both waiters
# used "no sweep is running" they would fire in the same poll window and
# double-book the card -- and the loser would either corrupt the winner's timings
# or die on coldrun.sh's own guard, depending on ordering.
#
# So this waits on a condition that can only become true AFTER phase 3 has
# finished: every tag in models_requant.txt has both tier files. That is
# unambiguous, survives a restart of either chain, and cannot be satisfied early.
#
# coldrun.sh still carries its own "a sweep is already running" guard as a
# second line of defence. Two independent checks, because the failure mode here
# is a wasted day of GPU rather than an error message.
set -u

BASE=${BASE:-/mnt-1/benchmarks}
RESULTS=${RESULTS:-$BASE/1947full}
TAGLIST=${TAGLIST:-$BASE/models_requant.txt}
MAX_WAIT_MIN=${MAX_WAIT_MIN:-4320}   # 72h

log() { echo "$(date -u +%FT%TZ) $*"; }

ladder_scored() {
  python3 - "$TAGLIST" "$RESULTS" <<'EOF'
import os, re, sys
tags = [l.strip() for l in open(sys.argv[1]) if l.strip()]
res = sys.argv[2]
slug = lambda t: re.sub(r"[^A-Za-z0-9._-]", "_", t)
done = sum(1 for t in tags
           if os.path.exists(f"{res}/tierA_{slug(t)}_run1.json")
           and os.path.exists(f"{res}/tierB_{slug(t)}_run1.json"))
print(done, len(tags))
EOF
}

[ -s "$TAGLIST" ] || { log "ABORT: $TAGLIST is empty -- nothing to wait for"; exit 1; }
log "COLD_CHAIN_ARMED waiting for the ladder in $TAGLIST to be scored"

for _ in $(seq 1 "$MAX_WAIT_MIN"); do
  read -r done total <<<"$(ladder_scored)"
  if [ "$done" -ge "$total" ] && [ "$total" -gt 0 ]; then
    if ! pgrep -f "sweep_extra.sh" >/dev/null 2>&1 && ! pgrep -f "record_baseline.py" >/dev/null 2>&1; then
      log "ladder scored ($done/$total) and the slot is idle"
      break
    fi
    log "ladder scored ($done/$total) but a run is still in flight -- waiting"
  fi
  sleep 60
done

read -r done total <<<"$(ladder_scored)"
if [ "$done" -lt "$total" ]; then
  log "ABORT: ladder still incomplete ($done/$total) after ${MAX_WAIT_MIN}m"
  exit 1
fi

log "starting the full cold re-run"
cd "$BASE" || exit 1
bash "$BASE/coldrun.sh"
log "COLD_CHAIN_COMPLETE"
