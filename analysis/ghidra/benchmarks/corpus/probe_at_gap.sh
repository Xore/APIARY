#!/usr/bin/env bash
# probe_at_gap.sh -- run coldprobe.sh in the next natural gap of the phase-2
# sweep, then put the sweep back.
#
# The gap matters: the probe must measure a genuinely uncontended slot, so it
# cannot run alongside sweep_extra.sh. But sweep_extra must not be killed
# mid-run either -- do_run's own `rm -f "$out"` cleanup is skipped when the
# parent dies, which is how the 2026-08-31 abort left a valid-looking partial
# result carrying 11 of 14 cases (see STATE-2026-08-31-cpu-swap.md).
#
# So: wait for the next MODEL_DONE, stop the sweep's driver only, let any
# in-flight run finish on its own, probe, then relaunch. sweep_extra skips
# every model that already has both tier run1 files, so the relaunch resumes
# exactly where it stopped.
set -u
BASE=/mnt-1/benchmarks
LOG=$BASE/probe_at_gap.log

say() { echo "$(date -u +%FT%TZ) $*" | tee -a "$LOG"; }

baseline=$(grep -c MODEL_DONE "$BASE/extra.log")
say "ARMED baseline_model_done=$baseline"

# 1. wait for the sweep to finish its current model (up to 6h)
for _ in $(seq 1 720); do
  [ "$(grep -c MODEL_DONE "$BASE/extra.log")" -gt "$baseline" ] && break
  sleep 30
done
[ "$(grep -c MODEL_DONE "$BASE/extra.log")" -gt "$baseline" ] || { say "TIMEOUT waiting for MODEL_DONE -- doing nothing"; exit 1; }
say "GAP model finished: $(grep MODEL_DONE "$BASE/extra.log" | tail -1)"

# 2. stop the driver only, never an in-flight record_baseline
pkill -f "$BASE/sweep_extra.sh" 2>/dev/null
pkill -f "bash sweep_extra.sh"  2>/dev/null
sleep 3
say "driver stopped (sweep_extra procs now: $(pgrep -cf sweep_extra.sh))"

# 3. let any run that was already started finish by itself (up to 3h)
for _ in $(seq 1 360); do
  pgrep -f record_baseline.py >/dev/null || break
  sleep 30
done
pgrep -f record_baseline.py >/dev/null && { say "ABORT: a record_baseline is still in flight after 3h"; exit 1; }
say "slot is idle -- starting cold probe"

# 4. probe
bash "$BASE/coldprobe.sh" 2>&1 | tee -a "$LOG"
say "COLDPROBE finished rc=$?"

# 5. put the sweep back
cd "$BASE" || exit 1
setsid nohup bash "$BASE/sweep_extra.sh" >> "$BASE/extra.log" 2>&1 < /dev/null &
sleep 5
say "sweep relaunched (procs: $(pgrep -cf sweep_extra.sh))"
