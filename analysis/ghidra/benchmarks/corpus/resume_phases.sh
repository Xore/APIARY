#!/usr/bin/env bash
# resume_phases.sh -- #2985: lost in the same rebuild as gptoss_rerun.sh/
# requant_sweep.sh/slots_sweep.sh, never committed before now. Operational
# copy lives at /mnt-1/benchmarks/resume_phases.sh.
#
# Status: historical. Written to resume the a99e765 cold sweep after a RAM
# install; that sweep was aborted by operator decision on 2026-09-06 (folded
# into round 7, epic #3079 -- see halt_oldpin2.sh's ABORTED marker) before the
# RAM install happened, so the HEAD==a99e765 guard below can never pass again.
# Committed for the record, not as a live procedure. A RAM install resume for
# round 7 needs a script written against round7_coldrun.sh, not this one.
#
# Restart benchmark phases 2-4 after the RAM install.
#
# Relaunches the three original waiters unchanged rather than a rewritten chain:
# chain.sh polls for FULLRUN_COMPLETE, which is already in the log, so it breaks
# out on its first iteration and execs sweep_extra.sh -- keeping the gemma
# quant-ladder step it does on the way through. chain2b and chain3 then pick up
# on EXTRA_COMPLETE / REQUANT_SWEEP_COMPLETE as before.
set -u
cd /mnt-1/benchmarks || exit 1

echo "=== $(date -u +%FT%TZ) resume ==="

# the pinned head is load-bearing: post-merge main defaults to 17 corpus cases
# against the 14 this sweep measured, which would split the matrix down the middle
HEAD=$(git -C /mnt-1/benchmarks/APIARY rev-parse --short HEAD)
BRANCH=$(git -C /mnt-1/benchmarks/APIARY rev-parse --abbrev-ref HEAD)
echo "repo: $HEAD on $BRANCH"
if [ "$HEAD" != "a99e765" ]; then
  echo "ABORT: repo head moved off a99e765. Phases 2-3 must run on the same case"
  echo "       slice as phase 1. Reset it before resuming."
  exit 1
fi

if ! grep -q FULLRUN_COMPLETE /mnt-1/benchmarks/fullrun.log 2>/dev/null; then
  echo "ABORT: fullrun.log has no FULLRUN_COMPLETE -- phase 1 is not finished."
  exit 1
fi

# ollama comes back with the stack (unless-stopped) but not instantly
for i in $(seq 1 60); do
  curl -sf -m 5 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break
  [ "$i" = 60 ] && { echo "ABORT: ollama not responding after 5 min"; exit 1; }
  sleep 5
done
echo "ollama up; $(docker exec ghidra-ollama-1 ollama list 2>/dev/null | tail -n +2 | wc -l) models local"

for s in chain chain2b chain3; do
  if pgrep -f "/mnt-1/benchmarks/$s.sh" >/dev/null 2>&1; then
    echo "ABORT: $s.sh already running -- refusing to double-start the GPU queue"
    exit 1
  fi
done

cd /mnt-1/benchmarks
setsid nohup bash /mnt-1/benchmarks/chain.sh   >> /mnt-1/benchmarks/extra.log   2>&1 < /dev/null &
# 2026-09-05 (#1947 review): only launch a waiter whose downstream script
# still exists. gptoss_rerun.sh / requant_sweep.sh / slots_sweep.sh were lost
# in the rebuild and were never committed, so chain2b/chain3 would otherwise
# sit for 14 days on markers nothing can write and report as "running".
if [ -f /mnt-1/benchmarks/gptoss_rerun.sh ] && [ -f /mnt-1/benchmarks/requant_sweep.sh ]; then
  setsid nohup bash /mnt-1/benchmarks/chain2b.sh >> /mnt-1/benchmarks/requant.log 2>&1 < /dev/null &
else
  echo "SKIP chain2b: gptoss_rerun.sh/requant_sweep.sh missing -- phases 2.5/3 not queued"
fi
if [ -f /mnt-1/benchmarks/slots_sweep.sh ]; then
  setsid nohup bash /mnt-1/benchmarks/chain3.sh  >> /mnt-1/benchmarks/slots.log   2>&1 < /dev/null &
else
  echo "SKIP chain3: slots_sweep.sh missing -- phase 5 not queued"
fi
sleep 3
echo "relaunched:"
pgrep -af '/mnt-1/benchmarks/chain' || echo "  (nothing came up -- check the logs)"
echo "phase 2 (49-model extra roster) is now running; requant and slots chain behind it."
