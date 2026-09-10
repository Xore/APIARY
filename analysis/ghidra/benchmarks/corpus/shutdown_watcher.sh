#!/usr/bin/env bash
# shutdown_watcher.sh -- #2985: lost in the same rebuild as gptoss_rerun.sh/
# requant_sweep.sh/slots_sweep.sh, never committed before now. Operational
# copy lives at /var/benchmarks/shutdown_watcher.sh.
#
# Written for the a99e765 sweep's RAM install, which was superseded by the
# 2026-09-06 abort (round 7, epic #3079) before it ran -- per project record
# the RAM install itself still has not landed (CPU swap + 6.5T /var did). The
# FULLRUN_COMPLETE/chain.sh gate below is specific to that generation; a
# future RAM install during round 7 needs its gate rewritten against
# round7_coldrun.sh. Committed for the record and as a template, not live.
#
# Wait for the in-flight 38-model corpus sweep to finish, stop the chain before
# it starts the extra roster, then power the box down for a RAM install.
#
# The point of the gate is that phases 2-4 (extra roster, requant, slots) are the
# multi-day part and the ones that touch the largest models -- they should run on
# the upgraded machine, not this one. So this deliberately does NOT let chain.sh
# fire; it kills the waiters instead.
#
# On timeout it does NOT shut down. A stalled sweep is something to look at, not
# something to power off underneath.
set -u
LOG=/var/benchmarks/shutdown_watcher.log
exec >>"$LOG" 2>&1
echo "=== $(date -u +%FT%TZ) watcher armed; waiting for FULLRUN_COMPLETE ==="

DEADLINE=$(( $(date +%s) + 14*3600 ))
while :; do
  grep -q FULLRUN_COMPLETE /var/benchmarks/fullrun.log 2>/dev/null && break
  if [ "$(date +%s)" -ge "$DEADLINE" ]; then
    echo "$(date -u +%FT%TZ) TIMEOUT after 14h -- sweep did not complete. NOT shutting down."
    touch /var/benchmarks/WATCHER_TIMED_OUT
    exit 1
  fi
  sleep 60
done
echo "$(date -u +%FT%TZ) FULLRUN_COMPLETE seen"

# stop the chain before it launches the extra roster
for pat in '/var/benchmarks/chain.sh' '/var/benchmarks/chain2b.sh' 'chain3.sh' \
           '/var/benchmarks/sweep_extra.sh' '/var/benchmarks/requant_sweep.sh' \
           '/var/benchmarks/slots_sweep.sh'; do
  pkill -f "$pat" 2>/dev/null && echo "  killed: $pat"
done
sleep 5
echo "$(date -u +%FT%TZ) remaining benchmark procs:"
pgrep -af 'record_baseline|evaluate-models|sweep_extra|requant_sweep|slots_sweep|chain' || echo "  (none)"

# snapshot what we finished with, so the state is readable after the reboot
{
  echo "phase 1 halted for RAM install at $(date -u +%FT%TZ)"
  echo "models MODEL_DONE: $(grep -c MODEL_DONE /var/benchmarks/fullrun.log)"
  echo "result files: $(ls /var/benchmarks/1947full/*.json 2>/dev/null | wc -l)"
  echo "  tierA: $(ls /var/benchmarks/1947full/tierA_*.json 2>/dev/null | wc -l)"
  echo "  tierB: $(ls /var/benchmarks/1947full/tierB_*.json 2>/dev/null | wc -l)"
  echo "repo head (must stay pinned until phase 3 ends): $(git -C /var/benchmarks/APIARY rev-parse --short HEAD) on $(git -C /var/benchmarks/APIARY rev-parse --abbrev-ref HEAD)"
} > /var/benchmarks/PHASE1_SNAPSHOT.txt
cat /var/benchmarks/PHASE1_SNAPSHOT.txt

# unload the GPU so nothing is mid-write, then stop the stateful containers with a
# real timeout -- the default 10s is not enough for Elasticsearch to close cleanly
docker exec ghidra-ollama-1 ollama ps 2>/dev/null | awk 'NR>1{print $1}' | while read -r m; do
  [ -n "$m" ] && docker exec ghidra-ollama-1 ollama stop "$m" 2>/dev/null
done
echo "$(date -u +%FT%TZ) stopping stateful containers gracefully"
for c in hp-elasticsearch hp-kibana hp-keycloak-postgres ghosts-ghosts-postgres-1 dashkcnext-pg-85793; do
  docker stop -t 180 "$c" 2>/dev/null && echo "  stopped $c"
done

echo "$(date -u +%FT%TZ) POWERING OFF for RAM install"
sync
sudo -n systemctl poweroff
