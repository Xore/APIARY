#!/usr/bin/env bash
# monitor-disk-cpu.sh -- cron helper for #288, run every few minutes while a
# golden-image build is in flight. Logs qcow2 size (to catch the "stuck at
# 97.8MB, zero growth" signature from #288) and the qemu process's CPU%.
set -euo pipefail

FINAL_OUT="/var/dockge/sandbox/golden-images/win11-analysis.qcow2"
# build-with-retry.sh builds into this scratch dir and only moves the
# artifact into FINAL_OUT on success (its own "output directory already
# exists" workaround) -- while a build is in flight this is the file that is
# actually growing; FINAL_OUT still holds the previous golden image.
SCRATCH_OUT="/var/dockge/sandbox/golden-images/.build-tmp-win11-analysis/win11-analysis.qcow2"
LOG="/var/dockge/sandbox/monitor-disk-cpu.log"
ts="$(date -u +%FT%TZ)"

if [[ -f "$SCRATCH_OUT" ]]; then
  OUT="$SCRATCH_OUT"
  size="$(stat -c %s "$OUT")"
elif [[ -f "$FINAL_OUT" ]]; then
  OUT="$FINAL_OUT"
  size="$(stat -c %s "$OUT")"
else
  OUT="$FINAL_OUT"
  size="MISSING"
fi

qemu_line="$(ps -eo pid,pcpu,pmem,etimes,cmd | grep '[q]emu-system.*win11-analysis' | head -1 || true)"
if [[ -n "$qemu_line" ]]; then
  cpu="$(awk '{print $2}' <<<"$qemu_line")"
  mem="$(awk '{print $3}' <<<"$qemu_line")"
  etimes="$(awk '{print $4}' <<<"$qemu_line")"
else
  cpu="NOPROC"; mem="NOPROC"; etimes="NOPROC"
fi

echo "${ts} qcow2_bytes=${size} qcow2_path=${OUT} qemu_cpu%=${cpu} qemu_mem%=${mem} qemu_uptime_s=${etimes}" >> "$LOG"
