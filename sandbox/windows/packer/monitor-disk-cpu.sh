#!/usr/bin/env bash
# monitor-disk-cpu.sh -- cron helper for #288, run every few minutes while a
# golden-image build is in flight. Logs qcow2 size (to catch the "stuck at
# 97.8MB, zero growth" signature from #288) and the qemu process's CPU%.
set -euo pipefail

OUT="/var/dockge/sandbox/golden-images/win11-analysis.qcow2"
LOG="/var/dockge/sandbox/monitor-disk-cpu.log"
ts="$(date -u +%FT%TZ)"

if [[ -f "$OUT" ]]; then
  size="$(stat -c %s "$OUT")"
else
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

echo "${ts} qcow2_bytes=${size} qemu_cpu%=${cpu} qemu_mem%=${mem} qemu_uptime_s=${etimes}" >> "$LOG"
