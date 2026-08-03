#!/usr/bin/env bash
# monitor-screenshot.sh -- cron helper for #288, run on its own (coarser)
# interval from monitor-disk-cpu.sh. Grabs a VNC screenshot of the in-flight
# build so a black-screen/stuck-at-boot-prompt hang (per #288's prior
# incidents) is visible directly, not just inferred from disk growth.
set -euo pipefail

SHOTDIR="/var/dockge/sandbox/build-screenshots"
mkdir -p "$SHOTDIR"
ts="$(date -u +%Y%m%dT%H%M%SZ)"

vnc_port="$(ss -ltnp 2>/dev/null | grep qemu | grep -oP '127\.0\.0\.1:\K59[0-9]{2}' | head -1 || true)"
if [[ -z "$vnc_port" ]]; then
  echo "$(date -u +%FT%TZ) no qemu VNC listener found, skipping" >> "$SHOTDIR/screenshot.log"
  exit 0
fi

vncsnapshot -allowblank "127.0.0.1:$((vnc_port - 5900))" "$SHOTDIR/shot-${ts}.jpg" \
  >> "$SHOTDIR/screenshot.log" 2>&1 || echo "$(date -u +%FT%TZ) vncsnapshot failed for port $vnc_port" >> "$SHOTDIR/screenshot.log"
