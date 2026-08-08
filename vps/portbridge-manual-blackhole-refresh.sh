#!/bin/sh
set -eu

# #914: keeps portbridge's manual (operator-triggered) blackhole list current
# -- the dashboard-side companion to portbridge-blackhole-refresh.sh's own
# maltrail feed. Same shape as that script (poll on a timer, download to a
# temp file, atomic rename), pointed at the dashboard's own export endpoint
# instead of GitHub. See docs/dashboard-manual-ip-block-design.md decision 4
# for the full reasoning: the VPS PULLS this list, on a timer, over the
# WireGuard tunnel that already exists (home is reachable at 10.8.0.2,
# docs/CGNAT-DEPLOYMENT.md) -- no new inbound channel to the VPS, which is
# deliberately the more exposed, internet-facing box.
#
# Opt-in via the same "blackhole" compose profile portbridge-blackhole-
# refresh.sh already uses -- a deployment that doesn't run that profile is
# unaffected, exactly as before this addition.
#
# Downloads atomically (temp file + rename) so portbridge's own mtime-based
# reload (blackhole.go's readOne, which reads a source file only after Stat
# shows its mtime moved) never observes a partially-written file.
#
# Unlike portbridge-blackhole-refresh.sh, there is deliberately NO minimum-
# count sanity floor here: an empty manual list (no IP has ever been
# manually blocked) is a completely normal, expected steady state, not a
# sign of a broken download the way an unexpectedly-short maltrail mirror
# would be.

url="${MANUAL_BLACKHOLE_URL:-http://10.8.0.2:19090/export/portbridge-manual-blackhole.txt}"
dest="${BLACKHOLE_MANUAL_LIST:-/blackhole/manual.txt}"
interval="${MANUAL_REFRESH_INTERVAL_SECONDS:-300}"  # 5m -- an operator block should take effect quickly, unlike the mostly-static maltrail feed

mkdir -p "$(dirname "$dest")"

while true; do
  tmp="${dest}.tmp.$$"
  if curl -fsSL --max-time 30 -o "$tmp" "$url"; then
    mv -f "$tmp" "$dest"
    count=$(grep -c -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$dest" 2>/dev/null || echo 0)
    echo "portbridge-manual-blackhole-refresh: updated $dest ($count addresses)" >&2
  else
    echo "portbridge-manual-blackhole-refresh: download failed; keeping existing $dest, will retry next interval" >&2
    rm -f "$tmp"
  fi
  sleep "$interval"
done
