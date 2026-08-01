#!/bin/sh
set -eu

# Delete rotated portbridge.json.* files once they age past the retention
# window. #120: portbridge's own connLogger now rotates itself (close,
# rename, reopen at the same path -- see vps/portbridge/main.go), the same
# fix #79 gave Suricata's eve.json via rotate-interval, but nothing prunes
# the renamed files afterward. That's this script's only job, same pattern
# as suricata-log-maintenance.sh next to it.
#
# This has to run on the VPS, not the home stack's analysis/log-maintenance.sh:
# portbridge.json is shipped to the home side over the same read-only
# sshfs/NFS mount as Suricata's logs (see docker-compose.yml's portbridge
# volume comment), so nothing on that side can write here.
#
# The currently-open file is always well under the retention window (it's at
# most one rotation-threshold old), so -mmin naturally protects it -- no
# separate exclusion needed.

retention_min="${RETENTION_MINUTES:-4320}"   # 3 days, matches suricata-log-maintenance.sh
interval="${CHECK_INTERVAL:-3600}"
start_delay="${START_DELAY:-60}"
log_dir="${LOG_DIR:-/logs/portbridge}"

sleep "$start_delay"

while true; do
  find "$log_dir" -maxdepth 1 -name 'portbridge.json.*' -mmin "+${retention_min}" -print -delete 2>/dev/null || true
  sleep "$interval"
done
