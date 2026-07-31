#!/bin/sh
set -eu

# Delete rotated Suricata eve-*.json files once they age past the retention
# window. #79: Suricata's own rotate-interval (vps/suricata/suricata.yaml)
# closes and renames eve.json on a schedule, but it does not prune old
# rotated files itself -- that would just trade "one file grows forever" for
# "N files accumulate forever". EveBox and Elasticsearch already hold the
# searchable history, so the on-disk JSON only needs to outlive Filebeat's
# ingest lag by a comfortable margin, not last forever.
#
# The currently-open file is always well under the retention window (it's
# at most one rotate-interval old), so -mmin naturally protects it -- no
# separate exclusion needed.

retention_min="${RETENTION_MINUTES:-4320}"   # 3 days
interval="${CHECK_INTERVAL:-3600}"
start_delay="${START_DELAY:-60}"
log_dir="${LOG_DIR:-/logs/suricata}"

sleep "$start_delay"

while true; do
  find "$log_dir" -maxdepth 1 -name 'eve-*.json' -mmin "+${retention_min}" -print -delete 2>/dev/null || true
  sleep "$interval"
done
