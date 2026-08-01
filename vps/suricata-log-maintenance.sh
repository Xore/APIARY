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
#
# #113: the eve-*.json glob doesn't match the bare eve.json Suricata wrote
# before #79 switched it to rotate-interval naming -- that file froze the
# moment the switch happened (confirmed live: mtime exactly matches the
# first eve-*.json's ctime) and sat there unreachable by this cleanup,
# 7.28 GB and climbing toward being the majority of the directory forever.
# The same -mmin staleness check covers it below, rather than an
# unconditional delete, so this stays safe if some future misconfiguration
# ever has Suricata writing the bare filename again for real.
#
# #113 also rotates fast.log/stats.log here, which #79 never touched even
# though they have the identical unbounded-growth shape as eve.json did:
# vps/suricata/suricata.yaml gives both `append: yes` and no size/time
# rotation of their own. Neither is Filebeat input (only eve-*.json is,
# per analysis/filebeat.yml) and both are plain append-only text, so
# copytruncate is safe here the same way it already is for the sensor
# logs analysis/log-maintenance.sh rotates -- no JSON-stream offset
# tracking to protect, because nothing downstream reads these two files
# at all.

retention_min="${RETENTION_MINUTES:-4320}"   # 3 days
interval="${CHECK_INTERVAL:-3600}"
start_delay="${START_DELAY:-60}"
log_dir="${LOG_DIR:-/logs/suricata}"
max_bytes="${MAX_TEXT_LOG_BYTES:-268435456}"  # 256 MiB, matches log-maintenance.sh
rotations="${ROTATIONS:-4}"

size_of() {
  stat -c %s "$1" 2>/dev/null || wc -c < "$1"
}

rotate() {
  file="$1"
  [ -f "$file" ] || return 0
  size="$(size_of "$file")"
  [ "$size" -ge "$max_bytes" ] || return 0

  i="$rotations"
  while [ "$i" -gt 1 ]; do
    prev=$((i - 1))
    [ -f "$file.$prev.gz" ] && mv -f "$file.$prev.gz" "$file.$i.gz"
    i="$prev"
  done

  cp -p "$file" "$file.1"
  : > "$file"
  gzip -f "$file.1"
  echo "suricata-log-maintenance: rotated $file ($size bytes)" >&2
}

sleep "$start_delay"

while true; do
  find "$log_dir" -maxdepth 1 -name 'eve-*.json' -mmin "+${retention_min}" -print -delete 2>/dev/null || true
  find "$log_dir" -maxdepth 1 -name 'eve.json' -mmin "+${retention_min}" -print -delete 2>/dev/null || true
  rotate "$log_dir/fast.log"
  rotate "$log_dir/stats.log"
  sleep "$interval"
done
