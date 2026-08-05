#!/bin/sh
set -eu

# #263: nothing in this stack previously checked or alerted on actual free
# disk space. A bounded retention policy (#261) reduces the *rate* of
# growth but does not catch it if something else fills the disk (a stuck
# container's logs, a runaway payload capture, the ES snapshot repo). This
# is purely "notice and surface" -- pruning/rotation is #261/#252's job,
# a factory-reset recovery path is #262's.
#
# Runs on the same cadence as log-maintenance.sh by default.

interval="${CHECK_INTERVAL:-300}"
start_delay="${START_DELAY:-60}"
warn_percent_free="${DISK_WARN_PERCENT_FREE:-15}"
es_url="${ELASTICSEARCH_URL:-http://elasticsearch:9200}"
out="${DISK_SPACE_LOG:-/logs/diagnostics/disk-space.json}"
# Bind-mounted host paths to check by plain df. Colon-separated
# label=path pairs; label becomes the "source" field in the alert line.
paths="${DISK_CHECK_PATHS:-honeypot-logs=/logs:honeypot-state=/state:dionaea-payloads=/dionaea-lib}"

mkdir -p "$(dirname "$out")"

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# df -Pk: POSIX output, forced 1024-byte blocks so column parsing is
# predictable across busybox/coreutils/Alpine df implementations.
check_path() {
  label="$1"
  path="$2"
  [ -d "$path" ] || return 0
  line="$(df -Pk "$path" 2>/dev/null | tail -n 1)" || return 0
  total="$(echo "$line" | awk '{print $2}')"
  avail="$(echo "$line" | awk '{print $4}')"
  percent_used="$(echo "$line" | awk '{print $5}' | tr -d '%')"
  case "$percent_used" in ''|*[!0-9]*) return 0 ;; esac
  percent_free=$((100 - percent_used))
  if [ "$percent_free" -lt "$warn_percent_free" ]; then
    printf '{"@timestamp":"%s","event":{"module":"disk-space-check","category":"host"},"disk":{"source":"%s","path":"%s","percent_free":%s,"available_kb":%s,"total_kb":%s},"level":"warning"}\n' \
      "$(now)" "$label" "$path" "$percent_free" "$avail" "$total" >>"$out"
    echo "disk-space-check: WARNING $label ($path) at ${percent_free}% free" >&2
  fi
}

# es-data is a stack-private volume (docker-compose.elk.yml), deliberately
# never bind-mounted cross-stack -- _cat/allocation is the only view a
# sidecar outside that stack has of the filesystem backing it, and it is
# already the pattern elasticsearch-setup.sh uses to talk to Elasticsearch
# (plain HTTP over honeynet, no direct volume access).
check_elasticsearch() {
  line="$(curl -fsS "$es_url/_cat/allocation?h=disk.avail,disk.total,disk.percent&bytes=kb" 2>/dev/null | head -n 1)" || {
    echo "disk-space-check: elasticsearch unreachable, skipping" >&2
    return 0
  }
  [ -n "$line" ] || return 0
  avail="$(echo "$line" | awk '{print $1}')"
  total="$(echo "$line" | awk '{print $2}')"
  percent_used="$(echo "$line" | awk '{print $3}')"
  case "$percent_used" in ''|*[!0-9.]*) return 0 ;; esac
  percent_free=$((100 - ${percent_used%.*}))
  if [ "$percent_free" -lt "$warn_percent_free" ]; then
    printf '{"@timestamp":"%s","event":{"module":"disk-space-check","category":"host"},"disk":{"source":"elasticsearch-data","path":"es-data","percent_free":%s,"available_kb":%s,"total_kb":%s},"level":"warning"}\n' \
      "$(now)" "$percent_free" "$avail" "$total" >>"$out"
    echo "disk-space-check: WARNING elasticsearch-data at ${percent_free}% free" >&2
  fi
}

sleep "$start_delay"

while true; do
  old_ifs="$IFS"
  IFS=:
  for entry in $paths; do
    IFS="$old_ifs"
    label="${entry%%=*}"
    path="${entry#*=}"
    check_path "$label" "$path"
    IFS=:
  done
  IFS="$old_ifs"
  check_elasticsearch
  sleep "$interval"
done
