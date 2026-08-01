#!/bin/sh
set -eu

# Rotate human-readable sensor logs. JSON event streams are intentionally left
# alone so Filebeat inode/offset tracking and dashboard ingestion stay intact.
max_bytes="${MAX_LOG_BYTES:-268435456}"
interval="${CHECK_INTERVAL:-300}"
rotations="${ROTATIONS:-4}"
start_delay="${START_DELAY:-60}"

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

  # copytruncate avoids requiring the Docker socket merely to signal/restart
  # writers. The short copy/truncate window may duplicate a partial line, which
  # is acceptable for diagnostic text logs and never affects JSON event logs.
  cp -p "$file" "$file.1"
  : > "$file"
  gzip -f "$file.1"
  echo "log-maintenance: rotated $file ($size bytes)" >&2
}

# Give operators time to archive an unexpectedly large pre-existing log before
# the first maintenance pass after a deployment.
sleep "$start_delay"

while true; do
  rotate /logs/dionaea/dionaea.log
  rotate /logs/dionaea/dionaea-errors.log
  # #115: six conpot personas (conpot, conpot-s7-1200, conpot-s7-1500,
  # conpot-iec104, conpot-guardian, conpot-kamstrup) each write their own
  # /logs/conpot*/conpot.log, matching the compose file's own volume layout
  # -- a single hardcoded path here only ever covered the base one. The glob
  # covers all of them, present or future, without another hardcoded line
  # per persona; an unmatched glob passes through as the literal pattern
  # string under this shell's default globbing, which rotate()'s own
  # [ -f "$file" ] guard already treats as "nothing to do."
  for f in /logs/conpot*/conpot.log; do
    rotate "$f"
  done
  rotate /logs/cowrie/cowrie.log
  sleep "$interval"
done
