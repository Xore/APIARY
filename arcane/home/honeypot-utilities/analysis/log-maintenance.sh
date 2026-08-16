#!/bin/sh
set -eu

# Rotate human-readable sensor logs. JSON event streams are exempt from THIS
# copytruncate rotation so Filebeat inode/offset tracking and dashboard
# ingestion stay intact -- but as of #120 several of them now rotate
# themselves natively (cowrie's own CowrieDailyLogFile, and a self-rotating
# logger in multipot/http-honeypot's Go writers), the same way #79 gave
# Suricata's eve.json a rotate-interval instead of an external copytruncate.
# Those writers close/rename/reopen on their own; all that's left for this
# script to do is prune the renamed files once they age out, same as
# vps/suricata-log-maintenance.sh already does for eve-*.json.
max_bytes="${MAX_LOG_BYTES:-268435456}"
interval="${CHECK_INTERVAL:-300}"
rotations="${ROTATIONS:-4}"
start_delay="${START_DELAY:-60}"
# #261: default derives from the shared HONEYPOT_RETENTION_DAYS knob at the
# same 1/10 ratio this repo's previous independent default already used
# (4320min = 3d against a 30d default) -- deliberately far shorter than
# elasticsearch-setup.sh's ILM retention, since this is only raw on-disk
# JSON that needs to outlive Filebeat's ingest lag, not the searchable
# history ES/Kibana hold. JSON_RETENTION_MINUTES still overrides directly.
json_retention_min="${JSON_RETENTION_MINUTES:-$(( ${HONEYPOT_RETENTION_DAYS:-30} * 1440 / 10 ))}"

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

  # #120: prune self-rotated JSON files once they age past retention. The
  # currently-open file is always being actively written, so -mmin naturally
  # excludes it without a separate exclusion -- same reasoning as
  # vps/suricata-log-maintenance.sh's eve-*.json pruning. cowrie's own
  # CowrieDailyLogFile suffixes with a plain date (cowrie.json.2026-08-02);
  # the Go writers (multipot, http-honeypot for both http.json and
  # api.json) suffix with a full timestamp (multipot.json.20260802-153045).
  # Both start with a digit right after the extra dot, so one glob per
  # directory covers either shape.
  find /logs/cowrie -maxdepth 1 -name 'cowrie.json.[0-9]*' -mmin "+${json_retention_min}" -print -delete 2>/dev/null || true
  find /logs/multipot -maxdepth 1 -name 'multipot.json.[0-9]*' -mmin "+${json_retention_min}" -print -delete 2>/dev/null || true
  find /logs/http-honeypot -maxdepth 1 -name 'http.json.[0-9]*' -mmin "+${json_retention_min}" -print -delete 2>/dev/null || true
  find /logs/api-honeypot -maxdepth 1 -name 'api.json.[0-9]*' -mmin "+${json_retention_min}" -print -delete 2>/dev/null || true
  # #1389: ip-enrichment-worker's own output (OUT_DIR, default /logs/enriched)
  # now self-rotates the same way (rotate.go's outputWriter), suffixing every
  # source's output flatly in that one directory -- cowrie.json.<stamp>,
  # dionaea-incident.json.<stamp>, and so on for every source
  # discoverSources() registers, present or future. One glob covers all of
  # them, same reasoning as the conpot persona glob in the rotate() loop
  # above.
  find /logs/enriched -maxdepth 1 -name '*.json.[0-9]*' -mmin "+${json_retention_min}" -print -delete 2>/dev/null || true
  # #1389 part 2: dionaea/log_rotation_patch.py gives dionaea.json/
  # dionaea_incident.json the same self-rotation, suffixed the same way
  # (dionaea.json.<stamp>, with a further .2/.3/... suffix on the rare
  # collision -- still starts with a digit right after .json., so the same
  # glob shape covers it).
  find /logs/dionaea -maxdepth 1 -name 'dionaea.json.[0-9]*' -mmin "+${json_retention_min}" -print -delete 2>/dev/null || true
  find /logs/dionaea -maxdepth 1 -name 'dionaea_incident.json.[0-9]*' -mmin "+${json_retention_min}" -print -delete 2>/dev/null || true

  sleep "$interval"
done
