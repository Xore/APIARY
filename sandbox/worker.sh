#!/usr/bin/env bash
set -euo pipefail

root=/var/lib/honeypot-sandbox
exec 9>/run/lock/honeypot-sandbox-worker.lock
flock -n 9 || exit 0
mkdir -p "$root/inbox"/{queued,running,completed,failed,samples} "$root/export"
chmod 0700 "$root/inbox"/{queued,running,completed,failed,samples} "$root/export"
status_export=/usr/local/libexec/honeypot-sandbox/status-export.py
"$status_export" --worker-state running
finish_status() {
  code=$?
  if (( code == 0 )); then
    "$status_export" --worker-state idle
  else
    "$status_export" --worker-state error
  fi
}
trap finish_status EXIT

shopt -s nullglob
while true; do
  queued_jobs=("$root/inbox/queued"/*.json)
  ((${#queued_jobs[@]})) || break
  for queued in "${queued_jobs[@]}"; do
    name=$(basename "$queued")
    running="$root/inbox/running/$name"
    mv "$queued" "$running"
    sha=$(jq -r '.sha256 // empty' "$running")
    if [[ ! $sha =~ ^[0-9a-f]{64}$ || $name != "$sha.json" || ! -f $root/inbox/samples/$sha ]]; then
      printf 'invalid request\n' >"$root/inbox/failed/$name.error"
      mv "$running" "$root/inbox/failed/$name"
      continue
    fi
    log="$root/inbox/running/$sha.log"
    if /usr/local/libexec/honeypot-sandbox/run-linux-sample.sh \
        --i-understand-this-executes-untrusted-code "$root/inbox/samples/$sha" | tee "$log"; then
      result=$(sed -n 's/^RESULT_DIR=//p' "$log" | tail -n 1)
      if [[ $result == "$root/results/"* && -f $result/report.json ]]; then
        export_tmp="$root/export/$(basename "$result").json.new"
        if /usr/local/libexec/honeypot-sandbox/export-result.py \
            --request "$running" --result "$result" --output "$export_tmp"; then
          mv "$export_tmp" "${export_tmp%.new}"
          job=$(basename "$result")
          for capture in network.pcap guest-network.pcap; do
            [[ -f $result/$capture && ! -L $result/$capture ]] || continue
            size=$(stat -c %s "$result/$capture")
            (( size <= 67108864 )) || continue
            suffix=host
            [[ $capture == guest-network.pcap ]] && suffix=guest
            install -m 0640 -o root -g xore "$result/$capture" "$root/export/$job.$suffix.pcap"
          done
          mv "$running" "$root/inbox/completed/$name"
          rm -f "$root/inbox/samples/$sha" "$log"
          "$status_export" --worker-state running
          continue
        fi
      fi
      printf 'result export failed at %s\n' "$(date -u +%FT%TZ)" >"$root/inbox/failed/$name.error"
      mv "$running" "$root/inbox/failed/$name"
      mv "$log" "$root/inbox/failed/$sha.log" 2>/dev/null || true
      "$status_export" --worker-state running
    else
      printf 'analysis failed at %s\n' "$(date -u +%FT%TZ)" >"$root/inbox/failed/$name.error"
      mv "$running" "$root/inbox/failed/$name"
      mv "$log" "$root/inbox/failed/$sha.log" 2>/dev/null || true
      "$status_export" --worker-state running
    fi
  done
done
