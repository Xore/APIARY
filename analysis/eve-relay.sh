#!/bin/sh
set -eu

source_file=${EVE_RELAY_SOURCE:-/source/eve.json}
relay_file=${EVE_RELAY_TARGET:-/relay/eve.json}
state_file=${EVE_RELAY_STATE:-/relay/source.offset}
poll_seconds=${EVE_RELAY_POLL_SECONDS:-2}
chunk_file="${state_file}.chunk"
next_state="${state_file}.new"

mkdir -p "$(dirname "$relay_file")" "$(dirname "$state_file")"
touch "$relay_file"
rm -f "$chunk_file" "$next_state"

offset=
if [ -s "$state_file" ]; then
  offset=$(cat "$state_file" 2>/dev/null || true)
fi

while :; do
  size=$(stat -c %s "$source_file" 2>/dev/null || true)
  case "$size" in
    ''|*[!0-9]*)
      sleep "$poll_seconds"
      continue
      ;;
  esac

  # A new relay starts at the current end of the remote file. The dashboard
  # needs fresh events, not a replay of the historical SSHFS corpus.
  case "$offset" in
    ''|*[!0-9]*)
      offset=$size
      printf '%s\n' "$offset" >"$next_state"
      mv -f "$next_state" "$state_file"
      ;;
  esac

  # Suricata truncates its active file during rotation. Keep the local relay
  # inode stable and append the replacement file from its beginning.
  if [ "$size" -lt "$offset" ]; then
    offset=0
    printf '0\n' >"$next_state"
    mv -f "$next_state" "$state_file"
  fi

  if [ "$size" -gt "$offset" ]; then
    count=$((size - offset))
    start=$((offset + 1))
    rm -f "$chunk_file"

    # Stage an exact-size chunk before appending it. A transient SSHFS read
    # failure can therefore never advance the checkpoint or corrupt the feed.
    tail -c +"$start" "$source_file" 2>/dev/null |
      head -c "$count" >"$chunk_file" || true
    copied=$(stat -c %s "$chunk_file" 2>/dev/null || printf '0')

    if [ "$copied" -eq "$count" ]; then
      cat "$chunk_file" >>"$relay_file"
      offset=$size
      printf '%s\n' "$offset" >"$next_state"
      mv -f "$next_state" "$state_file"
    fi
    rm -f "$chunk_file"
  fi

  sleep "$poll_seconds"
done
