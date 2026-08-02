#!/bin/sh
set -eu

# #268: keep portbridge's mass-scanner blackhole list (BLACKHOLE_LIST,
# blackhole.go) fresh. Same source T-Pot's blackhole.sh uses
# (docker/tpotinit/dist/bin/blackhole.sh) -- stamparm/maltrail's own
# mass_scanner.txt, one IPv4 address per line with a trailing
# "# host.example.com" comment. T-Pot re-downloads when its local copy is
# more than 30 days old; this refreshes on a shorter, configurable interval
# since portbridge's own reload (blackholeReloadInterval, 15m) is cheap and
# there is no reason to let the list go nearly a month stale by default.
#
# This is a separate, opt-in sidecar (docker-compose.yml's "blackhole"
# compose profile -- `docker compose --profile blackhole up`), not a change
# to portbridge itself: portbridge only ever reads a local file
# (BLACKHOLE_LIST) and never fetches anything over the network, so a
# deployment that doesn't want this feature at all can leave the profile
# inactive and portbridge behaves exactly as if BLACKHOLE_LIST were unset --
# see blackhole.go's newBlackhole/reload, which both treat a missing file as
# "no blocklist yet," not an error.
#
# Downloads atomically (temp file + rename) so portbridge's own mtime-based
# reload (which reads the file only after Stat shows the mtime moved) never
# observes a partially-written file.

url="${BLACKHOLE_LIST_URL:-https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt}"
dest="${BLACKHOLE_LIST:-/blackhole/mass_scanner.txt}"
interval="${REFRESH_INTERVAL_SECONDS:-86400}"  # 24h -- the upstream list does not churn faster than this

mkdir -p "$(dirname "$dest")"

while true; do
  tmp="${dest}.tmp.$$"
  if curl -fsSL --max-time 60 -o "$tmp" "$url"; then
    # Sanity check, same spirit as blackhole.sh's own myBASELINE=500 guard:
    # refuse a truncated/empty/error-page download rather than replacing a
    # good list with a useless one. The real list is currently ~19k entries;
    # 500 is a generous floor that only catches genuinely broken downloads.
    count=$(grep -c -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$tmp" 2>/dev/null || echo 0)
    if [ "$count" -ge 500 ]; then
      mv -f "$tmp" "$dest"
      echo "portbridge-blackhole-refresh: updated $dest ($count addresses)" >&2
    else
      echo "portbridge-blackhole-refresh: downloaded list only has $count addresses (want >=500) -- keeping existing $dest" >&2
      rm -f "$tmp"
    fi
  else
    echo "portbridge-blackhole-refresh: download failed; keeping existing $dest, will retry next interval" >&2
    rm -f "$tmp"
  fi
  sleep "$interval"
done
