#!/usr/bin/env bash
set -euo pipefail

root=/var/lib/honeypot-sandbox/requests
pending="$root/pending"
rejected="$root/rejected"
install -d -m 0700 -o root -g root "$pending" "$rejected"
# apiary-backend's backend-service-mounted (image USER nobody, uid 65534)
# is what CREATES the *.request files here -- install -d resets the base
# mode on every run, which collapses any ACL mask back down too (Linux:
# chmod on a dir with an ACL recomputes the mask from the requested group
# bits), silently reverting the grant below on this script's very next
# invocation if it isn't reasserted every time alongside it.
setfacl -m u:65534:rwx,mask::rwx "$pending" 2>/dev/null || true

exec 9>/run/lock/honeypot-sandbox-web-requests.lock
flock -n 9 || exit 0
shopt -s nullglob
while true; do
  requests=("$pending"/*.request)
  ((${#requests[@]})) || break
  for request in "${requests[@]}"; do
    name=$(basename "$request")
    hash=${name%.request}
    if [[ ! $hash =~ ^[0-9a-f]{32,64}$ ]]; then
      mv -f "$request" "$rejected/$name"
      printf 'invalid hash request at %s\n' "$(date -u +%FT%TZ)" >"$rejected/$name.error"
      continue
    fi
    if output=$(/usr/local/sbin/honeypot-sandbox-submit "$hash" 2>&1); then
      rm -f "$request"
      logger -t honeypot-sandbox "web request $hash: $output"
    else
      mv -f "$request" "$rejected/$name"
      printf '%s\n' "$output" >"$rejected/$name.error"
      logger -t honeypot-sandbox "rejected web request $hash: $output"
    fi
  done
done

# A burst can enqueue additional jobs while the path-triggered worker is already
# active. Starting it after the handoff closes that systemd path-unit race.
systemctl start --no-block honeypot-sandbox-worker.service
