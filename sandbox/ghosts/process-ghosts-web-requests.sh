#!/usr/bin/env bash
# process-ghosts-web-requests.sh — hash-resolution/submission handoff for the
# GHOSTS sandbox spool (#328), mirroring sandbox/windows/process-windows-web-requests.sh
# exactly (itself mirroring the Linux sandbox's process-web-requests.sh).
#
# The dashboard writes only an empty {sha256}.request into
# GHOSTS_SANDBOX_REQUEST_DIR (dashboard/sandbox_submit.go: "The dashboard
# writes no sample data and has no access to libvirt, Docker, or systemd").
# Something has to resolve that hash against the actual captured payload and
# copy it, root-owned, into GHOSTS_SANDBOX_SAMPLES_DIR before run_pending.sh
# can detonate it.
#
# Deliberately the *same default* samples_dir the Windows worker's own
# resolution script uses (/var/lib/honeypot-sandbox/inbox/samples), not a
# second, GHOSTS-only copy: both routes need the identical sample bytes, and
# whichever backend resolves first satisfies the other's request too --
# resolve_sample below is a no-op the moment that's already happened.
set -euo pipefail

request_dir=${GHOSTS_SANDBOX_REQUEST_DIR:-/var/lib/honeypot-ghosts-sandbox/requests/pending}
rejected_dir="$(dirname "$request_dir")/rejected"
samples_dir=${GHOSTS_SANDBOX_SAMPLES_DIR:-/var/lib/honeypot-sandbox/inbox/samples}

install -d -m 0700 -o root -g root "$request_dir" "$rejected_dir" "$samples_dir"

exec 9>/run/lock/honeypot-ghosts-sandbox-web-requests.lock
flock -n 9 || exit 0

# Same capture roots sandbox/windows/process-windows-web-requests.sh and
# sandbox/submit-capture.sh use -- keep this list in sync with both if either
# ever changes; there is no shared config between any of the three.
roots=(/opt/stacks/honeypot-stack/logs/cowrie/downloads)
labels=(cowrie)
dionaea_root="$(docker volume inspect dionaea-lib --format '{{.Mountpoint}}' 2>/dev/null || true)/binaries"
scripts_root="$(docker volume inspect dashboard-state --format '{{.Mountpoint}}' 2>/dev/null || true)/script-payloads"
[[ $dionaea_root == /* && -d $dionaea_root ]] && { roots+=("$dionaea_root"); labels+=(dionaea); }
[[ $scripts_root == /* && -d $scripts_root ]] && { roots+=("$scripts_root"); labels+=(scripts); }

resolve_sample() {
  local hash=$1 index root found path
  for index in "${!roots[@]}"; do
    root=${roots[$index]}
    found=$(find "$root" -xdev -type f -name "$hash" -print -quit 2>/dev/null || true)
    if [[ -n $found ]]; then echo "$found"; return 0; fi
  done
  if [[ ${#hash} -eq 64 ]]; then
    for index in "${!roots[@]}"; do
      root=${roots[$index]}
      while IFS= read -r -d '' path; do
        if [[ $(sha256sum "$path" | awk '{print $1}') == "$hash" ]]; then
          echo "$path"
          return 0
        fi
      done < <(find "$root" -xdev -type f -print0 2>/dev/null)
    done
  fi
  return 1
}

shopt -s nullglob
requests=("$request_dir"/*.request)
((${#requests[@]})) || exit 0

for request in "${requests[@]}"; do
  name=$(basename "$request")
  hash=${name%.request}
  hash=${hash,,}

  if [[ ! $hash =~ ^[0-9a-f]{32,64}$ ]]; then
    mv -f "$request" "$rejected_dir/$name"
    printf 'invalid hash request at %s\n' "$(date -u +%FT%TZ)" >"$rejected_dir/$name.error"
    logger -t honeypot-ghosts-sandbox "rejected malformed request $name"
    continue
  fi

  if [[ -f "$samples_dir/$hash" ]]; then
    continue
  fi

  if candidate=$(resolve_sample "$hash"); then
    install -m 0400 -o root -g root "$candidate" "$samples_dir/$hash.new"
    mv -f "$samples_dir/$hash.new" "$samples_dir/$hash"
    logger -t honeypot-ghosts-sandbox "resolved web request $hash -> $samples_dir/$hash"
  else
    logger -t honeypot-ghosts-sandbox "no capture resolves web request $hash yet"
  fi
done

systemctl start --no-block honeypot-ghosts-sandbox-worker.service
