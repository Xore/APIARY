#!/usr/bin/env bash
# process-windows-web-requests.sh -- the hash-resolution/submission handoff
# that was missing for Windows (see #47's tracking history and
# install-worker.sh's old header comment, which documented this exact gap
# rather than pretending it didn't exist).
#
# The dashboard writes only an empty {sha256}.request file into
# WINDOWS_SANDBOX_REQUEST_DIR -- deliberately no sample data (see
# sandbox_submit.go: "The dashboard writes no sample data and has no access
# to libvirt, Docker, or systemd; a root-owned host service consumes this
# narrow request spool"). Something has to resolve that hash against the
# actual captured payload and copy it, root-owned, into
# WINDOWS_SANDBOX_SAMPLES_DIR before run_pending.sh can detonate it. Mirrors
# sandbox/process-web-requests.sh (the Linux equivalent) in shape: a
# non-blocking lock so overlapping triggers collapse into one drain, and a
# request that is left in place (not consumed) for run_pending.sh to pick up
# next -- this script's only job is making sure the sample bytes exist
# before that handoff, not detonating anything itself.
set -euo pipefail

request_dir=${WINDOWS_SANDBOX_REQUEST_DIR:-/var/lib/honeypot-windows-sandbox/requests/pending}
rejected_dir="$(dirname "$request_dir")/rejected"
samples_dir=${WINDOWS_SANDBOX_SAMPLES_DIR:-/var/lib/honeypot-sandbox/inbox/samples}

install -d -m 0700 -o root -g root "$request_dir" "$rejected_dir" "$samples_dir"

exec 9>/run/lock/honeypot-windows-sandbox-web-requests.lock
flock -n 9 || exit 0

# Same capture roots submit-capture.sh (the Linux equivalent's resolution
# step) already knows about, and the same three sources dashboard's own
# s.payloadDirs is built from (store.go: "dionaea, cowrie and generated
# script artifact directories") -- keep this list in sync with
# sandbox/submit-capture.sh's copy if either ever changes; there is no
# shared config between the two, since one runs against the dashboard
# container's mounts and this one runs on the bare host.
roots=(/opt/stacks/apiary/logs/cowrie/downloads)
labels=(cowrie)
dionaea_root="$(docker volume inspect dionaea-lib --format '{{.Mountpoint}}' 2>/dev/null || true)/binaries"
scripts_root="$(docker volume inspect dashboard-state --format '{{.Mountpoint}}' 2>/dev/null || true)/script-payloads"
[[ $dionaea_root == /* && -d $dionaea_root ]] && { roots+=("$dionaea_root"); labels+=(dionaea); }
[[ $scripts_root == /* && -d $scripts_root ]] && { roots+=("$scripts_root"); labels+=(scripts); }

resolve_sample() {
  # $1 = sha256. Prints the resolved path on stdout, or nothing (and a
  # non-zero exit) if no capture root has a payload matching this hash.
  local hash=$1 index root found path
  # Fast path: a file literally named after the hash (Cowrie/scripts
  # convention; Dionaea names by MD5, which never matches a 64-char SHA-256
  # this way -- same reasoning as payload_analysis.go's payloadPath).
  for index in "${!roots[@]}"; do
    root=${roots[$index]}
    found=$(find "$root" -xdev -type f -name "$hash" -print -quit 2>/dev/null || true)
    if [[ -n $found ]]; then echo "$found"; return 0; fi
  done
  # Slow path: hash the content of every candidate file until one matches.
  # Only worth paying for a 64-char (SHA-256-shaped) request -- same
  # reasoning as payload_analysis.go's payloadPathBySHA256 fallback.
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
    logger -t honeypot-windows-sandbox "rejected malformed request $name"
    continue
  fi

  # Already resolved by an earlier run (e.g. a burst that retried before
  # this script's lock cleared) -- leave the request for run_pending.sh,
  # nothing to do here.
  if [[ -f "$samples_dir/$hash" ]]; then
    continue
  fi

  if candidate=$(resolve_sample "$hash"); then
    install -m 0400 -o root -g root "$candidate" "$samples_dir/$hash.new"
    mv -f "$samples_dir/$hash.new" "$samples_dir/$hash"
    logger -t honeypot-windows-sandbox "resolved web request $hash -> $samples_dir/$hash"
  else
    # Deliberately not moved to rejected/: run_pending.sh's own
    # missing-sample handling (mv to *.missing-sample) already covers this
    # exact case with the same "leave evidence, do not silently drop"
    # behavior this script would otherwise duplicate. Leaving the request in
    # place also lets a later resolution (a capture that lands after this
    # request was written) succeed on the *next* trigger instead of the
    # request already being gone.
    logger -t honeypot-windows-sandbox "no capture resolves web request $hash yet"
  fi
done

# Hand off explicitly, same as process-web-requests.sh's own
# "systemctl start --no-block honeypot-sandbox-worker.service" -- this is
# the *only* thing that starts the detonation worker for this spool now
# (honeypot-windows-sandbox-worker.path's Unit= points here, not there).
systemctl start --no-block honeypot-windows-sandbox-worker.service
