#!/usr/bin/env bash
# Drain the GHOSTS sandbox request spool (#328).
#
# The dashboard writes {sha256}.request into GHOSTS_SANDBOX_REQUEST_DIR and
# never touches a hypervisor itself, same as every other Workbench backend
# (dashboard/sandbox_submit.go). A systemd path unit notices the new file and
# starts this script, which detonates each pending sample on win11-ghosts and
# writes windows-ghosts-<job>.json into GHOSTS_SANDBOX_RESULTS_DIR for the
# dashboard to read back (#327).
#
# Mirrors sandbox/windows/run_pending.sh exactly in shape: a non-blocking
# lock so overlapping path-unit triggers collapse into one drain, and a
# request that is moved out of the spool before it runs so a crash cannot
# replay it forever.
set -euo pipefail

request_dir=${GHOSTS_SANDBOX_REQUEST_DIR:-/var/lib/honeypot-ghosts-sandbox/requests/pending}
results_dir=${GHOSTS_SANDBOX_RESULTS_DIR:-/var/lib/honeypot-ghosts-sandbox/export}
# Same shared inbox sandbox/windows/process-windows-web-requests.sh already
# resolves into -- a sample submitted to windows-sandbox is already sitting
# here, so a GHOSTS submission for the same hash needs no second copy.
samples_dir=${GHOSTS_SANDBOX_SAMPLES_DIR:-/var/lib/honeypot-sandbox/inbox/samples}
orchestrator=${GHOSTS_SANDBOX_ORCHESTRATOR:-/usr/local/libexec/honeypot-sandbox/ghosts/orchestrate/run_sample.py}
lock_file=${GHOSTS_SANDBOX_LOCK:-/run/lock/honeypot-ghosts-sandbox-worker.lock}

mkdir -p "$(dirname "$lock_file")"
exec 9>"$lock_file"
flock -n 9 || exit 0

mkdir -p "$request_dir" "$results_dir"
chmod 0700 "$request_dir" "$results_dir"

shopt -s nullglob
processed=0

for request in "$request_dir"/*.request; do
  sha=$(basename "$request" .request)

  if [[ ! $sha =~ ^[0-9a-f]{64}$ ]]; then
    echo "skipping malformed request: $(basename "$request")" >&2
    mv -f "$request" "$request.invalid"
    continue
  fi

  sample="$samples_dir/$sha"
  if [[ ! -f $sample ]]; then
    echo "sample $sha is not in $samples_dir — dropping request" >&2
    mv -f "$request" "$request.missing-sample"
    continue
  fi

  claimed="$request.running"
  mv -f "$request" "$claimed"

  echo "detonating $sha in ${VM_DOMAIN:-win11-ghosts} (WAN-permitted route)"
  if python3 "$orchestrator" --sample "$sample" --results-dir "$results_dir"; then
    rm -f "$claimed"
    processed=$((processed + 1))
  else
    mv -f "$claimed" "$request.failed"
    echo "detonation failed for $sha" >&2
  fi
done

echo "ghosts sandbox worker: $processed request(s) processed"
