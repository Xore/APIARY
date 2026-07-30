#!/usr/bin/env bash
# Drain the Windows sandbox request spool.
#
# The dashboard writes {sha256}.request into WINDOWS_SANDBOX_REQUEST_DIR and
# never touches a hypervisor itself (IMPLEMENTATION_PLAN.md §7.1). A systemd
# path unit notices the new file and starts this script, which detonates each
# pending sample in the Windows guest and writes {sha256}_sandbox.json into
# WINDOWS_SANDBOX_RESULTS_DIR for the dashboard to read back.
#
# Mirrors sandbox/worker.sh — the Linux equivalent — in the ways that matter:
# a non-blocking lock so overlapping path-unit triggers collapse into one
# drain, and a request that is moved out of the spool before it runs so a
# crash cannot replay it forever.
set -euo pipefail

request_dir=${WINDOWS_SANDBOX_REQUEST_DIR:-/windows-sandbox-requests}
results_dir=${WINDOWS_SANDBOX_RESULTS_DIR:-/windows-sandbox-results}
samples_dir=${WINDOWS_SANDBOX_SAMPLES_DIR:-/var/lib/honeypot-sandbox/inbox/samples}
orchestrator=${WINDOWS_SANDBOX_ORCHESTRATOR:-/opt/honeypot-sandbox/windows/orchestrate/run_sample.py}
lock_file=${WINDOWS_SANDBOX_LOCK:-/run/lock/honeypot-windows-sandbox-worker.lock}

# The path unit fires on every spool change, so several invocations can race
# during a burst. Only one may talk to the guest: a second concurrent
# detonation would revert the snapshot out from under the first.
mkdir -p "$(dirname "$lock_file")"
exec 9>"$lock_file"
flock -n 9 || exit 0

mkdir -p "$request_dir" "$results_dir"
chmod 0700 "$request_dir" "$results_dir"

shopt -s nullglob
processed=0

for request in "$request_dir"/*.request; do
  sha=$(basename "$request" .request)

  # The dashboard validates the hash before writing, but this worker holds the
  # hypervisor credentials and re-checks rather than trusting the spool.
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

  # Claim the request before detonating. If the host dies mid-run the file is
  # already out of the spool, so the path unit will not hand the same sample
  # back on the next boot.
  claimed="$request.running"
  mv -f "$request" "$claimed"

  echo "detonating $sha in ${VM_DOMAIN:-win11-sandbox}"
  if python3 "$orchestrator" --sample "$sample" --results-dir "$results_dir"; then
    rm -f "$claimed"
    processed=$((processed + 1))
  else
    # Keep the evidence of a failed run next to the spool. An operator needs to
    # know a sample was accepted and never produced a report.
    mv -f "$claimed" "$request.failed"
    echo "detonation failed for $sha" >&2
  fi
done

echo "windows sandbox worker: $processed request(s) processed"
