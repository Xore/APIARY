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
orchestrator=${WINDOWS_SANDBOX_ORCHESTRATOR:-/usr/local/libexec/honeypot-sandbox/windows/orchestrate/run_sample.py}
lock_file=${WINDOWS_SANDBOX_LOCK:-/run/lock/honeypot-windows-sandbox-worker.lock}
# #320: cross-pipeline lock shared with sandbox/cape/worker/cape-worker.py.
# CAPE's guest and win11-sandbox both run as KVM/QEMU domains on this host
# (16 logical CPUs total, win11-sandbox alone already configured for 8
# vCPU -- see docs/sandbox/cape/IMPLEMENTATION_PLAN.md's Host Constraints).
# Decision: one host-wide lock, only one KVM-backed detonation at a time
# across BOTH pipelines, not just within this one. Held only around the
# actual detonation call below, not the whole drain loop, so an idle worker
# never blocks the other pipeline. Empty disables it.
#
# #2962: ${VAR:-default} treats an explicitly-empty override the same as
# unset, so `export WINDOWS_SANDBOX_KVM_SHARED_LOCK=""` (exactly what
# tests/test_run_pending_stale_claims.sh does, to stay hypervisor-free) fell
# through to the real production lock path instead of disabling it -- the
# comment above already documented "empty disables it" as the intent.
# ${VAR-default} (no colon) only substitutes when VAR is truly unset.
kvm_lock_file=${WINDOWS_SANDBOX_KVM_SHARED_LOCK-/run/lock/honeypot-kvm-detonation.lock}

# The path unit fires on every spool change, so several invocations can race
# during a burst. Only one may talk to the guest: a second concurrent
# detonation would revert the snapshot out from under the first.
mkdir -p "$(dirname "$lock_file")"
exec 9>"$lock_file"
flock -n 9 || exit 0

mkdir -p "$request_dir" "$results_dir"
chmod 0700 "$request_dir" "$results_dir"

shopt -s nullglob

# The path unit only fires on spool changes, so a claim whose worker died
# mid-detonation (OOM kill, SIGKILL, host reboot) sits in *.request.running
# forever: no future spool change globs a *.request that no longer exists,
# and nothing else re-queues it. Mirrors sandbox/worker.sh's
# sweep_stranded_running -- age the claim off its mtime and recover it
# before the drain loop below even looks at the queue. A live detonation
# only ever takes as long as this same guest's own run, so anything still
# claimed past the stale threshold has no living owner left to finish it.
sweep_stranded_claims() {
  local stale_secs=${WINDOWS_SANDBOX_STALE_RUNNING_SECS:-1800}
  local claimed name mtime age
  for claimed in "$request_dir"/*.request.running; do
    [[ -e $claimed ]] || continue
    name=$(basename "$claimed")
    mtime=$(stat -c %Y "$claimed" 2>/dev/null) || continue
    age=$(($(date +%s) - mtime))
    ((age >= stale_secs)) || continue
    echo "recovering stranded claim $name (age ${age}s >= ${stale_secs}s, no living worker)" >&2
    mv -f "$claimed" "${claimed%.running}.failed"
  done
}
sweep_stranded_claims

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
  # #320's shared lock: block here, not skip -- a queued sample should
  # detonate once CAPE's current job finishes, not bail out and leave the
  # request stuck the way this worker's own non-blocking lock_file does.
  detonation_ok=1
  if [[ -n $kvm_lock_file ]]; then
    mkdir -p "$(dirname "$kvm_lock_file")"
    exec 8>"$kvm_lock_file"
    flock 8
    python3 "$orchestrator" --sample "$sample" --results-dir "$results_dir" || detonation_ok=0
    exec 8>&-
  else
    python3 "$orchestrator" --sample "$sample" --results-dir "$results_dir" || detonation_ok=0
  fi
  if [[ $detonation_ok -eq 1 ]]; then
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
