#!/usr/bin/env bash
# build-with-retry.sh — wraps `packer build` for win11-analysis.pkr.hcl with
# automatic retry on failure.
#
# Why: packer's WinRM communicator treats some transport-level errors as
# fatal on the very first occurrence, despite logging them with the same
# "Retryable error:" prefix used for errors it genuinely does retry (a plain
# TCP connection reset survived dozens of times across builds this same repo
# has already hardened against — see win11-analysis.pkr.hcl's
# valid_exit_codes comments for the reboot-kill exit-code incidents). One of
# these — "http response error: 401 - invalid content type" — killed a
# healthy, steadily-progressing build 4h20m in on 2026-08-01, immediately
# after a provisioner script had already exited 0 (see issue #194). Nothing
# in the guest script caused it: 03-flarevm-wait.ps1 makes no HTTP calls of
# its own: this is packer's own WinRM communicator hitting a bad poll
# response. There is no packer-level retry/backoff knob for this specific
# error class (winrm_timeout only governs the *initial* connect wait), so
# the fix lives at the process level: retry the whole build, since packer's
# own failure cleanup already deletes the output directory, there is no
# partial state to resume from anyway.
#
# Usage: build-with-retry.sh <iso_checksum> [max_attempts]
#   iso_checksum   passed straight through as packer's -var iso_checksum
#   max_attempts   default 3 (each attempt can take several hours; this
#                  bounds the total unattended time before giving up rather
#                  than retrying forever)
set -euo pipefail

checksum="${1:?usage: build-with-retry.sh <iso_checksum> [max_attempts]}"
max_attempts="${2:-3}"
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# #86: packer-golden-image-guide.md has described win11-analysis.qcow2.sha256
# as part of the storage layout since before any golden image existed to
# checksum. Nothing ever wrote it. The golden image is the root of trust for
# every detonation guest -- every sample run inherits whatever is in it -- so
# an unverified multi-GB file sitting on a shared spindle for months between
# rebuilds is exactly the thing worth hashing. Written here, right after a
# successful build, rather than as a separate manual step someone has to
# remember to run.
output_dir="/var/dockge/sandbox/golden-images"
vm_name="win11-analysis"
qcow2_path="$output_dir/$vm_name.qcow2"

# packer resolves cd_files entries (autounattend.xml) relative to its own
# working directory, not the .hcl file's location -- confirmed live:
# running this script from anywhere other than $dir made every attempt fail
# instantly with "Bad CD disk file 'autounattend.xml': stat: no such file or
# directory" instead of a real build, which a naive retry-forever wrapper
# read as "still trying" for hours. cd here so the script is invocation-
# directory-independent instead of relying on every caller to cd first.
cd "$dir"

attempt=1
while (( attempt <= max_attempts )); do
  echo "=== build-with-retry: attempt ${attempt}/${max_attempts} starting $(date -u +%FT%TZ) ==="
  if packer build -var "iso_checksum=${checksum}" "$dir/win11-analysis.pkr.hcl"; then
    echo "=== build-with-retry: attempt ${attempt} succeeded $(date -u +%FT%TZ) ==="
    if [[ -f "$qcow2_path" ]]; then
      echo "=== build-with-retry: writing $qcow2_path.sha256 ==="
      ( cd "$output_dir" && sha256sum "$vm_name.qcow2" > "$vm_name.qcow2.sha256" )
    else
      echo "=== build-with-retry: WARNING: packer reported success but $qcow2_path is missing, no checksum written ===" >&2
    fi
    exit 0
  fi
  echo "=== build-with-retry: attempt ${attempt} failed $(date -u +%FT%TZ), $(( max_attempts - attempt )) attempt(s) left ==="
  attempt=$(( attempt + 1 ))
done

echo "=== build-with-retry: all ${max_attempts} attempts failed ===" >&2
exit 1
