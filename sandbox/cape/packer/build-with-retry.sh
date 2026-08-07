#!/usr/bin/env bash
# build-with-retry.sh — wraps `packer build` for win11-cape.pkr.hcl with
# automatic retry on failure.
#
# Adapted from sandbox/windows/packer/build-with-retry.sh (#194's own retry
# reasoning applies unchanged: packer's WinRM communicator treats some
# transport-level errors as fatal on the first occurrence despite logging
# them with the same "Retryable error:" prefix used for errors it does
# retry). Differences from that file:
#
#   * starts pxe/unplug-pxe-after-delay.sh (shared, see win11-cape.pkr.hcl's
#     own pxe_dir comment for why it's not duplicated) pointed at THIS
#     build's own QMP socket before each attempt, and kills it after --
#     win11-analysis.pkr.hcl's own build never needed this script to start
#     it, because whoever runs that build has always started it by hand
#     alongside; wrapping it here means this build doesn't depend on a
#     human remembering to do that a second time for a second vm_name.
#   * vm_name/output/checksum-file naming: win11-cape, not win11-analysis
#   * builds into a staging_dir, then moves the result into shared_dir --
#     see win11-cape.pkr.hcl's own output_dir comment: Packer's qemu
#     builder refuses to run when output_directory already exists, and
#     shared_dir already holds win11-analysis.qcow2/win11-ghosts.qcow2.
#     win11-analysis.pkr.hcl never needed this because it always was the
#     first build into an empty shared_dir.
#
# NOT pxe/unplug-pxe-on-reset.sh (tried first, 2026-08-07): its own
# device_del approach needs QEMU hotplug support, which q35's implicit
# pcie.0 root bus does not provide -- confirmed live, "Bus 'pcie.0' does
# not support hotplugging", exactly the failure unplug-pxe-after-delay.sh's
# own header already documents discovering and designing around (set_link
# + eject, neither of which needs hotplug at all). Direct instruction: use
# the fixed-delay script, 120s.
#
# Usage: build-with-retry.sh <iso_checksum> [max_attempts]
set -euo pipefail

checksum="${1:?usage: build-with-retry.sh <iso_checksum> [max_attempts]}"
max_attempts="${2:-3}"
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

shared_dir="/var/dockge/sandbox/golden-images"
staging_dir="$shared_dir/.building-win11-cape"
vm_name="win11-cape"
staged_qcow2_path="$staging_dir/$vm_name.qcow2"
qcow2_path="$shared_dir/$vm_name.qcow2"
qmp_sock="/tmp/win11-cape-qmp.sock"
# Shared PXE staging script -- see win11-cape.pkr.hcl's pxe_dir variable
# comment for why this points at win11-analysis's own prepared directory
# rather than a second copy.
unplug_script="/var/dockge/stacks/apiary/sandbox/windows/packer/pxe/unplug-pxe-after-delay.sh"
unplug_delay=120
# ide1-cd0: confirmed against this build's own actual qemu command line
# (ide0-hd0 the disk, ide1-cd0 the Windows ISO, ide2-cd0 the autounattend
# CD) -- same drive ordering unplug-pxe-after-delay.sh's own header
# documents verifying for win11-analysis.pkr.hcl, since both templates
# attach drives in the same iso_url + cd_files order.
unplug_iso_device="ide1-cd0"

# packer resolves cd_files entries (autounattend.xml) relative to its own
# working directory, not the .hcl file's location -- same gotcha
# win11-analysis.pkr.hcl's own build-with-retry.sh already documents.
cd "$dir"

attempt=1
while (( attempt <= max_attempts )); do
  echo "=== build-with-retry (cape): attempt ${attempt}/${max_attempts} starting $(date -u +%FT%TZ) ==="

  # Same socket-path staleness concern applies here as it did for the
  # event-driven script this replaced: the path isn't touched between
  # attempts, so a leftover file from a killed prior attempt could
  # otherwise be mistaken for a live one. Remove it first, then wait for
  # THIS attempt's qemu to actually create it before connecting.
  rm -f "$qmp_sock"

  unplug_pid=""
  if [[ -f "$unplug_script" ]]; then
    (
      for _ in $(seq 1 120); do
        [[ -S "$qmp_sock" ]] && break
        sleep 1
      done
      if [[ -S "$qmp_sock" ]]; then
        python3 "$unplug_script" "$qmp_sock" "$unplug_delay" "$unplug_iso_device"
      else
        echo "=== unplug-pxe-after-delay.sh: ${qmp_sock} never appeared within 120s -- not starting it, PXE NIC/ISO will not be disabled this attempt ===" >&2
      fi
    ) &
    unplug_pid=$!
    echo "=== unplug-pxe-after-delay.sh: waiting for ${qmp_sock}, then disabling pxenet0 + ejecting ${unplug_iso_device} after ${unplug_delay}s (wrapper pid ${unplug_pid}) ==="
  else
    echo "=== WARNING: ${unplug_script} not found -- PXE NIC will not be" \
         "disabled after boot; build may loop back into PXE on Setup's own restarts ===" >&2
  fi

  # Guaranteed-empty per Packer's own requirement -- rm -rf only ever
  # touches this dedicated staging path, never shared_dir itself.
  rm -rf "$staging_dir"

  build_ok=1
  packer build -var "iso_checksum=${checksum}" "$dir/win11-cape.pkr.hcl" || build_ok=0

  if [[ -n "$unplug_pid" ]]; then
    kill "$unplug_pid" 2>/dev/null || true
    wait "$unplug_pid" 2>/dev/null || true
  fi

  if [[ $build_ok -eq 1 ]]; then
    echo "=== build-with-retry (cape): attempt ${attempt} succeeded $(date -u +%FT%TZ) ==="
    if [[ -f "$staged_qcow2_path" ]]; then
      echo "=== build-with-retry (cape): moving $staged_qcow2_path -> $qcow2_path ==="
      # -n: refuses to clobber an existing win11-cape.qcow2 rather than
      # silently overwriting a previously-built golden image on a rebuild
      # -- move the old one aside by hand first if that's really wanted.
      mv -n "$staged_qcow2_path" "$qcow2_path"
      rm -rf "$staging_dir"
      echo "=== build-with-retry (cape): writing $qcow2_path.sha256 ==="
      ( cd "$shared_dir" && sha256sum "$vm_name.qcow2" > "$vm_name.qcow2.sha256" )
    else
      echo "=== build-with-retry (cape): WARNING: packer reported success but $staged_qcow2_path is missing, nothing moved ===" >&2
    fi
    exit 0
  fi
  echo "=== build-with-retry (cape): attempt ${attempt} failed $(date -u +%FT%TZ), $(( max_attempts - attempt )) attempt(s) left ==="
  attempt=$(( attempt + 1 ))
done

echo "=== build-with-retry (cape): all ${max_attempts} attempts failed ===" >&2
exit 1
