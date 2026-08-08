#!/usr/bin/env bash
# harden-defender-offline.sh — write the Defender/Tamper Protection registry
# keys #91 asked for, offline, against a completed (shut down) golden image.
#
# Why this is not a Packer provisioner or post-processor: autounattend.xml
# already documents a measured, failed attempt at this from inside the
# guest --
#
#   "Disabling Defender outright is not possible here. Tamper Protection is
#    on by default in Windows 11 and guards its own registry key against
#    SYSTEM as well as Administrators -- measured on a booted build: every
#    policy key written during specialize was absent or reverted, and a
#    direct write returned 'Requested registry access is not allowed'.
#    specialize is simply not early enough; Defender is already protecting
#    itself by then."
#
# That is the *specialize* unattend pass, which runs during first boot --
# Windows, and Tamper Protection, are already running. This script instead
# writes the hive files directly while Windows is not running at all: no
# process is alive to enforce Tamper Protection, so there is nothing to
# fight. This is #91's own suggested alternative ("write them offline...
# with virt-win-reg against the built image").
#
# NOT wired into win11-analysis.pkr.hcl on purpose. A Packer provisioner or
# post-processor failure has already deleted a 6h26m build's entire output
# directory once for an unrelated reason (see that file's step-6 comment,
# #the-wevtutil-incident) -- the automated pipeline is not the place to add
# a step whose real-world behavior is not yet verified against a completed
# image. Run this by hand, once, after a build finishes and before treating
# the image as GOLDEN_READY (#52). If it proves out over a few builds, it
# can move into the pipeline as its own provisioner-independent stage.
#
# Usage: harden-defender-offline.sh [path-to-qcow2]
#   Defaults to the standard build output path. Refuses to touch the image
#   if any qemu-system process currently has it open (Packer build in
#   progress, or someone reverted a domain to it) -- libguestfs writing to
#   a qcow2 a live qemu process also has open is exactly how you corrupt
#   both.
set -euo pipefail

image="${1:-/var/dockge/sandbox/golden-images/win11-analysis.qcow2}"

if [ ! -f "$image" ]; then
  echo "harden-defender-offline: $image does not exist" >&2
  exit 1
fi

if pgrep -af qemu-system | grep -qF -- "$image"; then
  echo "harden-defender-offline: refusing to touch $image -- a qemu-system process has it open right now (build in progress, or a domain is running against it)." >&2
  exit 1
fi

for tool in virt-win-reg; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "harden-defender-offline: $tool not found -- apt install libguestfs-tools" >&2
    exit 1
  fi
done

echo "=== harden-defender-offline: $(date -u +%FT%TZ) -- image: $image ==="

# NOT CurrentControlSet: that symbolic alias resolves fine for virt-win-reg
# reads (confirmed) but not for `--merge`/reg_import -- hit live against
# win11-ghosts.qcow2, "cannot create \CurrentControlSet\Services\ since
# parent \CurrentControlSet\Services\ does not exist", because reg_import
# creates the literal path it's given rather than resolving the alias the
# way a live registry editor would. Resolve \Select\Current to the real
# ControlSetNNN ourselves and write that concrete path instead.
current="$(virt-win-reg "$image" 'HKEY_LOCAL_MACHINE\SYSTEM\Select' 2>/dev/null | sed -n 's/^"Current"=dword:0*\([0-9a-fA-F]*\)$/\1/p')"
[[ $current =~ ^[0-9a-fA-F]+$ ]] || { echo "harden-defender-offline: could not read SYSTEM\\Select\\Current from $image" >&2; exit 1; }
control_set="ControlSet$(printf '%03d' "$((16#$current))")"
echo "--- SYSTEM\\Select\\Current resolves to $control_set ---"

# Start=4 is SERVICE_DISABLED (services.h); services with no Start value
# already present are created with one rather than silently skipped, since
# New-Item/Set-ItemProperty from inside the guest already established these
# keys exist under every install this image is built from.
regfile="$(mktemp --suffix=.reg)"
trap 'rm -f "$regfile"' EXIT

cat > "$regfile" <<REGEOF
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\\$control_set\Services\WinDefend]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\\$control_set\Services\WdBoot]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\\$control_set\Services\WdFilter]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\\$control_set\Services\WdNisDrv]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\\$control_set\Services\WdNisSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\\$control_set\Services\Sense]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\\$control_set\Services\SecurityHealthService]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\\$control_set\Services\wscsvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features]
"TamperProtection"=dword:00000004
REGEOF

echo "--- writing ---"
# Re-checked immediately before the write, not just once at the top of the
# script: several read-only virt-win-reg calls and mktemp happened in
# between, long enough for another qemu-system process (a new build, or
# someone reverting a domain to this image) to have opened it in the
# meantime. Writing against an image a live qemu process also has open is
# exactly the corruption this script's header warns about.
if pgrep -af qemu-system | grep -qF -- "$image"; then
  echo "harden-defender-offline: refusing to write $image -- a qemu-system process has it open now (it did not when this script started)." >&2
  exit 1
fi
virt-win-reg --merge "$image" "$regfile"

echo "--- verifying (read back what was actually written) ---"
verify_failed=0
for svc in WinDefend WdBoot WdFilter WdNisDrv WdNisSvc Sense SecurityHealthService wscsvc; do
  value="$(virt-win-reg "$image" "HKEY_LOCAL_MACHINE\\SYSTEM\\$control_set\\Services\\$svc" 2>/dev/null | grep -i '"Start"' || true)"
  echo "  $svc: ${value:-<no Start value read back>}"
  if ! printf '%s' "$value" | grep -qi 'dword:00000004'; then
    verify_failed=1
  fi
done
value="$(virt-win-reg "$image" 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features' 2>/dev/null | grep -i '"TamperProtection"' || true)"
echo "  TamperProtection: ${value:-<no value read back>}"
if ! printf '%s' "$value" | grep -qi 'dword:00000004'; then
  verify_failed=1
fi

if [ "$verify_failed" -ne 0 ]; then
  echo "harden-defender-offline: at least one key did not read back as written -- do NOT trust this image as hardened. Investigate before GOLDEN_READY." >&2
  exit 1
fi

cat <<'EOF'

=== registry write verified. This does NOT yet prove Defender stays off
=== through a real boot -- that requires actually booting this image and
=== running (after a reboot, not in the same session that disabled it):
===
===   Get-MpComputerStatus | Select AMServiceEnabled, AntivirusEnabled
===
=== Both must read False. If either reads True, Tamper Protection (or
=== something else) reasserted itself and this approach needs more work
=== before the image can be trusted for detonation -- see #91.
EOF
