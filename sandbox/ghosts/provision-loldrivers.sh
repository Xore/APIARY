#!/usr/bin/env bash
# provision-loldrivers.sh — the admin-gated BYOVD toggle #467 asked for,
# implemented.
#
# #467's own resolution (see the issue's comments, especially the
# owner-decision one): win11-analysis.qcow2 gets LOLDrivers unconditionally
# (sandbox/windows/packer/scripts/10-loldrivers.ps1, baked into every
# build) because it's air-gapped -- a kernel-level BYOVD exploit there is
# fully contained and observed. win11-ghosts.qcow2 has real WAN egress
# (#325/#331), so the SAME driver set there is a genuine host/network
# compromise vector, not a simulated one -- the exact asymmetry the issue's
# risk analysis is about. The issue's final decision reverses "never" to
# "yes, but only behind an explicit admin gate with a loud risk warning,
# never default-on, never reachable by an unauthenticated or automated
# path." This script IS that gate: a deliberately separate, hand-run,
# opt-in tool, not a pipeline step. Nothing in win11-ghosts-kvm.xml,
# provision-golden-image.sh, run_pending.sh, or any dashboard/orchestration
# code calls this. It only ever runs because a human with shell access to
# this host typed the command below, on purpose, once.
#
# What this actually does, offline, against a shut-down win11-ghosts.qcow2
# (same "no live qemu-system process, no Tamper-Protection-style live
# enforcement to fight" approach as
# sandbox/windows/packer/harden-defender-offline.sh, which this script's
# registry-write step is a close sibling of):
#   1. Downloads the same curated driver set 10-loldrivers.ps1 bakes into
#      win11-analysis.qcow2 (kept as a second copy deliberately, not a
#      shared-file refactor of that already live-verified Packer
#      provisioner -- see the note below the driver list), hash-verifying
#      each one before use.
#   2. Copies the verified drivers into C:\Windows\Temp via virt-copy-in.
#   3. Disables the Microsoft Vulnerable Driver Blocklist via an offline
#      virt-win-reg merge (same registry path, same resolved-ControlSetNNN
#      technique harden-defender-offline.sh already proved out, since
#      virt-win-reg --merge does not follow the CurrentControlSet alias).
#
# This is NOT the same operation as a golden-image rebuild -- no Packer,
# no QEMU boot, no multi-hour unattended install. It is a few-minute
# libguestfs operation against an image that already exists. The issue's
# last comment ("needs multiple real golden-image builds/runs to test
# properly... pick up whenever golden-image cycles are available") is
# about *validating this end to end with actual detonation runs*
# (with-set vs without, gate-on vs gate-off), which is a separate,
# heavier undertaking than building the toggle itself. This script is the
# toggle; running it against the live win11-ghosts.qcow2 and then actually
# detonating something through it is the deliberately-deferred part.
#
# Usage:
#   sudo sandbox/ghosts/provision-loldrivers.sh --i-accept-the-real-wan-risk [/path/to/win11-ghosts.qcow2]
#     Defaults to /var/dockge/sandbox/golden-images/win11-ghosts.qcow2.
#     The --i-accept-the-real-wan-risk flag is not a formality -- omit it
#     (or run with no args) and this script prints the warning below and
#     exits without touching anything.

set -euo pipefail

cat_warning() {
  cat >&2 <<'EOF'
================================================================
 WARNING: this adds real, kernel-level attackable surface to a
 WAN-CONNECTED guest.
================================================================
win11-ghosts.qcow2 has a genuine route to the real internet
(#325/#331 -- required for GHOSTS' browsing/NPC realism). A
sample that successfully exploits one of these drivers for
kernel-level code execution on THIS guest is not a contained,
observed technique the way the same exploit is on the air-gapped
win11-analysis.qcow2 -- it is a real host/network compromise
vector. See #467 for the full risk analysis and the owner
decision that makes this an explicit, individually-authorized,
never-default choice.

Re-run with --i-accept-the-real-wan-risk if that is genuinely
what you intend to do, right now, to this specific image.
================================================================
EOF
}

ACCEPT_RISK=0
IMAGE=""
for arg in "$@"; do
  case "$arg" in
    --i-accept-the-real-wan-risk) ACCEPT_RISK=1 ;;
    -h|--help) cat_warning; exit 0 ;;
    *) IMAGE="$arg" ;;
  esac
done

if [[ "$ACCEPT_RISK" -ne 1 ]]; then
  cat_warning
  exit 2
fi

[[ ${EUID} -eq 0 ]] || { echo "provision-loldrivers: run as root" >&2; exit 1; }

image="${IMAGE:-/var/dockge/sandbox/golden-images/win11-ghosts.qcow2}"

case "$image" in
  *win11-analysis.qcow2)
    echo "provision-loldrivers: refusing to touch $image -- win11-analysis.qcow2 already gets this set unconditionally via 10-loldrivers.ps1 during its own Packer build. This script is for win11-ghosts.qcow2 only; pointing it at the analysis image would double-inject or mask a real build-pipeline gap." >&2
    exit 1
    ;;
esac

[[ -f "$image" ]] || { echo "provision-loldrivers: $image not found" >&2; exit 1; }

if pgrep -af qemu-system | grep -qF -- "$image"; then
  echo "provision-loldrivers: refusing to touch $image -- a qemu-system process has it open right now." >&2
  exit 1
fi

for tool in virt-win-reg virt-copy-in guestfish curl md5sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "provision-loldrivers: $tool not found -- apt install libguestfs-tools curl coreutils" >&2
    exit 1
  fi
done

echo "=== provision-loldrivers: $(date -u +%FT%TZ) -- image: $image ==="
echo "--- risk accepted via --i-accept-the-real-wan-risk; proceeding ---"

# Second copy of 10-loldrivers.ps1's driver list, deliberately not
# refactored into a single shared source: that script is an already
# live-verified Packer provisioner (its own header cites the exact
# 2026-08-03 live-verification run) baked into a build pipeline that takes
# hours to re-run end to end. Restructuring it to read an external file
# just to deduplicate five lines risks a subtle path/parsing break with no
# fast way to re-verify it right now. If this list ever needs to change,
# change it in BOTH files -- this comment and 10-loldrivers.ps1's own
# header cross-reference each other for exactly that reason.
drivers_name=(RTCore64.sys WinRing0x64.sys kprocesshacker.sys gdrv.sys dbutil_2_3.sys)
drivers_hash=(2d8e4f38b36c334d0a32a7324832501d 828bb9cb1dd449cd65a29b18ec46055f bbbc9a6cc488cfb0f6c6934b193891eb b0954711c133d284a171dd560c8f492a c996d7971c49252c582171d9380360f2)

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

staged=()
for i in "${!drivers_name[@]}"; do
  name="${drivers_name[$i]}"
  hash="${drivers_hash[$i]}"
  url="https://media.githubusercontent.com/media/magicsword-io/LOLDrivers/main/drivers/$hash.bin"
  dest="$work/$name"
  echo "[+] Downloading $name..."
  curl -fsSL -o "$dest" "$url"
  actual="$(md5sum "$dest" | cut -d' ' -f1)"
  if [[ "$actual" != "$hash" ]]; then
    echo "[!] $name hash mismatch: expected $hash, got $actual -- skipping" >&2
    rm -f "$dest"
    continue
  fi
  echo "[+] $name verified ($actual)."
  staged+=("$dest")
done

if [[ ${#staged[@]} -eq 0 ]]; then
  echo "provision-loldrivers: no drivers verified -- nothing to inject, refusing to touch the registry either" >&2
  exit 1
fi

echo "--- injecting ${#staged[@]}/${#drivers_name[@]} verified driver(s) into C:\\Windows\\Temp ---"
guestfish -a "$image" -i mkdir-p "/Windows/Temp" 2>/dev/null || true
for f in "${staged[@]}"; do
  base="$(basename "$f")"
  # Idempotent re-run: virt-copy-in errors if the destination file already
  # exists (same lesson provision-golden-image.sh already documents).
  guestfish -a "$image" -i rm-f "/Windows/Temp/$base" 2>/dev/null || true
  virt-copy-in -a "$image" "$f" "/Windows/Temp/"
done

echo "--- disabling Microsoft Vulnerable Driver Blocklist (offline registry write) ---"
# Same CurrentControlSet-alias caveat harden-defender-offline.sh documents:
# virt-win-reg --merge does not resolve \CurrentControlSet\, it creates the
# literal path given -- resolve \Select\Current to the real ControlSetNNN
# ourselves first.
current="$(virt-win-reg "$image" 'HKEY_LOCAL_MACHINE\SYSTEM\Select' 2>/dev/null | sed -n 's/^"Current"=dword:0*\([0-9a-fA-F]*\)$/\1/p')"
[[ $current =~ ^[0-9a-fA-F]+$ ]] || { echo "provision-loldrivers: could not read SYSTEM\\Select\\Current from $image" >&2; exit 1; }
control_set="ControlSet$(printf '%03d' "$((16#$current))")"
echo "--- SYSTEM\\Select\\Current resolves to $control_set ---"

regfile="$(mktemp --suffix=.reg)"
trap 'rm -f "$regfile"' EXIT

cat > "$regfile" <<REGEOF
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\\$control_set\Control\CI\Config]
"VulnerableDriverBlocklistEnable"=dword:00000000
REGEOF

virt-win-reg --merge "$image" "$regfile"

echo "--- verifying (read back what was actually written) ---"
value="$(virt-win-reg "$image" "HKEY_LOCAL_MACHINE\\SYSTEM\\$control_set\\Control\\CI\\Config" 2>/dev/null | grep -i '"VulnerableDriverBlocklistEnable"' || true)"
echo "  VulnerableDriverBlocklistEnable: ${value:-<no value read back>}"
if ! printf '%s' "$value" | grep -qi 'dword:00000000'; then
  echo "provision-loldrivers: registry value did not read back as written -- do NOT trust this image as gated-open. Investigate before use." >&2
  exit 1
fi

present="$(guestfish -a "$image" -i glob ls "/Windows/Temp/*.sys" 2>/dev/null || true)"
echo "  drivers present in C:\\Windows\\Temp: $(printf '%s\n' "$present" | grep -c '\.sys$' || true)"

cat <<EOF

=== done. $image now carries ${#staged[@]} LOLDrivers BYOVD file(s) and the
=== blocklist disabled, on a WAN-connected guest. This is NOT reverted by
=== anything at boot (same lesson as harden-defender-offline.sh's registry
=== writes) -- it persists until this image is rebuilt from
=== win11-analysis.qcow2 fresh via 'qemu-img convert' again.
===
=== This does not prove anything loads through a real boot yet -- that
=== needs an actual detonation run against this specific image, which is
=== the deferred "golden-image builds/runs to test properly" part of #467.
=== Do not treat this image as validated for that purpose until such a run
=== has actually happened.
EOF
