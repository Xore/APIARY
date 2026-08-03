#!/usr/bin/env bash
# prepare-pxe.sh -- builds the PXE boot staging directory this template's
# QEMU netdev (tftp=..., bootfile=ipxe.efi) serves from.
#
# Why PXE at all: booting from the Windows ISO's CD-ROM requires racing a
# "Press any key to boot from CD or DVD" prompt via VNC keystroke injection
# (the old boot_command). That race is flaky by design -- confirmed live
# across a full night of builds, it missed far more often than it hit,
# repeatedly leaving the guest stuck at BdsDxe "No bootable option or
# device was found" with a qcow2 that never grows past its initial
# allocation (see #288). PXE boot has no such prompt: the firmware just
# loads a network boot program and goes, so this failure class cannot
# happen at all via this path.
#
# How it works: OVMF's own built-in "UEFI PXEv4" client does DHCP+TFTP and
# loads exactly one file, which must be a real PE32+ EFI executable (a raw
# iPXE script is not enough -- confirmed live, OVMF rejects it with BdsDxe
# "Not Found"). That file is a *custom-built* ipxe.efi with this directory's
# boot.ipxe script EMBEDDED at compile time via iPXE's EMBED= build option.
# This is deliberate, not incidental: a stock ipxe.efi's autoboot sequence
# re-runs DHCP and looks for autoexec.ipxe over a `file:` URI scheme first
# (a local-filesystem lookup, not TFTP) -- confirmed live, that loops
# forever re-fetching ipxe.efi rather than ever reaching the script. QEMU's
# built-in slirp DHCP server also has no way to hand a *different* boot
# filename to iPXE clients vs plain PXE ROMs (the usual DHCP option 77
# "iPXE" user-class trick WDS/dnsmasq use), so serving a separate .ipxe
# script as a second boot stage isn't an option here either. Embedding the
# script is what actually works.
#
# The embedded script (boot.ipxe) chainloads wimboot with the Windows
# installer's own BCD/boot.sdi/boot.wim, copied byte-for-byte from the ISO
# -- wimboot's entire purpose is making bootmgfw (inside boot.wim) treat
# these as if they were read from a real disk, with no BCD editing needed.
# autounattend.xml still gets applied exactly as before: Windows Setup scans
# all attached media for it regardless of how WinPE itself was booted, so
# the secondary autounattend CD stays attached in win11-analysis.pkr.hcl.
#
# Secure Boot: OVMF only executes signed binaries when Secure Boot is
# enforced, and this custom ipxe.efi is not Microsoft-signed. Building a
# signed chain (enrolling a cert into OVMF's db) is real extra work with an
# actual security-relevant tradeoff (this template normally runs Secure
# Boot on deliberately, as an anti-detection measure -- see
# win11-analysis.pkr.hcl's firmware comment). The chosen approach: use the
# non-secboot OVMF variant for the *install* phase only. The final
# win11-kvm.xml detonation domain keeps the .ms secure-boot firmware
# unchanged -- the installed Windows Boot Manager is itself Microsoft-signed
# and boots fine under Secure Boot even though it wasn't installed under
# it, so detonation-time anti-detection posture (Confirm-SecureBootUEFI
# etc.) is unaffected by this.
#
# Usage: ./prepare-pxe.sh [path-to-Win11-iso]
# Regenerate after ever replacing the pinned ISO (autounattend.xml's
# iso_checksum comment explains why the checksum must match exactly).
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
iso="${1:-/var/dockge/sandbox/isos/Win11_Eval_x64.iso}"

if [[ ! -f "$iso" ]]; then
  echo "ISO not found: $iso" >&2
  exit 1
fi

echo "==> Extracting BCD, boot.sdi, boot.wim from $iso"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
7z x "$iso" -o"$tmpdir" boot/bcd boot/boot.sdi sources/boot.wim -y >/dev/null
mv "$tmpdir/boot/bcd" "$dir/BCD"
mv "$tmpdir/boot/boot.sdi" "$dir/BOOT.SDI"
mv "$tmpdir/sources/boot.wim" "$dir/boot.wim"

if [[ ! -f "$dir/wimboot" ]]; then
  echo "==> Downloading wimboot"
  curl -sSL -o "$dir/wimboot" https://github.com/ipxe/wimboot/releases/latest/download/wimboot
fi

if [[ ! -f "$dir/ipxe.efi" ]]; then
  echo "==> Building ipxe.efi with boot.ipxe embedded"
  if [[ ! -d "$dir/ipxe" ]]; then
    git clone --depth 1 https://github.com/ipxe/ipxe.git "$dir/ipxe"
  fi
  cp "$dir/boot.ipxe" "$dir/ipxe/src/embed.ipxe"
  make -C "$dir/ipxe/src" bin-x86_64-efi/ipxe.efi EMBED=embed.ipxe -j"$(nproc)"
  cp "$dir/ipxe/src/bin-x86_64-efi/ipxe.efi" "$dir/ipxe.efi"
fi

echo "==> PXE staging ready in $dir"
ls -la "$dir"/{BCD,BOOT.SDI,boot.wim,wimboot,ipxe.efi}
