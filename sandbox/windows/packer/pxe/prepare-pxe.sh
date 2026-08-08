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
# enforced, and this custom ipxe.efi is not Microsoft-signed by default.
# Rather than turning Secure Boot off for the install phase, this script
# builds and enrolls its own trust chain, so Secure Boot stays on the whole
# time (matching win11-kvm.xml's detonation-time firmware, which was always
# secure-boot-enforcing -- no split between install-time and detonation-time
# posture at all now):
#
#   1. Generate a self-signed cert+key (openssl) -- regenerated locally per
#      host, not a shared secret. Its only job is authorizing our own
#      ipxe.efi in a firmware trust store we also control; nothing about it
#      needs to be confidential or reused across machines to work, which is
#      exactly what makes this reproducible unattended on any host running
#      this script from scratch.
#   2. Sign ipxe.efi with it (sbsign, from sbsigntool).
#   3. Build a custom OVMF_VARS file (virt-fw-vars, from
#      python3-virt-firmware) with that cert enrolled into PK/KEK/db
#      *alongside* Microsoft's official win11 db/KEK certs (--microsoft-db
#      win11) -- our cert alone authorizes ipxe.efi, Microsoft's still
#      authorizes the Windows Boot Manager inside boot.wim/the installed OS.
#      Confirmed live both ways: the signed ipxe.efi boots clean under
#      OVMF_CODE_4M.secboot.fd with this vars file, and a deliberate
#      negative-control boot of the *unsigned* ipxe.efi against the same
#      vars file is correctly rejected ("Access Denied -- rejected probably
#      by Secure Boot"), proving enforcement is real and not silently
#      bypassed.
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

# Pinned to a specific release + checksum, not `releases/latest`: this
# binary chainloads into the signed boot chain built below (Secure Boot
# only re-verifies our own signature over whatever bytes were here at sign
# time, not wimboot's own provenance) -- a floating "latest" tag plus plain
# curl gives a compromised/rolled-back release or a MITM nothing to trip
# over. Bump both when deliberately upgrading wimboot.
WIMBOOT_VERSION=v2.9.0
WIMBOOT_SHA256=5f067ccdc4d084d5bf77b6c853bd0f8402dfc2b4cd1b103d358993ae97fae8e3
if [[ ! -f "$dir/wimboot" ]]; then
  echo "==> Downloading wimboot $WIMBOOT_VERSION"
  curl -sSL -o "$dir/wimboot" "https://github.com/ipxe/wimboot/releases/download/${WIMBOOT_VERSION}/wimboot"
  actual_sha256=$(sha256sum "$dir/wimboot" | cut -d' ' -f1)
  if [[ $actual_sha256 != "$WIMBOOT_SHA256" ]]; then
    rm -f "$dir/wimboot"
    echo "wimboot checksum mismatch: expected $WIMBOOT_SHA256, got $actual_sha256 -- refusing to use it" >&2
    exit 1
  fi
fi

if [[ ! -f "$dir/ipxe.efi.unsigned" ]]; then
  echo "==> Building ipxe.efi with boot.ipxe embedded"
  # Pinned to a specific commit (confirmed to build bin-x86_64-efi/ipxe.efi
  # cleanly) rather than a floating clone of master, for the same reason as
  # wimboot above -- this becomes part of the signed boot chain. Bump when
  # deliberately picking up upstream iPXE changes.
  IPXE_COMMIT=257e8faf109c7aecb2f18472927b680f77028eca
  if [[ ! -d "$dir/ipxe" ]]; then
    git init -q "$dir/ipxe"
    git -C "$dir/ipxe" fetch --depth 1 https://github.com/ipxe/ipxe.git "$IPXE_COMMIT"
    git -C "$dir/ipxe" checkout -q FETCH_HEAD
  fi
  cp "$dir/boot.ipxe" "$dir/ipxe/src/embed.ipxe"
  make -C "$dir/ipxe/src" bin-x86_64-efi/ipxe.efi EMBED=embed.ipxe -j"$(nproc)"
  cp "$dir/ipxe/src/bin-x86_64-efi/ipxe.efi" "$dir/ipxe.efi.unsigned"
fi

if [[ ! -f "$dir/pxe-cert.pem" ]]; then
  echo "==> Generating self-signed PXE signing cert (local to this host, not a shared secret)"
  openssl req -x509 -newkey rsa:2048 -keyout "$dir/pxe-cert.key" -out "$dir/pxe-cert.pem" \
    -days 3650 -nodes -subj "/CN=APIARY PXE boot signer/" 2>/dev/null
fi

echo "==> Signing ipxe.efi"
sbsign --key "$dir/pxe-cert.key" --cert "$dir/pxe-cert.pem" \
  --output "$dir/ipxe.efi" "$dir/ipxe.efi.unsigned"
sbverify --cert "$dir/pxe-cert.pem" "$dir/ipxe.efi" >/dev/null

echo "==> Building OVMF vars: our cert + Microsoft's win11 db/KEK, Secure Boot on"
if [[ ! -f "$dir/pxe-cert-guid.txt" ]]; then
  uuidgen > "$dir/pxe-cert-guid.txt"
fi
guid="$(cat "$dir/pxe-cert-guid.txt")"
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$dir/OVMF_VARS_4M.honeypot-pxe.fd"
virt-fw-vars --inplace "$dir/OVMF_VARS_4M.honeypot-pxe.fd" \
  --enroll-cert "$dir/pxe-cert.pem" \
  --microsoft-db win11 \
  --add-db "$guid" "$dir/pxe-cert.pem" \
  --sb

echo "==> PXE staging ready in $dir"
ls -la "$dir"/{BCD,BOOT.SDI,boot.wim,wimboot,ipxe.efi,OVMF_VARS_4M.honeypot-pxe.fd}
