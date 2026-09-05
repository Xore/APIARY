#!/usr/bin/env bash
# Host-dependent libvirt/QEMU paths for the Windows sandbox domains.
#
# The three domain XMLs (packer/win11-kvm.xml, ../../ghosts/win11-ghosts-kvm.xml,
# ../../cape/win11-cape-kvm.xml) were written against Ubuntu and name Debian's
# paths literally:
#
#   <emulator>/usr/bin/qemu-system-x86_64</emulator>
#   <loader ...>/usr/share/OVMF/OVMF_CODE_4M.secboot.fd</loader>
#   <nvram template='/usr/share/OVMF/OVMF_VARS_4M.ms.fd' ...>
#
# None of those exist on the Rocky 10 homeserver (#1609's rebuild), so every
# `virsh define` failed:
#
#   qemu-img: Could not open '/usr/share/OVMF/OVMF_VARS_4M.ms.fd'
#   chown: invalid user: 'libvirt-qemu:kvm'
#   error: Cannot check QEMU binary /usr/bin/qemu-system-x86_64
#
# EL ships the same EDK2 builds and the same QEMU under different names:
# /usr/libexec/qemu-kvm, and /usr/share/edk2/ovmf/OVMF_{CODE,VARS}.secboot.fd
# (the enrolled-keys pair -- see /usr/share/qemu/firmware/30-edk2-ovmf-x64-sb-
# enrolled.json, whose features list is `enrolled-keys` + `secure-boot`, i.e.
# exactly what Debian's *_4M.ms.fd provides and what the Windows 11 installer
# requires).
#
# Resolved at use time rather than baked into the XMLs, so the XMLs stay one
# spec for both distros and an operator running kvm_manage.sh by hand gets the
# same answer the installer does.
#
# Each function prints a path and returns 1 with a message on stderr if nothing
# on this host matches -- callers must not silently continue with an empty
# string, which is how a domain gets defined against no firmware at all.

_first_existing() {
  local candidate
  for candidate in "$@"; do
    [[ -e "$candidate" ]] && { printf '%s\n' "$candidate"; return 0; }
  done
  return 1
}

# The QEMU system emulator libvirt should run the domain with.
sandbox_qemu_emulator() {
  _first_existing \
    /usr/bin/qemu-system-x86_64 \
    /usr/libexec/qemu-kvm \
    /usr/bin/qemu-kvm \
    || { echo "no QEMU x86_64 emulator found (looked for qemu-system-x86_64, qemu-kvm)" >&2; return 1; }
}

# Secure-Boot-capable OVMF code image (read-only half of the pflash pair).
sandbox_ovmf_code() {
  _first_existing \
    /usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
    /usr/share/edk2/ovmf/OVMF_CODE.secboot.fd \
    || { echo "no Secure Boot OVMF code image found (install ovmf on Debian, edk2-ovmf on EL)" >&2; return 1; }
}

# OVMF variables template WITH the Microsoft keys enrolled -- Windows 11 will
# not boot Secure Boot against an unenrolled template.
sandbox_ovmf_vars_template() {
  _first_existing \
    /usr/share/OVMF/OVMF_VARS_4M.ms.fd \
    /usr/share/edk2/ovmf/OVMF_VARS.secboot.fd \
    || { echo "no enrolled-keys OVMF vars template found (install ovmf on Debian, edk2-ovmf on EL)" >&2; return 1; }
}

# Owner for files libvirt's QEMU process must write (nvram, disks).
# Debian runs QEMU as libvirt-qemu:kvm, EL as qemu:qemu.
sandbox_qemu_owner() {
  if id -u libvirt-qemu >/dev/null 2>&1; then
    echo "libvirt-qemu:kvm"
  elif id -u qemu >/dev/null 2>&1; then
    echo "qemu:qemu"
  else
    echo "no libvirt-qemu or qemu user on this host" >&2
    return 1
  fi
}

# Per-domain UEFI variables file.
#
# The XMLs ask libvirt to build the domain's nvram as qcow2 from a raw
# template (<nvram template='...' templateFormat='raw' format='qcow2'>). EL's
# libvirt refuses that outright:
#
#   error: Failed to start domain 'win11-ghosts'
#   error: Operation not supported: conversion of the nvram template to
#          another target format is not supported
#
# and it refuses it even when the qcow2 already exists, so pre-creating one
# (which is what the installer did, for the Debian-side variant of this same
# libvirt refusal) does not help. Verified live on 2026-09-05: with a raw copy
# of the vars template and <nvram format='raw'>, the identical domain starts.
#
# A raw copy is what the qcow2 held anyway -- 528 KiB of UEFI variables, no
# compression worth having -- so both distros now get the same simple thing.
sandbox_nvram_raw_path() {
  local declared="$1"
  printf '%s\n' "${declared%.qcow2}.fd"
}

# sandbox_ensure_nvram <path> -- create the domain's nvram from this host's
# enrolled-keys template if it is not there yet. Idempotent.
sandbox_ensure_nvram() {
  local target="$1" template owner
  [[ -f "$target" ]] && return 0
  template="$(sandbox_ovmf_vars_template)" || return 1
  owner="$(sandbox_qemu_owner)" || return 1
  mkdir -p "$(dirname "$target")"
  cp "$template" "$target" || return 1
  chown "$owner" "$target" || return 1
  chmod 0600 "$target"
}

# Print the nvram path a domain XML declares (the qcow2 one, as written).
sandbox_nvram_path_in_xml() {
  sed -n "s#.*<nvram[^>]*>\\(.*\\)</nvram>.*#\\1#p" "$1" | head -1
}

# Just the user half of sandbox_qemu_owner, for setfacl/getent callers.
sandbox_qemu_user() {
  local owner
  owner="$(sandbox_qemu_owner)" || return 1
  printf '%s\n' "${owner%%:*}"
}

# Print a domain XML with the Debian paths rewritten to this host's, on stdout.
# A host that already has the literal paths (Debian) gets the file back byte
# for byte, so nothing changes where this was already working.
sandbox_render_domain_xml() {
  local xml="$1" emulator code vars
  emulator="$(sandbox_qemu_emulator)" || return 1
  code="$(sandbox_ovmf_code)" || return 1
  vars="$(sandbox_ovmf_vars_template)" || return 1
  local declared raw
  declared="$(sandbox_nvram_path_in_xml "$xml")"
  raw="$(sandbox_nvram_raw_path "$declared")"
  sed \
    -e "s#/usr/bin/qemu-system-x86_64#${emulator}#g" \
    -e "s#/usr/share/OVMF/OVMF_CODE_4M.secboot.fd#${code}#g" \
    -e "s#/usr/share/OVMF/OVMF_VARS_4M.ms.fd#${vars}#g" \
    -e "s#<nvram[^>]*>${declared}</nvram>#<nvram format='raw'>${raw}</nvram>#" \
    "$xml"
}

# sandbox_define_domain <xml> -- render the XML for this host, make sure the
# domain's nvram exists, and define it. The single place both the installer
# and kvm_manage.sh go through, so they cannot disagree.
sandbox_define_domain() {
  local xml="$1" rendered raw rc=0
  raw="$(sandbox_nvram_raw_path "$(sandbox_nvram_path_in_xml "$xml")")"
  [[ -n "$raw" ]] || { echo "no <nvram> element in $xml" >&2; return 1; }
  sandbox_ensure_nvram "$raw" || return 1
  rendered="$(mktemp /tmp/apiary-domain.XXXXXX.xml)"
  if sandbox_render_domain_xml "$xml" > "$rendered"; then
    virsh define "$rendered" || rc=1
  else
    rc=1
  fi
  rm -f "$rendered"
  return "$rc"
}
