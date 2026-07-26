#!/usr/bin/env bash
set -euo pipefail

base=${1:?usage: create-overlay.sh /var/lib/honeypot-sandbox/base/golden.qcow2 analysis-id}
analysis_id=${2:?analysis id required}
[[ $analysis_id =~ ^[a-zA-Z0-9._-]+$ ]] || { echo "invalid analysis id" >&2; exit 2; }
[[ -f $base ]] || { echo "base image not found: $base" >&2; exit 2; }

overlay="/var/lib/honeypot-sandbox/overlays/${analysis_id}.qcow2"
[[ ! -e $overlay ]] || { echo "overlay already exists: $overlay" >&2; exit 2; }
qemu-img create -f qcow2 -F qcow2 -b "$base" "$overlay"
chmod 0640 "$overlay"
chown libvirt-qemu:libvirt "$overlay" 2>/dev/null || chown root:libvirt "$overlay"
echo "$overlay"
