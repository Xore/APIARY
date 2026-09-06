#!/usr/bin/env bash
set -euo pipefail

base=${1:?usage: create-overlay.sh /var/lib/honeypot-sandbox/base/golden.qcow2 analysis-id}
analysis_id=${2:?analysis id required}
[[ $analysis_id =~ ^[a-zA-Z0-9._-]+$ ]] || { echo "invalid analysis id" >&2; exit 2; }
[[ -f $base ]] || { echo "base image not found: $base" >&2; exit 2; }

# The account QEMU runs as is libvirt-qemu on Debian and qemu on EL -- this
# script assumed Debian's and silently fell back to a "root:libvirt" group
# ownership that does not actually grant the EL qemu user access either
# (#3019, same class of fix as repair-permissions.sh in #3015/#3020).
# Resolved through the same helper the Windows sandbox uses.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=windows/setup/host-paths.sh
. "$script_dir/windows/setup/host-paths.sh"
qemu_user="$(sandbox_qemu_user)" || exit 1

overlay="/var/lib/honeypot-sandbox/overlays/${analysis_id}.qcow2"
[[ ! -e $overlay ]] || { echo "overlay already exists: $overlay" >&2; exit 2; }
qemu-img create -f qcow2 -F qcow2 -b "$base" "$overlay"
chmod 0640 "$overlay"
setfacl -m "u:${qemu_user}:rw" "$overlay"
echo "$overlay"
