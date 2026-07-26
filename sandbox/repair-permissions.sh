#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
getent passwd libvirt-qemu >/dev/null || { echo "libvirt-qemu account is missing" >&2; exit 1; }

root_dir=/var/lib/honeypot-sandbox
apt-get install -y acl

# QEMU gets traversal to the sandbox root, read-only golden-image access, and
# read/write access only to disposable overlays. Inbox/results remain private.
setfacl -m u:libvirt-qemu:x "$root_dir"
setfacl -m u:libvirt-qemu:rx,d:u:libvirt-qemu:rx "$root_dir/base"
setfacl -R -m u:libvirt-qemu:rX "$root_dir/base"
setfacl -m u:libvirt-qemu:rwx,d:u:libvirt-qemu:rwx "$root_dir/overlays"
setfacl -R -m u:libvirt-qemu:rwX "$root_dir/overlays"

echo "Sandbox QEMU ACLs applied"
getfacl -p "$root_dir" "$root_dir/base" "$root_dir/overlays"
