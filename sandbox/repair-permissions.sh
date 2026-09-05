#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
# The account QEMU runs as is libvirt-qemu on Debian and qemu on EL -- this
# script assumed Debian's and aborted the whole sandbox-host-foundation step
# with "libvirt-qemu account is missing" on the rebuilt Rocky homeserver
# (#1609). Resolved through the same helper the Windows sandbox uses.
# shellcheck source=windows/setup/host-paths.sh
. "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/windows/setup/host-paths.sh"
qemu_user="$(sandbox_qemu_user)" || exit 1

root_dir=/var/lib/honeypot-sandbox
# acl is a dependency of this script, not of a distro: install-host.sh already
# puts it there on both, so this is only for a standalone run. Unconditional
# apt-get made it exit 127 on EL and take sandbox-host-foundation with it
# (#1609).
command -v setfacl >/dev/null 2>&1 || {
  if command -v apt-get >/dev/null 2>&1; then apt-get install -y acl
  elif command -v dnf >/dev/null 2>&1; then dnf install -y acl
  else echo "setfacl is missing and no apt-get/dnf to install it" >&2; exit 1
  fi
}

# QEMU gets traversal to the sandbox root, read-only golden-image access, and
# read/write access only to disposable overlays. Inbox/results remain private.
setfacl -m u:"${qemu_user}":x "$root_dir"
setfacl -m u:"${qemu_user}":rx,d:u:"${qemu_user}":rx "$root_dir/base"
setfacl -R -m u:"${qemu_user}":rX "$root_dir/base"
setfacl -m u:"${qemu_user}":rwx,d:u:"${qemu_user}":rwx "$root_dir/overlays"
setfacl -R -m u:"${qemu_user}":rwX "$root_dir/overlays"

echo "Sandbox QEMU ACLs applied"
getfacl -p "$root_dir" "$root_dir/base" "$root_dir/overlays"
