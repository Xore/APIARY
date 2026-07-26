#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root: sudo $0" >&2
  exit 1
fi

apt-get update
# Keep the complete QEMU package set in Ubuntu's standard family. Mixing the
# HWE qemu-system package with qemu-utils/OVMF selects mutually conflicting
# ubuntu-virt and ubuntu-virt-hwe dependency families on Ubuntu 26.04.
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  qemu-system-x86 libvirt-daemon-system libvirt-clients virtinst \
  libguestfs-tools ovmf swtpm swtpm-tools qemu-utils nftables acl tcpdump

install -d -m 0750 -o root -g libvirt /var/lib/honeypot-sandbox
install -d -m 0750 -o root -g libvirt /var/lib/honeypot-sandbox/{base,overlays,inbox,results,pcap}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bash "$script_dir/repair-permissions.sh"

systemctl enable --now libvirtd.service 2>/dev/null || true
systemctl enable --now virtqemud.socket virtnetworkd.socket 2>/dev/null || true
bash "$script_dir/apply-network-filter.sh"

if ! virsh net-info honeypot-sandbox >/dev/null 2>&1; then
  virsh net-define "$script_dir/network.xml"
fi
virsh net-autostart honeypot-sandbox
virsh net-start honeypot-sandbox 2>/dev/null || true

# The default libvirt NAT network is unnecessary and dangerous for malware VMs.
if virsh net-info default >/dev/null 2>&1; then
  virsh net-autostart default --disable 2>/dev/null || true
  virsh net-destroy default 2>/dev/null || true
fi

echo "Sandbox host foundation installed. No guest VM has been created."
virsh net-dumpxml honeypot-sandbox
