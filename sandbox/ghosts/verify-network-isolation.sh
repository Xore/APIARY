#!/usr/bin/env bash
# verify-network-isolation.sh — proves the virbr-ghosts network policy
# (#325) from inside a guest, not just by reading the firewall rules.
#
# Boots a throwaway clone of the Linux sandbox's own golden Ubuntu image
# (/var/lib/honeypot-sandbox/base/ubuntu-noble.qcow2) on the ghosts network,
# injects netcheck-guest.sh, lets it run and power the guest off, then
# copies the result back out. Nothing here is GHOSTS- or Windows-specific --
# it tests the bridge/iptables policy, which doesn't care what OS is
# attached to it.
#
# Re-run this after any libvirt, iptables, or host networking change, the
# same "verify, don't just configure" standard sandbox-network.xml already
# holds the isolated network to.
#
# Usage: sudo sandbox/ghosts/verify-network-isolation.sh

set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
base=/var/lib/honeypot-sandbox/base/ubuntu-noble.qcow2
kernel=/var/lib/honeypot-sandbox/base/boot/vmlinuz
initrd=/var/lib/honeypot-sandbox/base/boot/initrd.img
vm=ghosts-netcheck-$$
overlay="/var/lib/honeypot-sandbox/overlays/${vm}.qcow2"
work="$(mktemp -d)"
mac="52:54:00:ee:$(printf '%02x' $((RANDOM % 256))):$(printf '%02x' $((RANDOM % 256)))"

[[ -f $base ]] || { echo "missing $base -- run sandbox/prepare-linux-base.sh first" >&2; exit 1; }
[[ -f $kernel && -f $initrd ]] || { echo "missing extracted kernel/initrd -- run sandbox/extract-linux-boot.sh first" >&2; exit 1; }
virsh net-info ghosts >/dev/null 2>&1 || { echo "libvirt network 'ghosts' does not exist -- run install-network.sh net-setup first" >&2; exit 1; }

cleanup() {
  virsh destroy "$vm" >/dev/null 2>&1 || true
  virsh undefine "$vm" >/dev/null 2>&1 || true
  rm -f -- "$overlay"
  rm -rf -- "$work"
}
trap cleanup EXIT

echo "== creating throwaway overlay"
qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$overlay"
# The golden image deliberately ships no network config -- the isolated
# pipelines configure their interface by hand (guest-runner.sh does a plain
# `ip address add`) because their network has no DHCP server to answer in
# the first place. virbr-ghosts does, so this throwaway guest needs a
# systemd-networkd DHCP config it wouldn't otherwise have, dropped in
# offline the same way the other pipelines drop in their own runtime files.
virt-customize -a "$overlay" \
  --write '/etc/systemd/network/20-dhcp.network:[Match]
Name=en*
[Network]
DHCP=yes' \
  --firstboot "$here/netcheck-guest.sh" \
  --run-command 'rm -f /etc/machine-id && touch /etc/machine-id' \
  >/dev/null

echo "== booting on the ghosts network"
virt-install --name "$vm" --import --transient --noautoconsole \
  --memory 1024 --vcpus 1 --cpu host-model,disable=vmx --osinfo ubuntu24.04 \
  --boot "kernel=$kernel,initrd=$initrd,kernel_args=root=LABEL=cloudimg-rootfs ro console=ttyS0" \
  --disk "path=$overlay,format=qcow2,bus=sata,cache=none" \
  --network "network=ghosts,model=virtio,mac=$mac,filterref.filter=honeypot-sandbox-strict" \
  --graphics none --video none --sound none \
  --serial "file,path=$work/console.log" >/dev/null

echo "== waiting for the guest to finish and power off"
deadline=$((SECONDS + 180))
while virsh domstate "$vm" >/dev/null 2>&1 && (( SECONDS < deadline )); do
  sleep 3
done
if virsh domstate "$vm" >/dev/null 2>&1; then
  echo "guest did not power off within 3 minutes -- forcing destroy" >&2
  virsh destroy "$vm" >/dev/null 2>&1 || true
fi

echo "== extracting results"
if ! virt-copy-out --ro -a "$overlay" /root/netcheck-result.txt "$work" 2>/dev/null; then
  echo "FAIL: netcheck-result.txt was never written -- the guest likely never booted or the test script crashed" >&2
  echo "-- console log --" >&2
  tail -c 4096 "$work/console.log" >&2 2>/dev/null || true
  exit 1
fi

virt-copy-out --ro -a "$overlay" /root/netcheck-diag.txt "$work" 2>/dev/null || true

echo
[[ -f "$work/netcheck-diag.txt" ]] && { echo "-- diagnostics --"; cat "$work/netcheck-diag.txt"; echo; }
cat "$work/netcheck-result.txt"
echo

if grep -q '^FAIL' "$work/netcheck-result.txt"; then
  echo "RESULT: FAIL -- one or more checks did not hold. Do not detonate real samples on this network." >&2
  exit 1
fi
echo "RESULT: PASS -- all checks held."
