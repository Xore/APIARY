#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

root_dir=/var/lib/honeypot-sandbox
base=${1:-${SANDBOX_LINUX_BASE:-$root_dir/base/ubuntu-noble.qcow2}}
boot_dir="$root_dir/base/boot"
work=$(mktemp -d "$root_dir/base/.boot-extract.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

[[ -r $base ]] || { echo "Missing sandbox base image: $base" >&2; exit 1; }

kernel_name=$(
  virt-ls -a "$base" /boot |
    awk '/^vmlinuz-[0-9]/{print}' |
    sort -V |
    tail -n 1
)
[[ -n $kernel_name ]] || { echo "No Linux kernel found in $base" >&2; exit 1; }
initrd_name="initrd.img-${kernel_name#vmlinuz-}"

virt-copy-out --ro -a "$base" \
  "/boot/$kernel_name" "/boot/$initrd_name" "$work"

install -d -m 0755 -o root -g root "$boot_dir"
install -m 0644 -o root -g root "$work/$kernel_name" "$boot_dir/vmlinuz"
install -m 0644 -o root -g root "$work/$initrd_name" "$boot_dir/initrd.img"
printf '%s\n' "$kernel_name" >"$boot_dir/version"
chmod 0644 "$boot_dir/version"

echo "Extracted direct-boot kernel: $kernel_name"
