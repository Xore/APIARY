#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_xml="$script_dir/network-filter.xml"
name=honeypot-sandbox-strict
existing=$(virsh nwfilter-dumpxml "$name" 2>/dev/null || true)

if [[ -z $existing ]]; then
  virsh nwfilter-define "$source_xml" >/dev/null
  echo "Defined libvirt network filter: $name"
  exit 0
fi

# Preserve libvirt's existing UUID so nwfilter-define updates the named filter
# instead of rejecting the repository XML as a conflicting new object.
uuid=$(sed -n "s:.*<uuid>\([^<]*\)</uuid>.*:\1:p" <<<"$existing" | head -n 1)
[[ $uuid =~ ^[0-9a-fA-F-]{36}$ ]] || { echo "Could not read UUID for $name" >&2; exit 1; }
temporary=$(mktemp)
trap 'rm -f -- "$temporary"' EXIT
awk -v uuid="$uuid" 'NR==1 { print; print "  <uuid>" uuid "</uuid>"; next } { print }' "$source_xml" >"$temporary"
virsh nwfilter-define "$temporary" >/dev/null
echo "Updated libvirt network filter: $name ($uuid)"
