#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: sudo $0 --i-understand-this-executes-untrusted-code /absolute/path/to/sample" >&2
  exit 2
}

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
[[ ${1:-} == --i-understand-this-executes-untrusted-code ]] || usage
sample=${2:-}
[[ $sample == /* && -f $sample && ! -L $sample ]] || usage

root_dir=/var/lib/honeypot-sandbox
if [[ -r /etc/default/honeypot-sandbox ]]; then
  # Root-owned policy only; never source request or sample-controlled content.
  # shellcheck disable=SC1091
  source /etc/default/honeypot-sandbox
fi
base=${SANDBOX_LINUX_BASE:-$root_dir/base/ubuntu-noble.qcow2}
windows_mode=${SANDBOX_WINDOWS_MODE:-wine}
network_mode=${SANDBOX_NETWORK_MODE:-isolated}
memory_mb=${SANDBOX_VM_MEMORY_MB:-3072}
[[ $windows_mode == static || $windows_mode == wine ]] || {
  echo "SANDBOX_WINDOWS_MODE must be static or wine" >&2
  exit 1
}
[[ $network_mode == isolated || $network_mode == controlled ]] || {
  echo "SANDBOX_NETWORK_MODE must be isolated or controlled" >&2
  exit 1
}
[[ $memory_mb =~ ^[0-9]+$ ]] && ((memory_mb >= 2048 && memory_mb <= 8192)) || {
  echo "SANDBOX_VM_MEMORY_MB must be between 2048 and 8192" >&2
  exit 1
}
[[ -r $base ]] || { echo "Missing base image: run sandbox/prepare-linux-base.sh" >&2; exit 1; }
virsh net-info honeypot-sandbox >/dev/null

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
hash=$(sha256sum "$sample" | awk '{print $1}')
classification=$(python3 "$script_dir/guest-payload-classifier.py" "$sample")
kind=$(jq -r '.code' <<<"$classification")
platform=$(jq -r '.platform | ascii_downcase' <<<"$classification")
[[ $platform == windows ]] || platform=linux
stamp=$(date -u +%Y%m%dT%H%M%SZ)
job="${platform}-${stamp}-${hash:0:12}"
overlay="$root_dir/overlays/$job.qcow2"
result="$root_dir/results/$job"
vm="hpsbx-${hash:0:12}-${stamp//[^0-9]/}"
mac="52:54:00:${hash:0:2}:${hash:2:2}:${hash:4:2}"
pcap_pid=

stop_capture() {
  if [[ -n ${pcap_pid:-} ]]; then
    kill -INT "$pcap_pid" >/dev/null 2>&1 || true
    wait "$pcap_pid" 2>/dev/null || true
    pcap_pid=
  fi
}

cleanup() {
  stop_capture
  virsh destroy "$vm" >/dev/null 2>&1 || true
  virsh undefine "$vm" --nvram >/dev/null 2>&1 || virsh undefine "$vm" >/dev/null 2>&1 || true
  rm -f -- "$overlay"
}
trap cleanup EXIT INT TERM

mkdir -p "$result"
chmod 0700 "$result"
date -u +%FT%TZ >"$result/host-started-at.txt"
qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$overlay"
virt-customize -a "$overlay" \
  --mkdir /opt/honeypot/input \
  --copy-in "$sample:/opt/honeypot/input" \
  --copy-in "$script_dir/guest-runner.sh:/usr/local/sbin" \
  --copy-in "$script_dir/guest-pe-forensics.py:/usr/local/sbin" \
  --copy-in "$script_dir/guest-payload-classifier.py:/usr/local/sbin" \
  --copy-in "$script_dir/linux-runner.service:/etc/systemd/system" \
  --run-command "mv '/opt/honeypot/input/$(basename "$sample")' /opt/honeypot/input/sample" \
  --run-command 'chmod 0700 /usr/local/sbin/guest-runner.sh && mv /usr/local/sbin/guest-runner.sh /usr/local/sbin/honeypot-guest-runner' \
  --run-command 'chmod 0500 /usr/local/sbin/guest-pe-forensics.py && mv /usr/local/sbin/guest-pe-forensics.py /usr/local/sbin/honeypot-pe-forensics' \
  --run-command 'chmod 0500 /usr/local/sbin/guest-payload-classifier.py && mv /usr/local/sbin/guest-payload-classifier.py /usr/local/sbin/honeypot-payload-classifier' \
  --write "/etc/honeypot-sandbox-windows-mode:$windows_mode" \
  --write "/etc/honeypot-sandbox-network-mode:$network_mode" \
  --run-command 'ln -sf /etc/systemd/system/linux-runner.service /etc/systemd/system/multi-user.target.wants/linux-runner.service' \
  --run-command 'rm -f /etc/machine-id && touch /etc/machine-id'

# libguestfs may replace the overlay inode during customization, so explicitly
# restore the narrow per-file ACL after it finishes instead of relying only on
# the overlay directory's default ACL.
setfacl -m u:libvirt-qemu:rw "$overlay"

# Capture on the host bridge, filtered to this job's fixed MAC. The guest never
# receives packet-capture access and cannot alter the root-owned PCAP.
tcpdump -i virbr-hpsbx -U -n -s 0 -w "$result/network.pcap" "ether host $mac" \
  >"$result/tcpdump.log" 2>&1 &
pcap_pid=$!
sleep 1
kill -0 "$pcap_pid" 2>/dev/null || { cat "$result/tcpdump.log" >&2; exit 1; }

virt-install --name "$vm" --import --transient --noautoconsole \
  --memory "$memory_mb" --vcpus 2 --cpu host-model --osinfo ubuntu24.04 \
  --disk "path=$overlay,format=qcow2,bus=virtio,cache=none" \
  --network "network=honeypot-sandbox,model=virtio,mac=$mac,filterref.filter=honeypot-sandbox-strict" \
  --graphics none --video none --sound none \
  --console pty,target.type=serial

deadline=$((SECONDS + 240))
while virsh domstate "$vm" >/dev/null 2>&1 && (( SECONDS < deadline )); do
  sleep 2
done
if virsh domstate "$vm" >/dev/null 2>&1; then
  echo "VM exceeded host deadline; forcing shutdown" >"$result/host-timeout.txt"
  virsh destroy "$vm" >/dev/null
fi
stop_capture

virt-copy-out -a "$overlay" /var/lib/honeypot-result "$result"
mv "$result/honeypot-result"/* "$result"/ 2>/dev/null || true
rmdir "$result/honeypot-result" 2>/dev/null || true
printf '%s  %s\n' "$hash" "$(basename "$sample")" >"$result/submitted.sha256"
jq -n \
  --arg job "$job" --arg sha256 "$hash" --arg sample "$(basename "$sample")" \
  --arg completed_at "$(date -u +%FT%TZ)" \
  --arg exit_status "$(cat "$result/exit-status.txt" 2>/dev/null || printf unknown)" \
  '{version:1,job:$job,sha256:$sha256,sample:$sample,completed_at:$completed_at,exit_status:$exit_status,network:"isolated",overlay_destroyed:true}' \
  >"$result/report.json"
chmod -R go-rwx "$result"
echo "Analysis complete: $result"
echo "RESULT_DIR=$result"
