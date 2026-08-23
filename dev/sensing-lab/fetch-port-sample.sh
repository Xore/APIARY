#!/usr/bin/env bash
# Pull a port-filtered pcap sample from the VPS.
#
# Filtering happens on the capture host, so scanning gigabytes there costs a
# few megabytes here -- the opposite trade to copying pcap and filtering
# locally, and the only version of this that respects the lab's storage caps.
#
# Filtering is done by pcap-port-filter.py rather than tcpdump: the VPS runs
# AppArmor, whose tcpdump profile refuses to read the capture directory even as
# root (`head` on a file succeeds, `tcpdump -r` on the same file does not).
#
# Every scan also runs a known-busy CONTROL_PORT and prints both counts, so a
# zero result can always be told apart from a broken scan. That distinction was
# not free: the first version of this reported "no ICS traffic found" when in
# fact every read had been denied.
#
#   SAMPLE_NAME=web SAMPLE_PORTS=80,443 ./fetch-port-sample.sh
#   PCAP_DIR=var/pcap-web ./run-zeek.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SAMPLE_NAME="${SAMPLE_NAME:?set SAMPLE_NAME, e.g. web or ics}"
SAMPLE_PORTS="${SAMPLE_PORTS:?set SAMPLE_PORTS, a comma-separated list}"
VPS_HOST="${VPS_HOST:-vps}"
VPS_PCAP_DIR="${VPS_PCAP_DIR:-/opt/stacks/apiary/logs/suricata/pcap}"
SCAN_FILES="${SCAN_FILES:-3000}"
# Hard ceiling on what lands here. Dense ports (80/443) would otherwise write
# far more than the lab is allowed to hold.
MAX_OUT_BYTES="${MAX_OUT_BYTES:-$((60 * 1024 * 1024))}"
CONTROL_PORT="${CONTROL_PORT:-23}"

dest="${here}/var/pcap-${SAMPLE_NAME}"
mkdir -p "$dest"

echo "sensing-lab: scanning the newest ${SCAN_FILES} capture files on ${VPS_HOST}"
echo "sensing-lab: ports ${SAMPLE_PORTS} (control ${CONTROL_PORT}), cap $((MAX_OUT_BYTES / 1024 / 1024)) MB"

scp -q "${here}/pcap-port-filter.py" "${VPS_HOST}:/tmp/pcap-port-filter.py"

remote_script=$(cat <<REMOTE
set -e
files=\$(ls -t '${VPS_PCAP_DIR}'/log.pcap* 2>/dev/null | head -${SCAN_FILES})
if [ -z "\$files" ]; then echo "no capture files found" >&2; exit 1; fi
echo "== ${SAMPLE_NAME} (${SAMPLE_PORTS}) ==" >&2
MAX_OUT_BYTES=${MAX_OUT_BYTES} python3 /tmp/pcap-port-filter.py \
    /tmp/sample-${SAMPLE_NAME}.pcap '${SAMPLE_PORTS}' \$files
echo "== CONTROL (${CONTROL_PORT}) ==" >&2
MAX_OUT_BYTES=$((8 * 1024 * 1024)) python3 /tmp/pcap-port-filter.py \
    /tmp/sample-control.pcap '${CONTROL_PORT}' \$files
REMOTE
)

ssh -o ConnectTimeout=20 "$VPS_HOST" "$remote_script"

scp -q "${VPS_HOST}:/tmp/sample-${SAMPLE_NAME}.pcap" "${dest}/sample.pcap"
ssh -o ConnectTimeout=20 "$VPS_HOST" \
    "rm -f /tmp/sample-${SAMPLE_NAME}.pcap /tmp/sample-control.pcap /tmp/pcap-port-filter.py"

bytes=$(stat -c %s "${dest}/sample.pcap" 2>/dev/null || echo 0)
echo "sensing-lab: var/pcap-${SAMPLE_NAME}/sample.pcap is $((bytes / 1024)) KB"
if (( bytes <= 24 )); then
    echo "sensing-lab: the sample holds no packets. Compare the control count" \
         "above: a non-zero control means the scan worked and there genuinely" \
         "was no matching traffic in that window." >&2
    exit 1
fi

"${here}/usage.sh"
echo "sensing-lab: now run —  PCAP_DIR=var/pcap-${SAMPLE_NAME} ./run-zeek.sh"
