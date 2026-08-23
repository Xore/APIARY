#!/usr/bin/env bash
# Pull an ICS-only pcap sample (#1736).
#
# The plain fetch-sample.sh takes the newest files, and the first run that way
# produced zero ICS records: scans against 102/502/2404/20000/44818/47808 are
# sparse next to the telnet/VNC/SIP background noise, so a recency-ordered
# sample of any reasonable size is likely to miss them entirely.
#
# So filter rather than sample, and filter on the capture host so that only
# matching packets cross the network -- scanning gigabytes there costs a few
# megabytes here.
#
# Filtering is done by pcap-port-filter.py rather than tcpdump. The VPS runs
# AppArmor, whose tcpdump profile refuses to read the capture directory even
# as root: `head` on a file succeeds while `tcpdump -r` on the same file
# returns "Permission denied". The Python filter needs only the standard
# library and is not confined by that profile.
#
# Output lands in var/pcap-ics/. run-zeek.sh merges whatever directory it is
# pointed at:  PCAP_DIR=var/pcap-ics ./run-zeek.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dest="${here}/var/pcap-ics"

VPS_HOST="${VPS_HOST:-vps}"
VPS_PCAP_DIR="${VPS_PCAP_DIR:-/opt/stacks/apiary/logs/suricata/pcap}"
ICS_SCAN_FILES="${ICS_SCAN_FILES:-3000}"

# Every ICS port portbridge forwards, plus the S7/Modbus alternates:
# 102/1102/2102 S7comm over COTP, 502/1502/2502 Modbus, 2404 IEC-104,
# 20000 DNP3, 44818 EtherNet/IP-CIP, 47808 BACnet, 10001/50100 misc.
ICS_PORTS="${ICS_PORTS:-102,1102,2102,502,1502,2502,2404,20000,44818,47808,10001,50100}"

# A port we know carries heavy traffic. The scan runs with this appended and
# reports the two counts separately, so "no ICS packets" can be distinguished
# from "the scan read nothing". Getting this wrong once already produced a
# confident, entirely false "no ICS traffic found".
CONTROL_PORT="${CONTROL_PORT:-23}"

mkdir -p "$dest"

echo "sensing-lab: scanning the newest ${ICS_SCAN_FILES} capture files on ${VPS_HOST}"
echo "sensing-lab: ICS ports ${ICS_PORTS}  (control port ${CONTROL_PORT})"

scp -q "${here}/pcap-port-filter.py" "${VPS_HOST}:/tmp/pcap-port-filter.py"

# Two passes over the same file list: the ICS ports we care about, and the
# control port. Both counts are reported.
remote_script=$(cat <<REMOTE
set -e
files=\$(ls -t '${VPS_PCAP_DIR}'/log.pcap* 2>/dev/null | head -${ICS_SCAN_FILES})
if [ -z "\$files" ]; then echo "no capture files found" >&2; exit 1; fi
echo "== ICS ==" >&2
python3 /tmp/pcap-port-filter.py /tmp/ics-sample.pcap '${ICS_PORTS}' \$files
echo "== CONTROL (port ${CONTROL_PORT}) ==" >&2
python3 /tmp/pcap-port-filter.py /tmp/control-sample.pcap '${CONTROL_PORT}' \$files
REMOTE
)

ssh -o ConnectTimeout=20 "$VPS_HOST" "$remote_script"

scp -q "${VPS_HOST}:/tmp/ics-sample.pcap" "${dest}/ics-sample.pcap"
ssh -o ConnectTimeout=20 "$VPS_HOST" 'rm -f /tmp/ics-sample.pcap /tmp/control-sample.pcap /tmp/pcap-port-filter.py'

bytes=$(stat -c %s "${dest}/ics-sample.pcap" 2>/dev/null || echo 0)
echo "sensing-lab: ics-sample.pcap is $((bytes / 1024)) KB"
if (( bytes <= 24 )); then
    echo "sensing-lab: the ICS sample holds no packets. Check the control count" \
         "printed above: a non-zero control means the scan worked and there" \
         "genuinely was no ICS traffic in that window." >&2
    exit 1
fi
echo "sensing-lab: now run —  PCAP_DIR=var/pcap-ics ./run-zeek.sh"
