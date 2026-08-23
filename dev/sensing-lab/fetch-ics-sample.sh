#!/usr/bin/env bash
# Pull an ICS-only pcap sample (#1736).
#
# A thin wrapper over fetch-port-sample.sh, kept because the ICS port list is
# worth naming once rather than retyping, and because #1736 documents this
# command.
#
# Why filter at all: the first lab run took the newest capture files and
# produced zero ICS records. Measured, ICS traffic is about 1% of the telnet
# noise on this perimeter, so a recency-ordered sample of any reasonable size
# will miss it.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Every ICS port portbridge forwards, plus the S7/Modbus alternates:
# 102/1102/2102 S7comm over COTP, 502/1502/2502 Modbus, 2404 IEC-104,
# 20000 DNP3, 44818 EtherNet/IP-CIP, 47808 BACnet, 10001/50100 misc.
export SAMPLE_NAME="${SAMPLE_NAME:-ics}"
export SAMPLE_PORTS="${SAMPLE_PORTS:-102,1102,2102,502,1502,2502,2404,20000,44818,47808,10001,50100}"
# ICS traffic is sparse enough that the default output cap is never the
# binding constraint, but keep one anyway.
export MAX_OUT_BYTES="${MAX_OUT_BYTES:-$((60 * 1024 * 1024))}"

exec "${here}/fetch-port-sample.sh"
