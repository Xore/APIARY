#!/usr/bin/env bash
# Show what the lab is consuming against its caps. Cheap enough to call after
# every operation, which is why the fetch and run scripts both do.
#
# Reports every pcap* and logs* directory under var/, not a fixed pair. An
# earlier version hardcoded var/pcap and var/logs and therefore under-reported
# by 3x the moment the ICS sample added var/pcap-ics and var/logs-ics -- a
# storage guard that quietly under-counts is worse than none, because it
# invites exactly the growth it exists to prevent.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLE_MAX_BYTES="${SAMPLE_MAX_BYTES:-$((200 * 1024 * 1024))}"
LOGS_MAX_BYTES="${LOGS_MAX_BYTES:-$((500 * 1024 * 1024))}"

dir_bytes() { du -sb "$1" 2>/dev/null | cut -f1 || echo 0; }

mb() { echo $(( $1 / 1024 / 1024 )); }

group_total() {
    # $1 = glob prefix under var/ ("pcap" or "logs")
    local total=0 d
    for d in "${here}"/var/"$1"*; do
        [[ -d "$d" ]] || continue
        total=$(( total + $(dir_bytes "$d") ))
    done
    echo "$total"
}

report_group() {
    local label="$1" prefix="$2" cap="$3"
    local total pct d used
    total=$(group_total "$prefix")
    pct=$(( cap > 0 ? total * 100 / cap : 0 ))
    printf '  %-6s TOTAL %6s MB / %6s MB  (%3s%%)\n' "$label" "$(mb "$total")" "$(mb "$cap")" "$pct"
    for d in "${here}"/var/"$prefix"*; do
        [[ -d "$d" ]] || continue
        used=$(dir_bytes "$d")
        printf '           %-16s %6s MB\n' "$(basename "$d")" "$(mb "$used")"
    done
}

echo "sensing-lab disk usage:"
report_group "pcap" "pcap" "$SAMPLE_MAX_BYTES"
report_group "logs" "logs" "$LOGS_MAX_BYTES"
printf '  %-6s %6s MB\n' "var/" "$(mb "$(dir_bytes "${here}/var")")"
