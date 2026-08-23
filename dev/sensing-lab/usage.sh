#!/usr/bin/env bash
# Show what the lab is consuming against its caps. Cheap enough to call after
# every operation, which is why fetch-sample.sh and run-zeek.sh both do.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLE_MAX_BYTES="${SAMPLE_MAX_BYTES:-$((200 * 1024 * 1024))}"
LOGS_MAX_BYTES="${LOGS_MAX_BYTES:-$((500 * 1024 * 1024))}"

report() {
    local label="$1" dir="$2" cap="$3"
    local used pct
    used=$(du -sb "$dir" 2>/dev/null | cut -f1 || echo 0)
    pct=$(( cap > 0 ? used * 100 / cap : 0 ))
    printf '  %-10s %6s MB / %6s MB  (%3s%%)\n' \
        "$label" "$((used / 1024 / 1024))" "$((cap / 1024 / 1024))" "$pct"
}

echo "sensing-lab disk usage:"
report "pcap" "${here}/var/pcap" "$SAMPLE_MAX_BYTES"
report "logs" "${here}/var/logs" "$LOGS_MAX_BYTES"
