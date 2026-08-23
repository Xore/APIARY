#!/usr/bin/env bash
# Run Zeek over the local pcap sample, into a size-capped log directory.
#
# Refuses to start if var/logs is already over budget, so a forgotten previous
# run cannot quietly grow across invocations.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pcap_dir="${here}/var/pcap"
log_dir="${here}/var/logs"

IMAGE="${IMAGE:-apiary-sensing-lab:zeek8}"
LOGS_MAX_BYTES="${LOGS_MAX_BYTES:-$((500 * 1024 * 1024))}"
ENGINE="${ENGINE:-podman}"

if [[ ! -d "$pcap_dir" ]] || [[ -z "$(ls -A "$pcap_dir" 2>/dev/null)" ]]; then
    echo "sensing-lab: no pcap sample yet — run ./fetch-sample.sh first" >&2
    exit 1
fi

used=$(du -sb "$log_dir" 2>/dev/null | cut -f1 || echo 0)
if (( used >= LOGS_MAX_BYTES )); then
    echo "sensing-lab: var/logs is at $((used / 1024 / 1024)) MB, over the" \
         "$((LOGS_MAX_BYTES / 1024 / 1024)) MB cap. Run ./clean.sh." >&2
    exit 1
fi

mkdir -p "$log_dir"

# One Zeek run over the whole sample. -C skips checksum validation, which
# matters because the VPS captures on an offload-enabled NIC and would
# otherwise discard most packets as bad-checksum.
echo "sensing-lab: running Zeek over $(ls "$pcap_dir" | wc -l) pcap file(s)"
"$ENGINE" run --rm \
    -v "${pcap_dir}:/work/pcap:ro,Z" \
    -v "${log_dir}:/work/logs:Z" \
    "$IMAGE" -lc '
        set -e
        cd /work/logs
        zeek -C -r <(cat /work/pcap/*) \
             /usr/local/share/zeek-lab/local.zeek 2>&1 | tail -20 || true
        # Fall back to per-file runs if the concatenation was rejected: pcap
        # files with differing link types cannot be cat-ed together.
        if [ -z "$(ls -A /work/logs 2>/dev/null)" ]; then
            echo "sensing-lab: concatenated read produced nothing, retrying per file"
            for f in /work/pcap/*; do
                zeek -C -r "$f" /usr/local/share/zeek-lab/local.zeek 2>&1 | tail -5 || true
            done
        fi
    '

echo
echo "sensing-lab: per-log record counts"
printf '  %-28s %10s\n' "LOG" "RECORDS"
for f in "$log_dir"/*.log; do
    [[ -e "$f" ]] || continue
    printf '  %-28s %10s\n' "$(basename "$f")" "$(wc -l < "$f")"
done

after=$(du -sb "$log_dir" 2>/dev/null | cut -f1 || echo 0)
if (( after >= LOGS_MAX_BYTES )); then
    echo
    echo "sensing-lab: WARNING — var/logs now $((after / 1024 / 1024)) MB," \
         "at/over the cap. Next run will refuse until ./clean.sh."
fi

"${here}/usage.sh"
