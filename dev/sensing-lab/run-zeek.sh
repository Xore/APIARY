#!/usr/bin/env bash
# Run Zeek over the local pcap sample, into a size-capped log directory.
#
# Refuses to start if var/logs is already over budget, so a forgotten previous
# run cannot quietly grow across invocations.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# PCAP_DIR/LOG_DIR select which sample to parse, so the ICS sample
# (fetch-ics-sample.sh, #1736) and the general one can coexist and be compared
# without either overwriting the other's logs. Relative paths resolve against
# the lab directory so `PCAP_DIR=var/pcap-ics ./run-zeek.sh` reads naturally.
pcap_dir="${PCAP_DIR:-var/pcap}"
log_dir="${LOG_DIR:-}"
[[ "$pcap_dir" = /* ]] || pcap_dir="${here}/${pcap_dir}"
if [[ -z "$log_dir" ]]; then
    # Default the log directory to match the sample, so var/pcap-ics parses
    # into var/logs-ics rather than silently mixing with the general run.
    suffix="$(basename "$pcap_dir")"; suffix="${suffix#pcap}"
    log_dir="${here}/var/logs${suffix}"
fi
[[ "$log_dir" = /* ]] || log_dir="${here}/${log_dir}"

IMAGE="${IMAGE:-apiary-sensing-lab:zeek8}"
LOGS_MAX_BYTES="${LOGS_MAX_BYTES:-$((500 * 1024 * 1024))}"
ENGINE="${ENGINE:-podman}"

if [[ ! -d "$pcap_dir" ]] || [[ -z "$(ls -A "$pcap_dir" 2>/dev/null)" ]]; then
    echo "sensing-lab: no pcap sample yet — run ./fetch-sample.sh first" >&2
    exit 1
fi

# Budget against ALL logs* directories, not just this run's. With more than
# one sample in play (var/logs and var/logs-ics), a per-directory check would
# let the aggregate drift past the cap while each half looked fine.
used=0
for d in "${here}"/var/logs*; do
    [[ -d "$d" ]] || continue
    used=$(( used + $(du -sb "$d" 2>/dev/null | cut -f1 || echo 0) ))
done
if (( used >= LOGS_MAX_BYTES )); then
    echo "sensing-lab: var/logs* total $((used / 1024 / 1024)) MB, over the" \
         "$((LOGS_MAX_BYTES / 1024 / 1024)) MB cap. Run ./clean.sh." >&2
    exit 1
fi

mkdir -p "$log_dir"

# One Zeek run over the whole sample, as a single logical capture.
#
# The files must be *merged*, not concatenated. Every pcap carries its own
# 24-byte global header, so `cat a.pcap b.pcap` leaves that header sitting
# mid-stream where libpcap reads it as a packet header and derives a garbage
# capture length from the magic number. mergecap rewrites one header and
# orders the packets by timestamp.
#
# Piping it straight into Zeek keeps this within the storage budget: a merged
# copy on disk would double the sample's footprint for the length of the run.
#
# Running once over the merged stream rather than once per file also matters
# for correctness -- Suricata rotates its pcap every 4 MB, so connections
# routinely span file boundaries. Per-file runs would cut those flows in half
# and report each half as its own truncated connection.
#
# -C skips checksum validation: the VPS captures on an offload-enabled NIC, so
# most packets carry checksums the kernel never finished computing, and Zeek
# would otherwise discard them.
echo "sensing-lab: running Zeek over $(ls "$pcap_dir" | wc -l) pcap file(s)"
"$ENGINE" run --rm \
    -v "${pcap_dir}:/work/pcap:ro,Z" \
    -v "${log_dir}:/work/logs:Z" \
    "$IMAGE" -c '
        set -o pipefail
        # -c, not -lc: a login shell re-reads /etc/profile and discards the
        # image PATH, so zeek is simply "command not found". PATH is exported
        # again here so the entrypoint cannot silently matter.
        export PATH=/usr/local/zeek/bin:$PATH
        cd /work/logs
        mergecap -w - -F pcap /work/pcap/* \
            | zeek -C -r - /usr/local/share/zeek-lab/local.zeek 2>&1 | tail -20
    ' || {
        # Fail loudly. A harness that reports success when the parse failed is
        # worse than no harness: the record counts below would read as "this
        # traffic contains nothing" rather than "nothing ran".
        echo "sensing-lab: Zeek run FAILED — see output above" >&2
        exit 1
    }

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
