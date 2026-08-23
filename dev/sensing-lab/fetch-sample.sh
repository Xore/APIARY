#!/usr/bin/env bash
# Pull a BOUNDED sample of real captured traffic from the VPS.
#
# The production corpus is ~44 GB across ~11 000 files. This never rsyncs the
# directory: it lists newest-first and copies whole files one at a time,
# stopping the moment the next file would cross SAMPLE_MAX_BYTES. Worst case
# on disk is the cap plus one file (~4 MB), never the corpus.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dest="${here}/var/pcap"

VPS_HOST="${VPS_HOST:-vps}"
VPS_PCAP_DIR="${VPS_PCAP_DIR:-/opt/stacks/apiary/logs/suricata/pcap}"
SAMPLE_MAX_BYTES="${SAMPLE_MAX_BYTES:-$((200 * 1024 * 1024))}"

mkdir -p "$dest"

current=$(du -sb "$dest" 2>/dev/null | cut -f1 || echo 0)
if (( current >= SAMPLE_MAX_BYTES )); then
    echo "sensing-lab: var/pcap already holds $((current / 1024 / 1024)) MB," \
         "at or over the $((SAMPLE_MAX_BYTES / 1024 / 1024)) MB cap."
    echo "sensing-lab: run ./clean.sh first, or raise SAMPLE_MAX_BYTES deliberately."
    exit 0
fi

echo "sensing-lab: listing ${VPS_HOST}:${VPS_PCAP_DIR} (newest first)"
# -printf keeps this to one round trip: size and name, no per-file stat over ssh.
listing=$(ssh -o ConnectTimeout=15 "$VPS_HOST" \
    "find '${VPS_PCAP_DIR}' -maxdepth 1 -type f -name 'log.pcap*' -printf '%T@ %s %p\n' \
     | sort -rn | head -400") || {
    echo "sensing-lab: could not list the VPS pcap directory" >&2
    exit 1
}

budget=$(( SAMPLE_MAX_BYTES - current ))
copied=0
files=0

while read -r _mtime size path; do
    [[ -n "${path:-}" ]] || continue
    name="$(basename "$path")"
    [[ -e "${dest}/${name}" ]] && continue
    if (( size > budget )); then
        # Newest-first ordering means later files are older, not smaller, so
        # stopping here is the right call rather than scanning for a fit.
        break
    fi
    scp -q -o ConnectTimeout=15 "${VPS_HOST}:${path}" "${dest}/${name}"
    budget=$(( budget - size ))
    copied=$(( copied + size ))
    files=$(( files + 1 ))
done <<< "$listing"

echo "sensing-lab: copied ${files} file(s), $((copied / 1024 / 1024)) MB"
"${here}/usage.sh"
