#!/usr/bin/env bash
# Reclaim everything the lab has written. Nothing under var/ is ever an
# artefact worth keeping -- the pcap sample is re-fetchable and the logs are
# reproducible from it.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

before=$(du -sb "${here}/var" 2>/dev/null | cut -f1 || echo 0)
rm -rf "${here}/var/pcap" "${here}/var/logs"
echo "sensing-lab: reclaimed $((before / 1024 / 1024)) MB"
