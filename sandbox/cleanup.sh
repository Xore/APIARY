#!/usr/bin/env bash
set -euo pipefail

root=/var/lib/honeypot-sandbox
raw_days=${SANDBOX_RAW_RETENTION_DAYS:-30}
export_days=${SANDBOX_EXPORT_RETENTION_DAYS:-180}
[[ $raw_days =~ ^[0-9]+$ && $export_days =~ ^[0-9]+$ ]] || exit 2
find "$root/results" -mindepth 1 -maxdepth 1 -type d -mtime "+$raw_days" -exec rm -rf -- {} +
find "$root/export" -mindepth 1 -maxdepth 1 -type f \( -name 'linux-*.json' -o -name 'windows-*.json' -o -name 'linux-*.pcap' -o -name 'windows-*.pcap' \) -mtime "+$export_days" -delete
find "$root/inbox/completed" -mindepth 1 -maxdepth 1 -type f -name '*.json' -mtime "+$export_days" -delete
find "$root/inbox/failed" -mindepth 1 -maxdepth 1 -type f -mtime +30 -delete
find "$root/inbox/samples" -mindepth 1 -maxdepth 1 -type f -mtime +7 -delete
