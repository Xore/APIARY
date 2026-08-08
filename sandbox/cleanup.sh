#!/usr/bin/env bash
set -euo pipefail

root=/var/lib/honeypot-sandbox
raw_days=${SANDBOX_RAW_RETENTION_DAYS:-30}
export_days=${SANDBOX_EXPORT_RETENTION_DAYS:-180}
[[ $raw_days =~ ^[0-9]+$ && $export_days =~ ^[0-9]+$ ]] || exit 2

# Each directory is guarded: results/ in particular isn't created by
# install-worker.sh, only lazily by run-linux-sample.sh on the first actual
# detonation -- on a fresh host (or one where nothing has been detonated
# yet) that directory doesn't exist, and under set -e an unguarded find
# would abort this whole retention pass before reaching any later line.
[[ ! -d "$root/results" ]] || find "$root/results" -mindepth 1 -maxdepth 1 -type d -mtime "+$raw_days" -exec rm -rf -- {} +
[[ ! -d "$root/export" ]] || find "$root/export" -mindepth 1 -maxdepth 1 -type f \( -name 'linux-*.json' -o -name 'windows-*.json' -o -name 'linux-*.pcap' -o -name 'windows-*.pcap' \) -mtime "+$export_days" -delete
[[ ! -d "$root/inbox/completed" ]] || find "$root/inbox/completed" -mindepth 1 -maxdepth 1 -type f -name '*.json' -mtime "+$export_days" -delete
[[ ! -d "$root/inbox/failed" ]] || find "$root/inbox/failed" -mindepth 1 -maxdepth 1 -type f -mtime +30 -delete
[[ ! -d "$root/inbox/samples" ]] || find "$root/inbox/samples" -mindepth 1 -maxdepth 1 -type f -mtime +7 -delete
