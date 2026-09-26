#!/bin/sh
set -eu

# Prune rotated Zeek logs on the VPS, where they are actually written.
#
# #3284: this is the root cause of both open ops issues, and it was invisible
# from the homeserver. honeypot-elk's filebeat reads /logs/zeek over an sshfs
# mount that is deliberately read-only (root@10.8.0.1:/opt/stacks/apiary/logs/zeek
# -> /var/dockge/stacks/apiary/logs/zeek, fuse.sshfs ro in /etc/fstab), so
# log-maintenance.sh on the homeserver prints the paths it wants to delete and
# then silently fails every one of them -- its find carries 2>/dev/null || true,
# which is why 12,390 "deleted" zeek paths appeared in that container's log
# with the file count unchanged.
#
# Zeek rotates hourly by rename-and-reopen and never truncates in place, so a
# rotated generation is finished the moment it is closed: -mmin only ever fires
# on files nothing will append to again. The bare-name match also covers the
# live file of a dead sensor, whose mtime freezes (same shape
# suricata-log-maintenance.sh uses for eve.json).
#
# Consequence of not having this: 13,717 accumulated hourly rotations (16 GB),
# and one filestream harvester per file on every hp-filebeat restart, which is
# what drove the Go runtime past its 10000-thread limit. It also fed #3283 --
# one Elasticsearch index per day per log type, 836 of the cluster's 1091
# shards, several holding a single document.
#
# #261: default derives from the shared HONEYPOT_RETENTION_DAYS knob, same
# ratio and reasoning as analysis/log-maintenance.sh's json_retention_min and
# suricata-log-maintenance.sh's retention_min. Elasticsearch holds the
# searchable history; this is only the on-disk copy, which needs to outlive
# Filebeat's ingest lag by a comfortable margin, not last forever.

retention_min="${RETENTION_MINUTES:-$(( ${HONEYPOT_RETENTION_DAYS:-30} * 1440 / 10 ))}"
interval="${CHECK_INTERVAL:-3600}"
start_delay="${START_DELAY:-60}"
log_dir="${LOG_DIR:-/opt/stacks/apiary/logs/zeek}"

sleep "$start_delay"

while true; do
  find "$log_dir" -maxdepth 1 -name '*.log' -mmin "+${retention_min}" -print -delete 2>/dev/null || true
  sleep "$interval"
done
