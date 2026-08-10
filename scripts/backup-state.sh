#!/usr/bin/env bash
# backup-state.sh — archive the dashboard state volume (Milestone G).
#
# The dashboard-state named volume holds every settings-owned file —
# dashboard-config.json, dashboard-users.json, dashboard-audit.jsonl,
# dashboard-config-history.jsonl — plus the sandbox payload scripts that
# share the volume. Payload Workbench recipes/runs now live in Elasticsearch
# (dashboard/workbench_es.go, #405 follow-up), not this volume — they are
# backed up by the ES snapshot process, not this script. This script
# snapshots the whole volume into a timestamped
# tarball alongside the other host-level state backups and prunes old ones.
#
# Usage:   scripts/backup-state.sh [volume-name]
# Env:     BACKUP_DIR  target directory   (default: the host state backups dir)
#          KEEP        archives to retain (default: 14)
#
# Restore: see docs/settings-operations.md — stop the dashboard, untar one
# archive back into the volume, start the dashboard. The settings stores
# validate every file on load and fall back to the .bak generation or to
# compiled defaults read-only, so a partial restore degrades safely.

set -euo pipefail

VOLUME="${1:-dashboard-state}"
BACKUP_DIR="${BACKUP_DIR:-/opt/stacks/apiary/state/backups}"
KEEP="${KEEP:-14}"

if ! docker volume inspect "$VOLUME" >/dev/null 2>&1; then
    echo "backup-state: docker volume '$VOLUME' not found" >&2
    echo "usage: $0 [volume-name]  (e.g. \$(docker volume ls --format '{{.Name}}' | grep dashboard-state))" >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
target="$BACKUP_DIR/dashboard-state-$stamp.tar.gz"

docker run --rm \
    -v "$VOLUME:/state:ro" \
    -v "$BACKUP_DIR:/backup" \
    alpine:3 tar czf "/backup/dashboard-state-$stamp.tar.gz" -C /state .

# Prune oldest archives beyond KEEP, newest first.
find "$BACKUP_DIR" -maxdepth 1 -name 'dashboard-state-*.tar.gz' -printf '%T@ %p\n' \
    | sort -rn | tail -n "+$((KEEP + 1))" | cut -d' ' -f2- | xargs -r rm -f

echo "backup-state: wrote $target"
