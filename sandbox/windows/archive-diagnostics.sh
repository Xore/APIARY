#!/usr/bin/env bash
# archive-diagnostics.sh -- #528: wraps analysis/archive_diagnostics.py so
# archive-diagnostics.service can pass real defaults. systemd's own
# ExecStart= line does not support bash-style ${VAR:-default} expansion
# (only plain $VAR/${VAR} substitution of Environment=/EnvironmentFile=
# values), so that defaulting has to happen here instead -- same reason
# golden-image-status.service delegates to golden-image-status.sh rather
# than inlining its own logic directly in ExecStart=.
set -euo pipefail

RESULTS_DIR="${WINDOWS_SANDBOX_RESULTS_DIR:-/var/lib/honeypot-windows-sandbox/export}"
STORE_DIR="${CDC_STORE_DIR:-/var/lib/honeypot-windows-sandbox/procmon-cdc-store}"
AFTER_DAYS="${RESULTS_ARCHIVE_AFTER_DAYS:-30}"

exec python3 /usr/local/libexec/honeypot-sandbox/windows/analysis/archive_diagnostics.py archive \
  --results-dir "$RESULTS_DIR" \
  --store-dir "$STORE_DIR" \
  --after-days "$AFTER_DAYS"
