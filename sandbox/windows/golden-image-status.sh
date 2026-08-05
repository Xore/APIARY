#!/usr/bin/env bash
# golden-image-status.sh -- #86: writes the win11-analysis.qcow2 golden
# image's build age and checksum-verification state as a small JSON file so
# the dashboard can surface staleness without anyone remembering to check
# packer-golden-image-guide.md's manual cadence table by hand.
#
# This is the "documented manual cadence with a staleness check on the
# dashboard" half of #86 that the issue itself proposes as the alternative
# to a cron-triggered rebuild -- a scheduled *rebuild* needs #86's own
# blockers resolved first (can't share /dev/kvm with a live detonation,
# can't -force over a known-good image before the replacement is verified,
# needs a non-expired eval ISO). A staleness *report* has none of those
# problems: it only stats files, never touches the VM or the image.
#
# Written into WINDOWS_SANDBOX_RESULTS_DIR (already bind-mounted read-only
# into the dashboard container for per-job results) as a sibling file, so
# no new mount or env var is needed to read it back out.
set -euo pipefail

SANDBOX_ROOT="${SANDBOX_ROOT:-/var/dockge/sandbox}"
GOLDEN_IMAGE="${GOLDEN_IMAGE:-$SANDBOX_ROOT/golden-images/win11-analysis.qcow2}"
RESULTS_DIR="${WINDOWS_SANDBOX_RESULTS_DIR:-/var/lib/honeypot-windows-sandbox/export}"
OUT="$RESULTS_DIR/golden-image-status.json"

# Cadence thresholds from packer-golden-image-guide.md's "Keeping the Golden
# Image Fresh" table: monthly rebuild, and the Windows evaluation ISO's own
# 90-day expiry (a rebuild past this point produces an already-expired
# guest, so it is flagged separately and more urgently than the routine
# monthly cadence).
MONTHLY_DAYS=30
ISO_EVAL_DAYS=90

mkdir -p "$RESULTS_DIR"

if [[ ! -f "$GOLDEN_IMAGE" ]]; then
    printf '{"error":"golden image not found","path":%s}\n' "\"$GOLDEN_IMAGE\"" > "$OUT.tmp"
    mv -f "$OUT.tmp" "$OUT"
    exit 0
fi

built_epoch="$(stat -c '%Y' "$GOLDEN_IMAGE")"
now_epoch="$(date -u +%s)"
age_days=$(( (now_epoch - built_epoch) / 86400 ))
built_at="$(date -u -d "@$built_epoch" +%FT%TZ)"

checksum_file="$GOLDEN_IMAGE.sha256"
checksum_written=false
[[ -f "$checksum_file" ]] && checksum_written=true

checksum_verified=false
verified_stamp="$GOLDEN_IMAGE.sha256.verified"
if [[ -f "$verified_stamp" ]]; then
    current="$(stat -c '%Y-%s' "$GOLDEN_IMAGE")"
    [[ "$(cat "$verified_stamp")" == "$current" ]] && checksum_verified=true
fi

stale_monthly=false
(( age_days >= MONTHLY_DAYS )) && stale_monthly=true

stale_iso_eval=false
(( age_days >= ISO_EVAL_DAYS )) && stale_iso_eval=true

cat > "$OUT.tmp" <<JSON
{
  "path": "$GOLDEN_IMAGE",
  "built_at": "$built_at",
  "age_days": $age_days,
  "checksum_written": $checksum_written,
  "checksum_verified": $checksum_verified,
  "stale_monthly": $stale_monthly,
  "stale_iso_eval": $stale_iso_eval,
  "checked_at": "$(date -u -d "@$now_epoch" +%FT%TZ)"
}
JSON
mv -f "$OUT.tmp" "$OUT"
