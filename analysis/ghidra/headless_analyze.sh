#!/usr/bin/env bash
# headless_analyze.sh
# Submit a single sample to the Ghidra REST service and collect all artifacts.
# Usage: ./headless_analyze.sh <sample_path> <output_dir>
# Requires: curl, jq
# Env: GHIDRA_API_BASE (default: http://127.0.0.1:9090)

set -euo pipefail

SAMPLE="${1:-}"
OUT_DIR="${2:-/tmp/ghidra_out}"
API="${GHIDRA_API_BASE:-http://127.0.0.1:9090}"

if [[ -z "$SAMPLE" || ! -f "$SAMPLE" ]]; then
  echo "Usage: $0 <sample_path> [output_dir]" >&2
  exit 1
fi

SHA=$(sha256sum "$SAMPLE" | awk '{print $1}')
mkdir -p "$OUT_DIR/$SHA"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

# ── 1. Upload and analyze ────────────────────────────────────────────────────
log "Uploading $SAMPLE to Ghidra service..."
ANALYSIS_ID=$(curl -sf -X POST "$API/analyze" \
  -F "file=@$SAMPLE" \
  -F "analysis_timeout=1800" \
  | jq -r '.analysis_id')

if [[ -z "$ANALYSIS_ID" || "$ANALYSIS_ID" == "null" ]]; then
  echo "ERROR: Failed to start analysis" >&2
  exit 1
fi
log "Analysis ID: $ANALYSIS_ID"

# ── 2. Wait for completion ───────────────────────────────────────────────────
DEADLINE=$((SECONDS + 1800))
while [[ $SECONDS -lt $DEADLINE ]]; do
  STATUS=$(curl -sf "$API/analyses/$ANALYSIS_ID/status" | jq -r '.status')
  log "Status: $STATUS"
  [[ "$STATUS" == "completed" ]] && break
  [[ "$STATUS" == "failed" ]] && { echo "ERROR: Analysis failed"; exit 1; }
  sleep 20
done

# ── 3. Export artifacts ──────────────────────────────────────────────────────
log "Exporting functions..."
curl -sf "$API/functions?analysis_id=$ANALYSIS_ID" \
  | jq . > "$OUT_DIR/$SHA/functions.json"

log "Exporting strings..."
curl -sf "$API/strings?analysis_id=$ANALYSIS_ID" \
  | jq . > "$OUT_DIR/$SHA/strings.json"

log "Exporting imports..."
curl -sf "$API/imports?analysis_id=$ANALYSIS_ID" \
  | jq . > "$OUT_DIR/$SHA/imports.json"

# Decompile top 10 functions by caller count (most suspicious)
log "Decompiling top functions..."
TOP_FUNCS=$(cat "$OUT_DIR/$SHA/functions.json" | jq -r '[.[] | select(.is_thunk==false)] | sort_by(-.caller_count) | .[0:10] | .[].address')
DECOMP="$OUT_DIR/$SHA/decompiled.json"
echo '[' > "$DECOMP"
FIRST=1
for ADDR in $TOP_FUNCS; do
  [[ $FIRST -eq 0 ]] && echo ',' >> "$DECOMP"
  curl -sf "$API/decompile/$ADDR?analysis_id=$ANALYSIS_ID" >> "$DECOMP"
  FIRST=0
  sleep 1
done
echo ']' >> "$DECOMP"

log "Done. Artifacts in $OUT_DIR/$SHA/"
ls -lh "$OUT_DIR/$SHA/"
