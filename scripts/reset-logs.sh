#!/usr/bin/env bash
# reset-logs.sh — wipe all cowrie and/or conpot log data and restart fresh.
#
# Usage:
#   ./scripts/reset-logs.sh            # wipe BOTH cowrie and conpot (all variants)
#   ./scripts/reset-logs.sh cowrie     # cowrie only
#   ./scripts/reset-logs.sh conpot     # all conpot variants only
#   ./scripts/reset-logs.sh --dry-run  # show what would be deleted, do nothing
#
# Run from the stack root (same dir as docker-compose.yml).
# Requires: docker, sudo (for log dir ownership under /opt/stacks/).

set -euo pipefail

LOGS_BASE="/opt/stacks/honeypot-stack/logs"
STATE_BASE="/opt/stacks/honeypot-stack/state"

DRY=false
TARGET="all"   # all | cowrie | conpot

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=true ;;
    cowrie)    TARGET="cowrie" ;;
    conpot)    TARGET="conpot" ;;
    all)       TARGET="all" ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

run() {
  if $DRY; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

STEP() { echo; echo "===> $*"; }

# ─────────────────────────────────────────────────────────────────────────────
# 1. Stop the targeted containers
# ─────────────────────────────────────────────────────────────────────────────
STEP "Stopping containers"

COWRIE_SERVICES="cowrie payload-dedupe yara-scanner"
CONPOT_SERVICES="conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup"

case "$TARGET" in
  cowrie) SERVICES="$COWRIE_SERVICES" ;;
  conpot) SERVICES="$CONPOT_SERVICES" ;;
  all)    SERVICES="$COWRIE_SERVICES $CONPOT_SERVICES" ;;
esac

run docker compose stop $SERVICES

# ─────────────────────────────────────────────────────────────────────────────
# 2. Wipe log directories
# ─────────────────────────────────────────────────────────────────────────────
STEP "Deleting log files"

wipe_dir() {
  local dir="$1"
  if [ -d "$dir" ]; then
    echo "  rm -rf ${dir}/*"
    run sudo find "$dir" -mindepth 1 -delete
  else
    echo "  (skipped, not found: $dir)"
  fi
}

if [[ "$TARGET" == "cowrie" || "$TARGET" == "all" ]]; then
  # JSON event logs and text logs
  wipe_dir "${LOGS_BASE}/cowrie"
  # Filebeat registry: must be cleared so Filebeat re-ingests from offset 0
  # on the new log file instead of skipping it as "already seen".
  echo "  rm -rf ${STATE_BASE}/filebeat/*"
  run sudo find "${STATE_BASE}/filebeat" -mindepth 1 -delete
fi

if [[ "$TARGET" == "conpot" || "$TARGET" == "all" ]]; then
  for variant in conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup; do
    wipe_dir "${LOGS_BASE}/${variant}"
  done
  if [[ "$TARGET" == "all" ]]; then
    echo "  rm -rf ${STATE_BASE}/filebeat/*"
    run sudo find "${STATE_BASE}/filebeat" -mindepth 1 -delete
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. Re-create log directories with correct ownership
#    (mirrors what log-init does on a fresh stack start)
# ─────────────────────────────────────────────────────────────────────────────
STEP "Re-creating log directories"

if [[ "$TARGET" == "cowrie" || "$TARGET" == "all" ]]; then
  run sudo mkdir -p "${LOGS_BASE}/cowrie/downloads"
  run sudo chown -R 2000:2000 "${LOGS_BASE}/cowrie"
fi

if [[ "$TARGET" == "conpot" || "$TARGET" == "all" ]]; then
  for variant in conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup; do
    run sudo mkdir -p "${LOGS_BASE}/${variant}"
    run sudo chown -R 2000:2000 "${LOGS_BASE}/${variant}"
  done
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. Remove Elasticsearch indices for the wiped sensors
#    (optional — skip if ES is down or you want to keep historical kibana data)
# ─────────────────────────────────────────────────────────────────────────────
STEP "Deleting Elasticsearch indices (optional, errors are non-fatal)"

ES="http://localhost:9200"   # adjust if ES is not on localhost

delete_es_index() {
  local pattern="$1"
  echo "  DELETE ${ES}/${pattern}"
  if ! $DRY; then
    curl -sf -X DELETE "${ES}/${pattern}" -o /dev/null || echo "  (index not found or ES down — skipped)"
  fi
}

if [[ "$TARGET" == "cowrie" || "$TARGET" == "all" ]]; then
  delete_es_index "honeypot-cowrie-*"
fi

if [[ "$TARGET" == "conpot" || "$TARGET" == "all" ]]; then
  delete_es_index "honeypot-conpot-*"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 5. Restart containers
# ─────────────────────────────────────────────────────────────────────────────
STEP "Starting containers"
run docker compose up -d $SERVICES

STEP "Done"
echo "Tail logs with:  docker compose logs -f $SERVICES"
