#!/usr/bin/env bash
# reset-logs.sh — wipe sensor log data and restart fresh.
#
# Usage:
#   ./scripts/reset-logs.sh                  # wipe ALL sensors
#   ./scripts/reset-logs.sh cowrie           # cowrie only
#   ./scripts/reset-logs.sh conpot           # all conpot variants
#   ./scripts/reset-logs.sh multipot         # multipot only
#   ./scripts/reset-logs.sh http             # http-honeypot + api-honeypot
#   ./scripts/reset-logs.sh dionaea          # dionaea logs (not binaries)
#   ./scripts/reset-logs.sh dnp3             # dnp3 honeypot
#   ./scripts/reset-logs.sh tanner           # tanner + snare
#   ./scripts/reset-logs.sh suricata         # suricata EVE + pcap
#   ./scripts/reset-logs.sh --dry-run        # preview, no changes
#   ./scripts/reset-logs.sh cowrie conpot    # multiple targets
#
# Run from the stack root (same dir as docker-compose.yml).
# Requires: docker, sudo (log dirs are owned by container UIDs).

set -euo pipefail

LOGS_BASE="/opt/stacks/honeypot-stack/logs"
STATE_BASE="/opt/stacks/honeypot-stack/state"

DRY=false
declare -A TARGETS

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=true ;;
    cowrie|conpot|multipot|http|dionaea|dnp3|tanner|suricata|all)
      TARGETS["$arg"]=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

# Default to all when no target given
[[ ${#TARGETS[@]} -eq 0 ]] && TARGETS["all"]=1

wants() {
  [[ -v TARGETS["all"] ]] || [[ -v TARGETS["$1"] ]]
}

run() {
  if $DRY; then echo "[dry-run] $*"; else "$@"; fi
}

STEP() { echo; echo "===> $*"; }

wipe_dir() {
  local dir="$1"
  if [ -d "$dir" ]; then
    echo "  wipe: $dir"
    run sudo find "$dir" -mindepth 1 -delete
  else
    echo "  (skip, not found: $dir)"
  fi
}

mkown() {
  local dir="$1" uid="$2"
  run sudo mkdir -p "$dir"
  run sudo chown -R "$uid" "$dir"
}

delete_es() {
  local pattern="$1"
  echo "  DELETE http://localhost:9200/${pattern}"
  $DRY && return
  curl -sf -X DELETE "http://localhost:9200/${pattern}" -o /dev/null \
    || echo "  (not found or ES down — skipped)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Build service list for stop/start
# ─────────────────────────────────────────────────────────────────────────────
SERVICES=()
wants cowrie  && SERVICES+=(cowrie payload-dedupe yara-scanner)
wants conpot  && SERVICES+=(conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup)
wants multipot && SERVICES+=(multipot)
wants http    && SERVICES+=(http-honeypot api-honeypot)
wants dionaea && SERVICES+=(dionaea tftp-relay)
wants dnp3    && SERVICES+=(dnp3)
wants tanner  && SERVICES+=(tanner tanner_api tanner_web snare)
wants suricata && SERVICES+=(evebox)  # suricata itself is host-level; evebox reads its logs

# ─────────────────────────────────────────────────────────────────────────────
STEP "Stopping: ${SERVICES[*]}"
run docker compose stop "${SERVICES[@]}"

# ─────────────────────────────────────────────────────────────────────────────
STEP "Wiping log files"

CLEAR_FILEBEAT=false

if wants cowrie; then
  wipe_dir "${LOGS_BASE}/cowrie"
  CLEAR_FILEBEAT=true
fi

if wants conpot; then
  for v in conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup; do
    wipe_dir "${LOGS_BASE}/$v"
  done
  CLEAR_FILEBEAT=true
fi

if wants multipot; then
  wipe_dir "${LOGS_BASE}/multipot"
  CLEAR_FILEBEAT=true
fi

if wants http; then
  wipe_dir "${LOGS_BASE}/http-honeypot"
  wipe_dir "${LOGS_BASE}/api-honeypot"
  CLEAR_FILEBEAT=true
fi

if wants dionaea; then
  # Wipe JSON event logs only — NOT the dionaea-lib Docker volume which
  # holds captured binaries (smb/ftp/tftp roots). To also purge binaries:
  #   docker compose stop dionaea && docker volume rm honeypot-stack_dionaea-lib
  wipe_dir "${LOGS_BASE}/dionaea"
  CLEAR_FILEBEAT=true
fi

if wants dnp3; then
  wipe_dir "${LOGS_BASE}/dnp3"
  CLEAR_FILEBEAT=true
fi

if wants tanner; then
  wipe_dir "${LOGS_BASE}/tanner"
  wipe_dir "${LOGS_BASE}/snare"
  CLEAR_FILEBEAT=true
fi

if wants suricata; then
  # Wipe EVE JSON (dashboard/Kibana source). Preserve the pcap sub-dir by
  # default since pcaps are also consumed by Arkime — uncomment lines below
  # to wipe pcaps too.
  wipe_dir "${LOGS_BASE}/suricata"
  # Wipe EveBox SQLite state so alerts reset too
  run docker volume rm --force honeypot-stack_evebox-data 2>/dev/null || true
  CLEAR_FILEBEAT=true
fi

if $CLEAR_FILEBEAT; then
  echo "  wipe: ${STATE_BASE}/filebeat (Filebeat registry)"
  run sudo find "${STATE_BASE}/filebeat" -mindepth 1 -delete
fi

# ─────────────────────────────────────────────────────────────────────────────
STEP "Re-creating log directories with correct ownership"

if wants cowrie; then
  mkown "${LOGS_BASE}/cowrie/downloads" 2000:2000
fi

if wants conpot; then
  for v in conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup; do
    mkown "${LOGS_BASE}/$v" 2000:2000
  done
fi

if wants multipot; then
  # multipot runs as nobody (65534)
  mkown "${LOGS_BASE}/multipot" 65534:65534
fi

if wants http; then
  mkown "${LOGS_BASE}/http-honeypot" 65534:65534
  mkown "${LOGS_BASE}/api-honeypot"  65534:65534
fi

if wants dionaea; then
  mkown "${LOGS_BASE}/dionaea" 1000:1000
fi

if wants dnp3; then
  mkown "${LOGS_BASE}/dnp3" 65534:65534
fi

if wants tanner; then
  mkown "${LOGS_BASE}/tanner" 65534:65534
  mkown "${LOGS_BASE}/snare"  65534:65534
fi

if wants suricata; then
  mkown "${LOGS_BASE}/suricata/pcap" 65534:65534
fi

# ─────────────────────────────────────────────────────────────────────────────
STEP "Deleting Elasticsearch indices (non-fatal)"

wants cowrie   && delete_es "honeypot-cowrie-*"
wants conpot   && delete_es "honeypot-conpot-*"
wants multipot && delete_es "honeypot-multipot-*"
wants http     && delete_es "honeypot-http-*"
wants dionaea  && delete_es "honeypot-dionaea-*"
wants dnp3     && delete_es "honeypot-dnp3-*"
wants tanner   && delete_es "honeypot-tanner-*"
wants suricata && delete_es "filebeat-*" && delete_es "honeypot-suricata-*"

# ─────────────────────────────────────────────────────────────────────────────
STEP "Starting: ${SERVICES[*]}"
run docker compose up -d "${SERVICES[@]}"

STEP "Done"
echo "Tail logs with:  docker compose logs -f ${SERVICES[*]}"
