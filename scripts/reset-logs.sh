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
# Run from the stack root (same dir as docker-compose.yml/compose.yml).
# Requires: docker, sudo (log dirs are owned by container UIDs).
#
# #258 proof of concept: the six conpot services now deploy as their own
# Dockge stack (/opt/stacks/honeypot-conpot/compose.yml), not inside
# honeypot-stack's own compose.yml. A bare `docker compose stop/up` run from
# this directory resolves against *this* directory's compose.yml (Compose's
# default file-discovery prefers compose.yml over docker-compose.yml, which
# is why this already worked against the deployed stack rather than the
# repo-tracked filename) and would silently find nothing for conpot's
# service names now that they live in a different project. conpot's stop/up
# runs from that stack's own directory instead, matching how it was actually
# deployed, so Compose resolves the same project it was created under.

set -euo pipefail

LOGS_BASE="/opt/stacks/honeypot-stack/logs"
STATE_BASE="/opt/stacks/honeypot-stack/state"
CONPOT_STACK_DIR="/opt/stacks/honeypot-conpot"
CONPOT_SERVICES=(conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup)

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
# conpot is deliberately excluded from SERVICES -- it lives in its own
# Dockge stack/compose project now (CONPOT_STACK_DIR above) and is
# stopped/started there separately, not via this array.
SERVICES=()
wants cowrie  && SERVICES+=(cowrie payload-dedupe yara-scanner)
wants multipot && SERVICES+=(multipot)
wants http    && SERVICES+=(http-honeypot api-honeypot)
wants dionaea && SERVICES+=(dionaea tftp-relay)
wants dnp3    && SERVICES+=(dnp3)
wants tanner  && SERVICES+=(tanner tanner_api tanner_web snare)
wants suricata && SERVICES+=(evebox)  # suricata itself is host-level; evebox reads its logs

conpot_compose() {
  # `docker compose stop/up <service>` with a zero-length SERVICES array
  # stops/starts *everything* in the compose file, not nothing -- so this
  # (and the matching call for the main stack below) only fires when conpot
  # is actually one of the requested targets.
  if [ ! -d "$CONPOT_STACK_DIR" ]; then
    echo "  (skip: $CONPOT_STACK_DIR does not exist -- honeypot-conpot not deployed here)"
    return 0
  fi
  ( cd "$CONPOT_STACK_DIR" && run docker compose "$@" "${CONPOT_SERVICES[@]}" )
}

# ─────────────────────────────────────────────────────────────────────────────
STEP "Stopping: ${SERVICES[*]}$(wants conpot && echo " ${CONPOT_SERVICES[*]}")"
[[ ${#SERVICES[@]} -gt 0 ]] && run docker compose stop "${SERVICES[@]}"
wants conpot && conpot_compose stop

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
  #   docker compose stop dionaea && docker volume rm dionaea-lib
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
STEP "Starting: ${SERVICES[*]}$(wants conpot && echo " ${CONPOT_SERVICES[*]}")"
[[ ${#SERVICES[@]} -gt 0 ]] && run docker compose up -d "${SERVICES[@]}"
wants conpot && conpot_compose up -d

STEP "Done"
echo "Tail logs with:  docker compose logs -f ${SERVICES[*]}"
wants conpot && echo "  (cd $CONPOT_STACK_DIR && docker compose logs -f ${CONPOT_SERVICES[*]})"
