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
# #258: conpot, cowrie, multipot, http (http-honeypot+api-honeypot), and dnp3
# each now deploy as their own Dockge stack (/opt/stacks/honeypot-<name>/
# compose.yml), not inside honeypot-stack's own compose.yml. A bare
# `docker compose stop/up` run from this directory resolves against *this*
# directory's compose.yml (Compose's default file-discovery prefers
# compose.yml over docker-compose.yml, which is why this already worked
# against the deployed stack rather than the repo-tracked filename) and
# would silently find nothing for those services' names now that they live
# in a different project. Their stop/up runs from each stack's own directory
# instead, matching how they were actually deployed, so Compose resolves the
# same project each was created under.

set -euo pipefail

LOGS_BASE="/opt/stacks/honeypot-stack/logs"
STATE_BASE="/opt/stacks/honeypot-stack/state"

# Every target that moved into its own stack (#258), and which services live
# there. cowrie is the one target with a foot in both worlds: cowrie itself
# moved out, but payload-dedupe/yara-scanner (which read its captured
# downloads) stayed in the main stack -- see the SERVICES array below.
SPLIT_TARGETS=(conpot cowrie multipot http dnp3)
declare -A SPLIT_STACK_DIR=(
  [conpot]="/opt/stacks/honeypot-conpot"
  [cowrie]="/opt/stacks/honeypot-cowrie"
  [multipot]="/opt/stacks/honeypot-multipot"
  [http]="/opt/stacks/honeypot-http"
  [dnp3]="/opt/stacks/honeypot-dnp3"
)
declare -A SPLIT_STACK_SERVICES=(
  [conpot]="conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup"
  [cowrie]="cowrie"
  [multipot]="multipot"
  [http]="http-honeypot api-honeypot"
  [dnp3]="dnp3"
)

DRY=false
declare -A TARGETS
have_target=false

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=true ;;
    cowrie|conpot|multipot|http|dionaea|dnp3|tanner|suricata|all)
      TARGETS["$arg"]=1
      have_target=true ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

# Default to all when no target given. Not "${#TARGETS[@]} -eq 0" -- on a
# freshly `declare -A`'d array with nothing ever assigned into it yet, this
# bash version's `set -u` treats ${#TARGETS[@]} itself as an unbound
# variable reference (confirmed: -v TARGETS[key] does not have this
# problem, only the count expansion does), even though the array was
# properly declared. A plain flag sidesteps the whole question.
$have_target || TARGETS["all"]=1

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
# cowrie/multipot/http/dnp3/conpot themselves are deliberately excluded from
# SERVICES -- each lives in its own Dockge stack/compose project now
# (SPLIT_STACK_DIR above) and is stopped/started there separately, via
# split_stack_compose below, not through this array.
SERVICES=()
wants cowrie  && SERVICES+=(payload-dedupe yara-scanner)  # cowrie itself moved out (#258)
wants dionaea && SERVICES+=(dionaea tftp-relay)
wants tanner  && SERVICES+=(tanner tanner_api tanner_web snare)
wants suricata && SERVICES+=(evebox)  # suricata itself is host-level; evebox reads its logs

split_stack_compose() {
  # split_stack_compose <target> <docker compose args...> -- e.g.
  # `split_stack_compose cowrie stop` or `split_stack_compose dnp3 up -d`.
  # A zero-length service list would make `docker compose stop/up` with no
  # arguments act on *everything* in that compose file, not nothing, so
  # callers only ever invoke this for a target actually in SPLIT_TARGETS.
  local target="$1"; shift
  local dir="${SPLIT_STACK_DIR[$target]}"
  # Deliberate word-splitting of a fixed, script-defined list (not user
  # input) into a services array -- SC2206 does not apply here.
  # shellcheck disable=SC2206
  local services=(${SPLIT_STACK_SERVICES[$target]})
  if [ ! -d "$dir" ]; then
    echo "  (skip $target: $dir does not exist -- honeypot-$target not deployed here)"
    return 0
  fi
  ( cd "$dir" && run docker compose "$@" "${services[@]}" )
}

split_targets_wanted() {
  local out=() t
  for t in "${SPLIT_TARGETS[@]}"; do
    wants "$t" && out+=("${SPLIT_STACK_SERVICES[$t]}")
  done
  echo "${out[*]}"
}

# ─────────────────────────────────────────────────────────────────────────────
STEP "Stopping: ${SERVICES[*]} $(split_targets_wanted)"
[[ ${#SERVICES[@]} -gt 0 ]] && run docker compose stop "${SERVICES[@]}"
for t in "${SPLIT_TARGETS[@]}"; do wants "$t" && split_stack_compose "$t" stop; done

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
STEP "Starting: ${SERVICES[*]} $(split_targets_wanted)"
[[ ${#SERVICES[@]} -gt 0 ]] && run docker compose up -d "${SERVICES[@]}"
for t in "${SPLIT_TARGETS[@]}"; do wants "$t" && split_stack_compose "$t" up -d; done

STEP "Done"
echo "Tail logs with:  docker compose logs -f ${SERVICES[*]}"
for t in "${SPLIT_TARGETS[@]}"; do
  wants "$t" && echo "  (cd ${SPLIT_STACK_DIR[$t]} && docker compose logs -f ${SPLIT_STACK_SERVICES[$t]})"
done
