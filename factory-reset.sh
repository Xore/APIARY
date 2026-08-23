#!/usr/bin/env bash
set -euo pipefail

# #262: this repo had no documented "the stack is in a bad state, how do I
# get back to clean" path -- T-Pot's README has one (stop, back up data/,
# wipe it, git reset --hard, reinstall). This repo already has the pieces
# T-Pot's single script covers (analysis/backup-honeypot.sh for the backup,
# docs/STACK-REBUILD.md's runbook for the stop/wipe/restart sequence across
# the ~13 independent Dockge stacks #258 split this into), but nothing tied
# them into one entry point the way T-Pot's is. This is that entry point --
# see docs/RECOVERY.md for the full walkthrough.
#
# Every destructive step is opt-in and requires --apply, matching this
# repo's own git-safety conventions (never a blind --hard/-f by default).
# Run with no flags and this only takes a backup -- analysis/backup-honeypot.sh
# runs against the live stack with no downtime, so a routine "get me a
# snapshot" run never has to stop anything.
#
# Know what that backup covers before trusting it ahead of a --wipe: config,
# secrets, the Keycloak identity database and small config-bearing volumes --
# NOT Elasticsearch data, captured payloads, PCAP or sandbox images. --wipe
# then restore brings the stack back configured and authenticated with an
# empty event history. docs/BACKUP-ESSENTIALS.md has the full in/out list and
# the off-host equivalent (scripts/backup-essentials.sh).
#
# Usage:
#   ./factory-reset.sh                          # backup only, nothing else touched
#   ./factory-reset.sh --apply --wipe           # backup, stop, wipe, restart
#   ./factory-reset.sh --apply --git-ref <ref>  # backup, stop, git reset --hard <ref>, restart
#   ./factory-reset.sh --apply --wipe --no-restart   # backup, stop, wipe, leave stopped

apply=false
wipe=false
restart=true
git_ref=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) apply=true; shift ;;
    --wipe) wipe=true; shift ;;
    --no-restart) restart=false; shift ;;
    --git-ref) git_ref="${2:?--git-ref requires a value}"; shift 2 ;;
    -h|--help)
      sed -n '4,24p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ $(id -u) -ne 0 ]]; then
  echo "Run as root: sudo ./factory-reset.sh [options]" >&2
  exit 1
fi

export STACK_DIR="${STACK_DIR:-/opt/stacks/apiary}"

if [[ -n "$git_ref" && "$apply" != true ]]; then
  echo "--git-ref requires --apply" >&2
  exit 2
fi
if [[ "$wipe" == true && "$apply" != true ]]; then
  echo "--wipe requires --apply" >&2
  exit 2
fi

log() { printf '[factory-reset] %s\n' "$*"; }

# The 12 independent Dockge stacks docs/STACK-REBUILD.md's own live-verified
# runbook stops/starts (2026-08-02), same order. Sensor stacks added since
# that runbook was last confirmed live (dicompot, dns-honeypot,
# citrix-honeypot, cisco-asa-honeypot, rdp-honeypot -- see
# scripts/reset-logs.sh's SPLIT_STACK_DIR for the current full list) are
# included here too, grouped with the other standalone sensors in step 4
# where docs/STACK-REBUILD.md says order doesn't matter. honeypot-init and
# honeypot-elk stay first/second on both ends -- everything else depends on
# their output, and Elasticsearch itself must already be up before
# honeypot-init's elasticsearch-setup/arkime-init jobs can run cold.
STOP_ORDER=(
  honeypot-elk honeypot-dashboard honeypot-utilities honeypot-payload-analysis
  honeypot-dionaea honeypot-tanner honeypot-dnp3 honeypot-http honeypot-multipot
  honeypot-cowrie honeypot-conpot honeypot-dicompot honeypot-dns-honeypot
  honeypot-citrix-honeypot honeypot-cisco-asa-honeypot honeypot-rdp-honeypot
  honeypot-init
)
# External-referenced volumes honeypot-init's compose file expects to
# already exist (arcane/home/honeypot-init/compose.yml, external: true) -- if --wipe
# removed them, they need an empty placeholder before honeypot-init can
# start, same as docs/STACK-REBUILD.md step 3 documents.
EXTERNAL_PLACEHOLDER_VOLUMES=(dionaea-lib yara-results)

# Named Docker volumes docs/STACK-REBUILD.md's own "what gets wiped" list
# names explicitly. es-data is intentionally NOT removed by docker volume
# rm here -- Elasticsearch's own data directory is what the fresh
# elasticsearch-setup/arkime-init run (after honeypot-init restarts)
# expects to find *absent*, but removing a volume still attached to a
# just-stopped container can fail with "volume is in use" if the stop
# above raced it; wipe_volumes below removes it last, after every
# consumer is confirmed stopped.
WIPE_VOLUMES=(
  es-data dionaea-lib dashboard-state yara-results evebox-config
  arkime-pcap snare-pages reporter-data
)

run_backup() {
  log "backing up via analysis/backup-honeypot.sh (config/secrets/identity, stack stays live)"
  "$STACK_DIR"/analysis/backup-honeypot.sh
}

stop_stacks() {
  local name dir
  for name in "${STOP_ORDER[@]}"; do
    dir="/opt/stacks/$name"
    [[ -d "$dir" ]] || { log "skip $name (not deployed here)"; continue; }
    log "stopping $name"
    (cd "$dir" && docker compose -f compose.yml down) || log "WARNING: $name did not stop cleanly, continuing"
  done
}

start_stacks() {
  local name dir
  # Elasticsearch before honeypot-init (docs/STACK-REBUILD.md step 3) --
  # elasticsearch-setup/arkime-init hang forever on a cold start otherwise.
  for name in honeypot-elk honeypot-init; do
    dir="/opt/stacks/$name"
    [[ -d "$dir" ]] || { log "skip $name (not deployed here)"; continue; }
    log "starting $name"
    (cd "$dir" && docker compose -f compose.yml up -d) || log "WARNING: $name did not start cleanly, continuing"
    if [[ "$name" == "honeypot-elk" ]]; then
      log "waiting for elasticsearch to report healthy"
      for _ in $(seq 1 60); do
        [[ "$(docker inspect -f '{{.State.Health.Status}}' hp-elasticsearch 2>/dev/null)" == "healthy" ]] && break
        sleep 5
      done
    fi
  done
  for name in "${STOP_ORDER[@]}"; do
    [[ "$name" == "honeypot-elk" || "$name" == "honeypot-init" ]] && continue
    dir="/opt/stacks/$name"
    [[ -d "$dir" ]] || { log "skip $name (not deployed here)"; continue; }
    log "starting $name"
    (cd "$dir" && docker compose -f compose.yml up -d) || log "WARNING: $name did not start cleanly, continuing"
  done
}

wipe_volumes() {
  log "removing named Docker volumes: ${WIPE_VOLUMES[*]}"
  local vol
  for vol in "${WIPE_VOLUMES[@]}"; do
    # Project-scoped (unnamed) volumes get a project prefix -- confirmed
    # live for evebox-config (scripts/reset-logs.sh: honeypot-elk_evebox-config).
    # Try both the bare name (explicit shared `name:` volumes) and the
    # honeypot-elk_-prefixed form (that stack owns every project-scoped one
    # currently in WIPE_VOLUMES) unconditionally rather than falling back on
    # failure -- `docker volume rm --force` exits 0 even for a volume that
    # doesn't exist, so a `first || second` chain would never reach the
    # second attempt.
    docker volume rm --force "$vol" >/dev/null 2>&1 || true
    docker volume rm --force "honeypot-elk_$vol" >/dev/null 2>&1 || true
  done
}

recreate_external_placeholders() {
  local vol
  for vol in "${EXTERNAL_PLACEHOLDER_VOLUMES[@]}"; do
    docker volume inspect "$vol" >/dev/null 2>&1 || docker volume create "$vol" >/dev/null
  done
}

wipe_state() {
  # Sensor logs, per-sensor ownership, and the matching Elasticsearch
  # cleanup are all handled by scripts/reset-logs.sh already -- reusing it
  # instead of re-deriving per-sensor UIDs here, since every one of those
  # UIDs (and the snare root:root exception) came from a real live
  # incident (docs/STACK-REBUILD.md's pitfalls section).
  log "wiping sensor logs via scripts/reset-logs.sh"
  (cd "$STACK_DIR" && ./scripts/reset-logs.sh all) || log "WARNING: reset-logs.sh did not complete cleanly, continuing"

  log "wiping remaining state (Filebeat registry, dedupe cache, init markers)"
  local dir
  for dir in state/filebeat state/dedupe state/init-markers; do
    [[ -d "$STACK_DIR/$dir" ]] || continue
    find "$STACK_DIR/$dir" -mindepth 1 -delete
  done

  wipe_volumes
}

reset_git_tree() {
  log "resetting tracked config to $git_ref"
  git -C "$STACK_DIR" fetch origin
  git -C "$STACK_DIR" reset --hard "$git_ref"
}

run_backup

if [[ "$apply" != true ]]; then
  log "dry run (no --apply): backed up only, nothing else touched"
  exit 0
fi

log "stopping every stack"
stop_stacks

if [[ "$wipe" == true ]]; then
  wipe_state
fi
if [[ -n "$git_ref" ]]; then
  reset_git_tree
fi

if [[ "$restart" == true ]]; then
  [[ "$wipe" == true ]] && recreate_external_placeholders
  log "starting every stack"
  start_stacks
else
  log "--no-restart: stacks left stopped"
fi

log "done"
