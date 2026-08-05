#!/usr/bin/env bash
# deploy-dashboard-rolling.sh — zero-downtime dashboard redeploy (#266).
#
# The old process (`docker compose up -d --build dashboard`, still what
# every other split stack's own deploy step does) does a blind Recreate:
# a real window with no listener at all while the container restarts.
# #212's client-side GET retry (hp-settings.js's api() helper) papers over
# that for reads; writes were never retried and still 5xx in that window.
#
# This builds the shared image once, then restarts dashboard and
# dashboard-b one at a time, waiting for each to report healthy before
# touching the other -- vps/traefik/dynamic.yml's honeypot-dashboard
# service lists both as loadBalancer servers with an active healthCheck,
# so Traefik stops sending a replica live traffic the moment it starts
# failing (checked directly against the backend, not through the
# forward-auth-gated router), well before this script even restarts it.
# The other replica, still healthy, serves every request in the meantime.
#
# Usage:
#   ./scripts/deploy-dashboard-rolling.sh
#
# Run from the actual Dockge-managed dashboard stack directory on the
# homeserver (/opt/stacks/honeypot-dashboard) -- see
# feedback_dashboard_deploy_path in this repo's own deploy docs for why
# that path, not a git checkout, is the real build tree. Requires
# docker-compose.dashboard.yml (this repo's copy or the deployed one) in
# the current directory or passed via COMPOSE_FILE.

set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.dashboard.yml}"
REPLICAS=(dashboard dashboard-b)
CONTAINER_NAMES=(hp-dashboard hp-dashboard-b)
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-60}"

log() { printf '[deploy-dashboard-rolling] %s\n' "$*" >&2; }

if [[ ! -f "$COMPOSE_FILE" ]]; then
  log "FATAL: $COMPOSE_FILE not found in $(pwd) -- run from the dashboard stack directory or set COMPOSE_FILE"
  exit 1
fi

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

wait_healthy() {
  local container="$1"
  local waited=0
  while (( waited < HEALTH_TIMEOUT_SECONDS )); do
    local status
    status="$(docker inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null || echo "missing")"
    if [[ "$status" == "healthy" ]]; then
      return 0
    fi
    if [[ "$status" == "missing" ]]; then
      log "FATAL: container $container does not exist -- did up -d fail?"
      return 1
    fi
    sleep 2
    waited=$((waited + 2))
  done
  log "FATAL: $container did not become healthy within ${HEALTH_TIMEOUT_SECONDS}s (last status: $status)"
  return 1
}

log "building shared image (honeypot-dashboard:latest) once for both replicas..."
compose build dashboard

for i in "${!REPLICAS[@]}"; do
  replica="${REPLICAS[$i]}"
  container="${CONTAINER_NAMES[$i]}"
  other_index=$(( (i + 1) % ${#REPLICAS[@]} ))
  other="${CONTAINER_NAMES[$other_index]}"

  log "verifying $other is healthy before touching $replica (it must carry all traffic during $replica's restart)..."
  if ! wait_healthy "$other"; then
    log "FATAL: refusing to restart $replica -- $other is not healthy, restarting $replica now would mean a real gap in dashboard availability, not a rolling update"
    exit 1
  fi

  log "recreating $replica from the freshly built image..."
  compose up -d --no-deps "$replica"

  log "waiting for $replica ($container) to report healthy..."
  if ! wait_healthy "$container"; then
    log "$replica failed its post-restart healthcheck -- $other is still serving all traffic. Not proceeding to the next replica. Investigate $replica (docker logs $container) before re-running this script."
    exit 1
  fi
  log "$replica is healthy."
done

log "both replicas updated and healthy. Rolling deploy complete."
