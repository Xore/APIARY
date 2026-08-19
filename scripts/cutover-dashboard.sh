#!/usr/bin/env bash
# cutover-dashboard.sh — automates docs/DASHBOARD-CUTOVER.md's homeserver-
# side steps (2-4 preflight, 6 cutover, and its rollback), replacing the
# manual "bring up the next profile, curl by hand, hand-edit compose.yml"
# sequence #1628 flagged as having no dry-run or rollback step.
#
# What this script does NOT do (see docs/DASHBOARD-CUTOVER.md for the
# full procedure and why):
#   - step 5 (Traefik repoint): the VPS-side socat forward
#     (socat-hp-dashboard) points at a FIXED home-side address
#     (10.8.0.2:19090) regardless of which container answers there in the
#     current single-host topology — moving the port binding (this
#     script's cutover mode) is what actually redirects traffic. If a
#     future cross-host split ever needs a real Traefik change, that's
#     deployed by .github/workflows/deploy.yml's own dedicated step
#     (DOMAIN-secret-substituted, SSH'd to the VPS) — a homeserver script
#     cannot drive that pipeline and does not try to.
#   - step 7 (full live validation) and step 8/9 (stop-then-delete the old
#     tiers, worker retirement): deliberately manual/separate — a script
#     should not be the thing deciding "this looks fine, proceed."
#   - the actual compose.yml source edit for the port move: `cutover` mode
#     applies it via a small override file layered on top of the checked-
#     in compose.yml (see below), not a live-only hand-edit of the base
#     file — the real edit, if kept, should land as a normal PR so a
#     later Arcane gitops-sync can't silently revert it.
#
# Usage (run from the honeypot-dashboard Arcane stack directory — same
# convention as deploy-dashboard-rolling.sh; the honeypot-dashboard-backend
# stack is expected as the sibling directory ../honeypot-dashboard-backend,
# matching how Arcane's directory-aware sync materializes both):
#   ./cutover-dashboard.sh preflight   # bring up `next`, verify, touch nothing external
#   ./cutover-dashboard.sh cutover     # stop dashboard, move the port to dashboard-next
#   ./cutover-dashboard.sh rollback    # reverse the port move, restart dashboard
set -euo pipefail

DASHBOARD_DIR="$(pwd)"
BACKEND_DIR="$DASHBOARD_DIR/../honeypot-dashboard-backend"
OVERRIDE_FILE="$DASHBOARD_DIR/cutover.override.yml"
HP_BIND="${HP_BIND:-10.8.0.2}"

usage() {
  echo "usage: $0 {preflight|cutover|rollback}" >&2
  exit 1
}

require_dashboard_dir() {
  [[ -f "$DASHBOARD_DIR/compose.yml" ]] || {
    echo "run from the honeypot-dashboard stack directory (compose.yml not found here)" >&2
    exit 1
  }
  [[ -f "$BACKEND_DIR/compose.yml" ]] || {
    echo "expected the honeypot-dashboard-backend stack at $BACKEND_DIR (compose.yml not found there)" >&2
    exit 1
  }
}

# Hard-fails (not a warning) if DASHBOARD_SERVICE_TOKEN resolves empty in
# either stack — an empty token means the two tiers trust every request
# from anything else on honeynet, not just each other (docs/DASHBOARD-
# CUTOVER.md step 2's own hard prerequisite).
check_service_token() {
  local dir="$1" label="$2" token
  # docker compose config renders `- SERVICE_TOKEN=${DASHBOARD_SERVICE_TOKEN:-}`
  # as a `SERVICE_TOKEN: <value>` mapping line; strip the key and any
  # quoting to get just the resolved value.
  token="$( (cd "$dir" && docker compose config 2>/dev/null) | grep -m1 'SERVICE_TOKEN:' | sed -E 's/^[^:]*:[[:space:]]*"?//; s/"?[[:space:]]*$//' )"
  if [[ -z "$token" || "$token" == "null" ]]; then
    echo "FATAL: DASHBOARD_SERVICE_TOKEN resolves empty for $label — set it before preflight, not after" >&2
    exit 1
  fi
}

# Throwaway curl on the same honeynet bridge dashboard-next/backend-service/
# backend-service-mounted already join — no host port ever published, so
# this is non-invasive to whatever is currently bound to 19090.
check_honeynet_healthz() {
  local name="$1" host="$2" port="$3"
  echo -n "  $name ($host:$port/healthz) ... "
  if docker run --rm --network honeynet curlimages/curl -sf --max-time 5 "http://$host:$port/healthz" >/dev/null 2>&1; then
    echo "ok"
  else
    echo "FAILED" >&2
    return 1
  fi
}

check_container_running() {
  local name="$1" container="$2"
  echo -n "  $name ($container) ... "
  local state
  state="$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null || echo missing)"
  if [[ "$state" == "running" ]]; then
    echo "running"
  else
    echo "FAILED (state: $state)" >&2
    return 1
  fi
}

cmd_preflight() {
  require_dashboard_dir
  echo "== checking DASHBOARD_SERVICE_TOKEN is set in both stacks =="
  check_service_token "$DASHBOARD_DIR" "honeypot-dashboard"
  check_service_token "$BACKEND_DIR" "honeypot-dashboard-backend"
  echo "  ok"

  echo "== validating compose config for the next profile =="
  (cd "$DASHBOARD_DIR" && docker compose --profile next config --quiet)
  (cd "$BACKEND_DIR" && docker compose --profile next config --quiet)
  echo "  ok"

  echo "== bringing up the next profile in both stacks (idempotent) =="
  (cd "$DASHBOARD_DIR" && docker compose --profile next up -d)
  (cd "$BACKEND_DIR" && docker compose --profile next up -d)

  echo "== waiting for the next tier to report healthy =="
  local ok=1
  for _ in $(seq 1 60); do
    ok=1
    check_honeynet_healthz "dashboard-next" dashboard-next 8080 || ok=0
    check_honeynet_healthz "backend-service" backend-service 8081 || ok=0
    check_honeynet_healthz "backend-service-mounted" backend-service-mounted 8082 || ok=0
    [[ "$ok" == 1 ]] && break
    sleep 2
  done
  [[ "$ok" == 1 ]] || { echo "FATAL: next tier did not become healthy in time" >&2; exit 1; }

  echo "== confirming the loopback-only worker containers are running =="
  check_container_running "backend-worker" hp-apiary-worker
  check_container_running "backend-worker-importer" hp-apiary-worker-importer
  check_container_running "backend-worker-enrichment" hp-apiary-worker-enrichment

  echo
  echo "preflight OK. Nothing external was touched — dashboard is still the"
  echo "only thing Traefik reaches. Next: docs/DASHBOARD-CUTOVER.md step 4's"
  echo "manual verification (golden-path pages, /api/live, login), then"
  echo "'$0 cutover' when ready."
}

cmd_cutover() {
  require_dashboard_dir
  echo "== re-running preflight as a precondition =="
  cmd_preflight
  echo

  echo "== stopping dashboard (frees host port for dashboard-next; the"
  echo "   container and its image are left in place for rollback) =="
  (cd "$DASHBOARD_DIR" && docker compose stop dashboard)

  echo "== applying the port move via $OVERRIDE_FILE =="
  echo "   (adds ports: to dashboard-next without touching the checked-in"
  echo "   compose.yml live — if this stays, land it as a normal PR so a"
  echo "   later Arcane gitops-sync can't silently revert it)"
  cat >"$OVERRIDE_FILE" <<EOF
# Generated by cutover-dashboard.sh — see docs/DASHBOARD-CUTOVER.md step 6.
# Not meant to be committed as-is; if the cutover sticks, move this
# ports: mapping into compose.yml itself in a real PR and delete this file.
services:
  dashboard-next:
    ports:
      - "${HP_BIND}:19090:8080"
EOF
  (cd "$DASHBOARD_DIR" && docker compose -f compose.yml -f cutover.override.yml up -d dashboard-next)

  echo "== waiting for dashboard-next to report healthy on the live port =="
  for _ in $(seq 1 60); do
    curl -sf --max-time 5 "http://${HP_BIND}:19090/healthz" >/dev/null 2>&1 && { echo "  healthy on ${HP_BIND}:19090"; break; }
    sleep 2
  done

  echo
  echo "Cutover applied. dashboard-next now answers on ${HP_BIND}:19090;"
  echo "dashboard is stopped (not removed — '$0 rollback' reverses this)."
  echo "Next: docs/DASHBOARD-CUTOVER.md step 7's full live validation,"
  echo "*before* step 8's bake-period stop-the-old-tiers step."
}

cmd_rollback() {
  require_dashboard_dir
  echo "== reversing the port move =="
  if [[ -f "$OVERRIDE_FILE" ]]; then
    (cd "$DASHBOARD_DIR" && docker compose -f compose.yml -f cutover.override.yml stop dashboard-next)
    rm -f "$OVERRIDE_FILE"
    (cd "$DASHBOARD_DIR" && docker compose up -d dashboard-next)
  else
    echo "  no $OVERRIDE_FILE found — assuming the port was never moved by this script"
  fi

  echo "== restarting dashboard =="
  (cd "$DASHBOARD_DIR" && docker compose up -d dashboard)

  echo "== waiting for dashboard to report healthy (reusing deploy-dashboard-rolling.sh's own check) =="
  for _ in $(seq 1 60); do
    state="$(docker inspect --format '{{.State.Health.Status}}' hp-dashboard 2>/dev/null || echo missing)"
    [[ "$state" == "healthy" ]] && { echo "  dashboard healthy."; echo; echo "Rollback complete."; exit 0; }
    sleep 2
  done
  echo "FATAL: dashboard did not report healthy in time after rollback" >&2
  exit 1
}

case "${1:-}" in
  preflight) cmd_preflight ;;
  cutover) cmd_cutover ;;
  rollback) cmd_rollback ;;
  *) usage ;;
esac
