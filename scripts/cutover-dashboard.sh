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
#
# The 19090 binding lives on dashboard-next permanently in compose.yml as
# of the #1628 cutover holding through step 7 -- `cutover` mode originally
# applied it live via a generated override.yml layered on the checked-in
# file instead, exactly to avoid a live-only hand-edit an Arcane gitops-
# sync could silently revert. It did worse than silently revert it: with
# dashboard's own (now-removed) conflicting ports: line still in
# compose.yml, a routine sync after the port move tried to rebind 19090
# out from under dashboard-next and failed the sync outright. `rollback`
# now generates that same kind of override.yml in the other direction --
# temporarily giving 19090 back to dashboard -- since dashboard's own
# entry carries no ports: of its own anymore.
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
  # quoting to get just the resolved value. Needs --profile next: the only
  # services that reference SERVICE_TOKEN (dashboard-next/backend-worker
  # here, backend-service in the sibling stack) are themselves next-profile-
  # gated, and `docker compose config` excludes inactive-profile services
  # from its output the same way `up` does — without the flag this always
  # greps nothing and reports a false "empty" even when the token is set
  # (caught live during #1628's first real preflight run, not by shellcheck).
  token="$( (cd "$dir" && docker compose --profile next config 2>/dev/null) | grep -m1 'SERVICE_TOKEN:' | sed -E 's/^[^:]*:[[:space:]]*"?//; s/"?[[:space:]]*$//' )"
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
  # Order matters on a host where apiary-backend:latest has never been
  # built: only $BACKEND_DIR's backend-service declares `build:` for that
  # image (the honeynet-shared tag every backend-worker*/backend-service-
  # mounted service in $DASHBOARD_DIR references but does not itself build).
  # Bringing up $DASHBOARD_DIR first leaves Compose with no local image and
  # no build context for those services, so it falls back to pulling
  # `apiary-backend:latest` from Docker Hub's default namespace and fails
  # closed with "pull access denied" (caught live during #1628's first real
  # preflight run, not by shellcheck). $BACKEND_DIR first builds the image
  # once; $DASHBOARD_DIR's own services then resolve it from the local
  # image cache instead of attempting a pull.
  (cd "$BACKEND_DIR" && docker compose --profile next up -d)
  (cd "$DASHBOARD_DIR" && docker compose --profile next up -d)

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

  if [[ -f "$OVERRIDE_FILE" ]]; then
    echo "== removing a leftover rollback override (inert here -- plain"
    echo "   'up -d dashboard-next' below never reads it -- but stale and"
    echo "   confusing to leave around) =="
    rm -f "$OVERRIDE_FILE"
  fi

  echo "== bringing up dashboard-next on the now-permanent 19090 binding =="
  echo "   (compose.yml itself carries 19090 on dashboard-next since the"
  echo "   #1628 cutover held through step 7 -- no override file needed"
  echo "   here anymore; \$0 rollback still generates one to give the port"
  echo "   back to dashboard temporarily)"
  (cd "$DASHBOARD_DIR" && docker compose up -d dashboard-next)

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
  echo "== stopping dashboard-next (frees the 19090 binding it now carries"
  echo "   permanently in compose.yml) =="
  (cd "$DASHBOARD_DIR" && docker compose stop dashboard-next)

  echo "== temporarily giving 19090 back to dashboard via $OVERRIDE_FILE =="
  echo "   (dashboard's own compose.yml entry has carried no ports: since"
  echo "   the cutover held -- this override is a live-only, not-committed"
  echo "   reversal, same spirit the original cutover override had before"
  echo "   it got promoted into compose.yml itself)"
  cat >"$OVERRIDE_FILE" <<EOF
# Generated by cutover-dashboard.sh rollback — see docs/DASHBOARD-CUTOVER.md.
# Not meant to be committed; delete once dashboard-next is cut back over
# ('$0 cutover' does this automatically on its next run).
services:
  dashboard:
    ports:
      - "${HP_BIND}:19090:8080"
EOF
  (cd "$DASHBOARD_DIR" && docker compose -f compose.yml -f cutover.override.yml up -d dashboard)

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
