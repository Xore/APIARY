#!/usr/bin/env bash
# deploy-dashboard-rolling.sh — plain single-replica dashboard redeploy.
#
# The #266 zero-downtime rolling pair (dashboard + dashboard-b) is retired
# per Xore: the deployment runs exactly one dashboard replica now, and a
# redeploy is a straightforward build + recreate, accepting the brief
# recreate window on this single-operator deployment. The script name is
# kept so existing automation and docs keep working.
#
# Usage:
#   ./scripts/deploy-dashboard-rolling.sh
#
# Run from the actual Arcane-managed dashboard stack directory on the
# homeserver (/var/dockge/stacks/honeypot-dashboard) -- Arcane's
# directory-aware sync materializes arcane/home/honeypot-dashboard/* there,
# so that path, not a git checkout, is the real build tree.
set -euo pipefail

[[ -f compose.yml ]] || { echo "run from the dashboard stack directory (compose.yml not found)" >&2; exit 1; }

echo "building honeypot-dashboard:latest ..."
docker compose build dashboard

echo "recreating dashboard ..."
docker compose up -d dashboard

echo "waiting for the container to report healthy ..."
for _ in $(seq 1 60); do
  state="$(docker inspect --format '{{.State.Health.Status}}' hp-dashboard 2>/dev/null || echo missing)"
  [[ "$state" == "healthy" ]] && { echo "dashboard healthy."; exit 0; }
  sleep 2
done
echo "dashboard did not report healthy in time" >&2
exit 1
