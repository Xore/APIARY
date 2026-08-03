#!/usr/bin/env bash
# build-dashboard-frontend.sh — regenerate the dashboard's compiled frontend
# asset (dashboard/static/hp-api.js) from dashboard/frontend/src/.
#
# #191 removed the Tailwind CSS build entirely, and the dashboard's
# app-specific CSS has since been folded into Xore/theme's theme.css (vendored
# at dashboard/static/theme.css, see scripts/sync-theme.sh) -- no CSS build
# step of any kind. Only hp-api.js (the TypeScript/esbuild bundle) is still
# generated.
#
# The "Dashboard frontend" CI job (.github/workflows/quality.yml) rebuilds
# hp-api.js and fails when the committed output is stale, so run this after
# every edit under dashboard/frontend/src/ and commit the regenerated asset
# together with your source change. Never hand-edit the compiled file — the
# minifier's property ordering cannot be reproduced by hand.
#
# Usage:
#   ./scripts/build-dashboard-frontend.sh          # build, report asset status
#   ./scripts/build-dashboard-frontend.sh --check  # build, fail if the asset is stale (like CI)
#
# Can be run from any directory; the script locates the stack root itself.
# Requires: npm (Node 22+) or, as a fallback, docker.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND="$ROOT/dashboard/frontend"
ASSETS=(dashboard/static/hp-api.js)

MODE=report
for arg in "$@"; do
  case "$arg" in
    --check) MODE=check ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg (try --help)" >&2; exit 2 ;;
  esac
done

cd "$ROOT"

if command -v npm >/dev/null 2>&1; then
  npm --prefix "$FRONTEND" ci --no-audit --no-fund
  npm --prefix "$FRONTEND" run typecheck
  npm --prefix "$FRONTEND" run build
elif command -v docker >/dev/null 2>&1; then
  docker run --rm -v "$ROOT/dashboard:/app" -w /app/frontend node:22-alpine \
    sh -c "npm ci && npm run typecheck && npm run build"
else
  echo "error: neither npm nor docker is available to build the frontend" >&2
  exit 1
fi

if git diff --quiet -- "${ASSETS[@]}"; then
  echo "compiled assets unchanged — nothing to commit"
elif [ "$MODE" = check ]; then
  echo "error: compiled assets are stale — run scripts/build-dashboard-frontend.sh and commit:" >&2
  git diff --stat -- "${ASSETS[@]}" >&2
  exit 1
else
  echo "compiled assets updated — commit them together with your source change:"
  git diff --stat -- "${ASSETS[@]}"
fi
