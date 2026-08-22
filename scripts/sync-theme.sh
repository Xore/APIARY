#!/usr/bin/env bash
# Re-vendor frontend-next/public/static/theme.css from a local Xore/theme
# clone and rewrite frontend-next/theme.lock with the new commit and hash.
#
# Usage: scripts/sync-theme.sh [path-to-local-theme-clone] [ref]
#   path defaults to ../theme, ref defaults to the clone's HEAD.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
clone="${1:-$root/../theme}"
ref="${2:-HEAD}"
# #1659: repointed at frontend-next after the Go dashboard's retirement --
# dashboard/frontend/theme.lock and dashboard/static/theme.css no longer
# exist.
lock="$root/arcane/home/honeypot-dashboard/frontend-next/theme.lock"
vendored="$root/arcane/home/honeypot-dashboard/frontend-next/public/static/theme.css"

if [ ! -d "$clone/.git" ]; then
  echo "not a git clone: $clone" >&2
  echo "Usage: scripts/sync-theme.sh [path-to-local-theme-clone] [ref]" >&2
  exit 1
fi

commit="$(git -C "$clone" rev-parse "$ref")"
date="$(git -C "$clone" log -1 --format=%cI "$commit")"
repository="$(git -C "$clone" remote get-url origin 2>/dev/null || echo https://github.com/Xore/theme)"
repository="${repository%.git}"

git -C "$clone" show "$commit:theme.css" >"$vendored"
sha256="$(sha256sum "$vendored" | cut -d' ' -f1)"

cat >"$lock" <<EOF
# Vendored Xore/theme pin. Written by scripts/sync-theme.sh, enforced by
# scripts/check-vendored-theme.sh. frontend-next/public/static/theme.css
# must stay byte-identical to theme.css at this commit.
repository=$repository
commit=$commit
date=$date
sha256=$sha256
EOF

echo "vendored Xore/theme@${commit:0:7} ($date)"
echo
echo "Next:"
echo "  1. npm --prefix arcane/home/honeypot-dashboard/frontend-next run typecheck && npm --prefix arcane/home/honeypot-dashboard/frontend-next run build"
echo "  2. review the theme changelog for token or component changes"
