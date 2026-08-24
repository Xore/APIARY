#!/usr/bin/env bash
# Fail when frontend code references a CSS custom property the vendored
# stylesheet no longer defines.
#
# Why this exists: canvas-rendered surfaces (ECharts, the cytoscape graphs,
# xterm) cannot use var() -- they resolve a token to a pixel value through
# getComputedStyle and paint it. Every one of those call sites carries a
# hardcoded fallback for the SSR case, and those fallbacks are dark-theme
# literals.
#
# So a token rename upstream does not break the build and does not throw. It
# silently switches every affected chart to a dark colour, in every theme,
# and the page still renders. That happened for real in #1825: Xore/theme#104
# renamed the surface, border and text tokens to numbered ramps, and 31
# references across four files quietly started painting dark surfaces onto
# light cards.
#
# A missing token is a rename that has not been followed. Fail loudly.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="$root/arcane/home/honeypot-dashboard/frontend-next/src"
css="$root/arcane/home/honeypot-dashboard/frontend-next/public/static/theme.css"

[ -d "$src" ] || { echo "missing $src" >&2; exit 1; }
[ -f "$css" ] || { echo "missing $css" >&2; exit 1; }

missing=0
# Only tokens the code actually reaches for: var(--x), '--x' or "--x".
# A bare match would sweep up comment prose and CSS-in-JS custom properties
# the component defines for itself.
while read -r token; do
  [ -n "$token" ] || continue
  if ! grep -qE "^[[:space:]]*${token}:" "$css"; then
    echo "theme token $token is referenced but not defined in the vendored theme.css:" >&2
    grep -rn --include='*.ts' --include='*.tsx' -- "$token" "$src" | head -5 | sed 's/^/    /' >&2
    missing=$((missing + 1))
  fi
done < <(
  grep -rhoE "(var\(--[a-z][a-z0-9-]{2,}|'--[a-z][a-z0-9-]{2,}'|\"--[a-z][a-z0-9-]{2,}\")" \
    "$src" --include=*.ts --include=*.tsx 2>/dev/null \
  | sed -E "s/^var\(//; s/^['\"]//; s/['\"]$//" \
  | sort -u
)

if [ "$missing" -gt 0 ]; then
  echo "" >&2
  echo "$missing token(s) missing. If Xore/theme renamed them, follow the rename" >&2
  echo "in the frontend rather than leaving the hardcoded fallbacks to take over." >&2
  exit 1
fi

echo "theme tokens ok: every custom property referenced from frontend-next exists in theme.css"
