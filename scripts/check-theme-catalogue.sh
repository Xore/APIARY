#!/usr/bin/env bash
# Keep the theme catalogue and the vendored stylesheet in step.
#
# #1758: the same nine names lived in four hardcoded lists across two
# repositories. Two of them are in theme.css, which this repo vendors
# byte-for-byte and cannot edit, so a theme added upstream and not added here
# is invisible in the picker, and a theme listed here with no block upstream
# renders as the default with no indication anything is wrong. Neither fails
# a build.
#
# The stylesheet owns the tokens. This owns the catalogue. This checks they
# describe the same set.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$root/arcane/home/honeypot-dashboard/frontend-next/src/lib/themes.ts"
css="$root/arcane/home/honeypot-dashboard/frontend-next/public/static/theme.css"

[ -f "$manifest" ] || { echo "missing $manifest" >&2; exit 1; }
[ -f "$css" ] || { echo "missing $css" >&2; exit 1; }

# Ids declared in the manifest: `{ id: 'slate', …`
listed="$(grep -oE "id: '[a-z][a-z0-9-]*'" "$manifest" | sed -E "s/id: '(.*)'/\1/" | sort -u)"

# Ids the stylesheet defines a theme block for.
declared="$(grep -oE '\[data-hp-theme="[a-z][a-z0-9-]*"\]' "$css" \
  | sed -E 's/.*"([^"]+)".*/\1/' | sort -u)"

missing_css="$(comm -23 <(echo "$listed") <(echo "$declared"))"
missing_manifest="$(comm -13 <(echo "$listed") <(echo "$declared"))"

status=0
if [ -n "$missing_css" ]; then
  echo "these themes are in the catalogue but have no block in theme.css:" >&2
  echo "$missing_css" | sed 's/^/    /' >&2
  echo "  they would render as the default, silently." >&2
  status=1
fi
if [ -n "$missing_manifest" ]; then
  echo "these themes exist in theme.css but are not in the catalogue:" >&2
  echo "$missing_manifest" | sed 's/^/    /' >&2
  echo "  they cannot be picked, and settings search will not find them." >&2
  status=1
fi

[ "$status" -eq 0 ] || exit 1

count="$(echo "$listed" | grep -c . || true)"
echo "theme catalogue ok: $count themes, and theme.css defines a block for each"
