#!/usr/bin/env bash
# #2256: the vendored GHOSTS config (sandbox/ghosts/vendor/ghosts-src/) must
# never ship a resolvable third-party domain — CMU's upstream sample config
# defaults to posting NPC content to a real internet domain and pushing a
# visible-browser timeline to the enrolled Windows guest, and several
# unreferenced sample timeline files carried more of the same. #2256's fix
# removed every one found at the time; this check keeps a future vendor bump
# (or a hand-edit) from silently reintroducing one.
#
# Scope: *.json under appsettings*.json and the two config/ trees actually
# baked into the ghosts-api / ghosts-client-test images -- handler timelines,
# health checks, and the animator settings, i.e. files that hold an actual
# dial target (PostUrl, a handler's CommandArgs, health.json's CheckUrls).
# Deliberately excludes .csv/.txt content-library files (blog-content.csv,
# email-content.csv, user-agents/*.txt, ...): these are bulk filler TEXT
# BODIES a handler posts/pastes, not URLs the code fetches, so they
# legitimately contain arbitrary embedded links as part of their content
# without that being an egress target. Everything else under vendor/
# (source, tests, unrelated data files) is out of scope — this is an egress
# check, not a general vendored-tree linter.
#
# Usage: scripts/check-ghosts-vendored-egress.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vendor="$root/sandbox/ghosts/vendor/ghosts-src"

targets=(
  "$vendor/Ghosts.Api/appsettings.json"
  "$vendor/Ghosts.Api/config"
  "$vendor/Ghosts.Client.Universal/config"
)

for t in "${targets[@]}"; do
  [ -e "$t" ] || { echo "missing $t -- vendored tree layout changed, update this script" >&2; exit 1; }
done

# Each entry is a file (repo-relative path) allowed to carry a URL, plus the
# one-line reason it's safe. Every allowance must be a real, checked-in fact
# about that specific file -- not a blanket directory exemption -- so a new
# file with a new domain still trips the check.
declare -A ALLOWED_FILES=(
  ["sandbox/ghosts/vendor/ghosts-src/Ghosts.Api/config/chat.json"]="localhost-only (Mattermost ContentEngine, inert while AnimatorSettings.Animations.IsEnabled=false)"
  ["sandbox/ghosts/vendor/ghosts-src/Ghosts.Api/config/military_mos.json"]="Wikipedia citation-link VALUES read locally by Ghosts.Animator/MilitaryRanks.cs and stored into generated profile data -- never fetched by our code (see VENDORED.md)"
  ["sandbox/ghosts/vendor/ghosts-src/Ghosts.Client.Universal/config/application.json"]="ApiRootUrl points at the compose-internal ghosts-api service name, not a public host"
  ["sandbox/ghosts/vendor/ghosts-src/Ghosts.Api/config/SeedData/seed.json"]="fictional blue-team exercise records (.atropia.mil/.redcell.local decoy domains plus MITRE/VirusTotal citation-link values in narrative text) -- database seed data read once at startup, never dispatched anywhere; explicitly out of scope for #2256's cleanup"
)

fail=0
while IFS=: read -r file rest; do
  repo_rel="${file#"$root"/}"
  # Any URL host we don't recognise as compose-internal or localhost.
  if grep -qE 'https?://(localhost|ghosts-api|ghosts-postgres)([:/]|$)' <<<"$rest"; then
    continue
  fi
  if [ -n "${ALLOWED_FILES[$repo_rel]+x}" ]; then
    continue
  fi
  echo "::error file=$repo_rel::resolvable third-party URL in vendored GHOSTS config: $rest" >&2
  echo "  $repo_rel: $rest" >&2
  fail=1
done < <(grep -rnE --include='*.json' 'https?://' "${targets[@]}" 2>/dev/null || true)

if [ "$fail" -ne 0 ]; then
  echo "" >&2
  echo "A resolvable third-party domain was found in vendored GHOSTS config." >&2
  echo "Either remove it (preferred, see VENDORED.md's #2256 section for the" >&2
  echo "precedent) or add it to ALLOWED_FILES in this script with a specific," >&2
  echo "checked reason -- not a blanket exemption." >&2
  exit 1
fi

echo "ok: no resolvable third-party domains in vendored GHOSTS config"
