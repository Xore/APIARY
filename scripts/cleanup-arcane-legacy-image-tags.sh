#!/usr/bin/env bash
# cleanup-arcane-legacy-image-tags.sh — #2235: Arcane's hourly image-update-
# check reports permanent errors for two classes of local-only image tags it
# mistakes for pullable remote refs:
#
#   1. arcane.local/<project>-<hash8>/<svc>:latest — Arcane's own legacy
#      build-tag namespace. arcane.local has no DNS entry on the host, so
#      any resolve attempt fails outright. Most of these are orphaned
#      residue from historic builds: no container references them, and they
#      point at image IDs that differ from the current build.
#   2. Unqualified local build/debug tags (zeek81-patched, apiary-probe:1,
#      etc.) that Arcane's local-build detection doesn't recognize because
#      they aren't compose-default-named images of an imported project, so
#      it defaults them to docker.io/library/<name> and gets "denied".
#
# This script removes the tags in both classes that no container (running
# or stopped) still references — safe by construction, since deleting a tag
# no container points at cannot break anything running. Tags a container
# does reference are left alone and reported for a manual redeploy instead
# (e.g. honeypot-ghidra's two live containers, tracked separately in #2235).
#
# Read-only by default; pass --apply to actually remove tags.
set -euo pipefail

DRY_RUN=1
for arg in "$@"; do
  case "$arg" in
    --apply) DRY_RUN=0 ;;
    --dry-run) DRY_RUN=1 ;;
    *)
      echo "usage: $0 [--apply|--dry-run]" >&2
      exit 2
      ;;
  esac
done

# Ad-hoc debug/test builds named in #2235 that fall outside Arcane's
# compose-project-import detection. Extend this list as new one-off local
# builds accumulate — it is not meant to be exhaustive forever, just to
# retire the known offenders without deleting anything not on it.
STALE_LOCAL_TAGS=(
  "zeek81-patched"
  "zeek81-unpatched"
  "zeek-1821-test"
  "xore-zeek:local"
  "apiary-probe:1"
  "apiary-ip-enrichment-worker"
  "ghidra-revdeck"
  "fake-ollama-test:local"
  "galah-llm-broker-test:local"
  "canarytokens-full-test-canarytokens-adapter"
)

is_referenced_by_a_container() {
  local ref="$1"
  [[ -n "$(docker ps -a --filter "ancestor=${ref}" --format '{{.ID}}')" ]]
}

candidate_tags() {
  local all
  all="$(docker image ls --format '{{.Repository}}:{{.Tag}}')"
  grep -E '^arcane\.local/' <<<"$all" || true
  local tag
  for tag in "${STALE_LOCAL_TAGS[@]}"; do
    if [[ "$tag" == *:* ]]; then
      grep -xF "$tag" <<<"$all" || true
    else
      grep -xF "${tag}:latest" <<<"$all" || true
    fi
  done
}

removed=0
skipped_in_use=0

while IFS= read -r ref; do
  [[ -z "$ref" ]] && continue
  if is_referenced_by_a_container "$ref"; then
    echo "SKIP (in use, redeploy the owning stack first): ${ref}"
    skipped_in_use=$((skipped_in_use + 1))
    continue
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "WOULD REMOVE: ${ref}"
  else
    echo "REMOVE: ${ref}"
    docker rmi "$ref"
  fi
  removed=$((removed + 1))
done < <(candidate_tags | sort -u)

echo
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "dry-run: ${removed} tag(s) would be removed, ${skipped_in_use} still in use (rerun with --apply)"
else
  echo "removed ${removed} tag(s), ${skipped_in_use} left in place (still in use)"
fi
