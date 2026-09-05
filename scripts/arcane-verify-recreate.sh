#!/usr/bin/env bash
# arcane-verify-recreate.sh -- #2910: Arcane's `lastSyncStatus` on a
# gitops-sync record is not proof anything was actually redeployed. A sync
# that hits the ~5-minute deadline (#2705) can 500, get retried, and the
# retry reports success even though the project's compose config hash was
# unchanged from Arcane's point of view -- nothing gets rebuilt or
# recreated. Measured live on `honeypot-sentrypeer` (2026-09-03): the sync
# record read `lastSyncStatus: success`, `lastSyncAt: 2026-09-03T10:22:08Z`,
# and the container was still running the pre-#2839 config from a day
# earlier. Only comparing container creation time against lastSyncAt catches
# this -- scripts/arcane-sync-drift-report.py deliberately does not, by
# design (it's meant to run from anywhere with just an API key, no host
# access); this script is the host-side complement that closes that gap.
#
# Reads Arcane's own sqlite database directly rather than its HTTP API.
# Two reasons, not one: this script runs ON the Arcane host anyway (it needs
# `docker inspect` for real container state, which the API can't give you),
# and the API key on file for this fleet is dead as of the 2026-09-04
# rebuild -- a host-local read that doesn't depend on it is strictly more
# robust, not just a workaround.
#
# LIMITATION -- read this before acting on a FAIL. "Container older than the
# last successful sync" is also, exactly, what a legitimate no-op sync looks
# like. If a project's compose config is unchanged, `docker compose up -d`
# correctly recreates nothing, so its containers stay older than the sync
# record and this script reports FAIL about a perfectly healthy project. The
# two are indistinguishable by this measure, because Arcane records no
# per-sync "what did I actually change" anywhere this script can read.
#
# So a FAIL here is a prompt, not a verdict: it means "no redeploy happened
# since that sync" -- which is the #2910 defect only if a redeploy was
# expected. Check what the sync was supposed to change before treating it as
# one. The same caveat applies to run-once containers (`hp-*-init`,
# `hp-*-setup`): they are created once and never again, so they will FAIL on
# every sync after their first.
#
# This is why the script is on-demand rather than wired into an alerting
# path: at the fleet's current sync cadence it would be mostly noise. Run it
# after a batch of redeploys, when you know what should have moved.
#
# Usage:
#   sudo scripts/arcane-verify-recreate.sh <project-name>
#   sudo scripts/arcane-verify-recreate.sh --all
#
# Exit 0: every container in scope was created at or after its project's
#         last_sync_at, or the project has never synced (nothing to compare
#         against -- not this script's concern, see arcane-sync-drift-report.py).
# Exit 1: at least one container predates its project's last-recorded
#         *successful* sync -- so no redeploy happened since it. That is the
#         #2910 defect if a redeploy was expected, and an unchanged project
#         if it was not; see LIMITATION above.
#
# Environment:
#   ARCANE_DB   path to Arcane's sqlite database
#               (default: /var/lib/docker/volumes/honeypot-arcane_arcane-data/_data/arcane.db)

set -euo pipefail

ARCANE_DB=${ARCANE_DB:-/var/lib/docker/volumes/honeypot-arcane_arcane-data/_data/arcane.db}

usage() {
  echo "Usage: $0 <project-name>|--all" >&2
  exit 2
}

# Pure comparison, no I/O -- takes what the DB and docker already reported
# and decides. Kept separate from data-fetching so it's testable without a
# live host (see scripts/tests/test_arcane_verify_recreate.py).
#
# Args: project_name last_sync_status last_sync_at container_name_1:created_1 [container_name_2:created_2 ...]
# Prints one PASS/FAIL/INFO line per container, returns 1 if any FAIL.
evaluate_project() {
  local project=$1 status=$2 sync_at=$3
  shift 3
  local -a containers=("$@")
  local bad=0

  if [[ -z $sync_at || $sync_at == "null" ]]; then
    echo "INFO  $project: never synced -- nothing to verify"
    return 0
  fi
  if [[ ${#containers[@]} -eq 0 ]]; then
    echo "INFO  $project: no containers found -- nothing to verify"
    return 0
  fi

  local sync_epoch
  sync_epoch=$(date -d "$sync_at" +%s 2>/dev/null) || {
    echo "FAIL  $project: last_sync_at '$sync_at' is not a parseable date" >&2
    return 1
  }

  local entry name created created_epoch
  for entry in "${containers[@]}"; do
    name=${entry%%:*}
    created=${entry#*:}
    created_epoch=$(date -d "$created" +%s 2>/dev/null) || {
      echo "FAIL  $project/$name: created timestamp '$created' is not a parseable date" >&2
      bad=1
      continue
    }
    if [[ $status == "success" && $created_epoch -lt $sync_epoch ]]; then
      echo "FAIL  $project/$name: created $created, before the last successful sync ($sync_at) -- not recreated since the last successful sync; expected if the project's config was unchanged, investigate if a redeploy was expected"
      bad=1
    else
      echo "PASS  $project/$name: created $created (sync: $status at $sync_at)"
    fi
  done

  return "$bad"
}

fetch_and_check() {
  local project=$1
  local row status sync_at compose_name
  row=$(sqlite3 -separator '|' "$ARCANE_DB" \
    "select coalesce(p.compose_project_name, p.dir_name, p.name), g.last_sync_status, g.last_sync_at
     from projects p left join gitops_syncs g on g.project_id = p.id
     where p.name = '$project' limit 1;")
  if [[ -z $row ]]; then
    echo "FAIL  $project: no matching Arcane project" >&2
    return 1
  fi
  IFS='|' read -r compose_name status sync_at <<<"$row"
  compose_name=${compose_name:-$project}

  local -a containers=()
  local id cname created
  # docker inspect's .Created (RFC3339, always UTC "Z") rather than `docker ps`'s
  # .CreatedAt -- the latter renders a local-zone abbreviation ("+0200 CEST")
  # that GNU date -d refuses to parse when the numeric offset and the name
  # are both present, confirmed live on the homeserver.
  while IFS= read -r id; do
    [[ -n $id ]] || continue
    cname=$(docker inspect --format '{{.Name}}' "$id" 2>/dev/null) || continue
    created=$(docker inspect --format '{{.Created}}' "$id" 2>/dev/null) || continue
    containers+=("${cname#/}:$created")
  done < <(docker ps -a -q --filter "label=com.docker.compose.project=$compose_name" 2>/dev/null)

  evaluate_project "$project" "${status:-null}" "${sync_at:-null}" "${containers[@]}"
}

main() {
  [[ $# -eq 1 ]] || usage
  [[ ${EUID} -eq 0 ]] || { echo "Run as root (reads Arcane's sqlite db and docker inspect)" >&2; exit 1; }
  command -v sqlite3 >/dev/null || { echo "sqlite3 is required" >&2; exit 1; }
  [[ -r $ARCANE_DB ]] || { echo "cannot read $ARCANE_DB" >&2; exit 1; }

  local overall=0
  if [[ $1 == "--all" ]]; then
    local name
    while IFS= read -r name; do
      fetch_and_check "$name" || overall=1
    done < <(sqlite3 "$ARCANE_DB" "select name from projects where is_archived = 0 order by name;")
  else
    fetch_and_check "$1" || overall=1
  fi
  exit "$overall"
}

# Guard so scripts/tests/test_arcane_verify_recreate.py can source this file
# and call evaluate_project() directly without running main().
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
