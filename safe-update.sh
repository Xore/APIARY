#!/usr/bin/env bash
set -euo pipefail

# #267: nothing in this repo's deploy path takes a snapshot before mutating
# anything. Per docs/CI-CD.md, home deployment does `docker compose up -d
# --build` on every push -- if a bad deploy needs rolling back, or `.env`/
# config drift needs to be diffed against what was actually running, there
# is nothing to compare against except `git log` archaeology after the fact.
#
# This is the lightweight "about to deploy, keep a snapshot in case this is
# bad" step -- read-only, no stack stop/wipe/restart, safe to run before any
# deploy (manual or CI). Complements factory-reset.sh (#262), which is the
# heavier "stack is already broken, nuke and restart clean" path -- that one
# stops stacks and can wipe state; this one only ever reads and copies.
#
# Usage:
#   ./safe-update.sh                # snapshot only, prints the rollback command
#   ./safe-update.sh --snapshot-dir <dir>

STACK_DIR="${STACK_DIR:-/opt/stacks/honeypot-stack}"
snapshot_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --snapshot-dir) snapshot_dir="${2:?--snapshot-dir requires a value}"; shift 2 ;;
    -h|--help)
      sed -n '4,17p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "$STACK_DIR" ]]; then
  echo "STACK_DIR does not exist: $STACK_DIR" >&2
  exit 1
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
[[ -n "$snapshot_dir" ]] || snapshot_dir="$STACK_DIR/state/deploy-snapshots/$stamp"

log() { printf '[safe-update] %s\n' "$*"; }

mkdir -p "$snapshot_dir"

log "recording current git state"
git -C "$STACK_DIR" rev-parse HEAD > "$snapshot_dir/git-head-sha.txt"
git -C "$STACK_DIR" status --short > "$snapshot_dir/git-status.txt" || true
# Uncommitted changes to files git already tracks -- config drift a plain
# commit SHA wouldn't reveal (e.g. a hand-edited compose file that was
# never committed). Untracked drift (.env, per-stack config not in git)
# is captured separately below since `git diff` can't see it at all.
git -C "$STACK_DIR" diff > "$snapshot_dir/git-diff-tracked.patch" || true

log "backing up .env files (not .env.example)"
mkdir -p "$snapshot_dir/env"
find "$STACK_DIR" -maxdepth 3 -name "*.env" -not -name "*.env.example" -print0 2>/dev/null |
  while IFS= read -r -d '' env_file; do
    rel="${env_file#"$STACK_DIR"/}"
    dest="$snapshot_dir/env/${rel//\//__}"
    cp -p "$env_file" "$dest"
    log "  $rel -> ${dest#"$snapshot_dir"/}"
  done

chmod -R go-rwx "$snapshot_dir"

log "snapshot complete: $snapshot_dir"
log ""
log "rollback path if the next deploy goes bad:"
log "  git -C '$STACK_DIR' checkout \$(cat '$snapshot_dir/git-head-sha.txt')"
log "  # restore any .env drift you actually want back from $snapshot_dir/env/"
log "  # then redeploy each affected stack: docker compose -f compose.yml up -d --build"
