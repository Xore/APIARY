#!/usr/bin/env bash
# mirror-benchmark-workarea.sh -- #3104: /mnt-1/benchmarks on homeserver has
# no durable copy. The existing snapshot at ~/apiary-bench-snapshots/ was
# built by hand and has gone stale (its own notes still called this host
# "xps13" / 192.168.42.15 -- that machine is retired; this workstation is
# "hermes", 192.168.42.253).
#
# Pull-only, by necessity: SSH homeserver -> hermes has no key installed
# (Permission denied, publickey) and #2985 already lost operational scripts
# once to an un-backed-up work area -- this must run FROM hermes, not be
# pushed from homeserver.
#
# Deliberately separate from scripts/backup-essentials.sh: that script backs
# up secrets/config already local to this workstation and fans out to three
# destinations by design; this pulls bulk-ish (tens of MB) data from a
# second host and has nothing to fan out to a USB drive for. Folding the two
# together would change backup-essentials' contract for a use case it wasn't
# built for.
#
# Excludes exactly the directories confirmed >1 GB and reproducible without
# this mirror: the two pinned git checkouts (clone + pin from the commit
# their own STATE-*.md records) and the three model-weight caches (re-pullable
# via ollama). Everything else under /mnt-1/benchmarks -- scripts, rosters,
# logs, result JSON, status markers, transcripts -- is the irreplaceable part
# #2985 already lost once, and is small enough (double-digit MB) to keep in
# full.
#
# Usage:
#   scripts/mirror-benchmark-workarea.sh            # pull and report
#   scripts/mirror-benchmark-workarea.sh --dry-run  # show what would transfer
set -euo pipefail

DEST=${DEST:-"$HOME/apiary-bench-snapshots/homeserver-workarea/"}
SRC_HOST=${SRC_HOST:-homeserver}
SRC=${SRC:-/var/benchmarks/}

EXCLUDES=(
  --exclude=APIARY/
  --exclude=APIARY-round7/
  --exclude=f16work/
  --exclude=oversized-model-cache/
  --exclude=local-gguf/
)

mkdir -p "$DEST"
rsync -az --info=stats2 "${EXCLUDES[@]}" "$@" "${SRC_HOST}:${SRC}" "$DEST"
