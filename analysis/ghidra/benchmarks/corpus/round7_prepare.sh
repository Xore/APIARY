#!/usr/bin/env bash
# round7_prepare.sh -- everything round 7 needs before its first GPU minute,
# in dependency order, each step resume-safe:
#   1. round7_prep_pin.sh      pinned checkout, detached at the round-7 pin
#   2. round7_build_corpus.sh  17-case corpus rebuilt in the provenance container,
#                              verified byte-for-byte against the pinned manifest
#   3. round7_cache.sh         17-case Tier B (Ghidra) cache in its own directory
# Then run round7_smoke.sh, read its two lines, and only then round7_launch.sh.
#
# Operational copy lives at /mnt-1/benchmarks/round7_prepare.sh.
set -euo pipefail
BASE=${BASE:-/mnt-1/benchmarks}
log() { echo "$(date -u +%FT%TZ) $*"; }
log "step 1/3 pin"
bash "$BASE/round7_prep_pin.sh"
if [ -f "$BASE/corpus-round7/manifest.json" ] && diff -q "$BASE/corpus-round7/manifest.json" \
     "$BASE/APIARY-round7/analysis/ghidra/benchmarks/corpus/manifest.json" >/dev/null 2>&1; then
  log "step 2/3 corpus already built and identical to the pinned manifest -- skipping"
else
  log "step 2/3 corpus (apt + 850 builds in debian:trixie-slim)"
  bash "$BASE/round7_build_corpus.sh"
fi
log "step 3/3 Tier B cache"
bash "$BASE/round7_cache.sh"
log "ROUND7_PREPARED -- next: bash $BASE/round7_smoke.sh"
