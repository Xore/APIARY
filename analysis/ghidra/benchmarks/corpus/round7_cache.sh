#!/usr/bin/env bash
# round7_cache.sh -- regenerate the Tier B (Ghidra decompilation) cache for the
# round-7 pin's 17-case corpus, into its OWN directory. The 14-case cache at
# /var/benchmarks/tierb-cache stays for the a99e765 clone.
#
# Operational copy lives at /var/benchmarks/round7_cache.sh.
#
# GHIDRA_VERSION must be exported by hand because the headless service
# publishes no version of its own (#2983); the line printed first is the
# container's own application.properties so the two can be compared.
set -euo pipefail
BASE=${BASE:-/var/benchmarks}
REPO=${REPO:-$BASE/APIARY-round7}
CORPUS=${CORPUS:-$BASE/corpus-round7}
CACHE=${CACHE:-$BASE/tierb-cache-round7}
export GHIDRA_VERSION=${GHIDRA_VERSION:-11.3.2}
docker exec ghidra-ghidra-1 grep ^application.version /opt/ghidra/Ghidra/application.properties
[ -f "$CORPUS/manifest.json" ] || { echo "ABORT: $CORPUS has no manifest.json -- run round7_build_corpus.sh first"; exit 1; }
cd "$REPO"
PYTHONDONTWRITEBYTECODE=1 python3 analysis/ghidra/benchmarks/ghidra_cache.py \
  --corpus "$CORPUS" --cache "$CACHE" --service http://127.0.0.1:9090 2>&1 | tail -25
echo "cache entries: $(ls "$CACHE"/*.json | grep -vc index.json)"
