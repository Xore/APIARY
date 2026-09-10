#!/usr/bin/env bash
# round7_smoke.sh -- prove the round-7 benchmark LEG scores on the new pin
# before the roster is launched (#1947 rule 7: verify the benchmark leg, not
# the pull). One Tier A and one Tier B run of a small local model into a
# separate directory that no results glob reads.
#
# Operational copy lives at /var/benchmarks/round7_smoke.sh.
set -u
BASE=${BASE:-/var/benchmarks}
REPO=${REPO:-$BASE/APIARY-round7}
OUT=${OUT:-$BASE/smoke-round7}
CACHE=${CACHE:-$BASE/tierb-cache-round7}
TAG=${TAG:-qwen2.5:7b-instruct-q4_K_M}
mkdir -p "$OUT"
cd "$REPO" || exit 1
for tier in A B; do
  extra=""; [ "$tier" = "B" ] && extra="--ghidra-cache $CACHE"
  docker exec ghidra-ollama-1 ollama stop "$TAG" >/dev/null 2>&1
  timeout 3600 python3 analysis/ghidra/benchmarks/corpus/record_baseline.py \
    --tier "$tier" $extra --model "$TAG" --operator smoke-round7 --provenance synthetic \
    --output "$OUT/tier${tier}_smoke.json" > "$OUT/tier${tier}.log" 2>&1
  rc=$?
  summary=$(python3 - "$OUT/tier${tier}_smoke.json" <<'PY' 2>&1
import json, sys
d = json.load(open(sys.argv[1]))
cases = d["cases"]
empty = sum(1 for c in cases.values() if c.get("empty_answer"))
print(f"score {d['total_score']}/{d['total_max_score']} cases {d['case_count']} empty_answers {empty} digest {d.get('model_digest','?')[:12]}")
PY
)
  echo "$(date -u +%FT%TZ) tier $tier rc=$rc $summary"
done
docker exec ghidra-ollama-1 ollama stop "$TAG" >/dev/null 2>&1
echo "transcript runs in the round-7 clone: $(ls "$REPO/docs/benchmarks/runs" 2>/dev/null | wc -l)"
