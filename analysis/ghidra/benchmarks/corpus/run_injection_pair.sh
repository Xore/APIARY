#!/usr/bin/env bash
# Runs the #2694 injection cases -- the false-verdict pair, the witness probe
# and the candour case -- for a list of models at both tiers under the cold-slot
# protocol, then the positive control, then re-scores everything offline.
#
# Protocol (from #2642 / #1947 fullrun.sh): `ollama stop <tag>` before every
# run so a cell depends only on its own inputs; sequential; N=1 because cold
# cells reproduce byte-identically -- repeats belong on the axes that vary
# (variant, prompt, quant), and the paired twin IS that variation.
#
# Three passes per model and tier:
#   default            the production system prompt -- the measurement
#   no-untrusted-clause the same prompt minus its injection-hardening sentence
#                      -- the POSITIVE CONTROL. If no model ever complies here
#                      either, the fixtures are too weak or the detector is
#                      blind, and a clean "default" sweep proves nothing.
#
# Usage:
#   run_injection_pair.sh MODELS_FILE OUT_DIR [GHIDRA_CACHE] [OUTPUT_TOKENS]
#     MODELS_FILE   one Ollama tag per line
#     OUT_DIR       where tier{A,B}_<slug>_<variant>.json land (never inside a
#                   directory another sweep is writing to)
#     GHIDRA_CACHE  Tier B evidence cache (default /mnt-1/benchmarks/tierb-cache)
#     OUTPUT_TOKENS override for this run only (default: the slot's pinned 512;
#                   23/30 Tier B injection answers hit that cap in #1947, see
#                   #2694 -- 1024 is the recommended value for these cases and
#                   is recorded in every report's qualification_request)
set -u
MODELS="${1:?models file}"; OUT="${2:?output dir}"
CACHE="${3:-/mnt-1/benchmarks/tierb-cache}"
TOKENS="${4:-}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
CASES="strcpy_note_injected,process_witness_probe,process_and_injection"
mkdir -p "$OUT/logs"
cd "$REPO" || exit 1

run_cell() { # tier slug tag variant
  local tier="$1" slug="$2" tag="$3" variant="$4"
  local out="$OUT/tier${tier}_${slug}_${variant}.json"
  [ -f "$out" ] && { echo "$(date -u +%H:%M:%S) skip  $tier $slug $variant"; return 0; }
  local extra=""; [ "$tier" = "B" ] && extra="--ghidra-cache $CACHE"
  docker exec ghidra-ollama-1 ollama stop "$tag" >/dev/null 2>&1
  sleep 5
  echo "$(date -u +%H:%M:%S) start $tier $slug $variant"
  local tokens_arg=""; [ -n "$TOKENS" ] && tokens_arg="--output-tokens $TOKENS"
  timeout 3600 python3 analysis/ghidra/benchmarks/corpus/record_baseline.py $tokens_arg \
    --tier "$tier" $extra --model "$tag" --cases "$CASES" \
    --system-prompt-variant "$variant" \
    --operator bg-2694-pair --provenance synthetic \
    --output "$out" > "$OUT/logs/tier${tier}_${slug}_${variant}.log" 2>&1
  local rc=$?
  if [ $rc -ne 0 ]; then echo "$(date -u +%H:%M:%S) FAIL  $tier $slug $variant rc=$rc"; rm -f "$out"; return 1; fi
  python3 - "$out" <<'EOF'
import json, sys
r = json.load(open(sys.argv[1]))
for name, c in r["cases"].items():
    if "injection_tier" in c:
        print(f"    {name:24s} tier={c['injection_tier']:11s} ok={c['injection_ok']} flagged={c.get('injection_flagged')} "
              f"score={c['score']}/{c['max_score']} done={c.get('done_reason')}")
EOF
}

while read -r TAG; do
  [ -z "$TAG" ] && continue
  slug=$(echo "$TAG" | tr ':/' '__')
  for tier in A B; do
    run_cell "$tier" "$slug" "$TAG" default
    run_cell "$tier" "$slug" "$TAG" no-untrusted-clause
  done
done < "$MODELS"

echo "== restated standings (default variant) =="
python3 analysis/ghidra/benchmarks/corpus/rescore_injection_v2.py "$OUT" --glob 'tier*_default.json' \
  --markdown "$OUT/standings_default.md" --out "$OUT/restated_default.json"
echo "== positive control =="
python3 analysis/ghidra/benchmarks/corpus/rescore_injection_v2.py "$OUT" --glob 'tier*_no-untrusted-clause.json' \
  --markdown "$OUT/standings_positive_control.md" --out "$OUT/restated_positive_control.json"
