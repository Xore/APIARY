#!/usr/bin/env bash
# coldprobe.sh -- #3023: did llm-worker contention move phase-2 scores, or only
# wall clock?
#
# Phase 2 ran without the cold-slot protocol's worker-stop step, so 36 of its 52
# models were measured while hp-llm-worker issued a competing /api/chat every
# ~4 minutes against the same OLLAMA_MAX_LOADED_MODELS=1 slot. Phase 2 shows 12
# escalations; phase 4's cold cells were +-0 across three runs on four
# architectures. That is suggestive, not proof -- so measure it instead of
# arguing about it.
#
# Two models, both ALREADY measured and both still local (no pull, no delete):
#
#   DeepHat-V1-7B:Q4_K_M   4.7 GB, fully GPU-resident   stored A=[63,63]
#     -> the control. A resident model has no CPU-offload nondeterminism, so if
#        its cold score differs from its contended one, contention moved scores
#        and phase 2 needs re-running.
#
#   ravenx-cyberagent-35b:Q4_K_M   21 GB, spills to CPU   stored B=[64,63,64]
#     -> the escalated cell. If cold gives three identical values the escalation
#        was contention; if it still disagrees the nondeterminism is intrinsic to
#        spilling (float reduction order across threads), which would exonerate
#        phase 2 rather than condemn it.
#
# Results go to a SEPARATE directory so no roster row is polluted, and the
# stored phase-2 files are never touched.
#
# Preconditions this asserts rather than assumes: hp-llm-worker down,
# sweep_extra.sh not running, no record_baseline in flight.
set -u
REPO=/mnt-1/benchmarks/APIARY
OUT=/mnt-1/benchmarks/coldprobe
CACHE=/mnt-1/benchmarks/tierb-cache
mkdir -p "$OUT/logs"

die() { echo "ABORT: $*" >&2; exit 1; }

pgrep -f "sweep_extra.sh"     >/dev/null && die "sweep_extra.sh is running -- stop it between models first"
pgrep -f "record_baseline.py" >/dev/null && die "a record_baseline run is in flight"
docker ps --format '{{.Names}}' | grep -qx hp-llm-worker && die "hp-llm-worker is up -- this probe measures its absence"
[ -d "$CACHE" ] || die "tierb-cache missing"
head=$(git -C "$REPO" rev-parse --short HEAD)
[ "$head" = "a99e765" ] || die "repo head is $head, not a99e765 -- wrong scoring vintage"

cd "$REPO" || die "no repo"

run() { # tier tag slug n
  local tier="$1" tag="$2" slug="$3" n="$4"
  local out="$OUT/cold_tier${tier}_${slug}_run${n}.json"
  [ -f "$out" ] && { echo "skip $tier $slug run$n (present)"; return 0; }
  local extra=""; [ "$tier" = "B" ] && extra="--ghidra-cache $CACHE"
  docker exec ghidra-ollama-1 ollama stop "$tag" >/dev/null 2>&1   # cold every run
  sleep 5
  echo "$(date -u +%H:%M:%S) start $tier $slug run$n  (load $(cut -d' ' -f1 /proc/loadavg))"
  timeout 10800 python3 analysis/ghidra/benchmarks/corpus/record_baseline.py \
    --tier "$tier" $extra --model "$tag" \
    --operator coldprobe-3023 --provenance synthetic \
    --output "$out" > "$OUT/logs/cold_tier${tier}_${slug}_run${n}.log" 2>&1
  local rc=$?
  if [ $rc -eq 0 ] && [ -f "$out" ]; then
    echo "$(date -u +%H:%M:%S) done  $tier $slug run$n score=$(python3 -c "import json;print(json.load(open('$out'))['total_score'])")"
  else
    echo "$(date -u +%H:%M:%S) FAIL  $tier $slug run$n rc=$rc"
    rm -f "$out"
  fi
}

echo "=== $(date -u +%FT%TZ) COLDPROBE_START head=$head ==="

# control: fully resident, stored Tier A = [63, 63]
run A 'hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M' 'deephat_7b' 1
run A 'hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M' 'deephat_7b' 2

# the escalated cell: spills to CPU, stored Tier B = [64, 63, 64]
run B 'ravenx-cyberagent-35b:Q4_K_M' 'ravenx35b' 1
run B 'ravenx-cyberagent-35b:Q4_K_M' 'ravenx35b' 2
run B 'ravenx-cyberagent-35b:Q4_K_M' 'ravenx35b' 3

echo
echo "=== verdict inputs ==="
printf 'deephat_7b   TierA  contended=[63,63]     cold=['
for n in 1 2; do f="$OUT/cold_tierA_deephat_7b_run${n}.json"; [ -f "$f" ] && printf '%s,' "$(python3 -c "import json;print(json.load(open('$f'))['total_score'])")"; done
printf ']\n'
printf 'ravenx35b    TierB  contended=[64,63,64]  cold=['
for n in 1 2 3; do f="$OUT/cold_tierB_ravenx35b_run${n}.json"; [ -f "$f" ] && printf '%s,' "$(python3 -c "import json;print(json.load(open('$f'))['total_score'])")"; done
printf ']\n'
echo "=== $(date -u +%FT%TZ) COLDPROBE_COMPLETE ==="
