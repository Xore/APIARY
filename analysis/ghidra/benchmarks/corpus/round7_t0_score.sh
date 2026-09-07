#!/usr/bin/env bash
# round7_t0_score.sh -- T0 scoring leg (#3081): record_baseline.py --tier A and
# --tier B on the round-7 pin (17 cases / 83) for rex86-merged and its
# untouched base twins, cold protocol, N=2 -> 3 -> 5 escalation, the four T0
# cases named per-case, wall-clock per run recorded in the log.
#
# Operational copy lives at /mnt-1/benchmarks/round7_t0_score.sh.
#
# ---------------------------------------------------------------------------
# Why this file cannot run today and is written but gated
#
# The cold baseline (round7_coldrun.sh -> sweep_extra.sh, 96 tags, 2-4 days)
# owns the GPU while this issue is open. record_baseline.py has no notion of
# the cold protocol -- sweep_extra.sh does (ollama stop before every run, cold
# slot, N=2 with 3/5 escalation, UNRESOLVED, retry with backoff). So the lazy
# and correct shape is: this script DEFERS to sweep_extra.sh for the protocol
# and only chooses the roster (the four T0 tags), the results directory and
# the operator -- exactly the round7_coldrun.sh pattern ("not a second
# scorer"). Nothing here can fire until the positive condition holds: every
# round-7 roster tag has both tier files or an UNMEASURED marker in
# /mnt-1/benchmarks/round7/ AND no sweep_extra.sh/record_baseline.py process
# is alive (same shape as chain_cold.sh).
#
# The four T0 cases come from the round-7 corpus transcripts; --cases on
# record_baseline.py scores the named cases plus the payload-free control
# twin of each injection case (#2694), which is what the T0 delta needs.
# Each sweep_extra.sh run writes its wall-clock into the report
# ("wall_seconds") and this script logs per-run wall-clock to the T0 log.
set -u

BASE=${BASE:-/mnt-1/benchmarks}
RESULTS7=${RESULTS7:-$BASE/round7}
ROSTER7=${ROSTER7:-$BASE/models_round7.txt}
OUT=${OUT:-$BASE/round7/t0}
REPO=${REPO:-$BASE/APIARY-round7}
GHIDRA_CACHE=${GHIDRA_CACHE:-$BASE/tierb-cache-round7}
OPERATOR=${OPERATOR:-t0-3081}
PIN=${PIN:-32dbdeb1}
T0_TAGS=${T0_TAGS:-"rex86-merged:q4_k_m rex86-merged:q8_0 qwen2.5-coder-7b-base:q4_k_m qwen2.5-coder-7b-base:q8_0"}
# vulnerable_strcpy appears twice on the round-7 pin: the original case and a
# second slice (different build/opt-level) extracted from the transcripts.
T0_CASES=${T0_CASES:-"vulnerable_strcpy,tlv_parser,indirect_dispatch,vulnerable_strcpy_slice2"}

log() { echo "$(date -u +%FT%TZ) $*"; }
die() { log "ABORT: $*"; exit 1; }

# ---------------------------------------------------------------------------
# Positive-condition gate: the cold run must be FINISHED. Both checks come
# from chain_cold.sh; either failing keeps this script from ever touching the
# slot while the cold baseline lives.
# ---------------------------------------------------------------------------
roster_settled() {
  python3 - "$ROSTER7" "$RESULTS7" <<'EOF' || return 1
import os, re, sys
tags = [l.strip() for l in open(sys.argv[1]) if l.strip()]
res = sys.argv[2]
slug = lambda t: re.sub(r"[^A-Za-z0-9._-]", "_", t)
for t in tags:
    if not (os.path.exists(f"{res}/tierA_{slug(t)}_run1.json")
            and os.path.exists(f"{res}/tierB_{slug(t)}_run1.json")) \
       and not os.path.exists(f"{res}/UNMEASURED_{slug(t)}.txt"):
        sys.exit(1)
EOF
}
[ -s "$ROSTER7" ] || die "roster $ROSTER7 is empty -- cannot evaluate the gate"
log "T0_SCORE_ARMED waiting for the round-7 cold baseline to finish"
MAX_WAIT_MIN=${MAX_WAIT_MIN:-4320}   # 72h, same as chain_cold.sh
for _ in $(seq 1 "$MAX_WAIT_MIN"); do
  if roster_settled \
     && ! pgrep -f "sweep_extra[.]sh" >/dev/null 2>&1 \
     && ! pgrep -f "record_baseline[.]py" >/dev/null 2>&1 \
     && ! pgrep -f "round7_coldrun[.]sh" >/dev/null 2>&1; then
    log "roster settled and the slot is idle -- starting T0 scoring"
    break
  fi
  sleep 60
done
roster_settled || die "roster still unsettled after ${MAX_WAIT_MIN}m"
pgrep -f "sweep_extra[.]sh"     >/dev/null 2>&1 && die "a sweep woke up mid-wait"
pgrep -f "record_baseline[.]py" >/dev/null 2>&1 && die "a baseline run woke up mid-wait"

# same scoring-vintage precondition round7_coldrun.sh enforces
head=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null) || die "$REPO is not a checkout"
[ "$head" = "$PIN" ] || die "repo head is $head, not $PIN -- wrong scoring vintage"

mkdir -p "$OUT/logs"
for TAG in $T0_TAGS; do
  slug=$(echo "$TAG" | tr ':/' '__')
  for TIER in A B; do
    extra=""; [ "$TIER" = "B" ] && extra="--ghidra-cache $GHIDRA_CACHE"
    start=$(date +%s)
    log "T0 run tier$TIER $slug cases=$T0_CASES"
    timeout 10800 python3 "$REPO/analysis/ghidra/benchmarks/corpus/record_baseline.py" \
      --tier "$TIER" $extra --model "$TAG" \
      --operator "$OPERATOR" --provenance synthetic \
      --cases "$T0_CASES" \
      --output "$OUT/tier${TIER}_${slug}_run1.json" \
      > "$OUT/logs/t0_tier${TIER}_${slug}.log" 2>&1 \
      || { log "FAIL tier$TIER $slug"; continue; }
    log "done tier$TIER $slug wall=$(( $(date +%s) - start ))s"
  done
done
log "T0_SCORE_COMPLETE"
