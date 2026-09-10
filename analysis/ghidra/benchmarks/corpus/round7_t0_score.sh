#!/usr/bin/env bash
# round7_t0_score.sh -- T0 scoring leg (#3081): record_baseline.py --tier A and
# --tier B on the round-7 pin (17 cases / 83) for rex86-merged and its
# untouched base twins, the full 17-case slice scored per tag (the full-pin
# basis -- --cases would split the vintage from the cold baseline and break
# pin comparability), the four T0 cases additionally extracted from the run's
# transcripts for the per-case read, cold protocol throughout.
#
# Operational copy lives at /var/benchmarks/round7_t0_score.sh.
#
# ---------------------------------------------------------------------------
# Why this file cannot run today and is written but gated
#
# The cold baseline (round7_coldrun.sh -> sweep_extra.sh, 96 tags, 2-4 days)
# owns the GPU while this issue is open. sweep_extra.sh owns the cold protocol
# (ollama stop before every run, cold slot, N=2 with 3/5 escalation,
# UNRESOLVED, retry with backoff); record_baseline.py does not. This script
# cannot defer to sweep_extra.sh for the protocol -- it needs --cases-free
# full-slice runs and per-tier wall-clock that the shared driver does not
# parameterise -- so the scoring loop below REPLICATES sweep_extra.sh's
# do_run/escalation shape exactly (same timeouts, same backoff, same marker
# files) rather than inventing a fourth protocol.
#
# Nothing here can fire until the positive condition holds: every round-7 T0
# tag has both tier files or an UNMEASURED marker in /var/benchmarks/round7/
# AND no sweep_extra.sh / record_baseline.py / round7_coldrun.sh process is
# alive (same shape as chain_cold.sh).
#
# The four T0 cases come from the round-7 corpus transcripts. vulnerable_strcpy
# appears on the pin once per corpus slice (the original case, plus the second
# #160-named slice at a different build/opt-level); there is no
# vulnerable_strcpy_slice2 case stem in the rubric, so the "second slice" is
# NOT a --cases value -- it is read out of the vulnerable_strcpy case's
# per-slice transcript entries after the full-slice run (extract_cases below).
set -u

BASE=${BASE:-/var/benchmarks}
RESULTS7=${RESULTS7:-$BASE/round7}
OUT=${OUT:-$BASE/round7/t0}
REPO=${REPO:-$BASE/APIARY-round7}
GHIDRA_CACHE=${GHIDRA_CACHE:-$BASE/tierb-cache-round7}
OPERATOR=${OPERATOR:-t0-3081}
PIN=${PIN:-32dbdeb1}
MAXTRY=${MAXTRY:-3}
T0_TAGS=${T0_TAGS:-"rex86-merged:q4_k_m rex86-merged:q8_0 qwen2.5-coder-7b-base:q4_k_m qwen2.5-coder-7b-base:q8_0"}
# Real rubric stems only (rev_cases_v2_rubric.json). The second
# vulnerable_strcpy slice is a transcript read, not a case name.
T0_CASES=${T0_CASES:-"vulnerable_strcpy tlv_parser indirect_dispatch"}

log() { echo "$(date -u +%FT%TZ) $*"; }
die() { log "ABORT: $*"; exit 1; }
slug_of() { echo "$1" | tr ':/' '__'; }

# ---------------------------------------------------------------------------
# Positive-condition gate: the cold run must be FINISHED. Both checks come
# from chain_cold.sh; either failing keeps this script from ever touching the
# slot while the cold baseline lives. The T0 gate only needs the four T0 tags
# settled: rex86-merged and its base twins are registered by
# round7_t0_merge_export.sh AFTER the cold run, so requiring the whole 96-tag
# roster here would deadlock with the merge leg that follows it.
# A tag is settled by sweep_extra.sh's marker spellings: UNMEASURED_<slug>.status
# (current), UNMEASURED_<slug>.txt (older), a plain UNMEASURED marker file,
# or the UNRESOLVED pair (ran N=5, no majority -- a recorded, reviewable state).
# ---------------------------------------------------------------------------
roster_settled() {
  python3 - "$RESULTS7" $T0_TAGS <<'EOF' || return 1
import os, sys
res = sys.argv[1]
def slug(t):
    return t.replace(":", "_").replace("/", "_")
for t in sys.argv[2:]:
    s = slug(t)
    if os.path.exists(f"{res}/tierA_{s}_run1.json") and os.path.exists(f"{res}/tierB_{s}_run1.json"):
        continue
    if any(os.path.exists(f"{res}/{p}") for p in (
            f"UNMEASURED_{s}.status", f"UNMEASURED_{s}.txt", "UNMEASURED",
            f"UNRESOLVED_tierA_{s}.status", f"UNRESOLVED_tierB_{s}.status")):
        continue
    sys.exit(1)
EOF
}
slot_busy() {
  pgrep -f "sweep_extra[.]sh"     >/dev/null 2>&1 \
    || pgrep -f "record_baseline[.]py" >/dev/null 2>&1 \
    || pgrep -f "round7_coldrun[.]sh"  >/dev/null 2>&1
}
log "T0_SCORE_ARMED waiting for the round-7 cold baseline to finish"
MAX_WAIT_MIN=${MAX_WAIT_MIN:-4320}   # 72h, same as chain_cold.sh
for _ in $(seq 1 "$MAX_WAIT_MIN"); do
  if roster_settled && ! slot_busy; then
    log "T0 tags settled and the slot is idle -- starting T0 scoring"
    break
  fi
  sleep 60
done
roster_settled || die "T0 tags still unsettled after ${MAX_WAIT_MIN}m"
slot_busy && die "a run woke up mid-wait"

# same scoring-vintage precondition round7_coldrun.sh enforces
head=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null) || die "$REPO is not a checkout"
[ "$head" = "$PIN" ] || die "repo head is $head, not $PIN -- wrong scoring vintage"

score_of() { python3 -c "import json;print(json.load(open('$1'))['total_score'])" 2>/dev/null; }

# UNRESOLVED marker -- identical JSON shape to sweep_extra.sh's
# mark_unresolved_if_no_majority, so aggregators read both the same way.
mark_unresolved_if_no_majority() { # tier slug tag
  python3 - "$OUT" "$1" "$2" "$3" <<'EOF'
import json, sys, datetime, collections, pathlib
base, tier, slug, tag = sys.argv[1:5]
scores = []
for n in range(1, 6):
    p = pathlib.Path(base) / f"tier{tier}_{slug}_run{n}.json"
    if p.exists():
        try:
            scores.append(json.loads(p.read_text())["total_score"])
        except Exception:
            pass
if not scores:
    sys.exit(0)
counts = collections.Counter(scores)
top, n_top = counts.most_common(1)[0]
tied = [v for v, c in counts.items() if c == n_top]
out = pathlib.Path(base) / f"UNRESOLVED_tier{tier}_{slug}.status"
if len(tied) > 1 or n_top < 2:
    out.write_text(json.dumps({
        "tag": tag, "tier": tier, "status": "UNRESOLVED",
        "reason": f"no majority across {len(scores)} runs",
        "runs": scores, "counts": dict(counts),
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }))
    print(f"UNRESOLVED tier{tier} {slug} runs={scores}")
else:
    out.unlink(missing_ok=True)
    print(f"resolved tier{tier} {slug} runs={scores} -> {top} (x{n_top}, N={len(scores)})")
EOF
}

# One scoring run -- same shape as sweep_extra.sh do_run: ollama stop first
# (cold slot), retry with backoff, wall-clock recorded on SUCCESS and FAIL.
# The full 17-case slice runs (no --cases): the full-pin basis is the point.
do_run() { # tier slug tag n
  local tier="$1" slug="$2" tag="$3" n="$4"
  local out="$OUT/tier${tier}_${slug}_run${n}.json"
  if [ -f "$out" ]; then
    log "skip tier$tier $slug run$n (already scored)"
    return 0
  fi
  local extra=""; [ "$tier" = "B" ] && extra="--ghidra-cache $GHIDRA_CACHE"
  local try=1
  while [ $try -le $MAXTRY ]; do
    docker exec ghidra-ollama-1 ollama stop "$tag" >/dev/null 2>&1
    sleep 5
    local start=$(date +%s)
    log "start tier$tier $slug run$n try$try"
    timeout 10800 python3 "$REPO/analysis/ghidra/benchmarks/corpus/record_baseline.py" \
      --tier "$tier" $extra --model "$tag" \
      --operator "$OPERATOR" --provenance synthetic \
      --output "$out" \
      > "$OUT/logs/t0_tier${tier}_${slug}_run${n}_try${try}.log" 2>&1
    local rc=$?
    local wall=$(( $(date +%s) - start ))
    if [ $rc -eq 0 ] && [ -f "$out" ]; then
      log "done  tier$tier $slug run$n wall=${wall}s score=$(score_of "$out")"
      return 0
    fi
    log "FAIL  tier$tier $slug run$n try$try rc=$rc wall=${wall}s"
    rm -f "$out"
    local w
    for w in $(seq 1 30); do
      curl -sf -m 5 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break
      sleep 10
    done
    sleep $((try * 20)); try=$((try + 1))
  done
  log "GIVEUP tier$tier $slug $tag"
  echo "GIVEUP $tag tier$tier" >> "$OUT/failures.txt"
  return 1
}

# Per-case read: pull the four T0 cases (including vulnerable_strcpy's
# per-slice entries -- every record for that case, one per corpus slice) out
# of the run's transcript JSONL. The transcript path is what
# record_baseline.py prints ("transcripts: <path>") into the run log.
extract_cases() { # tier slug n
  local tier="$1" slug="$2" n="$3"
  local log="$OUT/logs/t0_tier${tier}_${slug}_run${n}_try1.log"
  local tpath
  tpath=$(grep -m1 '^transcripts:' "$log" 2>/dev/null | awk '{print $2}')
  [ -n "$tpath" ] && [ -f "$tpath" ] || { log "no transcript for tier$tier $slug run$n -- per-case read skipped"; return 0; }
  python3 - "$tpath" "$OUT" "$tier" "$slug" $T0_CASES <<'EOF'
import json, sys, pathlib
tpath, out, tier, slug = sys.argv[1:5]
wanted = set(sys.argv[5:])
recs = {}
for line in open(tpath, encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    try:
        r = json.loads(line)
    except Exception:
        continue
    if r.get("case") in wanted:
        recs.setdefault(r["case"], []).append(r)
dest = pathlib.Path(out) / "cases"
dest.mkdir(parents=True, exist_ok=True)
for case, entries in sorted(recs.items()):
    p = dest / f"{case}__tier{tier}_{slug}.json"
    p.write_text(json.dumps({"case": case, "tier": tier, "slug": slug,
                             "slices": entries}, indent=2))
    print(f"extracted {case}: {len(entries)} slice entries -> {p}")
EOF
}

mkdir -p "$OUT/logs"
for TAG in $T0_TAGS; do
  slug=$(slug_of "$TAG")
  # already fully measured (full-pin basis)? then skip without touching the slot
  if [ -f "$OUT/tierA_${slug}_run1.json" ] && [ -f "$OUT/tierB_${slug}_run1.json" ]; then
    log "SKIP $TAG (already measured)"
    continue
  fi
  # Ollama sometimes rewrites quant-shaped tag case on write (#1947 bug class,
  # fixed for sweep_extra.sh by 32dbdeb1): match case-insensitively and hand
  # record_baseline.py / ollama stop the spelling Ollama actually holds. slug
  # stays derived from the roster's own spelling above, so output filenames
  # are unaffected. A tag not installed under any case is left as-is and
  # falls through do_run's existing failure path.
  RESOLVED=$(docker exec ghidra-ollama-1 ollama list 2>/dev/null | awk '{print $1}' | grep -ixF "$TAG" | head -1)
  if [ -n "$RESOLVED" ] && [ "$RESOLVED" != "$TAG" ]; then
    log "tag case differs: roster '$TAG' -> ollama '$RESOLVED'"
    TAG="$RESOLVED"
  fi
  for TIER in A B; do
    if do_run "$TIER" "$slug" "$TAG" 1; then
      extract_cases "$TIER" "$slug" 1
      do_run "$TIER" "$slug" "$TAG" 2 || continue
      s1=$(score_of "$OUT/tier${TIER}_${slug}_run1.json")
      s2=$(score_of "$OUT/tier${TIER}_${slug}_run2.json")
      if [ "$s1" != "$s2" ]; then
        log "ESCALATE tier$TIER $slug ($s1 != $s2)"
        echo "$TIER $slug $s1 $s2" >> "$OUT/escalated.txt"
        do_run "$TIER" "$slug" "$TAG" 3
        # run 3 is decisive only if it AGREES with one of the first two
        # (#3036); otherwise two more runs, then the UNRESOLVED marker.
        s3=$(score_of "$OUT/tier${TIER}_${slug}_run3.json")
        if [ -n "$s3" ] && [ "$s1" != "$s3" ] && [ "$s2" != "$s3" ]; then
          log "NOMAJORITY tier$TIER $slug ($s1/$s2/$s3) -> N=5"
          do_run "$TIER" "$slug" "$TAG" 4
          do_run "$TIER" "$slug" "$TAG" 5
          mark_unresolved_if_no_majority "$TIER" "$slug" "$TAG"
        fi
      fi
    fi
  done
  docker exec ghidra-ollama-1 ollama stop "$TAG" >/dev/null 2>&1
done
log "T0_SCORE_COMPLETE"
