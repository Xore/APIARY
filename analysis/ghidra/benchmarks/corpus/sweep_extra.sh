#!/usr/bin/env bash
# Extra-roster sweep: pull -> benchmark -> delete, one model at a time.
#
# Operational copy of this file runs from /var/benchmarks/sweep_extra.sh on
# the homeserver (its BASE/REPO/LIST/PRESEED/CHECK_NAMES paths below are that
# host's layout) -- committed here so a script driving multi-hundred-GB pulls
# and real benchmark runs is reviewable and isn't one `rm` away from being
# lost (#2728), same reasoning as this directory's
# preseed_ollama_config_blob.sh. Keep this in sync with the live copy by
# hand; there is no automated deploy path for benchmark-host scratch scripts.
#
# Why this shape: /var is at 89% and the extra roster is ~150 GB of weights.
# Keeping every model resident would fill the filesystem that holds the Docker
# volumes and the Elasticsearch data. Benchmarking needs a model only while it
# runs, so each tag is pulled, measured on both tiers, then removed. Disk stays
# bounded at roughly one model (~20 GB) no matter how many tags are queued.
#
# Only tags this script pulled are ever removed. Pre-existing roster models are
# never touched.
#
# Same cold-slot protocol as the main sweep: `ollama stop` before every run,
# sequential, N=2 with escalation to N=3 on disagreement, retry with backoff.
#
# #2728: `ollama pull` fetches a small (~480B) ollama-compat config blob that
# HuggingFace generates on demand; for some repos that takes longer than
# Ollama's 30s per-request deadline, so the pull dies with "context deadline
# exceeded" *after* every multi-GB weight layer already reached 100%, and
# retrying reproduces the same failure identically forever. PRESEED fetches
# that one blob with curl (no such deadline), verifies it, and drops it into
# the blob store before every pull, so the race stops mattering. Pull stderr
# used to go to /dev/null, which is what made #2728 slow to diagnose -- it
# now lands in a per-model log under $BASE/logs.
set -u
# Overridable so a second roster can reuse this driver instead of copying its
# run/escalation/UNRESOLVED logic. requant_sweep.sh (#2245) builds a ladder of
# self-quantized tags and then runs exactly this script over them, so the
# self-quant rows are scored by the same code, at the same pin, as every
# as-published row they are meant to be compared against.
BASE=${BASE:-/var/benchmarks/1947full}
REPO=${REPO:-/var/benchmarks/APIARY}
LIST=${LIST:-/var/benchmarks/models_extra_all.txt}
PRESEED=${PRESEED:-/var/benchmarks/preseed.sh}
MAXTRY=${MAXTRY:-3}

# #3023: the cold-slot protocol #2641 established requires that nothing else
# touches the GPU -- `ollama stop` on the tag under test is necessary but not
# sufficient. Phase 2 ran without this and hp-llm-worker spent ~11 hours issuing
# a competing /api/chat every ~4 minutes against the same
# OLLAMA_MAX_LOADED_MODELS=1 slot. The measured consequence was extra escalations
# rather than wrong scores, but "the protocol depended on an operator
# remembering" is the defect. Enforce it here, and put the workers back on exit
# however the run ends.
STOP_WORKERS=${STOP_WORKERS:-1}
LIVE_WORKERS=${LIVE_WORKERS:-"hp-llm-worker ghidra-revdeck-1"}

# #2245/#3031: `ollama rm` after every model was correct when /var sat at 92%,
# and is actively harmful now that it has terabytes free -- it destroyed all ten
# of the requant plan's source models, and it is why a cold re-run of 89 models
# has to re-download 80 of them. Keep weights while there is room; the floor
# still protects the filesystem that holds the Docker volumes and the ES data.
KEEP_WEIGHTS_ABOVE_GB=${KEEP_WEIGHTS_ABOVE_GB:-1000}

# #3087: round 7 scores on its own pin with its own 17-case Tier B cache and
# its own operator tag, so both are overridable; the defaults are the a99e765
# sweep's, unchanged. round7_coldrun.sh sets them.
GHIDRA_CACHE=${GHIDRA_CACHE:-/var/benchmarks/tierb-cache}
OPERATOR=${OPERATOR:-bg-1947extra}

# #2738: fail fast on any roster entry Ollama's client-side hf.co name
# validation would reject before a sweep wastes time discovering it --
# see /var/benchmarks/oversized-model-aliases.tsv for the bisection and
# the recovery path for an entry that does trip this.
CHECK_NAMES=/var/benchmarks/check-roster-name-lengths.sh
if [ -x "$CHECK_NAMES" ]; then
  "$CHECK_NAMES" "$LIST" || exit 1
fi

mkdir -p "$BASE/logs"
cd "$REPO" || exit 1

STOPPED_WORKERS=""
restore_workers() {
  [ -n "$STOPPED_WORKERS" ] || return 0
  for c in $STOPPED_WORKERS; do
    docker start "$c" >/dev/null 2>&1 \
      && echo "$(date -u +%H:%M:%S) restored $c" \
      || echo "$(date -u +%H:%M:%S) WARN could not restart $c -- do it by hand"
  done
  STOPPED_WORKERS=""
}
if [ "$STOP_WORKERS" = "1" ]; then
  for c in $LIVE_WORKERS; do
    if docker ps --format '{{.Names}}' | grep -qx "$c"; then
      docker stop "$c" >/dev/null 2>&1 && STOPPED_WORKERS="$STOPPED_WORKERS $c" \
        && echo "$(date -u +%FT%TZ) cold protocol: stopped $c"
    fi
  done
  # EXIT alone is not enough: this script is routinely killed between models.
  trap 'restore_workers' EXIT INT TERM
fi

score_of() { python3 -c "import json;print(json.load(open('$1'))['total_score'])" 2>/dev/null; }

# #2728: writes a machine-readable marker next to the tierA/tierB result
# files for a model that never produced a score, so an aggregator (or a
# human running `ls`) cannot mistake "never ran" for "ran and scored badly" --
# the deeper defect the issue reported: a failed pull became an unmeasured
# model that looked like ordinary roster attrition.
mark_unmeasured() { # slug tag reason
  python3 - "$BASE/UNMEASURED_${1}.status" "$2" "$3" <<'EOF'
import json, sys, datetime
path, tag, reason = sys.argv[1], sys.argv[2], sys.argv[3]
json.dump({"tag": tag, "status": "UNMEASURED", "reason": reason,
           "ts": datetime.datetime.now(datetime.timezone.utc).isoformat()}, open(path, "w"))
EOF
}

# #3036: the third state. mark_unmeasured() separates "never ran" from "ran and
# scored badly"; this separates both from "ran fine, five times, and the harness
# still cannot say what the score is". Writes a marker only when no value has a
# plurality, and records every run so the spread is visible rather than summarised.
mark_unresolved_if_no_majority() { # tier slug tag
  python3 - "$BASE" "$1" "$2" "$3" <<'EOF'
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
# A plurality needs to be strictly more common than every other value; a 2-2 tie
# is not a result either.
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

do_run() { # tier slug tag n
  local tier="$1" slug="$2" tag="$3" n="$4"
  local out="$BASE/tier${tier}_${slug}_run${n}.json"
  [ -f "$out" ] && { echo "$(date -u +%H:%M:%S) skip $tier $slug run$n"; return 0; }
  local extra=""; [ "$tier" = "B" ] && extra="--ghidra-cache $GHIDRA_CACHE"
  local try=1
  while [ $try -le $MAXTRY ]; do
    docker exec ghidra-ollama-1 ollama stop "$tag" >/dev/null 2>&1
    sleep 5
    echo "$(date -u +%H:%M:%S) start $tier $slug run$n try$try"
    timeout 10800 python3 analysis/ghidra/benchmarks/corpus/record_baseline.py \
      --tier "$tier" $extra --model "$tag" \
      --operator "$OPERATOR" --provenance synthetic \
      --output "$out" > "$BASE/logs/x_tier${tier}_${slug}_run${n}_try${try}.log" 2>&1
    local rc=$?
    if [ $rc -eq 0 ] && [ -f "$out" ]; then
      echo "$(date -u +%H:%M:%S) done  $tier $slug run$n score=$(score_of "$out")"
      return 0
    fi
    echo "$(date -u +%H:%M:%S) FAIL  $tier $slug run$n try$try rc=$rc"
    rm -f "$out"
    for w in $(seq 1 30); do
      curl -sf -m 5 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break
      sleep 10
    done
    sleep $((try * 20)); try=$((try + 1))
  done
  echo "GIVEUP $tag tier$tier run$n" >> "$BASE/failures.txt"
  return 1
}

echo "$(date -u +%FT%TZ) EXTRA_START models=$(grep -cve '^\s*$' "$LIST")"

while read -r TAG; do
  [ -z "$TAG" ] && continue
  case "$TAG" in \#*) continue;; esac
  slug=$(echo "$TAG" | tr ':/' '__')
  # already fully measured? then skip without pulling
  if [ -f "$BASE/tierA_${slug}_run1.json" ] && [ -f "$BASE/tierB_${slug}_run1.json" ]; then
    echo "$(date -u +%H:%M:%S) SKIP $TAG (already measured)"
    continue
  fi

  PULLED=0
  # -i: Ollama rewrites some quantisation-shaped tags to uppercase on write
  # (#2738's raven aliases: `ollama create x:q4_k_m` lands as `x:Q4_K_M` --
  # see /var/benchmarks/oversized-model-aliases.tsv for the measured set),
  # so an imported alias may not case-match the roster's own spelling of
  # $TAG. Match case-insensitively so those entries are recognised as
  # present. Ollama resolves names case-insensitively itself, so handing the
  # roster's spelling on to pull/stop/rm below is safe either way.
  if ! docker exec ghidra-ollama-1 ollama list 2>/dev/null | awk '{print $1}' | grep -qixF "$TAG"; then
    free=$(df --output=avail -BG /var | tail -1 | tr -dc '0-9')
    echo "$(date -u +%H:%M:%S) PULL $TAG (/var free ${free}G)"
    if [ -x "$PRESEED" ]; then
      bash "$PRESEED" <(printf '%s\n' "$TAG")
    fi
    pull_log="$BASE/logs/pull_${slug}.log"
    if ! docker exec ghidra-ollama-1 ollama pull "$TAG" >"$pull_log" 2>&1; then
      reason=$(tail -1 "$pull_log" | tr -d '\r')
      echo "$(date -u +%H:%M:%S) PULL_FAILED $TAG ($reason) log=$pull_log"
      echo "PULL_FAILED $TAG: $reason" >> "$BASE/failures.txt"
      mark_unmeasured "$slug" "$TAG" "pull_failed: $reason"
      continue
    fi
    PULLED=1
    echo "$(date -u +%H:%M:%S) pulled $TAG"
  else
    echo "$(date -u +%H:%M:%S) already local: $TAG (will not delete)"
  fi

  # Ollama's stored spelling of a tag is not always the spelling you asked for:
  # it rewrites SOME quant-shaped tags and not others. Measured on tags this
  # repo created itself, all written lowercase:
  #     gemma4-26b-a4b-selfquant:q3_k_m   <- kept
  #     gemma4-26b-a4b-selfquant:Q4_K_M   <- uppercased by Ollama
  # The presence check above is `grep -qixF`, case-insensitive, so it passes --
  # but record_baseline.py resolves a model by EXACT string match against
  # /api/tags and exits "model tag is not installed". The result was three runs
  # failing, MODEL_DONE written, and the weights deleted, for three models that
  # had pulled perfectly (#1947 phase 2: Ornith Q3_K_M and gemma Q3_K_M/Q5_K_M --
  # the published twins of the self-quant ladder, i.e. the most decision-relevant
  # rows in the roster).
  #
  # Fixed here rather than in record_baseline.py on purpose: that file is on the
  # pinned a99e765 harness, and moving the pin to fix a name lookup would split
  # the scoring vintage for no benefit. Hand the scorer the name Ollama actually
  # holds.
  RESOLVED=$(docker exec ghidra-ollama-1 ollama list 2>/dev/null | awk '{print $1}' | grep -ixF "$TAG" | head -1)
  if [ -n "$RESOLVED" ] && [ "$RESOLVED" != "$TAG" ]; then
    echo "$(date -u +%H:%M:%S) tag case differs: roster '$TAG' -> ollama '$RESOLVED'"
    TAG="$RESOLVED"
  fi

  # #3090 tried a preflight probe here (one request before the tier loop) to
  # catch an always-500 model cheaply. Dropped in review: 31 of 167 stored
  # tierA run1 results show cold-load time >30s (max 694s), so the probe's
  # own timeout misread a healthy-but-cold model as dead and routed it to
  # mark_unmeasured() before it ever got a real run; raising the timeout only
  # turned the probe into a mandatory extra cold load per model (do_run()
  # below issues its own `ollama stop` before try 1 regardless). The
  # TIER_OK==0 fallback a few lines down already reaches mark_unmeasured()
  # for an always-500 model, at the cost of MAXTRY attempts instead of one --
  # correct beats cheap here.
  TIER_OK=0
  for tier in A B; do
    do_run "$tier" "$slug" "$TAG" 1 || continue
    TIER_OK=1
    do_run "$tier" "$slug" "$TAG" 2 || continue
    s1=$(score_of "$BASE/tier${tier}_${slug}_run1.json")
    s2=$(score_of "$BASE/tier${tier}_${slug}_run2.json")
    if [ "$s1" != "$s2" ]; then
      echo "$(date -u +%H:%M:%S) ESCALATE $tier $slug ($s1 != $s2)"
      echo "$tier $slug $s1 $s2" >> "$BASE/escalated.txt"
      do_run "$tier" "$slug" "$TAG" 3
      # #3036: run 3 is decisive only if it AGREES with one of the first two.
      # Nothing used to check that. A cell whose three runs are all distinct has
      # no majority and therefore no defensible score -- it looked identical to
      # a resolved cell, and an aggregator reading total_score would pick one
      # arbitrarily. Measured live: GLM-4.6-REAP-218B:i1-IQ1_S tier B came back
      # 55 / 57 / 54.
      s3=$(score_of "$BASE/tier${tier}_${slug}_run3.json")
      if [ -n "$s3" ] && [ "$s1" != "$s3" ] && [ "$s2" != "$s3" ]; then
        # Bounded, not unbounded: the row that provoked this costs ~45 min/run
        # (57 GB served, 65% on CPU), so an open-ended escalation could spend a
        # day on one cell. Two more runs, then stop and say so.
        echo "$(date -u +%H:%M:%S) NOMAJORITY $tier $slug ($s1/$s2/$s3) -> N=5"
        do_run "$tier" "$slug" "$TAG" 4
        do_run "$tier" "$slug" "$TAG" 5
        mark_unresolved_if_no_majority "$tier" "$slug" "$TAG"
      fi
    fi
  done

  if [ "$PULLED" = "1" ]; then
    docker exec ghidra-ollama-1 ollama stop "$TAG" >/dev/null 2>&1
    free_now=$(df --output=avail -BG /var | tail -1 | tr -dc '0-9')
    if [ "$free_now" -lt "$KEEP_WEIGHTS_ABOVE_GB" ]; then
      docker exec ghidra-ollama-1 ollama rm "$TAG" >/dev/null 2>&1 \
        && echo "$(date -u +%H:%M:%S) removed $TAG (free was ${free_now}G, floor ${KEEP_WEIGHTS_ABOVE_GB}G)"
    else
      echo "$(date -u +%H:%M:%S) kept $TAG (${free_now}G free, above the ${KEEP_WEIGHTS_ABOVE_GB}G floor)"
    fi
  fi
  # A model that pulled but produced no result on either tier used to leave only
  # a GIVEUP line in failures.txt and a MODEL_DONE in the log -- indistinguishable
  # from success to anything reading the results directory. That is the same
  # silent-hole class as the false EXTRA_COMPLETE in #3031.
  if [ "$TIER_OK" = "0" ] && [ ! -f "$BASE/tierA_${slug}_run1.json" ]; then
    mark_unmeasured "$slug" "$TAG" "pulled but every run failed on both tiers"
    echo "$(date -u +%H:%M:%S) UNMEASURED $TAG (pulled, no run produced a result)"
  fi
  echo "$(date -u +%H:%M:%S) MODEL_DONE $TAG"
done < "$LIST"

echo "$(date -u +%FT%TZ) EXTRA_COMPLETE"
