#!/usr/bin/env bash
# Extra-roster sweep: pull -> benchmark -> delete, one model at a time.
#
# Operational copy of this file runs from /mnt-1/benchmarks/sweep_extra.sh on
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
BASE=/mnt-1/benchmarks/1947full
REPO=/mnt-1/benchmarks/APIARY
LIST=/mnt-1/benchmarks/models_extra_all.txt
PRESEED=/mnt-1/benchmarks/preseed.sh
MAXTRY=3

# #2738: fail fast on any roster entry Ollama's client-side hf.co name
# validation would reject before a sweep wastes time discovering it --
# see /mnt-1/benchmarks/oversized-model-aliases.tsv for the bisection and
# the recovery path for an entry that does trip this.
CHECK_NAMES=/mnt-1/benchmarks/check-roster-name-lengths.sh
if [ -x "$CHECK_NAMES" ]; then
  "$CHECK_NAMES" "$LIST" || exit 1
fi

mkdir -p "$BASE/logs"
cd "$REPO" || exit 1

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

do_run() { # tier slug tag n
  local tier="$1" slug="$2" tag="$3" n="$4"
  local out="$BASE/tier${tier}_${slug}_run${n}.json"
  [ -f "$out" ] && { echo "$(date -u +%H:%M:%S) skip $tier $slug run$n"; return 0; }
  local extra=""; [ "$tier" = "B" ] && extra="--ghidra-cache /mnt-1/benchmarks/tierb-cache"
  local try=1
  while [ $try -le $MAXTRY ]; do
    docker exec ghidra-ollama-1 ollama stop "$tag" >/dev/null 2>&1
    sleep 5
    echo "$(date -u +%H:%M:%S) start $tier $slug run$n try$try"
    timeout 10800 python3 analysis/ghidra/benchmarks/corpus/record_baseline.py \
      --tier "$tier" $extra --model "$tag" \
      --operator bg-1947extra --provenance synthetic \
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
  # see /mnt-1/benchmarks/oversized-model-aliases.tsv for the measured set),
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

  for tier in A B; do
    do_run "$tier" "$slug" "$TAG" 1 || continue
    do_run "$tier" "$slug" "$TAG" 2 || continue
    s1=$(score_of "$BASE/tier${tier}_${slug}_run1.json")
    s2=$(score_of "$BASE/tier${tier}_${slug}_run2.json")
    if [ "$s1" != "$s2" ]; then
      echo "$(date -u +%H:%M:%S) ESCALATE $tier $slug ($s1 != $s2)"
      echo "$tier $slug $s1 $s2" >> "$BASE/escalated.txt"
      do_run "$tier" "$slug" "$TAG" 3
    fi
  done

  if [ "$PULLED" = "1" ]; then
    docker exec ghidra-ollama-1 ollama stop "$TAG" >/dev/null 2>&1
    docker exec ghidra-ollama-1 ollama rm "$TAG" >/dev/null 2>&1 \
      && echo "$(date -u +%H:%M:%S) removed $TAG (free now $(df --output=avail -BG /var | tail -1 | tr -dc '0-9')G)"
  fi
  echo "$(date -u +%H:%M:%S) MODEL_DONE $TAG"
done < "$LIST"

echo "$(date -u +%FT%TZ) EXTRA_COMPLETE"
