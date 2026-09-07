#!/usr/bin/env bash
# slots_sweep.sh -- the #1947 phase-5 / #2985 sessions+Rev·Deck slots leg,
# finally run for round 7 (plan §8): drive evaluate-models.py --slots
# sessions,revdeck over a roster. The ghidra slot stays held back (#1795:
# Tier B evidence first) -- record_baseline.py owns that axis.
#
# Operational copy: /mnt-1/benchmarks/slots_sweep.sh.
#
# Same regime as the corpus sweeps: cold slot, live workers stopped and
# restored by trap, one model loaded at a time, uptime per run recorded.
# evaluate-models.py is per-model stateless, so this loop is its own driver
# (sweep_extra.sh drives record_baseline.py, a different entry point -- there
# is no shared scorer to reuse for these slots).
set -u

BASE=${BASE:-/mnt-1/benchmarks}
OUT=${OUT:-$BASE/round7/slots}
LIST=${LIST:-$BASE/models_round7.txt}
REPO=${REPO:-$BASE/APIARY-round7}
OLLAMA=${OLLAMA:-ghidra-ollama-1}
SLOTS=${SLOTS:-sessions,revdeck}
CONTEXT=${CONTEXT:-8192}
STOP_WORKERS=${STOP_WORKERS:-1}
LIVE_WORKERS=${LIVE_WORKERS:-"hp-llm-worker ghidra-revdeck-1"}

log() { echo "$(date -u +%FT%TZ) $*"; }
die() { log "ABORT: $*"; exit 1; }

[ -s "$LIST" ] || die "LIST=$LIST is empty"
command -v docker >/dev/null || die "no docker"
docker ps --format '{{.Names}}' | grep -qx "$OLLAMA" || die "$OLLAMA is not running"
if pgrep -f "sweep_extra[.]sh" >/dev/null 2>&1 || pgrep -f "record_baseline[.]py" >/dev/null 2>&1; then
  die "a sweep is already running -- refusing to double-book the GPU"
fi

# Cold protocol: same shape as sweep_extra.sh's -- stop, trap, restore.
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
  trap 'restore_workers' EXIT INT TERM
fi

mkdir -p "$OUT/logs"
cd "$REPO" || die "$REPO is not usable"
head=$(git rev-parse --short HEAD)
log "SLOTS_SWEEP_START list=$LIST slots=$SLOTS out=$OUT pin=$head"

while read -r TAG; do
  [ -z "$TAG" ] && continue
  case "$TAG" in \#*) continue;; esac
  slug=$(echo "$TAG" | tr ':/' '__' | tr '[:upper:]' '[:lower:]')
  out_json="$OUT/slots_${slug}.json"
  if [ -s "$out_json" ]; then
    log "SKIP $TAG (already measured)"
    continue
  fi

  # Only pull what is not already local; local tags are never deleted
  # (the sweep_extra.sh lesson: deleting weights cost the requant sources).
  if ! docker exec "$OLLAMA" ollama list 2>/dev/null | awk '{print $1}' | grep -qixF "$TAG"; then
    if ! docker exec "$OLLAMA" ollama pull "$TAG" > "$OUT/logs/pull_${slug}.log" 2>&1; then
      log "PULL_FAILED $TAG -- marker written, next model"
      python3 - "$OUT" "UNMEASURED_slots_${slug}.status" "$TAG" "pull_failed" <<'EOF'
import json, sys, datetime
path, tag, reason = sys.argv[1], sys.argv[2], sys.argv[3]
json.dump({"tag": tag, "status": "UNMEASURED", "reason": reason,
           "ts": datetime.datetime.now(datetime.timezone.utc).isoformat()},
          open(f"{path}/{__import__('os').path.basename(sys.argv[2])}", "w"))
EOF
      continue
    fi
  fi

  # Re-stop the workers' Ollama competition and the tag under test before
  # each model: uptime recorded per run is only comparable from a cold slot.
  for c in $LIVE_WORKERS; do docker stop "$c" >/dev/null 2>&1 || true; done
  docker exec "$OLLAMA" ollama stop "$TAG" >/dev/null 2>&1 || true
  sleep 5

  up0=$(awk '{print int($1)}' /proc/uptime)
  log "start slots $TAG"
  if timeout 21600 python3 analysis/ghidra/benchmarks/evaluate-models.py \
       --slots "$SLOTS" --context "$CONTEXT" --operator bg-round7 \
       --provenance synthetic "$TAG" \
       > "$OUT/logs/slots_${slug}.log" 2>&1; then
    up=$(( $(awk '{print int($1)}' /proc/uptime) - up0 ))
    echo -e "$(date -u +%FT%TZ)\t$TAG\t${up}s" >> "$OUT/uptime.tsv"
    log "done  slots $TAG wall=${up}s"
  else
    rc=$?
    log "FAIL  slots $TAG rc=$rc -- marker written, next model"
    echo "$(date -u +%FT%TZ) GIVEUP slots $TAG rc=$rc" >> "$OUT/failures.txt"
  fi
  # keep the weights; drop nothing (KEEP_WEIGHTS lesson, sweep_extra.sh:153)
done < "$LIST"

log "SLOTS_SWEEP_COMPLETE"
