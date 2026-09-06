#!/usr/bin/env bash
# round7_launch.sh -- start the round-7 cold baseline detached, with the VRAM
# sampler beside it, after the smoke test has proved the leg scores.
#
# Operational copy lives at /mnt-1/benchmarks/round7_launch.sh.
#
# Refuses to launch unless round7_smoke.sh has left a Tier B result on this
# pin: a Tier-B-only failure is the exact 2026-09-04 defect (#2971), and the
# sweep would still write MODEL_DONE over the hole.
set -u
BASE=${BASE:-/mnt-1/benchmarks}
SMOKE=${SMOKE:-$BASE/smoke-round7/tierB_smoke.json}
[ -s "$SMOKE" ] || { echo "ABORT: no Tier B smoke result at $SMOKE -- run round7_smoke.sh first"; exit 1; }
python3 - "$SMOKE" <<'PY' || exit 1
import json, sys
d = json.load(open(sys.argv[1]))
assert d["case_count"] == 17, f"smoke scored {d['case_count']} cases, not 17 -- wrong pin or corpus"
# 83, not the 79 the resume plan guessed: max per case is required_groups + 1,
# measured on this pin by the smoke run (70/83 A, 69/83 B for qwen2.5:7b).
assert d["total_max_score"] == 83, f"smoke max is {d['total_max_score']}, not 83"
assert d["total_score"] > 0, "smoke scored 0 -- empty answers, do not launch"
print(f"smoke ok: {d['total_score']}/{d['total_max_score']} over {d['case_count']} cases")
PY
if pgrep -f "sweep_extra[.]sh" >/dev/null 2>&1 || pgrep -f "record_baseline[.]py" >/dev/null 2>&1; then
  echo "ABORT: a sweep is already running"; exit 1
fi
cd "$BASE" || exit 1
pgrep -f "keep_and_sample[.]sh" >/dev/null 2>&1 || \
  { setsid nohup bash "$BASE/keep_and_sample.sh" >> "$BASE/keepsample.log" 2>&1 < /dev/null & echo "sampler started"; }
setsid nohup bash "$BASE/round7_coldrun.sh" >> "$BASE/round7.log" 2>&1 < /dev/null &
echo "launched round7_coldrun.sh -> $BASE/round7.log"
