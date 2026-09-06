#!/usr/bin/env bash
# prep_round7_clone.sh -- pinned checkout for round 7 (epic #3079): a SECOND
# clone, detached at the round-7 pin. The a99e765 clone stays untouched -- its
# untracked transcripts are the phase-1/2 evidence and resume_phases.sh guards
# that HEAD. Operational copy: /mnt-1/benchmarks/round7_prep_pin.sh
set -euo pipefail
PIN=${PIN:-32dbdeb1face8c8e4791d31a8f4fbbe321e4f6fa}
DST=${DST:-/mnt-1/benchmarks/APIARY-round7}
OLD=${OLD:-/mnt-1/benchmarks/APIARY}
url=$(git -C "$OLD" remote get-url origin)
if [ -d "$DST/.git" ]; then
  echo "clone exists: $DST"
else
  git clone --quiet --no-checkout "$url" "$DST"
fi
git -C "$DST" fetch --quiet origin "$PIN" 2>/dev/null || git -C "$DST" fetch --quiet origin
git -C "$DST" checkout --quiet --detach "$PIN"
echo "round7 clone HEAD: $(git -C "$DST" rev-parse HEAD)"
python3 - "$DST" <<'PY'
import json, sys
from pathlib import Path
d = Path(sys.argv[1]) / "analysis/ghidra/benchmarks/corpus"
r = json.load(open(d / "rev_cases_v2_rubric.json"))
cases = r.get("cases", r)
m = json.load(open(d / "manifest.json"))
print("rubric cases:", len(cases))
print("manifest builds:", len(m["builds"]))
sl = [b for b in m["builds"] if b.get("toolchain") == "gcc-x86_64" and b.get("opt_level") == "-O0"]
print("gcc-x86_64 -O0 builds:", len(sl))
PY
