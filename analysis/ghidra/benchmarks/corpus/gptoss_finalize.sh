#!/usr/bin/env bash
# gptoss_finalize.sh -- #1947 phase 2.5 / #2279 step 3.
#
# Operational copy lives at /mnt-1/benchmarks/gptoss_finalize.sh. Committed here
# because its predecessor (gptoss_rerun.sh) was never committed and did not
# survive the 2026-09-03/04 rebuild (#2985).
#
# ---------------------------------------------------------------------------
# Why this is not the re-run its predecessor was going to be
#
# #2279 asks for the gpt-oss-family rows to be re-run under the harmony request
# shape before any cross-round comparison. Checking the stored results first --
# rather than burning GPU re-deriving them -- shows step 3 is already satisfied
# for the only model it could help, and that the remaining work is bookkeeping:
#
#   gpt-oss:20b             63/69   0 of 14 empty   answers 2913-5315 chars
#   GPT-OSS-Cyber non-i1     0/69  14 of 14 empty   0 chars
#   GPT-OSS-Cyber i1         0/69  14 of 14 empty   0 chars
#   CyberPal2.0-20B          0/69  14 of 14 empty   0 chars
#
# gpt-oss:20b was 11/69 with 11 of 14 empty BEFORE the fix, and the pinned
# harness (a99e765) IS #2679, the commit that ported the harmony branch into
# record_baseline.py. So its row is already a post-fix measurement and needs no
# re-run.
#
# The other three are not bad scores. They are empty answers. #2696 established
# with /api/generate raw:true and a hand-built harmony prompt that the weights
# are fine and the checkpoint simply emits nothing through any chat path -- three
# request shapes tried, all zero. #2982 covers the same class. Re-running them
# would spend ~30 GB of pulls and hours of GPU to re-derive a conclusion those
# issues already own.
#
# A 0 in a results table asserts the model answered badly. These models never
# answered. This script makes that difference machine-readable, which is the
# same distinction #2728's mark_unmeasured() draws for "never ran" and #3036's
# UNRESOLVED marker draws for "ran repeatedly, no majority".
#
# Usage:
#   bash gptoss_finalize.sh            # report and mark
#   DRY_RUN=1 bash gptoss_finalize.sh  # report only
set -u

BASE=${BASE:-/mnt-1/benchmarks}
RESULTS=${RESULTS:-$BASE/1947full}
DRY_RUN=${DRY_RUN:-0}

log() { echo "$(date -u +%FT%TZ) $*"; }

[ -d "$RESULTS" ] || { log "ABORT: no results dir at $RESULTS"; exit 1; }

log "GPTOSS_FINALIZE_START results=$RESULTS dry_run=$DRY_RUN"

python3 - "$RESULTS" "$DRY_RUN" <<'EOF'
import json, sys, pathlib, datetime, glob, re

results, dry = pathlib.Path(sys.argv[1]), sys.argv[2] == "1"

# The family is defined by ARCHITECTURE, not by tag substring. #2279 recorded
# why: is_harmony_served() matched the string "gpt-oss" in the tag, so
# CyberPal2.0-20B -- which is GptOssForCausalLM -- slipped past the fix even
# after it landed. These four are the architecture members present in the roster.
FAMILY = {
    "gpt-oss_20b": "gpt-oss:20b",
    "hf.co_mradermacher_GPT-OSS-Cybersecurity-20B-Merged-heretic-GGUF_Q4_K_M":
        "hf.co/mradermacher/GPT-OSS-Cybersecurity-20B-Merged-heretic-GGUF:Q4_K_M",
    "hf.co_mradermacher_GPT-OSS-Cybersecurity-20B-Merged-heretic-i1-GGUF_i1-Q4_K_M":
        "hf.co/mradermacher/GPT-OSS-Cybersecurity-20B-Merged-heretic-i1-GGUF:i1-Q4_K_M",
    "hf.co_mradermacher_CyberPal2.0-20B-GGUF_Q4_K_M":
        "hf.co/mradermacher/CyberPal2.0-20B-GGUF:Q4_K_M",
}

marked = ok = 0
for slug, tag in FAMILY.items():
    runs = {}
    for tier in ("A", "B"):
        for f in sorted(glob.glob(str(results / f"tier{tier}_{slug}_run*.json"))):
            try:
                d = json.loads(pathlib.Path(f).read_text())
            except Exception:
                continue
            cases = d.get("cases") or {}
            empty = sum(1 for v in cases.values() if v.get("empty_answer"))
            runs.setdefault(tier, []).append(
                {"score": d.get("total_score"), "empty": empty, "cases": len(cases),
                 "run_id": d.get("transcript_run_id")}
            )
    if not runs:
        print(f"  {tag}\n     no stored results -- nothing to finalize")
        continue

    all_empty = all(r["cases"] and r["empty"] == r["cases"] for rs in runs.values() for r in rs)
    summary = "  ".join(f"{t}={[r['score'] for r in rs]}" for t, rs in sorted(runs.items()))
    empties = "  ".join(f"{t}:{[f'{r['empty']}/{r['cases']}' for r in rs]}" for t, rs in sorted(runs.items()))

    if all_empty:
        out = results / f"UNMEASURABLE_{slug}.status"
        payload = {
            "tag": tag, "status": "UNMEASURABLE",
            "reason": "emits zero tokens through every chat path; the stored 0 is an "
                      "empty answer, not a bad one (see #2696, #2982)",
            "evidence": {t: rs for t, rs in runs.items()},
            "note": "#2696 proved the weights are fine via /api/generate raw:true with a "
                    "hand-built harmony prompt. Do not publish as a score, and do not "
                    "re-pull to re-derive this.",
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        print(f"  {tag}\n     {summary}   empty {empties}   -> UNMEASURABLE")
        if not dry:
            out.write_text(json.dumps(payload, indent=2))
        marked += 1
    else:
        print(f"  {tag}\n     {summary}   empty {empties}   -> real measurement, post-fix, keep")
        ok += 1

print()
print(f"  {ok} row(s) carry real post-fix scores; {marked} marked UNMEASURABLE")
if dry:
    print("  DRY_RUN -- nothing written")
EOF

log "GPTOSS_FINALIZE_COMPLETE"
