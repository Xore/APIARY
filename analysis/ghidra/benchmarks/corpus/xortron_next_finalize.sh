#!/usr/bin/env bash
# xortron_next_finalize.sh -- #2982, same bookkeeping shape as gptoss_finalize.sh
# (#3047 / #2279) but a different root cause.
#
# ---------------------------------------------------------------------------
# Root cause (confirmed live against the serving Ollama, read-only /api/show
# and /api/chat probes, 2026-09-07):
#
#   hf.co/mradermacher/XORTRON.CriminalComputing.2026.4B.Instruct.NEXT-i1-GGUF
#   hf.co/mradermacher/XORTRON.CriminalComputing.2026.27B.Instruct.NEXT-i1-GGUF
#
# are both architecture "qwen35" (Qwen3.5) and both fail every single request,
# any shape, with:
#
#   {"error":"llama-server process has terminated: exit status 1: error:
#   lexer: unknown escape character \u\nerror: std::exception"}
#
# The GGUF's embedded chat template contains a Python/Jinja2-style ’
# (right single quote) unicode escape inside a string literal. llama.cpp's Jinja
# implementation (minja) does not support \uXXXX escapes, so llama-server
# crashes rendering the template before generation ever starts -- for every
# request, regardless of prompt, request shape, reasoning_effort, or
# temperature. This is why the stored Tier A files are ~740 B with
# case_count: 0 (every case SKIPped on a transport error), not "empty answer"
# per case like the gpt-oss family (#2696/#2982's other three rows, finalized
# by gptoss_finalize.sh).
#
# The sibling build without ".NEXT" in the tag (same qwen35 architecture, same
# quantizer) has no \u escape in its template and scores normally -- this is a
# template bug specific to the .NEXT GGUF upload, not the architecture, an
# Ollama version gap, or anything this harness's request shape controls.
#
# Usage:
#   bash xortron_next_finalize.sh            # report and mark
#   DRY_RUN=1 bash xortron_next_finalize.sh  # report only
set -u

BASE=${BASE:-/var/benchmarks}
RESULTS=${RESULTS:-$BASE/1947full}
DRY_RUN=${DRY_RUN:-0}

log() { echo "$(date -u +%FT%TZ) $*"; }

[ -d "$RESULTS" ] || { log "ABORT: no results dir at $RESULTS"; exit 1; }

log "XORTRON_NEXT_FINALIZE_START results=$RESULTS dry_run=$DRY_RUN"

python3 - "$RESULTS" "$DRY_RUN" <<'EOF'
import json, sys, pathlib, datetime, glob

results, dry = pathlib.Path(sys.argv[1]), sys.argv[2] == "1"

FAMILY = {
    "hf.co_mradermacher_XORTRON.CriminalComputing.2026.4B.Instruct.NEXT-i1-GGUF_i1-Q4_K_M":
        "hf.co/mradermacher/XORTRON.CriminalComputing.2026.4B.Instruct.NEXT-i1-GGUF:i1-Q4_K_M",
    "hf.co_mradermacher_XORTRON.CriminalComputing.2026.27B.Instruct.NEXT-i1-GGUF_i1-Q4_K_M":
        "hf.co/mradermacher/XORTRON.CriminalComputing.2026.27B.Instruct.NEXT-i1-GGUF:i1-Q4_K_M",
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
            runs.setdefault(tier, []).append(
                {"score": d.get("total_score"), "cases": len(cases),
                 "run_id": d.get("transcript_run_id")}
            )
    if not runs:
        print(f"  {tag}\n     no stored results -- nothing to finalize")
        continue

    all_zero_cases = all(r["cases"] == 0 for rs in runs.values() for r in rs)
    summary = "  ".join(f"{t}={[r['score'] for r in rs]}" for t, rs in sorted(runs.items()))
    case_counts = "  ".join(f"{t}:{[r['cases'] for r in rs]}" for t, rs in sorted(runs.items()))

    if all_zero_cases:
        out = results / f"UNMEASURABLE_{slug}.status"
        payload = {
            "tag": tag, "status": "UNMEASURABLE",
            "reason": "llama-server crashes on this GGUF's embedded chat template "
                      "(minja lexer rejects a \\u2019 unicode escape) on every request; "
                      "the stored 0 is a transport failure, not a bad answer (see #2982)",
            "evidence": {t: rs for t, rs in runs.items()},
            "note": "confirmed live via /api/chat: "
                    "'llama-server process has terminated: exit status 1: error: lexer: "
                    "unknown escape character \\u'. Not a request-shape or "
                    "reasoning_effort issue -- the sibling build without .NEXT in the tag "
                    "(same qwen35 architecture) has no \\u escape in its template and "
                    "scores normally. Do not re-pull to re-derive this; fixing it needs a "
                    "corrected template in the upstream GGUF or a client-side template "
                    "override, neither of which this harness owns.",
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        print(f"  {tag}\n     {summary}   cases {case_counts}   -> UNMEASURABLE")
        if not dry:
            out.write_text(json.dumps(payload, indent=2))
        marked += 1
    else:
        print(f"  {tag}\n     {summary}   cases {case_counts}   -> has real cases, keep")
        ok += 1

print()
print(f"  {ok} row(s) carry real measurements; {marked} marked UNMEASURABLE")
if dry:
    print("  DRY_RUN -- nothing written")
EOF

log "XORTRON_NEXT_FINALIZE_COMPLETE"
