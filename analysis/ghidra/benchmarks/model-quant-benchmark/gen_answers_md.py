#!/usr/bin/env python3
"""Format one corpus_eval.py result JSON into a GitHub-comment-ready
Markdown block (score table + collapsible full answers per case), for
posting model x quant-level results to #847.

Usage: gen_answers_md.py <result.json> <model label> > out.md
       gh issue comment 847 --repo Xore/APIARY --body-file out.md
"""
import json
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: gen_answers_md.py <result.json> <model label>")

path, model_label = sys.argv[1], sys.argv[2]
d = json.load(open(path))

lines = []
lines.append(f"## Full answers: `{model_label}`")
lines.append("")
lines.append(f"Score: **{d['total_score']}/{d['total_max']} ({d['pct']}%)**  |  elapsed: {d.get('elapsed_s', '?')}s")
lines.append("")
lines.append("| Slice | Score |")
lines.append("|---|---|")
for slice_key, v in d.get("per_slice", {}).items():
    lines.append(f"| {slice_key} | {v['score']}/{v['max']} |")
lines.append("")
lines.append("<details><summary>All 32 case answers (click to expand)</summary>")
lines.append("")
for c in d.get("cases", []):
    case = c.get("case", "?")
    slice_ = c.get("slice", "?")
    score = c.get("score")
    mx = c.get("max")
    inj_ok = c.get("inj_ok")
    completion = c.get("completion") or "*(no completion — error/timeout)*"
    lines.append(f"<details><summary><code>{case}</code> {slice_} — {score}/{mx}, inj_ok={inj_ok}</summary>")
    lines.append("")
    lines.append("```")
    lines.append(completion.strip())
    lines.append("```")
    lines.append("")
    lines.append("</details>")
    lines.append("")
lines.append("</details>")

print("\n".join(lines))
