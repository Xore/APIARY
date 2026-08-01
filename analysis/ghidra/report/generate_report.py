#!/usr/bin/env python3
"""
generate_report.py — phase 5 of IMPLEMENTATION_PLAN.md: turn one Ghidra
result into a report a human can read.

    generate_report.py <sha256> [--results-dir DIR] [--pdf]

Reads ``{results_dir}/{sha256}_ghidra.json`` (the file worker/ghidra-worker.py
writes) and writes ``{sha256}_ghidra_report.html`` beside it. Called two ways:

- As a library, from ghidra-worker.py, immediately after it collects a
  result — mirrors sandbox/windows/orchestrate/run_sample.py's
  ``from generate_report import build_report`` pattern exactly.
- Standalone, from the CLI, against an already-written result file.

Reuses sandbox/windows/orchestrate/generate_report.py's shape rather than
inventing a second reporting style, per #78: offline, one escaping
chokepoint, missing artifacts degrade to "not observed" instead of raising.

There is no separate templates/ directory (the earlier "target" layout in
IMPLEMENTATION_PLAN.md's architecture tree named one) — the #56 report this
follows does not use one either, and one Python file covering both HTML and
CSS is not enough code to be worth splitting.

**No network.** This runs on the analysis host next to output produced by
live malware. The CSS is inlined and the call graph SVG (if one exists) is
inlined too, rather than linked, so the report stays a single self-contained
file with no relative dependency on another file surviving alongside it.

**Every string in the result JSON is attacker-controlled** — function names,
signatures, strings, import names, AI triage prose all came from, or were
derived from, the sample. Escaped exactly once, at the moment it is placed
into markup, by `esc()`. Nothing reaches the output any other way.

**Absence is normal.** A result JSON without a call graph, AI triage, fuzzy
hashes, lief or capa output is the common case, not an error. Every section
degrades to "not observed" rather than raising, because a partial report is
evidence and a traceback is not.
"""

import argparse
import html
import json
import logging
import os
import sys
from pathlib import Path

log = logging.getLogger(__name__)

# Long attacker-controlled values (a function signature, a decoded string) are
# truncated for display only. The full value stays in the result JSON, which
# is what you grep; the report is for reading.
MAX_CELL = 300

# Per-section row caps. A stripped binary can have thousands of functions, and
# a report nobody can open is a report nobody reads. Whenever a cap bites, the
# section says so — a silent truncation would read as "that is all there is".
MAX_ROWS = 200


def esc(value, limit: int = MAX_CELL) -> str:
    """The single escaping chokepoint. Everything rendered goes through here."""
    text = "" if value is None else str(value)
    if len(text) > limit:
        text = text[:limit] + " …[truncated]"
    return html.escape(text, quote=True)


# ── Sections ────────────────────────────────────────────────────────────────
# Each returns a finished HTML fragment and is responsible for its own
# "not observed" case, so the caller never has to know which fields a
# particular result happened to carry.


def section(title: str, body: str, note: str = "") -> str:
    note_html = f'<p class="note">{esc(note, 500)}</p>' if note else ""
    return f"<section><h2>{esc(title)}</h2>{note_html}{body}</section>"


def empty(reason: str) -> str:
    return f'<p class="empty">{esc(reason, 500)}</p>'


def table(headers: list, rows: list, note: str = "") -> str:
    """Rows are lists of raw values; escaping happens here and nowhere else."""
    if not rows:
        return empty("not observed")
    capped = rows[:MAX_ROWS]
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{esc(cell)}</td>" for cell in row) + "</tr>"
        for row in capped
    )
    more = ""
    if len(rows) > len(capped):
        more = f'<p class="note">Showing {len(capped)} of {len(rows)}.</p>'
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{more}{note}"


def kv_table(pairs: list) -> str:
    rows = [(label, value) for label, value in pairs if value not in (None, "")]
    if not rows:
        return empty("not observed")
    body = "".join(
        f"<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>" for label, value in rows
    )
    return f"<table class='kv'><tbody>{body}</tbody></table>"


def header_section(result: dict) -> str:
    """What was analysed, by which analyzer version, and whether the service's
    own hash of what it received agrees with the filename. A disagreement
    there means the sample was substituted in transit — worth surfacing above
    the fold, not buried in a field nobody reads."""
    sha = result.get("sha256", "")
    service_sha = result.get("service_sha256", "")
    rows = [
        ("SHA-256", sha),
        ("Exit status", result.get("exit_status")),
        ("Requested at", result.get("requested_at")),
        ("Started at", result.get("started_at")),
        ("Completed at", result.get("completed_at")),
        ("Analyzer version", result.get("analyzer_version")),
        ("Artifact schema version", result.get("artifact_schema_version")),
    ]
    body = kv_table(rows)
    if result.get("exit_status") == "error":
        body += f'<div class="banner error">Analysis failed: {esc(result.get("error", ""))}</div>'
    if service_sha and sha and service_sha != sha:
        body += (
            '<div class="banner error">The analyzer\'s own hash of the sample it '
            f"received ({esc(service_sha)}) does not match the requested SHA-256 "
            f"({esc(sha)}). Treat this result as untrustworthy.</div>"
        )
    return section("Sample", body)


def functions_section(result: dict) -> str:
    funcs = sorted(
        result.get("functions") or [], key=lambda f: -(f.get("size") or 0)
    )
    rows = [
        (f.get("address"), f.get("name"), f.get("signature"), f.get("size"))
        for f in funcs
    ]
    note = ""
    if result.get("functions_truncated"):
        note = '<p class="note">The analyzer truncated the function list.</p>'
    return section(
        "Functions",
        table(["address", "name", "signature", "size"], rows, note),
        "Largest first.",
    )


def strings_section(result: dict) -> str:
    rows = [(s,) for s in (result.get("strings") or [])]
    return section("Strings", table(["value"], rows))


def imports_section(result: dict) -> str:
    rows = [(i,) for i in (result.get("imports") or [])]
    return section(
        "Imports",
        table(["library!name"], rows),
        "Dynamic symbols the sample resolves at load time.",
    )


def crypto_section(result: dict) -> str:
    hits = result.get("findcrypt") or []
    rows = [(h.get("address"), h.get("constant"), h.get("algorithm")) for h in hits]
    return section(
        "Cryptographic constants",
        table(["address", "constant", "algorithm"], rows),
        "Addresses are file offsets, not virtual addresses.",
    )


def call_graph_section(result: dict, results_dir: Path) -> str:
    """Inlined, not linked — see the module docstring on why this report has
    no relative dependency on another file surviving alongside it."""
    name = result.get("call_graph_svg") or ""
    if not name or name != Path(name).name:
        return section("Call graph", empty("not observed"))
    svg_path = results_dir / name
    try:
        svg = svg_path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("could not read %s: %s", svg_path, exc)
        return section("Call graph", empty("not observed"))
    if not svg.lstrip().startswith("<?xml") and not svg.lstrip().startswith("<svg"):
        # dot writes an XML/SVG file; anything else on disk under this name
        # was not produced by build_call_graph() and is not trusted for
        # verbatim inclusion.
        return section("Call graph", empty("not observed"))
    return section("Call graph", f'<div class="callgraph">{svg}</div>')


def fuzzy_hash_section(result: dict) -> str:
    fh = result.get("fuzzy_hashes")
    if not fh:
        return section("Fuzzy hashes", empty("not observed"))
    rows = [
        ("ssdeep", fh.get("ssdeep") or fh.get("ssdeep_error")),
        ("tlsh", fh.get("tlsh") or fh.get("tlsh_error")),
    ]
    return section("Fuzzy hashes", kv_table(rows))


def structural_section(result: dict) -> str:
    lief = result.get("lief")
    if not lief:
        return section("Structural info (lief)", empty("not observed"))
    rows = [
        ("Format", lief.get("format")),
        ("Architecture", lief.get("architecture")),
        ("Entry point", lief.get("entrypoint")),
        ("Position independent", lief.get("is_pie")),
        ("Section count", lief.get("section_count")),
        ("Libraries", ", ".join(lief.get("libraries") or []) or None),
    ]
    body = kv_table(rows)
    sec_rows = [
        (s.get("name"), s.get("size"), s.get("entropy")) for s in (lief.get("sections") or [])
    ]
    body += table(["name", "size", "entropy"], sec_rows)
    if lief.get("sections_truncated"):
        body += '<p class="note">The section list was truncated.</p>'
    return section("Structural info (lief)", body)


def capa_section(result: dict) -> str:
    capa = result.get("capa")
    if not capa:
        return section(
            "Capabilities (capa)",
            empty("not observed"),
            "capa's default backend covers x86/amd64/arm64 only — absent "
            "here also means an unsupported architecture (e.g. MIPS/ARM32, "
            "common in this honeypot's IoT catch), same as a sidecar that "
            "was unavailable (#78).",
        )
    rows = [
        ("Architecture", capa.get("arch")),
        ("OS", capa.get("os")),
        ("Format", capa.get("format")),
    ]
    body = kv_table(rows)

    cap_rows = [
        (c.get("name"), c.get("namespace"), c.get("matches"))
        for c in (capa.get("capabilities") or [])
    ]
    body += "<h3>Capabilities</h3>" + table(["name", "namespace", "matches"], cap_rows)
    if capa.get("capabilities_truncated"):
        body += '<p class="note">The capability list was truncated.</p>'

    attack_rows = [
        (a.get("id"), a.get("tactic"), a.get("technique"), a.get("subtechnique"))
        for a in (capa.get("attack") or [])
    ]
    body += "<h3>MITRE ATT&amp;CK</h3>" + table(
        ["id", "tactic", "technique", "subtechnique"], attack_rows)

    mbc_rows = [
        (m.get("id"), m.get("objective"), m.get("behavior"), m.get("method"))
        for m in (capa.get("mbc") or [])
    ]
    body += "<h3>Malware Behavior Catalog</h3>" + table(
        ["id", "objective", "behavior", "method"], mbc_rows)

    return section(
        "Capabilities (capa)",
        body,
        "Rule matches, not a verdict — a capability being tagged here means "
        "code implementing it was found, not that it necessarily ran.",
    )


def ai_triage_section(result: dict) -> str:
    triage = result.get("ai_triage")
    if not triage:
        return section(
            "AI triage",
            empty("not observed"),
            "Local-only by policy (#66/#103); absent when no local endpoint "
            "is configured or the model produced nothing usable.",
        )
    rows = [
        ("Workflow", triage.get("workflow")),
        ("Model", triage.get("model")),
        ("Family guess", triage.get("family_guess") or "none offered"),
        ("Risk level", triage.get("risk_level") or "unrated"),
    ]
    body = kv_table(rows)
    behaviors = [(b,) for b in (triage.get("behaviors") or [])]
    body += "<h3>Behaviors</h3>" + table(["behavior"], behaviors)
    if triage.get("evidence_shown"):
        body += f'<p class="note">Evidence shown to the model: {esc(triage["evidence_shown"], 500)}</p>'
    return section(
        "AI triage",
        body,
        "A local model's hypothesis grounded in the artifacts above, not a "
        "verdict — read it with the same skepticism as an analyst's first pass.",
    )


def revdeck_section(result: dict) -> str:
    rd = result.get("revdeck")
    if not rd:
        return section(
            "Rev·Deck automated triage",
            empty("not observed"),
            "A second, independent AI aid alongside AI triage above, driving "
            "Rev·Deck's own bounded autonomous tool-calling loop against the "
            "Ghidra service (#78); absent when REVDECK_API_BASE is unset, "
            "the sidecar was unreachable, or the run produced no usable "
            "answer.",
        )
    rows = [
        ("Workflow", rd.get("workflow")),
        ("Status", rd.get("status")),
        ("Steps", rd.get("steps")),
        ("Tool calls", rd.get("tool_calls")),
    ]
    body = kv_table(rows)

    body += "<h3>Answer</h3>"
    answer = rd.get("answer") or ""
    body += f"<p>{esc(answer, 8000)}</p>" if answer else empty("not observed")

    citations = rd.get("citations") or {}
    valid_rows = [(c,) for c in (citations.get("valid") or [])]
    invalid_rows = [(c,) for c in (citations.get("invalid") or [])]
    if valid_rows or invalid_rows:
        body += "<h3>Citations</h3>" + table(["valid"], valid_rows)
        if invalid_rows:
            body += table(["invalid"], invalid_rows)

    warning_rows = [(w,) for w in (rd.get("warnings") or [])]
    if warning_rows:
        body += "<h3>Warnings</h3>" + table(["warning"], warning_rows)

    return section(
        "Rev·Deck automated triage",
        body,
        "A second, independent AI aid — Rev·Deck's own bounded autonomous "
        "tool-calling loop against the Ghidra service, distinct from AI "
        "triage above. A \"max_turns\" status means the step budget ran out "
        "before the model finished; the answer is still its best-effort "
        "synthesis, kept rather than discarded, and worth reading with the "
        "same skepticism as any other unverified claim here.",
    )


CSS = """
:root { color-scheme: light dark; }
body { font: 14px/1.55 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
       margin: 0 auto; max-width: 60rem; padding: 2rem 1.25rem 5rem; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
h2 { font-size: 1.15rem; margin: 2.25rem 0 .5rem; padding-bottom: .3rem;
     border-bottom: 1px solid currentColor; }
h3 { font-size: .95rem; margin: 1.25rem 0 .4rem; opacity: .85; }
table { border-collapse: collapse; width: 100%; margin: .4rem 0;
        font-size: .82rem; display: block; overflow-x: auto; }
th, td { border: 1px solid rgba(128,128,128,.45); padding: .3rem .45rem;
         text-align: left; vertical-align: top; word-break: break-word; }
th { background: rgba(128,128,128,.14); font-weight: 600; }
table.kv { display: table; }
table.kv th { width: 14rem; }
.note { font-size: .8rem; opacity: .75; margin: .3rem 0; }
.empty { font-size: .85rem; opacity: .6; font-style: italic; margin: .3rem 0; }
.banner { border: 1px solid rgba(128,128,128,.45); padding: .6rem .8rem;
          font-size: .82rem; margin: 1rem 0 0; }
.banner.error { border-color: #b00020; }
.callgraph { overflow-x: auto; }
.callgraph svg { max-width: 100%; height: auto; }
footer { margin-top: 3rem; font-size: .78rem; opacity: .65; }
"""


def build_html(result: dict, results_dir: Path) -> str:
    sha = result.get("sha256", "")

    sections = "".join([
        header_section(result),
        functions_section(result),
        strings_section(result),
        imports_section(result),
        crypto_section(result),
        call_graph_section(result, results_dir),
        structural_section(result),
        fuzzy_hash_section(result),
        capa_section(result),
        ai_triage_section(result),
        revdeck_section(result),
    ])

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Ghidra report — {esc(sha[:16])}</title>
<style>{CSS}</style>
</head>
<body>
<h1>Ghidra analysis report</h1>
<p class="note">{esc(sha)}</p>
<div class="banner">Generated offline on the analysis host from
{esc(sha)}_ghidra.json. Every value below was produced by, or extracted
from, untrusted code: treat function names, strings and imports as
attacker-controlled input, not as facts.</div>
{sections}
<footer>xore//honeypot-stack — no network access was used to produce this
report.</footer>
</body>
</html>
"""


def to_pdf(html_path: Path, pdf_path: Path) -> bool:
    """PDF is optional on purpose, same reasoning as #56: the renderers that
    produce a good one pull in a browser engine or most of a typesetting
    stack. HTML is the artifact that always exists; this is a convenience
    when WeasyPrint happens to be installed."""
    try:
        from weasyprint import HTML  # type: ignore
    except ImportError:
        log.warning(
            "weasyprint is not installed - the HTML report was written, "
            "no PDF was. Install it only if a PDF is genuinely needed."
        )
        return False
    try:
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
    except Exception as exc:  # rendering failures must not lose the HTML report
        log.error("PDF rendering failed (the HTML report is unaffected): %s", exc)
        return False
    return True


def build_report(result: dict, results_dir: Path) -> str | None:
    """Render one Ghidra result as an HTML report next to it in results_dir.

    Returns the bare filename on success (the shape ghidra-worker.py's
    call_graph_svg field already uses), or None if nothing could be written.
    Called from the worker with the in-memory result it just collected, so
    this never re-reads the JSON it is about to describe.
    """
    sha = result.get("sha256", "")
    if not sha:
        log.error("result has no sha256; nothing to name the report after")
        return None
    filename = f"{sha}_ghidra_report.html"
    out_path = results_dir / filename
    tmp = results_dir / f".{filename}.tmp"
    try:
        tmp.write_text(build_html(result, results_dir), encoding="utf-8")
        os.replace(tmp, out_path)
        out_path.chmod(0o600)
    except OSError as exc:
        log.error("could not write %s: %s", out_path, exc)
        tmp.unlink(missing_ok=True)
        return None
    return filename


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render a Ghidra result JSON as a report."
    )
    parser.add_argument("sha256", help="Sample SHA-256 (result file is {sha256}_ghidra.json)")
    parser.add_argument(
        "--results-dir",
        default=os.environ.get("GHIDRA_RESULTS_DIR", "/ghidra-results"),
        help="Directory holding {sha256}_ghidra.json (default: $GHIDRA_RESULTS_DIR)",
    )
    parser.add_argument("--pdf", action="store_true",
                         help="Also write a .pdf, if WeasyPrint is installed")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    results_dir = Path(args.results_dir)
    result_path = results_dir / f"{args.sha256}_ghidra.json"
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"could not read {result_path}: {exc}")

    filename = build_report(result, results_dir)
    if filename is None:
        return 1
    print(results_dir / filename)
    if args.pdf:
        html_path = results_dir / filename
        pdf_path = results_dir / f"{args.sha256}_ghidra_report.pdf"
        if to_pdf(html_path, pdf_path):
            print(pdf_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
