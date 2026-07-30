#!/usr/bin/env python3
"""
generate_report.py — step 13 of the run cycle: turn one detonation's artifact
directory into a report a human can read.

    generate_report.py <run_dir> [--pdf]

Reads the Phase 6 artifact tree written by run_sample.py and extract_iocs.py,
and writes report.html beside it (plus report.pdf with --pdf, if a renderer is
installed).

Three rules shape everything below.

**No network.** Not for fonts, not for stylesheets, not for enrichment. This
runs on the analysis host next to output that live malware produced, and a
report generator that phones out is a report generator that leaks which samples
you detonated and when. The CSS is inlined; there are no external references of
any kind.

**Every string here is attacker-controlled.** Sample filenames, registry paths,
HTTP URIs, process command lines — all of it was chosen by the thing being
analysed. It is escaped exactly once, at the moment it is placed into markup,
by `esc()`. Nothing reaches the output any other way.

**Absence is normal.** A sample that never touched the network leaves no
zeek_logs/. A guest that crashed leaves no regshot diff. Every section
degrades to "not observed" rather than raising, because a partial report is
evidence and a traceback is not.
"""

import argparse
import csv
import html
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

# Long attacker-controlled values (a base64 PowerShell cradle, a 4 KB URI) are
# truncated for display only. The full value stays in the artifact files, which
# are what you grep; the report is for reading.
MAX_CELL = 300

# Per-section row caps. A sample in a loop can emit a hundred thousand registry
# writes, and a report nobody can open is a report nobody reads. Whenever a cap
# bites, the section says so and names the file holding the rest — a silent
# truncation would read as "that is all that happened".
MAX_ROWS = 200


def esc(value, limit: int = MAX_CELL) -> str:
    """The single escaping chokepoint. Everything rendered goes through here."""
    text = "" if value is None else str(value)
    if len(text) > limit:
        text = text[:limit] + " …[truncated]"
    return html.escape(text, quote=True)


def read_json(path: Path):
    """Missing or corrupt artifacts are a normal outcome, not an error."""
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("could not read %s: %s", path.name, exc)
        return None


def read_jsonl(path: Path, limit: int = 5000) -> list:
    """Suricata's eve.json and Zeek's JSON logs are one object per line, and a
    truncated final line is expected when the capture is stopped mid-write."""
    out = []
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if len(out) >= limit:
                    break
    except FileNotFoundError:
        return []
    except OSError as exc:
        log.warning("could not read %s: %s", path.name, exc)
    return out


# ── Sections ────────────────────────────────────────────────────────────────
# Each returns a finished HTML fragment. Each is responsible for its own
# "not observed" case, so the caller never has to know which artifacts a
# particular run happened to produce.


def section(title: str, body: str, note: str = "") -> str:
    note_html = f'<p class="note">{esc(note, 500)}</p>' if note else ""
    return f"<section><h2>{esc(title)}</h2>{note_html}{body}</section>"


def empty(reason: str) -> str:
    return f'<p class="empty">{esc(reason, 500)}</p>'


def table(headers: list, rows: list, source: str = "") -> str:
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
        more = (
            f'<p class="note">Showing {len(capped)} of {len(rows)}'
            + (f" — the full set is in {esc(source)}" if source else "")
            + ".</p>"
        )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{more}"


def header_section(run_dir: Path, meta: dict) -> str:
    """What was detonated, when, and for how long. Without the observation
    window an empty report is ambiguous: a sample that did nothing and a sample
    that was watched for four seconds look identical."""
    if not meta:
        return section(
            "Sample",
            empty("metadata.json is missing — this directory may not be a completed run."),
        )
    rows = [
        ("SHA-256", meta.get("sha256", run_dir.name)),
        ("Filename as captured", meta.get("filename")),
        ("Detonated at", meta.get("detonated_at")),
        ("Observation window", f"{meta.get('observation_secs', '?')} s"),
    ]
    body = "".join(
        f"<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>" for label, value in rows
    )
    return section("Sample", f"<table class='kv'><tbody>{body}</tbody></table>")


def process_section(iocs: dict) -> str:
    """Sysmon event ID 1. The parent/child relationship is the single most
    useful thing in the report: it is what distinguishes a dropper from its
    payload and shows which living-off-the-land binary was abused."""
    procs = (iocs or {}).get("sysmon", {}).get("processes") or []
    rows = [
        (p.get("utc_time") or p.get("UtcTime"),
         p.get("parent") or p.get("ParentImage"),
         p.get("image") or p.get("Image"),
         p.get("command_line") or p.get("CommandLine"))
        for p in procs
    ]
    return section(
        "Process activity (Sysmon ID 1)",
        table(["time", "parent", "image", "command line"], rows, "sysmon.evtx"),
        "Parent → child. A chain that starts at the sample and ends in "
        "powershell.exe, rundll32.exe or mshta.exe is worth reading in full.",
    )


def network_section(run_dir: Path, iocs: dict) -> str:
    """Everything the sample tried to reach. Note that all of it was answered
    by INetSim — a resolved name here means the sample asked, not that the name
    exists or that anyone answered it in the real world."""
    summary = (iocs or {}).get("summary", {})
    parts = []

    dns = [(d,) for d in summary.get("unique_dns_domains", [])]
    parts.append("<h3>DNS queries</h3>" + table(["domain"], dns, "ioc_extracted.json"))

    ips = [(ip,) for ip in summary.get("unique_remote_ips", [])]
    parts.append("<h3>Remote addresses</h3>" + table(["address"], ips, "ioc_extracted.json"))

    urls = [(u,) for u in summary.get("unique_download_urls", [])]
    parts.append("<h3>Download URLs</h3>" + table(["url"], urls, "ioc_extracted.json"))

    # Zeek's http.log is the fuller record when the gateway ran; the IOC file
    # only keeps what matched a pattern.
    http_rows = []
    for entry in read_jsonl(run_dir / "zeek_logs" / "http.log"):
        http_rows.append((
            entry.get("ts"),
            entry.get("method"),
            entry.get("host"),
            entry.get("uri"),
            entry.get("status_code"),
        ))
    parts.append(
        "<h3>HTTP requests (Zeek)</h3>"
        + table(["ts", "method", "host", "uri", "status"], http_rows, "zeek_logs/http.log")
    )

    pcap = run_dir / "network.pcap"
    if pcap.exists():
        size = pcap.stat().st_size
        parts.append(
            f'<p class="note">Raw capture: network.pcap, {size} bytes. '
            "The logs above are derived from it; the pcap is the primary record.</p>"
        )

    return section(
        "Network",
        "".join(parts),
        "The sandbox bridge has no route to the internet. Every response the "
        "sample received came from INetSim, so nothing here reached a real host.",
    )


def alerts_section(run_dir: Path) -> str:
    """Suricata on the bridge. Signature hits are a starting point, not a
    verdict — the traffic they fired on was answered by a simulator."""
    rows = []
    for entry in read_jsonl(run_dir / "suricata_alerts.json"):
        if entry.get("event_type") != "alert":
            continue
        alert = entry.get("alert", {})
        rows.append((
            entry.get("timestamp"),
            alert.get("signature"),
            alert.get("category"),
            alert.get("severity"),
            f"{entry.get('src_ip')} → {entry.get('dest_ip')}:{entry.get('dest_port')}",
        ))
    return section(
        "Suricata alerts",
        table(["timestamp", "signature", "category", "severity", "flow"], rows,
              "suricata_alerts.json"),
    )


def filesystem_section(run_dir: Path) -> str:
    """What the sample left behind, from two angles: the files actually
    recovered from the guest, and Procmon's view of the writes."""
    parts = []

    drops = run_dir / "file_drops"
    dropped = sorted(p for p in drops.glob("**/*") if p.is_file()) if drops.is_dir() else []
    parts.append(
        "<h3>Recovered file drops</h3>"
        + table(
            ["path", "bytes"],
            [(p.relative_to(drops).as_posix(), p.stat().st_size) for p in dropped],
            "file_drops/",
        )
    )

    # Procmon exports are large and their column names vary by version, so
    # index by header name and skip rows that do not carry the ones we need.
    writes = []
    procmon = run_dir / "procmon.csv"
    if procmon.exists():
        try:
            with procmon.open(encoding="utf-8", errors="replace", newline="") as handle:
                for row in csv.DictReader(handle):
                    operation = (row.get("Operation") or "").strip()
                    if operation not in {"WriteFile", "CreateFile", "SetRenameInformationFile"}:
                        continue
                    writes.append((row.get("Time of Day"), row.get("Process Name"),
                                   operation, row.get("Path")))
        except OSError as exc:
            log.warning("could not read procmon.csv: %s", exc)
    parts.append(
        "<h3>File operations (Procmon)</h3>"
        + table(["time", "process", "operation", "path"], writes, "procmon.csv")
    )

    return section("Filesystem", "".join(parts))


def registry_section(run_dir: Path) -> str:
    """Regshot's before/after diff, verbatim. It is already a plain-text
    report; re-parsing it would only introduce a way to get it wrong."""
    diff = run_dir / "regshot_diff.txt"
    if not diff.exists():
        return section("Registry delta", empty("no regshot diff was produced"))
    try:
        text = diff.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return section("Registry delta", empty(f"could not read regshot_diff.txt: {exc}"))
    lines = text.splitlines()
    shown = lines[:MAX_ROWS * 5]
    note = ""
    if len(lines) > len(shown):
        note = f"Showing {len(shown)} of {len(lines)} lines — the rest is in regshot_diff.txt."
    return section(
        "Registry delta",
        f"<pre>{esc(chr(10).join(shown), limit=400000)}</pre>",
        note,
    )


def powershell_section(iocs: dict) -> str:
    """Script-block logging (4104) is the one place a fileless stage has to
    become readable text, so it earns its own section."""
    ps = (iocs or {}).get("powershell", {})
    cradles = [(c,) for c in ps.get("download_cradles", [])]
    urls = [(u,) for u in ps.get("ps_urls", [])]
    body = (
        "<h3>Download cradles</h3>"
        + table(["script block"], cradles, "powershell_scriptblock.evtx")
        + "<h3>URLs seen in script blocks</h3>"
        + table(["url"], urls, "powershell_scriptblock.evtx")
    )
    return section("PowerShell (4104)", body)


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
pre { font-size: .78rem; overflow-x: auto; padding: .6rem;
      border: 1px solid rgba(128,128,128,.45); }
.note { font-size: .8rem; opacity: .75; margin: .3rem 0; }
.empty { font-size: .85rem; opacity: .6; font-style: italic; margin: .3rem 0; }
.banner { border: 1px solid rgba(128,128,128,.45); padding: .6rem .8rem;
          font-size: .82rem; margin: 1rem 0 0; }
footer { margin-top: 3rem; font-size: .78rem; opacity: .65; }
"""


def build_html(run_dir: Path) -> str:
    meta = read_json(run_dir / "metadata.json") or {}
    iocs = read_json(run_dir / "ioc_extracted.json") or {}
    sha = meta.get("sha256", run_dir.name)

    sections = "".join([
        header_section(run_dir, meta),
        process_section(iocs),
        network_section(run_dir, iocs),
        alerts_section(run_dir),
        filesystem_section(run_dir),
        registry_section(run_dir),
        powershell_section(iocs),
    ])

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Sandbox report — {esc(sha[:16])}</title>
<style>{CSS}</style>
</head>
<body>
<h1>Windows sandbox report</h1>
<p class="note">{esc(sha)}</p>
<div class="banner">Generated offline on the analysis host from artifacts in
<code>{esc(run_dir.name)}</code>. Every value below was produced by, or in
response to, untrusted code: treat filenames, URLs and registry paths as
attacker-controlled input, not as facts.</div>
{sections}
<footer>xore//honeypot — generated {esc(generated)} — no network access was used
to produce this report.</footer>
</body>
</html>
"""


def to_pdf(html_path: Path, pdf_path: Path) -> bool:
    """PDF is optional on purpose. The renderers that produce a good one pull
    in a browser engine or most of a typesetting stack, and putting that on the
    analysis host to prettify a report is a poor trade. HTML is the artifact
    that always exists; this is a convenience when WeasyPrint happens to be
    installed."""
    try:
        from weasyprint import HTML  # type: ignore
    except ImportError:
        log.warning(
            "weasyprint is not installed — report.html was written, report.pdf was not. "
            "Install it only if a PDF is genuinely needed."
        )
        return False
    try:
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
    except Exception as exc:  # rendering failures must not lose the HTML report
        log.error("PDF rendering failed (report.html is unaffected): %s", exc)
        return False
    return True


def build_report(run_dir: Path, pdf: bool = False) -> Path:
    if not run_dir.is_dir():
        raise SystemExit(f"not a run directory: {run_dir}")
    html_path = run_dir / "report.html"
    html_path.write_text(build_html(run_dir), encoding="utf-8")
    log.info("wrote %s", html_path)
    if pdf and to_pdf(html_path, run_dir / "report.pdf"):
        log.info("wrote %s", run_dir / "report.pdf")
    return html_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render a Windows sandbox detonation directory as a report."
    )
    parser.add_argument("run_dir", help="Artifact directory for one sample (named by SHA-256)")
    parser.add_argument("--pdf", action="store_true",
                        help="Also write report.pdf, if WeasyPrint is installed")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    print(build_report(Path(args.run_dir), pdf=args.pdf))
    return 0


if __name__ == "__main__":
    sys.exit(main())
