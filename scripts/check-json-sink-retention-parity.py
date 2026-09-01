#!/usr/bin/env python3
"""Fail CI when a JSON-emitting /logs directory lacks either retention half.

The #120 contract is two-sided: each JSON-emitting sensor self-rotates its
sink into generations with a digit-leading suffix, and
honeypot-utilities' log-maintenance.sh prunes those generations once they
age past the shared window. #2196 shipped because mailoney broke BOTH
halves at once -- its sink appended forever AND no pruner glob existed --
and nothing structural would have caught either omission; only a person
reading compose volumes next to pruner code next to vendored sensors
could connect them. This script is that connection, checked mechanically
on every push.

The ROWS ledger below is deliberately hand-written rather than inferred:
it documents WHERE each half lives for every rotating sink we know about,
so adding a sensor means adding one reviewable row, and forgetting either
half fails here naming exactly which half is missing. Two sides per row:

- "writer": where the rotation implementation itself lives, proven by a
  grep token in that subtree (a knob name or rotate() definition);
- "glob": the exact pruner find-line fragment log-maintenance.sh must
  carry for that directory.

The reverse check keeps the ledger honest too: every `find /logs/<dir>`
line in the pruner must be claimed by some row, so pruning coverage
cannot silently grow an unledgered entry (or lose one).

#2216 review: the two checks above only see the halves an author already
remembered to touch. A brand-new stack that bind-mounts a log directory,
appends a `.json` sink into it forever, adds no pruner line and no ROW
passed all of them, which is exactly the drift acceptance criterion 4 of
that issue asks this script to fail on. So there is a third check, and it
starts from the one artifact a new stack cannot omit and still reach disk:
its compose bind mount. Every `/opt/stacks/apiary/logs/<dir>` mount under
arcane/home/*/compose.yml must be accounted for by name -- as a ROWS
directory, an EXEMPT entry with a written reason, or a KNOWN_UNCOVERED
entry naming the issue that tracks it. Anything else fails.

Two supporting rules keep that enumeration from rotting:

- a `-name` glob is credited only to the `find` line for its OWN
  directory, so moving one onto a neighbouring line (leaving a directory
  unpruned while every glob string still appears somewhere in the file)
  fails instead of passing;
- a ROWS/EXEMPT/KNOWN_UNCOVERED entry for a directory nothing mounts any
  more is reported as stale, so a retired stack takes its ledger entry
  with it.

Usage: python scripts/check-json-sink-retention-parity.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAINTENANCE = ROOT / "arcane" / "home" / "honeypot-utilities" / "analysis" / "log-maintenance.sh"
STACKS = ROOT / "arcane" / "home"
SKIP_DIRS = {"vendor", "node_modules"}

# Host side of every sensor log bind mount, and where the maintenance
# container sees it (honeypot-utilities/compose.yml mounts the whole parent).
LOGS_HOST_ROOT = "/opt/stacks/apiary/logs"
LOGS_CONTAINER_ROOT = "/logs"

# One row per self-rotating JSON directory under /logs.
# "writer" is (subtree to search, proof tokens); tokens are strings the
# rotation implementation cannot sensibly drop without stopping being one.
# http-honeypot's single binary serves both http.json and api.json (#120:
# see its persona_test.go) -- hence two rows sharing one writer.
ROWS = [
    {
        "dir": "/logs/cowrie",
        "globs": ["'cowrie.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-cowrie", ["CowrieDailyLogFile"]),
    },
    {
        "dir": "/logs/multipot",
        "globs": ["'multipot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-multipot/multipot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/http-honeypot",
        "globs": ["'http.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-http/http-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/api-honeypot",
        "globs": ["'api.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-http/http-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/enriched",
        "globs": ["'*.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dashboard/backend-service/src/ip_enrichment",
                   ["OUTPUT_MAX_BYTES"]),
    },
    {
        "dir": "/logs/dionaea",
        "globs": ["'dionaea.json.[0-9]*'", "'dionaea_incident.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dionaea/dionaea",
                   ["DIONAEA_LOG_MAX_BYTES"]),
    },
    {
        "dir": "/logs/mailoney",
        "globs": ["'mailoney.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-mailoney/mailoney",
                   ["MAILONEY_JSON_MAX_BYTES"]),
    },
    # #2323: the two zeek-proxy directories prune on the same two-sided
    # contract, but their writer half is Zeek's own rotation/extraction
    # (site scripts, not a Go knob), so the proof tokens are the redef /
    # hook that would have to disappear for the half to stop existing.
    {
        "dir": "/logs/zeek-proxy",
        "globs": ["'*.log'"],
        "writer": ("arcane/home/honeypot-elk/zeek-proxy",
                   ["Log::default_rotation_interval"]),
    },
    {
        "dir": "/logs/zeek-proxy-extract",
        "globs": ["'*.bin'"],
        "writer": ("arcane/home/honeypot-elk/zeek-proxy",
                   ["extract_filename"]),
    },
    # #2216: nine writers had neither half at all until this pass -- see
    # that issue for the fleet-wide audit. Each got the same self-rotator
    # multipot/http-honeypot already carry (LOG_MAX_BYTES + a rotate()
    # closing/renaming/reopening the sink), so the proof tokens match.
    {
        "dir": "/logs/rdp-honeypot",
        "globs": ["'rdp-honeypot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-rdp-honeypot/rdp-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/citrix-honeypot",
        "globs": ["'citrix-honeypot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-citrix-honeypot/citrix-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/dns-honeypot",
        "globs": ["'dns-honeypot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dns-honeypot/dns-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/cisco-asa-honeypot",
        "globs": ["'cisco-asa-honeypot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-cisco-asa-honeypot/cisco-asa-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/dicompot",
        "globs": ["'dicompot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dicompot/dicompot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/dnp3",
        "globs": ["'dnp3.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dnp3/dnp3-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/endlessh",
        "globs": ["'endlessh.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-endlessh/endlessh-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/canarytokens",
        "globs": ["'canarytokens.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-canarytokens/canarytokens-adapter",
                   ["LOG_MAX_BYTES", "func rotateLog()"]),
    },
    {
        "dir": "/logs/tftp-relay",
        "globs": ["'sessions.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dionaea/tftp-relay",
                   ["LOG_MAX_BYTES", "func (r *relay) rotateSessionLog()"]),
    },
]

# Mounted log directories that are deliberately outside the two-sided
# contract. Each reason has to say what the directory actually holds and why
# nothing needs pruning it -- "it looked fine" is not a reason, and a wrong
# one here is how a sink hides in plain sight.
EXEMPT = {
    "/logs/cowrie/downloads":
        "attacker payload corpus, not an event sink -- files are content-"
        "addressed by hash and are the evidence the payload workers index; "
        "deleting them on a log schedule would delete the samples.",
    "/logs/cowrie/lib-cowrie":
        "cowrie's own state directory (userdb, fs pickle), not a log stream.",
    "/logs/cowrie/tty":
        "recorded TTY session casts, served by the dashboard's replay view; "
        "same evidence reasoning as downloads/.",
    "/logs/mailoney/mail":
        "captured .eml bodies, already pruned by their own retention line "
        "(MAILONEY_MAIL_RETENTION_DAYS, #2196 part 2) rather than a JSON glob.",
    "/logs/dashboard-backend":
        "backend-service's own durable JSONL sink (obs.rs). Self-bounded "
        "rather than pruned: audit::rotate_if_oversized keeps exactly one "
        "retired .1 generation and deletes the previous one, capping the "
        "directory at 2 x MAX_SINK_BYTES (<=50MiB) with nothing left to age "
        "out (#2468).",
    "/logs/dashboard-backend-mounted":
        "the same obs.rs sink under the honeypot-dashboard project's own "
        "mount name; identical self-bounding (#2468).",
    "/logs/suricata":
        "written on the VPS, mounted read-only here for Filebeat. Its "
        "retention is vps/suricata-log-maintenance.sh's eve-*.json prune, "
        "which is where the writer is (#79/#113).",
    "/logs/suricata/pcap":
        "VPS-written pcap, read-only here; retention is the pcap sync "
        "window, not a JSON glob (#1737).",
    "/logs/arkime-raw":
        "Arkime's own pcap store (log.pcap.<epoch>), reclaimed by Arkime's "
        "freeSpaceG rather than by find -- deleting these behind its back "
        "would leave its session index pointing at nothing (#1737).",
    "/logs/zeek-extract":
        "legacy read-only mount kept for honeypot-payload-analysis; nothing "
        "in the fleet mounts it writable and it is empty on the live host -- "
        "carved files land in /logs/zeek-proxy-extract, which has its own "
        "row above (#2323).",
    "/logs/snare":
        "snare's runtime directory: a .cfg/.uuid/.pid plus a text snare.log "
        "and snare.err. No JSON event sink -- SNARE's events reach ES through "
        "tanner, not through this mount.",
    "/logs/tanner":
        "tanner.log/tanner.err text logs plus a static tanner_report.json "
        "the app writes once at startup; no appended event stream.",
}

# Mounted log directories that DO carry an unbounded or half-covered sink and
# are not fixed yet. This list is debt, not an exemption: it exists so the
# enumeration above can fail on a genuinely new stack today instead of
# waiting for the whole fleet to be clean first. Every entry names the issue
# that tracks it, and closing that issue means deleting the entry.
KNOWN_UNCOVERED = {
    "/logs/sentrypeer": "sentrypeer.json, 87.9MB and growing, vendored writer (#2826)",
    "/logs/beelzebub": "beelzebub.json, 84.6MB and growing, vendored writer (#2826)",
    "/logs/conpot": "conpot.json (32.1MB) has neither half; only conpot.log rotates (#2826)",
    "/logs/conpot-s7-1200": "same conpot.json gap as /logs/conpot (#2826)",
    "/logs/conpot-s7-1500": "same conpot.json gap as /logs/conpot (#2826)",
    "/logs/conpot-iec104": "same conpot.json gap as /logs/conpot (#2826)",
    "/logs/conpot-guardian": "same conpot.json gap as /logs/conpot (#2826)",
    "/logs/conpot-kamstrup": "same conpot.json gap as /logs/conpot (#2826)",
    "/logs/hellpot": "HellPot.log (11.4MB) is in neither the rotate() list nor a glob (#2826)",
    "/logs/galah": "event_log.json, no writer-side rotation, no glob (#2826)",
    "/logs/elasticpot":
        "writer half only -- self-rotates daily to elasticpot.json.<date>, but "
        "no find line prunes the generations (#2826)",
    "/logs/canarytokens/frontend":
        "vendored Canarytokens app's own frontend.log; the /logs/canarytokens "
        "prune line is -maxdepth 1 and cannot reach it (#2826)",
    "/logs/canarytokens/switchboard":
        "vendored Canarytokens app's own switchboard.log, same -maxdepth 1 "
        "reach problem (#2826)",
    "/logs/dashboard-bff":
        "the BFF tier's app.jsonl -- obs.server.ts mirrors obs.rs's shape but "
        "not its rotate_if_oversized, so this one is unbounded (#2826)",
}


def pruner_find_lines(text: str) -> dict[str, set[str]]:
    """Maps each `/logs/...` directory the pruner walks to the -name globs
    that line credits to IT, quotes stripped.

    Attribution is per line on purpose. Testing a glob against the whole
    file's text (as this script did before #2216's review) cannot tell
    `find /logs/tftp-relay -name 'sessions.json.[0-9]*'` from the same glob
    pasted onto /logs/dicompot's line, which leaves tftp-relay unpruned.
    """
    found: dict[str, set[str]] = {}
    for line in text.splitlines():
        match = re.search(r"\bfind\s+(/logs/\S+)", line)
        if not match:
            continue
        globs = {
            name.strip("'\"")
            for name in re.findall(r"-name\s+('[^']*'|\"[^\"]*\"|\S+)", line)
        }
        found.setdefault(match.group(1), set()).update(globs)
    return found


def mounted_log_dirs() -> dict[str, list[str]]:
    """Every `/opt/stacks/apiary/logs/<dir>` bind mount in the stacks, keyed
    by the container-side path the pruner would use, valued by where the
    mount is declared.

    The bare parent mount (`/opt/stacks/apiary/logs:/logs`, used by
    log-maintenance, Filebeat and ip-enrichment to see everything at once)
    names no individual sink and is skipped.
    """
    mount = re.compile(
        rf"^\s*-\s*[\"']?({re.escape(LOGS_HOST_ROOT)}(?:/[^:\"'\s]+)?)\s*:"
    )
    mounts: dict[str, list[str]] = {}
    for compose in sorted(STACKS.glob("*/compose.yml")):
        for number, line in enumerate(compose.read_text().splitlines(), 1):
            match = mount.match(line)
            if not match:
                continue
            host = match.group(1)
            if host == LOGS_HOST_ROOT:
                continue
            container = LOGS_CONTAINER_ROOT + host[len(LOGS_HOST_ROOT):]
            mounts.setdefault(container, []).append(
                f"{compose.relative_to(ROOT)}:{number}")
    return mounts


def tree_contains(rel_root: str, needle: str) -> bool:
    base = ROOT / rel_root
    if base.is_file():
        return needle in base.read_text(encoding="utf-8", errors="replace")
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if SKIP_DIRS.intersection(path.parts):
            continue
        try:
            if needle in path.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


def main() -> int:
    findings: list[str] = []
    maintenance_text = MAINTENANCE.read_text()
    pruned = pruner_find_lines(maintenance_text)
    mounts = mounted_log_dirs()

    for row in ROWS:
        row_id = f"{row['dir']} ({', '.join(row['globs'])})"
        for glob in row["globs"]:
            if glob.strip("'\"") not in pruned.get(row["dir"], set()):
                findings.append(
                    f"pruner half missing: {MAINTENANCE.relative_to(ROOT)} has "
                    f"no `find {row['dir']} ... -name {glob}` line"
                )
        rel_root, tokens = row["writer"]
        for token in tokens:
            if not tree_contains(rel_root, token):
                findings.append(
                    f"writer half missing: no rotation implementation carrying "
                    f"{token!r} found under {rel_root} (row {row_id})"
                )

    # Reverse direction: claim every find line the pruner actually carries.
    for find_dir in sorted(pruned):
        if not any(find_dir == row["dir"] or find_dir.startswith(row["dir"] + "/")
                   for row in ROWS):
            findings.append(
                f"unledgered pruner line: log-maintenance.sh runs `find {find_dir}` "
                f"but no ROW claims it -- add a parity row for it"
            )

    # #2216 acceptance criterion 4: a new stack's mount is the thing that
    # cannot be omitted, so start the enumeration there rather than from the
    # halves an author remembered to edit.
    ledgered = {row["dir"] for row in ROWS} | set(EXEMPT) | set(KNOWN_UNCOVERED)
    for mounted, origins in sorted(mounts.items()):
        if mounted in ledgered:
            continue
        findings.append(
            f"unledgered log mount: {origins[0]} bind-mounts {mounted} but "
            f"nothing accounts for it -- add a ROWS entry (it self-rotates "
            f"and is pruned), an EXEMPT reason (it needs neither), or a "
            f"KNOWN_UNCOVERED entry naming the issue that tracks the gap"
        )

    # ...and drop the entry when the stack goes. A ledger nobody prunes
    # starts describing a fleet that no longer exists (wordpot, #2469).
    for stale, source in (("ROWS", {row["dir"] for row in ROWS}),
                          ("EXEMPT", set(EXEMPT)),
                          ("KNOWN_UNCOVERED", set(KNOWN_UNCOVERED))):
        for entry in sorted(source - set(mounts)):
            findings.append(
                f"stale ledger entry: {stale} claims {entry} but no "
                f"arcane/home/*/compose.yml mounts it any more -- remove it"
            )

    if findings:
        print("JSON sink retention parity check failed:", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print(f"JSON sink retention parity check passed "
          f"({len(ROWS)} rotating directories, both halves present; "
          f"{len(mounts)} mounted log directories all accounted for, "
          f"{len(KNOWN_UNCOVERED)} of them known-uncovered).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
