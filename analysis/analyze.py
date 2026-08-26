#!/usr/bin/env python3
"""Summarise honeypot activity from Cowrie + http-honeypot JSON logs.

Reads newline-delimited JSON (Cowrie's cowrie.json and the http-honeypot's
http.json) and prints a triage report: who hit you, what credentials they
tried, what commands they ran, and what URLs they probed.

Stdlib only — runs anywhere Python 3.8+ is installed, no pip needed.

Human-readable output renders control characters visibly (<0x1b> and
friends) instead of emitting them: everything summarised here came off
the wire (#1984), and an attacker-supplied ESC sequence must not be able
to reposition or rewrite the analyst's terminal when the report runs.
The JSON export keeps the raw values — json.dump already escapes them.

Usage:
    python3 analyze.py /path/to/logdir
    python3 analyze.py cowrie.json http.json
    python3 analyze.py /var/log --top 15 --json summary.json

Tip: copy the logs out of the volume first, e.g.
    docker run --rm -v honeypot_honeypot-logs:/logs -v "$PWD":/out \\
        alpine sh -c 'cp /logs/*.json /out/'
"""

import argparse
import glob
import json
import os
import sys
from collections import Counter, defaultdict


def iter_events(paths):
    """Yield parsed JSON objects from every *.json file in the given paths."""
    files = []
    for p in paths:
        if os.path.isdir(p):
            files += glob.glob(os.path.join(p, "*.json"))
        else:
            files.append(p)
    if not files:
        sys.exit("no .json log files found in: " + ", ".join(paths))
    # Unparsable lines are counted, never silently dropped (#1985): a
    # truncated log used to shrink every table with no signal, reading
    # exactly like a quiet day. The summary prints once iteration ends --
    # the finally also catches an early exit -- so zero skips stay silent.
    skipped: dict[str, int] = {}
    try:
        for fn in sorted(set(files)):
            try:
                with open(fn, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            yield fn, json.loads(line)
                        except json.JSONDecodeError:
                            skipped[fn] = skipped.get(fn, 0) + 1
            except OSError as e:
                print(f"! skipping {fn}: {e}", file=sys.stderr)
    finally:
        for fn, n in sorted(skipped.items()):
            print(f"! skipped {n} unparsable line(s) in {fn}", file=sys.stderr)


# Every counted field is attacker-controlled (#1984): Cowrie records the
# username/password/command bytes clients actually send, http-honeypot the
# paths/user-agents they probe with. Printing any of these raw lets an ESC
# sequence execute against the *analyst's* terminal emulator — cursor moves,
# screen erasure, title rewriting, OSC 52 clipboard overwrite. Rendering
# each control character as its <0xNN> spelling keeps them visible as
# evidence while making them inert; plain <0xNN> text also survives
# terminals running under non-UTF-8 locales, unlike prettier glyphs.
_CONTROLS = "".join(map(chr, list(range(0x20)) + [0x7F] + list(range(0x80, 0xA0))))
_CONTROL_RENDERING = {ord(c): f"<0x{ord(c):02x}>" for c in _CONTROLS}


def _sanitize(value):
    """Render C0/C1 control characters as visible <0xNN> text."""
    return str(value).translate(_CONTROL_RENDERING)


class Stats:
    def __init__(self):
        self.src_ips = Counter()
        self.creds = Counter()          # "user / pass"
        self.usernames = Counter()
        self.passwords = Counter()
        self.commands = Counter()
        self.downloads = Counter()
        self.ssh_clients = Counter()    # SSH client version strings
        self.http_paths = Counter()
        self.http_categories = Counter()
        self.http_agents = Counter()
        self.protos = Counter()         # multipot: hits per protocol
        self.mp_commands = Counter()    # multipot: Redis/FTP/etc commands
        self.other_sensors = Counter()  # dionaea/conpot/etc: events per source
        self.sessions = set()
        self.login_success = 0
        self.login_failed = 0
        self.total = 0
        self.ips_by_source = defaultdict(Counter)  # ip -> {cowrie:n, http:n}

    def add_cowrie(self, e):
        self.total += 1
        eid = e.get("eventid", "")
        ip = e.get("src_ip")
        if ip:
            self.src_ips[ip] += 1
            self.ips_by_source[ip]["cowrie"] += 1
        if e.get("session"):
            self.sessions.add(("cowrie", e["session"]))

        if eid in ("cowrie.login.success", "cowrie.login.failed"):
            u = e.get("username", "")
            p = e.get("password", "")
            self.creds[f"{u} / {p}"] += 1
            self.usernames[u] += 1
            self.passwords[p] += 1
            if eid.endswith("success"):
                self.login_success += 1
            else:
                self.login_failed += 1
        elif eid == "cowrie.command.input":
            cmd = (e.get("input") or "").strip()
            if cmd:
                self.commands[cmd] += 1
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            url = e.get("url") or e.get("filename") or ""
            if url:
                self.downloads[url] += 1
        elif eid == "cowrie.client.version":
            v = e.get("version", "")
            if v:
                self.ssh_clients[v] += 1

    def add_http(self, e):
        # Skip the honeypot's own startup marker — it's not attacker traffic.
        if e.get("category") == "startup":
            return
        self.total += 1
        ip = e.get("src_ip")
        if ip:
            self.src_ips[ip] += 1
            self.ips_by_source[ip]["http"] += 1
        path = e.get("path")
        if path:
            self.http_paths[path] += 1
        cat = e.get("category")
        if cat:
            self.http_categories[cat] += 1
        ua = e.get("user_agent")
        if ua:
            self.http_agents[ua] += 1
        if e.get("username") or e.get("password"):
            u = e.get("username", "")
            p = e.get("password", "")
            self.creds[f"{u} / {p}"] += 1
            self.usernames[u] += 1
            self.passwords[p] += 1


    def add_multipot(self, e):
        # Skip the sensor's own lifecycle markers.
        if e.get("event") in ("listening", "multipot_started", "listen_error"):
            return
        self.total += 1
        ip = e.get("src_ip")
        proto = e.get("proto", "?")
        if ip:
            self.src_ips[ip] += 1
            self.ips_by_source[ip][proto] += 1
        self.protos[proto] += 1
        if e.get("event") == "login" or e.get("username") or e.get("password"):
            u = e.get("username", "")
            p = e.get("password", "")
            if u or p:
                self.creds[f"{u} / {p}"] += 1
                if u:
                    self.usernames[u] += 1
                if p:
                    self.passwords[p] += 1
            # "login" (ssh/telnet/...) and "auth_attempt" (VNC et al -- see
            # multipot's protocols.go) are both failures by construction;
            # counting only the first hid every VNC attempt (#1985).
            if e.get("event") in ("login", "auth_attempt"):
                self.login_failed += 1
        cmd = e.get("command")
        if cmd:
            self.mp_commands[f"[{proto}] {cmd}"] += 1


    def add_generic(self, e):
        """Third-party sensors (Dionaea, Conpot, …) — count by source IP."""
        # Every parsed event counts toward the header total, even records
        # with no address (#1985): other_sensors below already counts them,
        # so excluding them here made the two figures disagree.
        self.total += 1
        ip = (e.get("src_ip") or e.get("remote_host") or e.get("source_ip")
              or e.get("src_ip_addr") or e.get("peer_ip"))
        if ip:
            self.src_ips[ip] += 1
        conn = e.get("connection")
        label = e.get("sensor")
        if not label and isinstance(conn, dict):
            label = conn.get("protocol")        # Dionaea nests protocol here
        self.other_sensors[str(label or "unknown")] += 1
        u, p = e.get("username"), e.get("password")
        if u or p:
            self.creds[f"{u or ''} / {p or ''}"] += 1


def is_cowrie(e):
    return "eventid" in e and str(e["eventid"]).startswith("cowrie.")


def is_multipot(e):
    return e.get("sensor") == "multipot"


def is_http(e):
    s = e.get("sensor")
    if s:
        return s == "http-honeypot"
    # Unstamped legacy records fall back on actual HTTP fields -- never on
    # a bare "category", which any foreign sensor's event can carry (#1985).
    # That catch-all used to route the foreign event's IP into the http
    # column of ips_by_source and leak its values into three http tables.
    return "path" in e or "user_agent" in e


def print_table(title, counter, top):
    print(f"\n== {title} ==")
    if not counter:
        print("  (none)")
        return
    for value, count in counter.most_common(top):
        print(f"  {count:>6}  {_sanitize(value)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", default=["."],
                    help="log files or directories (default: current dir)")
    ap.add_argument("--top", type=int, default=10, help="rows per table (default 10)")
    ap.add_argument("--json", metavar="FILE", help="also write a JSON summary here")
    args = ap.parse_args()

    st = Stats()
    for _fn, e in iter_events(args.paths):
        if is_cowrie(e):
            st.add_cowrie(e)
        elif is_multipot(e):
            st.add_multipot(e)
        elif is_http(e):
            st.add_http(e)
        else:
            st.add_generic(e)

    print("=" * 60)
    print(" HONEYPOT ACTIVITY SUMMARY")
    print("=" * 60)
    print(f"  events parsed     : {st.total}")
    print(f"  unique source IPs : {len(st.src_ips)}")
    print(f"  sessions          : {len(st.sessions)}")
    print(f"  logins ok / failed: {st.login_success} / {st.login_failed}")

    print_table("Top source IPs", st.src_ips, args.top)
    print_table("Top credentials (user / pass)", st.creds, args.top)
    print_table("Top usernames", st.usernames, args.top)
    print_table("Top passwords", st.passwords, args.top)
    print_table("Hits per protocol (multipot)", st.protos, args.top)
    print_table("Other sensors (Dionaea/Conpot/…)", st.other_sensors, args.top)
    print_table("Service commands (multipot)", st.mp_commands, args.top)
    print_table("Top shell commands (Cowrie)", st.commands, args.top)
    print_table("Payload downloads (Cowrie)", st.downloads, args.top)
    print_table("SSH client versions", st.ssh_clients, args.top)
    print_table("Top HTTP paths", st.http_paths, args.top)
    print_table("HTTP probe categories", st.http_categories, args.top)
    print_table("Top HTTP user-agents", st.http_agents, args.top)

    if args.json:
        summary = {
            "events": st.total,
            "unique_src_ips": len(st.src_ips),
            "sessions": len(st.sessions),
            "login_success": st.login_success,
            "login_failed": st.login_failed,
            "top_src_ips": st.src_ips.most_common(args.top),
            "top_credentials": st.creds.most_common(args.top),
            "top_commands": st.commands.most_common(args.top),
            "top_http_paths": st.http_paths.most_common(args.top),
            "http_categories": st.http_categories.most_common(args.top),
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        print(f"\nwrote JSON summary -> {args.json}")


if __name__ == "__main__":
    main()
