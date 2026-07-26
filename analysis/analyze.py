#!/usr/bin/env python3
"""Summarise honeypot activity from Cowrie + http-honeypot JSON logs.

Reads newline-delimited JSON (Cowrie's cowrie.json and the http-honeypot's
http.json) and prints a triage report: who hit you, what credentials they
tried, what commands they ran, and what URLs they probed.

Stdlib only — runs anywhere Python 3.8+ is installed, no pip needed.

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
                        continue
        except OSError as e:
            print(f"! skipping {fn}: {e}", file=sys.stderr)


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
            if e.get("event") == "login":
                self.login_failed += 1
        cmd = e.get("command")
        if cmd:
            self.mp_commands[f"[{proto}] {cmd}"] += 1


    def add_generic(self, e):
        """Third-party sensors (Dionaea, Conpot, …) — count by source IP."""
        ip = (e.get("src_ip") or e.get("remote_host") or e.get("source_ip")
              or e.get("src_ip_addr") or e.get("peer_ip"))
        if ip:
            self.src_ips[ip] += 1
            self.total += 1
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
    return e.get("sensor") == "http-honeypot" or "category" in e


def print_table(title, counter, top, cols=("count", "value")):
    print(f"\n== {title} ==")
    if not counter:
        print("  (none)")
        return
    width = max(len(str(v)) for v, _ in counter.most_common(top))
    for value, count in counter.most_common(top):
        print(f"  {count:>6}  {value}")


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
