#!/usr/bin/env python3
"""Create a bounded JSON summary from untrusted powered-off guest output."""

import argparse
import collections
import json
import re
import subprocess
import zipfile
from datetime import datetime
from pathlib import Path

MAX_TEXT = 32768
MAX_LINES = 200
MAX_BUNDLE_FILE = 1024 * 1024
MAX_BUNDLE_TOTAL = 8 * 1024 * 1024
BUNDLE_FILES = (
    "report.json", "stdout.txt", "stderr.txt", "runner.log",
    "processes-before.txt", "processes-after.txt",
    "sockets-before.txt", "sockets-after.txt",
    "files-created-or-changed.tsv", "kernel.txt", "classification.json",
    "classification-error.txt", "pe-forensics.json", "pe-forensics-error.txt",
    "exiftool.txt", "pe-objdump.txt", "authenticode.txt",
    "strings-ascii.txt", "strings-utf16le.txt", "console.log", "qemu.log",
    "domain-state.txt", "qemu-status.txt", "tcpdump.log", "guest-tcpdump.log",
)


def text(path: Path, limit=MAX_TEXT):
    try:
        return path.read_bytes()[:limit].decode("utf-8", "replace")
    except OSError:
        return ""


def lines(path: Path, limit=MAX_LINES):
    return text(path, 131072).splitlines()[:limit]


def json_object(path: Path, limit=131072):
    try:
        value = json.loads(text(path, limit))
        return value if isinstance(value, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def hash_value(path: Path):
    return text(path, 256).split(" ", 1)[0].strip().lower()


def diagnostics_path(output: Path):
    if output.name.endswith(".json.new"):
        return output.with_name(output.name[:-9] + ".diagnostics.zip.new")
    if output.name.endswith(".json"):
        return output.with_name(output.name[:-5] + ".diagnostics.zip")
    return output.with_name(output.name + ".diagnostics.zip")


def write_diagnostics_bundle(result: Path, output: Path):
    total = 0
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in BUNDLE_FILES:
            path = result / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                data = path.read_bytes()[:MAX_BUNDLE_FILE]
            except OSError:
                continue
            if total + len(data) > MAX_BUNDLE_TOTAL:
                break
            archive.writestr(name, data)
            total += len(data)
    output.chmod(0o640)


def pe_forensics(path: Path):
    try:
        raw = json.loads(text(path, 524288))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(raw, dict) or not raw.get("detected"):
        return {}

    def bounded(value, limit=256):
        return str(value)[:limit]

    sections = []
    for item in raw.get("sections", [])[:96]:
        if isinstance(item, dict):
            sections.append({
                "name": bounded(item.get("name", ""), 32),
                "virtual_address": int(item.get("virtual_address", 0)),
                "virtual_size": int(item.get("virtual_size", 0)),
                "raw_size": int(item.get("raw_size", 0)),
                "entropy": float(item.get("entropy", 0)),
                "characteristics": bounded(item.get("characteristics", ""), 16),
            })
    imports = []
    for item in raw.get("imports", [])[:128]:
        if isinstance(item, dict):
            imports.append({
                "dll": bounded(item.get("dll", "")),
                "symbols": [bounded(name) for name in item.get("symbols", [])[:256]],
            })
    suspicious = {}
    if isinstance(raw.get("suspicious_imports"), dict):
        for group, names in list(raw["suspicious_imports"].items())[:32]:
            suspicious[bounded(group, 64)] = [bounded(name) for name in names[:64]]
    return {
        "detected": True,
        "machine": bounded(raw.get("machine", ""), 16),
        "pe_type": bounded(raw.get("pe_type", ""), 16),
        "compile_timestamp": bounded(raw.get("compile_timestamp", ""), 64),
        "entry_point": int(raw.get("entry_point", 0)),
        "image_base": int(raw.get("image_base", 0)),
        "subsystem": int(raw.get("subsystem", 0)),
        "dll": bool(raw.get("dll", False)),
        "imphash": bounded(raw.get("imphash", ""), 64),
        "signature_present": bool(raw.get("signature_present", False)),
        "sections": sections,
        "imports": imports,
        "exports": [bounded(name) for name in raw.get("exports", [])[:512]],
        "suspicious_imports": suspicious,
        "warnings": [bounded(item, 512) for item in raw.get("warnings", [])[:50]],
        "truncated": bool(raw.get("truncated", False)),
    }


def parse_time(value):
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def pcap_summary(path: Path):
    summary = {"packets": 0, "bytes": 0, "protocols": {}, "events": [], "attempts": []}
    try:
        summary["bytes"] = path.stat().st_size
        completed = subprocess.run(
            ["tcpdump", "-nn", "-tttt", "-c", "5000", "-r", str(path)],
            capture_output=True, text=True, timeout=20, check=False,
        )
        events = completed.stdout.splitlines()
        summary["packets"] = len(events)
        summary["events"] = events[:200]
        protocols = collections.Counter()
        for line in events:
            if " ARP," in line:
                protocols["ARP"] += 1
            elif " IP6 " in line:
                protocols["IPv6"] += 1
            elif " ICMP" in line:
                protocols["ICMP"] += 1
            elif " UDP," in line:
                protocols["UDP"] += 1
            elif " Flags [" in line:
                protocols["TCP"] += 1
            elif " IP " in line:
                protocols["IPv4"] += 1
            else:
                protocols["other"] += 1
        summary["protocols"] = dict(protocols)
    except (OSError, subprocess.SubprocessError):
        pass
    return summary


def dns_pcap_summary(path: Path):
    summary = {"queries": [], "events": []}
    try:
        completed = subprocess.run(
            ["tcpdump", "-nn", "-vvv", "-c", "5000", "-r", str(path), "port", "53"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        for line in completed.stdout.splitlines()[:1000]:
            event = line[:2048]
            summary["events"].append(event)
            match = re.search(r"\b(?:A|AAAA|CNAME|MX|NS|PTR|SOA|SRV|TXT)\?\s+([^\s]+)", line)
            if match:
                name = match.group(1).rstrip(".")[:253]
                if name and name not in summary["queries"]:
                    summary["queries"].append(name)
    except (OSError, subprocess.SubprocessError):
        pass
    summary["queries"] = summary["queries"][:500]
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    result = Path(args.result).resolve(strict=True)
    root = Path("/var/lib/honeypot-sandbox/results").resolve(strict=True)
    if result.parent != root:
        raise SystemExit("result path escaped sandbox results root")
    report = json.loads((result / "report.json").read_text(encoding="utf-8"))

    calls = collections.Counter()
    inet_connects = []
    for trace in sorted((result / "trace").glob("strace.*"))[:64]:
        for line in lines(trace, 20000):
            match = re.search(r"\s([A-Za-z_][A-Za-z0-9_]*)\(", line)
            if match:
                calls[match.group(1)] += 1
                if match.group(1) == "connect" and ("sa_family=AF_INET," in line or "sa_family=AF_INET6," in line):
                    inet_connects.append(line[:1024])

    changed = lines(result / "files-created-or-changed.tsv")
    network = pcap_summary(result / "network.pcap")
    guest_network = pcap_summary(result / "guest-network.pcap")
    network["guest_packets"] = guest_network["packets"]
    network["guest_pcap_bytes"] = guest_network["bytes"]
    network["guest_protocols"] = guest_network["protocols"]
    network["guest_events"] = guest_network["events"]
    dns = dns_pcap_summary(result / "guest-network.pcap")
    dns_queries = dns["queries"]
    network["dns_queries"] = dns_queries
    network["dns_events"] = dns["events"]
    network["attempts"] = inet_connects[:100]
    windows = pe_forensics(result / "pe-forensics.json")
    classification = json_object(result / "classification.json")
    if windows:
        windows["execution_mode"] = text(result / "execution-mode.txt", 64).strip()
        windows["authenticode"] = text(result / "authenticode.txt", 8192)
        windows["ascii_strings"] = lines(result / "strings-ascii.txt", 300)
        windows["utf16_strings"] = lines(result / "strings-utf16le.txt", 300)
    started_at = text(result / "host-started-at.txt", 128).strip() or text(result / "started-at.txt", 128).strip()
    completed_at = report.get("completed_at", "")
    started, completed = parse_time(started_at), parse_time(completed_at)
    duration_seconds = max(0, round((completed - started).total_seconds(), 3)) if started and completed else 0
    exit_status = str(report.get("exit_status", "unknown"))
    timeout_reason = "host deadline" if (result / "host-timeout.txt").exists() else ("guest execution deadline" if exit_status in ("124", "137") else "")
    guest_started = (result / "started-at.txt").exists()
    run_status = "failed" if timeout_reason or not guest_started else "completed"
    failure_reason = ""
    if timeout_reason == "host deadline" and not guest_started:
        failure_reason = "The virtual machine did not reach the guest analysis service before the host deadline."
    elif timeout_reason:
        failure_reason = f"Analysis exceeded the {timeout_reason}."
    elif not guest_started:
        failure_reason = "The guest analysis service did not produce a result."

    techniques = []
    technique_ids = set()
    def technique(identifier, name, evidence):
        if identifier not in technique_ids:
            technique_ids.add(identifier)
            techniques.append({"id": identifier, "name": name, "evidence": evidence[:256]})

    changed_text = "\n".join(changed).lower()
    if "authorized_keys" in changed_text:
        technique("T1098.004", "SSH Authorized Keys", "authorized_keys changed")
    if "/etc/cron" in changed_text or "systemd/system" in changed_text:
        technique("T1053.003", "Cron", "scheduled task or service path changed")
    if calls["execve"] or calls["execveat"]:
        technique("T1059", "Command and Scripting Interpreter", "execve/execveat observed")
    if inet_connects or network["packets"]:
        technique("T1046", "Network Service Discovery", "connect syscall or network packets observed")
    if calls["chmod"] or calls["fchmod"] or calls["fchmodat"]:
        technique("T1222.002", "Linux File Permissions Modification", "chmod-family syscall observed")
    if calls["unlink"] or calls["unlinkat"]:
        technique("T1070.004", "File Deletion", "unlink-family syscall observed")
    suspicious_imports = windows.get("suspicious_imports", {}) if windows else {}
    if suspicious_imports.get("process injection"):
        technique("T1055", "Process Injection", "PE imports process-injection APIs")
    if suspicious_imports.get("process execution"):
        technique("T1106", "Native API", "PE imports process-execution APIs")
    if suspicious_imports.get("network transfer"):
        technique("T1105", "Ingress Tool Transfer", "PE imports network-transfer APIs")
    if suspicious_imports.get("registry modification"):
        technique("T1112", "Modify Registry", "PE imports registry-modification APIs")
    if suspicious_imports.get("credential access"):
        technique("T1003", "OS Credential Dumping", "PE imports credential-access APIs")
    if suspicious_imports.get("anti-analysis"):
        technique("T1497", "Virtualization/Sandbox Evasion", "PE imports anti-analysis APIs")

    risk_score = 5
    risk_score += min(20, len(changed) // 5)
    risk_score += 15 if inet_connects else 0
    risk_score += 10 if network["packets"] else 0
    risk_score += 25 if any(item["id"] in ("T1098.004", "T1053.003") for item in techniques) else 0
    risk_score += 20 if any(calls[name] for name in ("setuid", "setgid", "mount", "ptrace", "bpf")) else 0
    risk_score += min(25, 5 * len(suspicious_imports))
    risk_score += 10 if dns_queries else 0
    risk_score += 15 if timeout_reason else 0
    risk_score = min(100, risk_score)
    risk_level = "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low"
    if not guest_started:
        risk_score = 0
        risk_level = "unrated"

    payload = {
        "version": 2,
        "job": report.get("job", result.name),
        "sha256": request["sha256"],
        "capture_name": request.get("capture_name", ""),
        "source": request.get("source", ""),
        "requested_at": request.get("requested_at", ""),
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": duration_seconds,
        "exit_status": exit_status,
        "run_status": run_status,
        "guest_started": guest_started,
        "failure_reason": failure_reason,
        "timeout_reason": timeout_reason,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "network": "isolated",
        "file_type": text(result / "file-type.txt", 2048).strip(),
        "platform": text(result / "platform.txt", 128).strip(),
        "analysis_path": text(result / "analysis-path.txt", 512).strip(),
        "execution_mode": text(result / "execution-mode.txt", 128).strip(),
        "classification": {
            "code": str(classification.get("code", ""))[:64],
            "label": str(classification.get("label", ""))[:128],
            "platform": str(classification.get("platform", ""))[:64],
            "category": str(classification.get("category", ""))[:64],
            "analysis_path": str(classification.get("analysis_path", ""))[:512],
            "dynamic": bool(classification.get("dynamic", False)),
        },
        "hashes": {
            "md5": hash_value(result / "sample.md5"),
            "sha1": hash_value(result / "sample.sha1"),
            "sha256": hash_value(result / "sample.sha256"),
        },
        "stdout": text(result / "stdout.txt"),
        "stderr": text(result / "stderr.txt"),
        "runner_log": text(result / "runner.log", 8192),
        "changed_files": changed,
        "sockets_before": lines(result / "sockets-before.txt", 100),
        "sockets_after": lines(result / "sockets-after.txt", 100),
        "top_syscalls": [{"name": name, "count": count} for name, count in calls.most_common(30)],
        "network_summary": network,
        "windows_forensics": windows,
        "artifacts": {
            "kernel": text(result / "kernel.txt", 4096),
            "exiftool": text(result / "exiftool.txt", 32768),
            "pe_objdump": text(result / "pe-objdump.txt", 65536),
            "processes_before": lines(result / "processes-before.txt", 250),
            "processes_after": lines(result / "processes-after.txt", 250),
            "host_tcpdump_log": text(result / "tcpdump.log", 8192),
            "guest_tcpdump_log": text(result / "guest-tcpdump.log", 8192),
            "classification_error": text(result / "classification-error.txt", 4096),
            "pe_forensics_error": text(result / "pe-forensics-error.txt", 4096),
            "console_log": text(result / "console.log", 32768),
            "qemu_log": text(result / "qemu.log", 32768),
            "domain_state": text(result / "domain-state.txt", 4096),
            "qemu_status": text(result / "qemu-status.txt", 4096),
            "host_phase": text(result / "host-phase.txt", 256).strip(),
        },
        "techniques": techniques,
        "truncated": True,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    output.chmod(0o640)
    write_diagnostics_bundle(result, diagnostics_path(output))


if __name__ == "__main__":
    main()
