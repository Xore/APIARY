#!/usr/bin/env python3
"""Exercise audit-sensor-event-coverage.py's extraction/matching logic
against small synthetic Go source, not the real sensors -- the real-tree
run (scripts/audit-sensor-event-coverage.py itself) is the audit; this is
what proves the regexes are correct in the first place.

Usage: scripts/tests/test_audit_sensor_event_coverage.py
"""
import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "audit-sensor-event-coverage.py"
spec = importlib.util.spec_from_file_location("audit_sensor_event_coverage", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

fails = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        fails.append(label)


def test_event_literal_extraction(tmp_path):
    src = tmp_path / "main.go"
    src.write_text(
        'log.emit(event{Event: "connect"})\n'
        'e := event{Event: "frame"}\n'
        'e.Event = "malformed_frame"\n'
        'h.log2(r, "get", reqPath, "")\n'
        'h.log2(r, "method_"+strings.ToLower(r.Method), reqPath, "")\n'
    )
    (tmp_path / "skip_test.go").write_text('event{Event: "should_not_appear"}')
    literal, dynamic = _emitted_kinds_direct(tmp_path)
    # "method_" itself is also captured as a literal prefix by LOG2_LITERAL_RE
    # (it's a real, if incomplete, quoted string in that call) -- the dynamic
    # set below is what actually flags it as unresolvable on its own.
    check(literal == {"connect", "frame", "malformed_frame", "get", "method_"}, f"extracts literal kinds, got {literal}")
    check(dynamic == {"method_*"}, f"flags the dynamic method_+ kind as unresolvable, got {dynamic}")
    check("should_not_appear" not in literal, "_test.go files are excluded")


def _emitted_kinds_direct(base_dir: Path):
    """emitted_kinds() takes a path relative to REPO_ROOT; call its regex
    logic directly against an absolute tmp dir instead of monkeypatching
    REPO_ROOT."""
    literal, dynamic_prefixes = set(), set()
    for go_file in base_dir.glob("*.go"):
        if go_file.name.endswith("_test.go"):
            continue
        text = go_file.read_text()
        for m in mod.EVENT_LITERAL_RE.finditer(text):
            literal.add(m.group(1) or m.group(2))
        for m in mod.LOG2_LITERAL_RE.finditer(text):
            literal.add(m.group(1))
        for m in mod.DYNAMIC_KIND_RE.finditer(text):
            import re
            prefix = re.search(r'"([a-zA-Z0-9_]*)"\s*\+', m.group(0))
            if prefix:
                dynamic_prefixes.add(prefix.group(1) + "*")
    return literal, dynamic_prefixes


def test_matched_kinds_and_fallback():
    section = '''
    if s, ok := e["sensor"].(string); ok && s == "x" {
        kind := str(e["event"])
        if kind == "listening" {
            ev.skip = true
            return ev
        }
        switch kind {
        case "connect":
            ev.detail = "connect"
        default:
            ev.detail = kind
        }
    }
    '''
    matched = mod.matched_kinds(section)
    check(matched == {"listening", "connect"}, f"matches both == comparisons and case labels, got {matched}")
    check(mod.has_generic_fallback(section) is True, "a switch default: counts as a generic fallback")

    no_fallback_section = 'if kind == "only_one" { ev.detail = "fixed text" }'
    check(mod.has_generic_fallback(no_fallback_section) is False, "no default/kind-concatenation means no fallback")


def test_section_extraction_stops_at_next_marker():
    real_section = mod.classify_section("dnp3-honeypot")
    check("dnp3-honeypot" in real_section, "finds the real dnp3-honeypot section in classify.go")
    check("dns-honeypot" not in real_section, "section extraction stops before the next '---- marker'")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        test_event_literal_extraction(Path(tmp))
    test_matched_kinds_and_fallback()
    test_section_extraction_stops_at_next_marker()
    if fails:
        print(f"\n{len(fails)} check(s) failed: {fails}")
        sys.exit(1)
    print("\nall checks passed")
