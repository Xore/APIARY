#!/usr/bin/env python3
"""Grep-level guard for prose that still cites a moved tree at its old home.

The motivating instance (#2352): #1502 relocated the YARA scanner to
arcane/home/honeypot-payload-analysis/analysis/yara/ and updated its checker
script, but the surrounding prose was never given the same pass -- six
documents pointed readers at the dead repository-root path, and the operator
README's documented sync command failed verbatim from a fresh checkout.

Rule: outside arcane/**, a *.md may reference a relocated path's bare prefix
only when the SAME LINE also names the real location (so the reader is never
sent somewhere that does not exist), or when it carries a `stale-path-ok:`
waiver for genuinely historical narrative. Extend RETIRED_PATHS when the next
tree moves instead of writing another bespoke gate.
"""
import re
import sys
from pathlib import Path

RETIRED_PATHS = {
    "analysis/yara/": "arcane/home/honeypot-payload-analysis/analysis/yara/",
}
WAIVER = "stale-path-ok:"


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    findings = []
    for md in sorted(repo.rglob("*.md")):
        rel = md.relative_to(repo)
        parts = rel.parts
        if not parts:
            continue
        # Moved trees document themselves; vendored dirs are out of scope.
        if parts[0] in {"arcane", "node_modules"} or ".git" in parts:
            continue
        text = md.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            for retired, current in RETIRED_PATHS.items():
                if current in line or WAIVER in line:
                    continue
                if re.search(r"(?<![\w/.])" + re.escape(retired), line):
                    findings.append(
                        f"{rel}:{lineno}: cites '{retired}' at its pre-move "
                        f"location; name '{current}' on the same line (or add "
                        f"a '{WAIVER}' waiver)\n    {line.strip()[:140]}"
                    )
    if findings:
        print("docs still cite retired paths at their old home:")
        print("\n".join(findings))
        return 1
    print("doc stale-path check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
