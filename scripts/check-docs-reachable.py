#!/usr/bin/env python3
"""Fail CI when a doc under docs/ cannot be reached from docs/README.md (#3332).

check-doc-paths-exist.py (#2458) already proves every relative link resolves.
What it cannot see is the opposite failure: a doc nothing links to. On
2026-09-26, 54 of 120 docs were unreachable from the documentation map --
runbooks included (HOST-TUNING.md, llm-worker/README.md,
deploy-profiles/README.md) -- so a reader starting at the map never found them.

Reachability is transitive: a doc counts if any chain of relative markdown
links from docs/README.md leads to it, so a component README can index its
own subtree. Only git-tracked files are considered, as in #2458.

Record trees are exempt as a whole -- they accumulate dated entries by design
and are read by date or by issue, not browsed from the map:

  docs/research/                            per-CVE / per-topic research notes
  docs/benchmarks/                          dated benchmark plans, runs, claim pools
  docs/sandbox/windows/vm-detection-results/ per-run VM-detection captures
  docs/design-lab/                          duplicate of branding/design-lab (#3310)
  docs/archive/                             retired docs kept for history

Anything else unreachable fails: link it from the map (or from a README the
map reaches), or move it into a record tree if that is what it is.

Usage: python scripts/check-docs-reachable.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
START = ROOT / "docs" / "README.md"
EXEMPT = (
    "docs/research/",
    "docs/benchmarks/",
    "docs/sandbox/windows/vm-detection-results/",
    "docs/design-lab/",
    "docs/archive/",
)
# Relative link targets ending in .md, anchors allowed and ignored.
LINK = re.compile(r"\]\(\s*<?([^)\s>#]+\.md)>?(?:#[^)]*)?\s*\)")


def tracked_docs() -> set[Path]:
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "docs/*.md", "docs/**/*.md"],
        check=True, capture_output=True, text=True,
    ).stdout
    return {(ROOT / line).resolve() for line in out.splitlines() if line}


def main() -> int:
    docs = tracked_docs()
    seen = {START.resolve()}
    queue = [START.resolve()]
    while queue:
        page = queue.pop()
        for target in LINK.findall(page.read_text(encoding="utf-8", errors="replace")):
            if "://" in target:
                continue
            resolved = (page.parent / target).resolve()
            if resolved in docs and resolved not in seen:
                seen.add(resolved)
                queue.append(resolved)
    unreachable = sorted(
        rel for rel in (str(p.relative_to(ROOT)) for p in docs - seen)
        if not rel.startswith(EXEMPT)
    )
    if unreachable:
        print("docs not reachable from docs/README.md (link them from the map, or from a README it reaches):")
        for rel in unreachable:
            print(f"  - {rel}")
        return 1
    print(f"docs reachability check passed ({len(seen)} reachable, {len(docs) - len(seen)} in exempt record trees)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
