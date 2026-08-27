#!/usr/bin/env python3
"""Fail CI when a prose doc cites a repo path that does not exist in the tree.

The pointer-rot family kept recurring by hand: #2352, #2353, #2356/#2453,
#2455, #2357 (whose target doc #2367 then retired outright), and five docs'
worth of pointers invalidated by #1659 alone. PR #2367 proved the catchable
shape -- a script extracted every repo-path-like token from docs/** prose and
tested it against the tree, surfacing every dead citation in that sweep -- but
it ran once, manually, and nothing stopped the next dead pointer after it
(#2458). This is that script as a standing gate.

Scope, per #2458's acceptance criteria:

- files: docs/**/*.md plus the root README.md (widen the FILES spec rather
  than special-casing);
- tokens: inline-code spans and bare prose tokens containing a slash, and
  relative markdown link targets -- the shapes a reader will actually try to
  resolve. Symbol-level anchors are out of scope by construction (path exists
  is the bar: `path.py:42` and `path.py#L42` validate the path part);
- resolution convention matters and is origin-aware, because the two shapes
  resolve differently everywhere they can be clicked or followed:
  * markdown link targets resolve the way GitHub renders them -- relative to
    the linking document (`../README.md` from docs/ reaches the root README);
  * backticked spans and bare prose tokens are repo-rooted citations -- a
    backticked `analysis/geoip/` in any doc claims that path from the repo
    root, wherever the sentence sits;
  resolution is against git-tracked paths only (the index), so a citation is
  judged against what a fresh checkout actually gets;
- code-comment references are out of scope: prose docs only.

Escape hatches, kept explicit rather than per-run judgement:

- host-side paths that only exist on a deployed machine (`/opt/...`,
  `/var/dockge/...`, anything absolute) are excluded by the leading-slash
  rule; host-side trees whose names collide with tracked prefixes are listed
  in HOST_ONLY;
- anything still unresolvable-but-correct takes a line in
  scripts/doc-path-lint-allowlist.txt with its reason inline -- deliberate
  historical references inside era records resolve or get an entry, they do
  not pass silently (#2367's era records went through exactly this choice).

Honest limitations, kept visible rather than hidden:

- tokens with placeholders (`<stack>`, `$VAR`, braces) or globs (`*.sh`)
  describe patterns, not paths, and are skipped -- a pattern citation cannot
  be verified mechanically and pretending otherwise would teach the lint to
  lie;
- a first segment that is not itself a tracked path is treated as not a repo
  path at all (branch names, `owner/repo` GitHub refs, CIDRs, image refs,
  URLs) -- that filter is what keeps the bare-prose rule quiet on prose that
  merely looks slashy. It deliberately does NOT apply to link targets: a
  relative link is a pointer by construction, so it is checked whatever it
  names;
- section anchors inside link targets and line anchors on cited files are
  not validated -- only the path is (per #2458).

Usage: python scripts/check-doc-paths-exist.py [--dump]
  --dump prints every extracted token and its verdict, exits 0 -- the
  calibration view used for #2458's zero-findings acceptance check.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
ALLOWLIST = ROOT / "scripts" / "doc-path-lint-allowlist.txt"

# Host-side trees whose names collide with tracked top-level prefixes, so the
# first-segment filter alone cannot screen them out (#2458's escape-hatch
# list). Keep this to names that are genuinely deploy-host-only.
HOST_ONLY = {"state"}

# Inline-code spans (single backticks, no spaces) -- a span with a space is a
# command fragment, not a path.
CODE_SPAN = re.compile(r"`([^`\s]+)`")
# Bare prose token with at least one slash; `*` is allowed through so a glob
# mention in prose reaches normalize(), which drops it whole instead of
# leaving a truncated path behind.
BARE_PATH = re.compile(r"(?<![\w/.\-])([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.*-]+)+)")
# Whole markdown link/image construct: [text](target). The link is checked
# by its target; the text (backticked or not) is a rendered label and is
# removed from the line so it is never re-checked as a span or bare token
# with repo-root semantics it does not have.
LINK = re.compile(r"!?\[([^\]]*)\]\(([^)\s]+)\)")
LINE_ANCHOR = re.compile(r"^(.+?)(?::\d+(?::\d+)?|#L\d+|:\d+[-.]\d+)+$")


def load_allowlist() -> dict[str, str]:
    """Exact-token entries -> reason, parsed from `token # reason` lines."""
    waived: dict[str, str] = {}
    if not ALLOWLIST.exists():
        return waived
    for raw in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        token, _, reason = line.partition("#")
        token = token.strip()
        if not token:
            continue
        waived[token] = (reason.strip() or "(no reason given)").strip()
    return waived


def load_tracked() -> tuple[set[str], set[str]]:
    """(tracked file paths, every tracked directory prefix)."""
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    files = set(out)
    dirs: set[str] = set()
    for path in files:
        parts = Path(path).parts
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]))
    return files, dirs


def normalize(token: str, require_slash: bool = True) -> str | None:
    """Clean a token for repo-root comparison; None = not a repo path."""
    token = token.strip()
    token = re.sub(r"^(?:\./)+", "", token)
    token = token.split("#", 1)[0]  # path exists is the bar; anchors are not
    while token and token[-1] in ".,;:!?'\")]}":
        token = token[:-1]
    match = LINE_ANCHOR.match(token)
    if match:
        token = match.group(1)
    while token and token[-1] in ".,;:!?'\")]}":
        token = token[:-1]
    if token.startswith("/") or (require_slash and "/" not in token):
        return None
    if re.search(r"[@<>{}$`|\\*\s]", token):
        return None
    if token.endswith("/"):
        token = token.rstrip("/")
    return token or None


def extract(text: str) -> list[tuple[str, str]]:
    """(raw token, kind) pairs from one document's text.

    kind is "span" (backticked), "link" (markdown link target), or "bare"
    (plain prose). Links are removed from the line first -- target checked,
    rendered text dropped -- so a link's label is never re-extracted as a
    span or bare token with repo-root semantics it does not have.
    """
    found: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line
        while True:
            match = LINK.search(stripped)
            if match is None:
                break
            target = match.group(2)
            if "://" not in target and not target.startswith(("#", "/")):
                found.append((target, "link"))
            stripped = stripped[: match.start()] + " " + stripped[match.end() :]
        for span in CODE_SPAN.findall(stripped):
            found.append((span, "span"))
        stripped = CODE_SPAN.sub(" ", stripped)
        found.extend((tok, "bare") for tok in BARE_PATH.findall(stripped))
    return found


def candidates(token: str, kind: str, doc: Path) -> list[str]:
    """Repo-rooted paths a token could claim, in origin-aware order.

    Markdown links are stricter than prose: any relative target -- with or
    without a directory component -- is a pointer GitHub will try to
    resolve, so it is checked even when it names a bare sibling file, and
    the not-a-repo-path first-segment screen does not apply to them.
    """
    norm = normalize(token, require_slash=(kind != "link"))
    if norm is None:
        return []
    # Markdown links resolve the way GitHub renders them: relative to the
    # linking document. A ../ citation in prose claims the same doc-relative
    # path implicitly. A ./ command example in prose, though, is a "run this
    # from the checkout root" instruction -- repo-rooted.
    if kind == "link" or token.startswith("../"):
        base = os.path.normpath(os.path.join(doc.parent.relative_to(ROOT), norm))
        return [base]
    return [norm]


def resolves(path: str, files: set[str], dirs: set[str]) -> bool:
    if path in files or path in dirs:
        return True
    prefix = f"{path}/"
    return any(f.startswith(prefix) for f in files) or any(d.startswith(prefix) for d in dirs)


def main() -> int:
    dump = "--dump" in sys.argv[1:]
    files, dirs = load_tracked()
    waived = load_allowlist()

    findings: list[str] = []
    seen: dict[str, str] = {}
    waived_seen: set[str] = set()
    for doc in FILES:
        if not doc.exists():
            findings.append(f"{doc.relative_to(ROOT)}: expected file is missing")
            continue
        rel = doc.relative_to(ROOT).as_posix()
        for token, kind in extract(doc.read_text(encoding="utf-8", errors="replace")):
            paths = candidates(token, kind, doc)
            if not paths:
                continue
            if token in waived or any(p in waived for p in paths):
                seen[paths[-1]] = "allowlisted"
                waived_seen.add(paths[-1])
                continue
            first = paths[0].split("/", 1)[0]
            if kind != "link" and (
                first in HOST_ONLY or (first not in dirs and first not in files)
            ):
                continue
            hit = next((p for p in paths if resolves(p, files, dirs)), None)
            if hit is not None:
                seen.setdefault(hit, "exists")
                continue
            seen.setdefault(paths[0], "MISSING")
            findings.append(f"{rel}: {kind} '{token}' -> no tracked path '{paths[0]}'")

    if dump:
        for token in sorted(seen, key=str.lower):
            print(f"  {token}  [{seen[token]}]")
        missing = sum(1 for v in seen.values() if v == "MISSING")
        print(f"{len(seen)} tokens resolved/allowlisted, {missing} distinct missing")
        return 0

    if findings:
        print("docs cite repo paths that do not exist (tracked-path check):")
        print("\n".join(f"  - {f}" for f in findings))
        print(
            "\nFix the citation, or if the reference is deliberate (era "
            "record, host-only layout, untracked-by-design file), add the "
            "exact token with its reason to "
            "scripts/doc-path-lint-allowlist.txt"
        )
        return 1

    print(
        "doc path existence check passed "
        f"({len(FILES)} files, {len(seen)} tokens, "
        f"{len(waived_seen)} allowlisted)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
