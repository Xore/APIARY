"""#1609 Phase 0: a systemd-invoked script must be executable in git.

This is the guard for the failure that opened #1609 in the first place.

`analysis/backup-honeypot.sh` is the ExecStart of `backup-honeypot.service`,
fired nightly by a timer. It lost its executable bit on the live host, so every
run since died with:

    Failed at step EXEC spawning .../backup-honeypot.sh: Permission denied
    (status 203/EXEC)

Nothing noticed for days. That script is what copies the stack's secrets off
the box, so the repeated "secrets have been lost across reinstalls" symptom
#1609 was opened to investigate had this as its actual mechanism.

Restoring the bit on the live host fixed the instance. It did not fix the
cause: the file was still mode 100644 *in git*, so the next deploy from a fresh
checkout would have reintroduced it. This test asserts the mode at the source.

systemd's ExecStart requires the executable bit -- it does not fall back to
running the file through a shell the way `bash foo.sh` does, which is why this
class of breakage is silent for scripts invoked this way and harmless for
scripts invoked any other way. So the check is deliberately scoped to ExecStart
targets rather than every .sh in the repo: most scripts here are legitimately
non-executable because something calls them with an explicit interpreter.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# ExecStart lines point at the *deployed* path. Anything under the deployed
# checkout maps back to a repo-relative file whose git mode we control.
DEPLOYED_CHECKOUT_PREFIXES = ("/opt/stacks/apiary/", "/var/dockge/stacks/apiary/")

EXECSTART_RE = re.compile(r"^\s*ExecStart=-?(?P<path>/\S+)", re.MULTILINE)


def _tracked_unit_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "*.service"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout
    return [REPO / p for p in out.split("\0") if p]


def _git_mode(rel: str) -> str | None:
    out = subprocess.run(
        ["git", "ls-files", "-s", "--", rel],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout.strip()
    return out.split()[0] if out else None


def _execstart_scripts() -> list[tuple[str, str]]:
    """(unit file, repo-relative script) for every ExecStart inside the checkout."""
    found: list[tuple[str, str]] = []
    for unit in _tracked_unit_files():
        text = unit.read_text(encoding="utf-8", errors="replace")
        for m in EXECSTART_RE.finditer(text):
            path = m.group("path")
            for prefix in DEPLOYED_CHECKOUT_PREFIXES:
                if path.startswith(prefix):
                    rel = path[len(prefix):]
                    if rel.endswith((".sh", ".py")):
                        found.append((str(unit.relative_to(REPO)), rel))
    return found


def test_execstart_targets_are_executable_in_git():
    """Every in-checkout ExecStart target is mode 100755 in the index."""
    offenders = []
    for unit, rel in _execstart_scripts():
        if not (REPO / rel).exists():
            offenders.append(f"{unit}: ExecStart target {rel} does not exist in the repo")
            continue
        mode = _git_mode(rel)
        if mode != "100755":
            offenders.append(
                f"{unit}: ExecStart target {rel} is git mode {mode}, not 100755 -- "
                f"systemd will fail it with 203/EXEC (Permission denied). "
                f"Fix with: git update-index --chmod=+x {rel}"
            )
    assert not offenders, "systemd ExecStart targets not executable in git:\n  " + "\n  ".join(offenders)


def test_the_backup_script_specifically_is_executable():
    """The #1609 regression itself, named explicitly so it cannot be lost in a refactor."""
    rel = "analysis/backup-honeypot.sh"
    assert (REPO / rel).exists(), f"{rel} is gone; if it moved, update this test and #1609's history"
    assert _git_mode(rel) == "100755", (
        f"{rel} is not executable in git. This is the exact regression that made "
        f"backup-honeypot.service fail 203/EXEC nightly and is the mechanism behind "
        f"#1609's repeated secret loss."
    )


def test_the_check_finds_something():
    """Guard against the scan silently matching nothing and passing vacuously."""
    assert _execstart_scripts(), (
        "no in-checkout ExecStart targets found at all -- the unit-file scan or the "
        "deployed-path prefixes have drifted, so this test would pass without checking anything"
    )
