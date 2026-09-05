"""#1609 Phase 5: the two installers share one framework, and it behaves.

install-vps.sh's header used to state that its status/retry/step framework was
"identical to install-homeserver.sh, deliberately not reimplemented
differently". That claim was false, and the divergence was not cosmetic:

    if "$@"; then return 0; fi
    rc=$?

A plain if/fi with no else that takes neither branch has an exit status of zero
regardless of what the condition returned, so `rc=$?` read 0 for a command that
had just FAILED -- and on the final attempt the function did `return "$rc"`,
reporting success. Every with_retry call in that script was incapable of
reporting failure. install-homeserver.sh had carried the fix (`"$@" && return
0`) since #787; it was never ported.

#2963 fixed the copy and landed a parity test that compared the two bodies.
This file replaces that test: there is only one body now
(scripts/lib/install-common.sh), so parity is structural rather than asserted,
and what is worth testing is that the extraction is real, that the library
behaves, and that the one failure mode which made this extraction risky --
running from the copy outside the checkout, where a script-relative `source`
finds nothing and `set -u` without `-e` lets the run continue half-defined --
fails loudly instead.
"""

from __future__ import annotations

import re
import subprocess
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LIB = REPO / "scripts" / "lib" / "install-common.sh"
HOME_INSTALLER = REPO / "scripts" / "install-homeserver.sh"
VPS_INSTALLER = REPO / "scripts" / "install-vps.sh"
ENTRYPOINT = REPO / "scripts" / "install.sh"

SHARED_FUNCTIONS = ["with_retry", "run_step", "skip_step", "print_summary"]


def _defines(path: Path, name: str) -> bool:
    return re.search(rf"^{re.escape(name)}\(\)\s*\{{", path.read_text(encoding="utf-8"), re.MULTILINE) is not None


def test_library_defines_the_shared_framework():
    missing = [fn for fn in SHARED_FUNCTIONS if not _defines(LIB, fn)]
    assert not missing, f"install-common.sh is missing: {missing}"


def test_installers_no_longer_carry_their_own_copies():
    """The extraction #1609 Phase 5 asks for, asserted as an absence."""
    duplicated = [
        f"{p.name}:{fn}"
        for fn in SHARED_FUNCTIONS
        for p in (HOME_INSTALLER, VPS_INSTALLER)
        if _defines(p, fn)
    ]
    assert not duplicated, (
        "installer defines a framework function locally instead of using "
        f"scripts/lib/install-common.sh: {duplicated}"
    )


def test_with_retry_captures_the_real_exit_code():
    """The specific #787 defect, asserted by shape so it cannot come back."""
    raw = re.search(r"^with_retry\(\)\s*\{(.*?)^\}", LIB.read_text(encoding="utf-8"), re.MULTILINE | re.DOTALL)
    assert raw, "install-common.sh has no with_retry"
    # Comments stripped: the defective form is quoted in the comment that
    # explains it, and matching that would assert the opposite of the point.
    body = "\n".join(l for l in raw.group(1).splitlines() if not l.strip().startswith("#"))
    assert '"$@" && return 0' in body, (
        'with_retry must use `"$@" && return 0` so the following `rc=$?` sees '
        "the real exit code (#787, and again in install-vps.sh per #1609)."
    )
    assert not re.search(r'if "\$@"; then', body), (
        'with_retry uses the `if "$@"; then` form, which cannot detect failure.'
    )


def test_both_installers_source_the_library_with_a_search_path():
    """Checkout, installed copy, or explicit override -- and never nothing."""
    for path in (HOME_INSTALLER, VPS_INSTALLER):
        text = path.read_text(encoding="utf-8")
        assert "APIARY_INSTALL_LIB" in text, f"{path.name}: no library override hook"
        assert "/usr/local/lib/apiary/install-common.sh" in text, (
            f"{path.name}: does not look for the installed copy of the library. "
            f"This script also runs from /usr/local/sbin (systemd under SELinux "
            f"cannot exec it out of /home or /root), where a script-relative "
            f"source finds nothing."
        )
        assert 'source "$APIARY_INSTALL_LIB_RESOLVED"' in text, (
            f"{path.name}: sources the library by some other path than the "
            f"resolved one, which can silently source nothing."
        )


def _run_without_library(installer: Path, tmp_path: Path) -> subprocess.CompletedProcess:
    """Copy the installer somewhere with no lib/ beside it, then run it."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    stray = tmp_path / installer.name
    stray.write_bytes(installer.read_bytes())
    stray.chmod(0o755)
    return subprocess.run(
        ["bash", str(stray), "--help"],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "APIARY_INSTALL_LIB": "/nonexistent/install-common.sh"},
    )


def test_missing_library_fails_loudly_not_silently(tmp_path):
    """The reason this extraction was deferred once.

    `source` of a missing file under `set -uo pipefail` (no -e) only warns; the
    run then continues with every framework call undefined. Both installers
    must exit instead, naming where they looked.
    """
    for installer in (HOME_INSTALLER, VPS_INSTALLER):
        proc = _run_without_library(installer, tmp_path / installer.stem)
        assert proc.returncode != 0, (
            f"{installer.name} continued past a missing framework library "
            f"(rc={proc.returncode}); it must exit."
        )
        assert "install-common.sh" in proc.stderr, (
            f"{installer.name}: unhelpful failure when the library is missing:\n{proc.stderr}"
        )
        assert "--install-self" in proc.stderr, (
            f"{installer.name}: does not tell the operator how to fix it:\n{proc.stderr}"
        )


def _harness(tmp_path: Path, body: str) -> subprocess.CompletedProcess:
    """Source the real library and run `body` against it."""
    script = tmp_path / "harness.sh"
    script.write_text(
        textwrap.dedent(
            f"""\
            set -uo pipefail
            INSTALLER_NAME="harness"
            LOG_DIR="{tmp_path}/log"
            MARKER_DIR="{tmp_path}/markers"
            source "{LIB}"
            install_common_require
            install_common_open_run_log
            """
        )
        + textwrap.dedent(body),
        encoding="utf-8",
    )
    return subprocess.run(["bash", str(script)], capture_output=True, text=True)


def test_with_retry_returns_the_failure_after_the_last_attempt(tmp_path):
    proc = _harness(
        tmp_path,
        """
        with_retry 2 0 bash -c 'exit 7'
        echo "rc=$?"
        """,
    )
    assert "rc=7" in proc.stdout, f"with_retry swallowed the failure:\n{proc.stdout}{proc.stderr}"


def test_with_retry_succeeds_on_a_later_attempt(tmp_path):
    proc = _harness(
        tmp_path,
        f"""
        flaky() {{
          local f="{tmp_path}/attempts"
          echo x >> "$f"
          [[ "$(wc -l < "$f")" -ge 2 ]]
        }}
        with_retry 3 0 flaky
        echo "rc=$?"
        """,
    )
    assert "rc=0" in proc.stdout, f"with_retry gave up on a retryable command:\n{proc.stdout}{proc.stderr}"


def test_run_step_records_failure_and_writes_no_marker(tmp_path):
    proc = _harness(
        tmp_path,
        f"""
        run_step failing "a step that fails" bash -c 'exit 3'
        print_summary
        echo "summary_rc=$?"
        [[ -f "{tmp_path}/markers/failing.done" ]] && echo "MARKER WRITTEN"
        """,
    )
    assert "FAILED (exit 3)" in proc.stdout, proc.stdout
    assert "summary_rc=1" in proc.stdout, "print_summary must report a non-zero result when a step failed"
    assert "MARKER WRITTEN" not in proc.stdout, "a failed step must not leave a completion marker"


def test_run_step_skips_on_marker_and_force_rerun_overrides_it(tmp_path):
    proc = _harness(
        tmp_path,
        """
        run_step alpha "first run" true
        run_step alpha "second run, marker present" bash -c 'echo RAN_AGAIN'
        FORCE_FROM=alpha
        run_step alpha "third run, forced" bash -c 'echo RAN_FORCED'
        print_summary
        """,
    )
    assert "SKIPPED (marker present)" in proc.stdout, proc.stdout
    # run_step redirects step output into the run log, so assert on status text.
    assert proc.stdout.count("[alpha] OK") == 2, (
        "--force-rerun-from must re-run the named step itself, not just the "
        f"steps after it (#518 test run 2):\n{proc.stdout}"
    )


def test_vps_installer_resolves_pkg_at_source_time(tmp_path):
    """A resumed run skips preflight; $PKG must still be set.

    step_preflight_os used to assign it, so any re-run past that step's marker
    hit `PKG: unbound variable` under `set -u` in every later package step.
    """
    text = VPS_INSTALLER.read_text(encoding="utf-8")
    assignment = re.search(r"^\s*(debian\)\s+PKG=apt|rhel\)\s+PKG=dnf)", text, re.MULTILINE)
    assert assignment, "install-vps.sh no longer derives PKG from DISTRO_FAMILY at source time"
    preflight = re.search(r"^step_preflight_os\(\)\s*\{(.*?)^\}", text, re.MULTILINE | re.DOTALL)
    assert preflight, "install-vps.sh has no step_preflight_os"
    assert "PKG=" not in preflight.group(1), (
        "step_preflight_os assigns PKG again; a marker-skipped preflight then "
        "leaves it unset on every resumed run."
    )


def test_single_entry_point_covers_both_profiles():
    text = ENTRYPOINT.read_text(encoding="utf-8")
    for profile, installer in (("home", "install-homeserver.sh"), ("vps", "install-vps.sh")):
        assert installer in text, f"scripts/install.sh does not dispatch profile {profile}"
    proc = subprocess.run(
        ["bash", str(ENTRYPOINT), "--profile", "nonsense"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, "an unknown profile must be rejected"
