"""#1609 Phase 5: the two installers' shared framework must not silently diverge.

install-vps.sh's header states its status/retry/step framework is "identical to
install-homeserver.sh, deliberately not reimplemented differently". That claim
was false, and the divergence was not cosmetic.

`with_retry` in install-vps.sh used:

    if "$@"; then return 0; fi
    rc=$?

A plain if/fi with no else that takes neither branch has an exit status of zero
regardless of what the condition returned, so `rc=$?` read 0 for a command that
had just FAILED -- and on the final attempt the function did `return "$rc"`,
reporting success. Every with_retry call in that script was incapable of
reporting failure. install-homeserver.sh carried the fix for this (`"$@" &&
return 0`) since #787, where it had been found reporting success for all 17
stacks while every scp genuinely failed. It was never ported.

This test compares the shared functions with comments and whitespace stripped,
so the two may keep their own inline history (which is genuinely different and
worth keeping) while their *behaviour* is held identical.

Why a parity test rather than a single sourced lib, which is what #1609 Phase 5
asks for: install-homeserver.sh is executed from a copy outside the checkout in
at least one supported path (systemd cannot exec it from /home or /root under
SELinux, so it is installed to /usr/local/sbin), and a `source
"$(dirname "$0")/lib/..."` breaks there in a way that is invisible until a
rebuild. Extracting the framework is still the right end state, but it wants a
clean-host run to validate rather than being landed blind. This test closes the
hole that actually bit -- silent behavioural drift -- and fails loudly the
moment either copy changes without the other.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HOME_INSTALLER = REPO / "scripts" / "install-homeserver.sh"
VPS_INSTALLER = REPO / "scripts" / "install-vps.sh"

# Functions both scripts define and which must behave identically.
# `log` is deliberately excluded: both define it as a single-line function and
# it has no failure semantics to get wrong -- this test is about behaviour that
# can silently break a run, not about formatting.
SHARED_FUNCTIONS = ["with_retry", "run_step"]


def _extract(path: Path, name: str) -> str | None:
    """Return the body of `name()` from a shell script, or None if absent."""
    text = path.read_text(encoding="utf-8")
    m = re.search(rf"^{re.escape(name)}\(\)\s*\{{\n(.*?)^\}}", text, re.MULTILINE | re.DOTALL)
    return m.group(1) if m else None


def _normalise(body: str) -> str:
    """Strip comments and whitespace so only executable shape is compared.

    Em dashes are folded to `--` as well. The two scripts genuinely differ there
    inside their user-facing log strings, and that difference cannot break a
    run -- failing CI on punctuation would just train people to ignore this
    test, which is the opposite of the point.
    """
    out = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        stripped = stripped.replace("\u2014", "--")
        out.append(re.sub(r"\s+", " ", stripped))
    return "\n".join(out)


def test_shared_framework_functions_exist_in_both():
    missing = [
        f"{p.name}:{fn}"
        for fn in SHARED_FUNCTIONS
        for p in (HOME_INSTALLER, VPS_INSTALLER)
        if _extract(p, fn) is None
    ]
    assert not missing, f"shared framework function missing: {missing}"


def test_shared_framework_functions_behave_identically():
    """Comments may differ; executable lines may not."""
    drift = []
    for fn in SHARED_FUNCTIONS:
        a = _normalise(_extract(HOME_INSTALLER, fn) or "")
        b = _normalise(_extract(VPS_INSTALLER, fn) or "")
        if a != b:
            drift.append(
                f"\n=== {fn} ===\n"
                f"--- install-homeserver.sh\n{a}\n"
                f"--- install-vps.sh\n{b}"
            )
    assert not drift, (
        "installer framework functions have diverged behaviourally. Both scripts "
        "claim to share this framework; keep them in step or update the claim.\n"
        + "\n".join(drift)
    )


def test_with_retry_captures_the_real_exit_code():
    """The specific #787 defect, asserted by shape so it cannot come back."""
    for path in (HOME_INSTALLER, VPS_INSTALLER):
        body = _extract(path, "with_retry")
        assert body is not None, f"{path.name} has no with_retry"
        norm = _normalise(body)
        assert '"$@" && return 0' in norm, (
            f'{path.name}: with_retry must use `"$@" && return 0` so the following '
            f"`rc=$?` sees the real exit code. An `if \"$@\"; then return 0; fi` "
            f"reads 0 for a failed command, making with_retry unable to report "
            f"failure at all (#787, and again in install-vps.sh per #1609 Phase 5)."
        )
        assert not re.search(r'if "\$@"; then', norm), (
            f"{path.name}: with_retry uses the `if \"$@\"; then` form, which "
            f"cannot detect failure. See #787."
        )
