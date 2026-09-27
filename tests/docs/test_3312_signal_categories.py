#!/usr/bin/env python3
"""#3312: a diagnostic that cries wolf on a healthy host is worse than no
diagnostic -- and this is the machinery that makes the three outcomes
distinguishable.

`diagnostics.yml` ended 160 consecutive scheduled runs in failure (2026-08-12
through 2026-09-27) and of the four things it named every one was either a
check that could not see the object it was looking at or a real host fault
with no category attached. The red X was the same red X for all of them, so
nobody triaged it and #3312 is the result. These tests pin the three
outcomes separately, because that separation is the whole fix:

  measured fault     a real regression. Exit 1.
  expected state     an object deliberately absent, with a dated, issue-
                     referencing declaration on the host. Exit 0, labelled
                     EXPECT, naming the owner issue and the expiry.
  unmeasurable       the check could not run. Counted and named, never folded
                     into a pass; fatal for the isolation barriers, whose
                     silence would otherwise read as safety.

Each test drives the real scripts/isolation-audit.sh against a synthesised
host (every external command is a PATH stub), so what is asserted here is the
behaviour on a host, not the presence of a string in the source.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import stat
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
AUDIT = REPO_ROOT / "scripts" / "isolation-audit.sh"
STANDDOWN = REPO_ROOT / "scripts" / "sandbox-standdown.sh"
LIB = REPO_ROOT / "scripts" / "diagnostics-lib.sh"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "diagnostics.yml"

sys.path.insert(0, str(REPO_ROOT / "tests" / "docs"))
from test_2295_isolation_audit_full_coverage import (  # noqa: E402
    CLEAN_RULES,
    FAKE_IP,
    FAKE_IPTABLES,
    FAKE_SUDO,
    FAKE_SYSTEMCTL,
)

# ---------------------------------------------------------------------------
# stubs
# ---------------------------------------------------------------------------

# STATE is baked in per-invocation, not exported, so each test gets a
# self-contained host.
FAKE_VIRSH = """#!/usr/bin/env bash
case "$1 $2" in
  "net-info ghosts") exit 0 ;;
  "net-info "*)
    [ "$STATE" = "healthy" ] && exit 0 || exit 1 ;;
  "net-dumpxml "*)
    [ "$STATE" = "healthy" ] || exit 1
    if [ "$FAKE_FORWARD" = "1" ]; then
      echo "<network><forward mode='route'/></network>"
    else
      echo "<network><name>sandbox</name></network>"
    fi
    exit 0 ;;
  "nwfilter-dumpxml "*)
    [ "$STATE" = "healthy" ] && { echo "<filter/>"; exit 0; } || exit 1 ;;
esac
exit 1
"""

# #3312: a real `ss` that answers, so the sshd check has something to judge.
# FAKE_SS_22 is the port-22 line; unset means nothing is listening on :22.
FAKE_SS = """#!/usr/bin/env bash
[ -n "${FAKE_SS_BROKEN:-}" ] && exit 1
[ -n "${FAKE_SS_22:-}" ] && echo "LISTEN 0 128 $FAKE_SS_22 0.0.0.0:*"
exit 0
"""

FAKE_DOCKER = """#!/usr/bin/env bash
if [ "$1" = "ps" ]; then
  [ -n "${FAKE_DOCKER_PS_FAIL:-}" ] && { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
  [ -n "${FAKE_NO_STACK_CONTAINERS:-}" ] && exit 0
  printf 'hp-cowrie\\thoneypot/cowrie\\nhp-arcane\\thoneypot/arcane\\n'
  exit 0
fi
if [ "$1" = "inspect" ]; then
  case "$2" in
    hp-cowrie) echo '[ALL]'; exit 0 ;;   # hardened
    hp-arcane) echo ''; exit 0 ;;       # the documented CAP_EXCEPTIONS entry
  esac
  exit 1
fi
if [ "$1" = "network" ]; then exit 1; fi   # sandbox compose not up
exit 0
"""

# The libvirt sockets are `[ -S ]`-tested at hardcoded absolute paths, so a
# faithful stand-in has to create real sockets. stat is stubbed to report the
# RHEL/Debian posture a healthy sandbox host actually has (root:libvirt, no
# world access), because a test namespace cannot create a real `libvirt` group
# without writing /etc/group on the host.
FAKE_STAT = """#!/usr/bin/env bash
fmt=""; target=""
while [ $# -gt 0 ]; do
  case "$1" in
    -c) fmt=$2; shift 2 ;;
    *) target=$1; shift ;;
  esac
done
case "$target" in
  /var/run/libvirt/*)
    case "$fmt" in
      '%a') echo 750 ;;
      '%U:%G') echo root:libvirt ;;
      *) echo 0 ;;
    esac ;;
  *) exec /usr/bin/stat "$fmt" "$target" ;;
esac
"""


def _stub(path: pathlib.Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture()
def fake_bin(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (
        ("sudo", FAKE_SUDO),
        ("iptables", FAKE_IPTABLES),
        ("ip", FAKE_IP),
        ("systemctl", FAKE_SYSTEMCTL),
        ("virsh", FAKE_VIRSH),
        ("ss", FAKE_SS),
        ("docker", FAKE_DOCKER),
        ("stat", FAKE_STAT),
    ):
        _stub(bindir / name, body)
    rules = tmp_path / "forward-rules.txt"
    rules.write_text(CLEAN_RULES, encoding="utf-8")
    return bindir, rules


# ---------------------------------------------------------------------------
# running the audit against a synthesised host
# ---------------------------------------------------------------------------


def _can_sandbox() -> bool:
    """True when this host can give the audit real /var/run/libvirt sockets."""
    if shutil.which("unshare") is None:
        return False
    if not pathlib.Path("/var/run/libvirt").is_dir():
        return False
    probe = subprocess.run(
        ["unshare", "-rm", "bash", "-c", "mount --bind /var/run/libvirt /var/run/libvirt"],
        capture_output=True,
    )
    return probe.returncode == 0


SANDBOX_OK = _can_sandbox()

# The stand-down declaration is written as root by scripts/sandbox-standdown.sh
# and read as the unprivileged runner user, so 0644 root:root is a contract the
# test asserts rather than an accident.
def _standdown_body(issue: str, until: str, reason: str) -> str:
    return f"# written by the test\nissue: {issue}\nuntil: {until}\nreason: {reason}\n"


def _run(fake_bin, tmp_path, state="healthy", standdown=None, audit=None, extra_env=None):
    bindir, rules_file = fake_bin
    socket_dir = tmp_path / "libvirt-run"
    socket_dir.mkdir(exist_ok=True)
    declaration = tmp_path / "sandbox-standdown"
    if standdown is not None:
        declaration.write_text(standdown, encoding="utf-8")
    audit = audit or AUDIT
    inner = f"""
set -e
mount --bind '{socket_dir}' /var/run/libvirt
chown 0:0 /var/run/libvirt/* 2>/dev/null || true
chmod 0750 /var/run/libvirt/* 2>/dev/null || true
STATE='{state}'
export STATE
if [ '{state}' = healthy ]; then
  python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind('/var/run/libvirt/libvirt-sock'); s.close()"
  python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind('/var/run/libvirt/libvirt-sock-ro'); s.close()"
  chown 0:0 /var/run/libvirt/* 2>/dev/null || true
fi
exec bash '{audit}'
"""
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    # Clear any FAKE_* inherited from the ambient environment *before* setting
    # this run's own values, so a developer's shell cannot decide a verdict.
    for key in list(env):
        if key.startswith("FAKE_"):
            del env[key]
    env["FAKE_RULES_FILE"] = str(rules_file)
    env["APIARY_STANDDOWN_FILE"] = str(declaration)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["unshare", "-rm", "bash", "-c", inner],
        env=env,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=120,
    )


def _future(days: int = 7) -> str:
    import datetime

    return (datetime.date.today() + datetime.timedelta(days=days)).isoformat()


def _fault_lines(stdout: str) -> list:
    """The findings the audit actually categorised as faults.

    Matched on the category column, not as a substring: the audit's own prose
    says the word ('anything else that breaks below is still a FAIL') when a
    stand-down is in force, and a substring test would then be asserting on its
    explanation rather than on its findings.
    """
    import re

    return re.findall(r"^\s*FAIL\s+\S.*$", stdout, re.MULTILINE)


def _expect_lines(stdout: str) -> list:
    """The findings the audit actually categorised as expected-by-declaration."""
    import re

    return re.findall(r"^\s*EXPECT\s+\S.*$", stdout, re.MULTILINE)


# ---------------------------------------------------------------------------
# the three outcomes, distinguished
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SANDBOX_OK, reason="needs a user+mount namespace to stage /var/run/libvirt")
def test_healthy_host_exits_zero(fake_bin, tmp_path):
    """The baseline every other test is measured against: nothing wrong, so
    nothing red. If this ever fails, the audit is crying wolf again."""
    result = _run(fake_bin, tmp_path, state="healthy")
    assert "VERDICT PASS" in result.stdout, result.stdout
    assert result.returncode == 0, result.stdout
    assert not _fault_lines(result.stdout), result.stdout


@pytest.mark.skipif(not SANDBOX_OK, reason="needs a user+mount namespace to stage /var/run/libvirt")
def test_broken_host_exits_one_and_names_the_fault(fake_bin, tmp_path):
    """The real-regression case: libvirt and its sandbox objects are gone with
    no declaration behind them (the 2026-09-23 state, #3338). Must stay red,
    and must name the cause rather than the symptom."""
    result = _run(fake_bin, tmp_path, state="broken")
    assert result.returncode == 1, result.stdout
    assert "libvirt network 'sandbox' does not exist" in result.stdout
    assert "'honeypot-sandbox-strict' nwfilter is missing" in result.stdout
    assert "libvirt socket not found" in result.stdout
    assert "VERDICT FAIL" in result.stdout
    assert not _expect_lines(result.stdout), result.stdout


@pytest.mark.skipif(not SANDBOX_OK, reason="needs a user+mount namespace to stage /var/run/libvirt")
def test_declared_standdown_exits_zero_where_broken_exits_one(fake_bin, tmp_path):
    """The expected-state case, and the reason this file exists. Same host as
    the test above -- libvirtd down, both networks gone, nwfilter gone -- with
    a live dated declaration standing behind it.

    Before #3312 this state was indistinguishable from the one above: both
    printed the same FAIL lines and both exited 1, which is why a legitimate
    stand-down and a real regression looked the same to whoever read the run.
    """
    result = _run(
        fake_bin,
        tmp_path,
        state="broken",
        standdown=_standdown_body("#3135", _future(7), "training leg holds the sandbox RAM/CPU"),
    )
    assert "EXPECT" in result.stdout, result.stdout
    assert "declared stand-down, #3135, until" in result.stdout
    assert "training leg holds the sandbox RAM/CPU" in result.stdout
    assert result.returncode == 0, (
        "a live, unexpired declaration must make the absence EXPECTED and the run "
        f"green; got exit {result.returncode}:\n{result.stdout}"
    )
    assert "VERDICT PASS" in result.stdout
    assert "excused by a live declaration" in result.stdout
    # The identical host, same everything but the declaration, is still red.
    (tmp_path / "sandbox-standdown").unlink()
    without = _run(fake_bin, tmp_path, state="broken")
    assert without.returncode == 1, without.stdout
    # ...and the specific lines that were red are now EXPECT, not deleted.
    assert "libvirt network 'sandbox' does not exist" in result.stdout
    assert not _fault_lines(result.stdout), result.stdout


@pytest.mark.skipif(not SANDBOX_OK, reason="needs a user+mount namespace to stage /var/run/libvirt")
def test_expired_declaration_stops_excusing_anything(fake_bin, tmp_path):
    """Anti-rot. An exception that outlived its window is not an exception: it
    is a stale file pretending to be an expectation, and it must be named and
    fatal, not quietly honoured."""
    result = _run(
        fake_bin,
        tmp_path,
        state="broken",
        standdown=_standdown_body("#3135", "2020-01-01", "a leg that ended in january"),
    )
    assert result.returncode == 1, result.stdout
    assert "does not count" in result.stdout
    assert "expired 2020-01-01" in result.stdout
    assert "clear it" in result.stdout
    assert "libvirt network 'sandbox' does not exist" in result.stdout
    assert not _expect_lines(result.stdout), result.stdout


@pytest.mark.skipif(not SANDBOX_OK, reason="needs a user+mount namespace to stage /var/run/libvirt")
@pytest.mark.parametrize(
    "body,why",
    [
        ("until: %s\nreason: r\n" % _future(3), "no issue"),
        ("issue: #1\nreason: r\n", "no until"),
        ("issue: #1\nuntil: %s\n" % _future(3), "no reason"),
        ("issue: 1\nuntil: %s\nreason: r\n" % _future(3), "issue is not a reference"),
        ("issue: #1\nuntil: not-a-date\nreason: r\n", "unparseable date"),
        ("issue: #1\nuntil: %s\nreason: r\n" % _future(400), "further out than the max window"),
    ],
)
def test_malformed_declaration_fails_closed(fake_bin, tmp_path, body, why):
    """A typo must never be able to neuter the audit. Every shape of a bad
    declaration -- missing field, wrong issue syntax, unparseable date, or a
    window so long it is really a permanent posture change -- has to land on
    the fault side of the line."""
    result = _run(fake_bin, tmp_path, state="broken", standdown=body)
    assert "does not count" in result.stdout, f"{why}:\n{result.stdout}"
    assert result.returncode == 1, f"{why}:\n{result.stdout}"
    assert not _expect_lines(result.stdout), f"{why}:\n{result.stdout}"


@pytest.mark.skipif(not SANDBOX_OK, reason="needs a user+mount namespace to stage /var/run/libvirt")
def test_declaration_never_excuses_a_forwarding_network(fake_bin, tmp_path):
    """A stand-down is an excuse for absence, not an amnesty. A network that IS
    defined and DOES forward is the exact thing the isolation audit exists to
    catch, and no declaration may cover it."""
    result = _run(
        fake_bin,
        tmp_path,
        state="healthy",
        standdown=_standdown_body("#3135", _future(7), "standing down anyway"),
        extra_env={"FAKE_FORWARD": "1"},
    )
    assert "can route to the internet" in result.stdout, result.stdout
    assert result.returncode == 1, result.stdout


@pytest.mark.skipif(not SANDBOX_OK, reason="needs a user+mount namespace to stage /var/run/libvirt")
def test_declaration_never_excuses_a_planted_forward_accept(fake_bin, tmp_path):
    """Same rule on the iptables side, which is the barrier that actually
    keeps a NAT-mode sandbox off the internet."""
    bindir, rules_file = fake_bin
    rules_file.write_text(CLEAN_RULES + "-A FORWARD -i virbr-sandbox -o eth0 -j ACCEPT\n", encoding="utf-8")
    result = _run(
        fake_bin,
        tmp_path,
        state="healthy",
        standdown=_standdown_body("#3135", _future(7), "standing down anyway"),
    )
    assert "an explicit ACCEPT rule references virbr-sandbox" in result.stdout
    assert result.returncode == 1, result.stdout


# ---------------------------------------------------------------------------
# unmeasurable is its own category, and is not a pass
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SANDBOX_OK, reason="needs a user+mount namespace to stage /var/run/libvirt")
def test_sshd_check_answers_when_sshd_is_simply_not_on_22(fake_bin, tmp_path):
    """The check used to be `ss -tlnp | grep ':22 '`, which exits 1 both when
    nothing listens on :22 and when ss could not run at all -- so on the live
    homeserver it had never once answered, and it reported 'could not confirm'
    about a host where the answer was simply 'nothing is listening'. That is a
    check that cannot tell a healthy host from a blind one, which is the same
    defect as no check at all."""
    result = _run(fake_bin, tmp_path, state="healthy")
    assert "nothing is listening on :22" in result.stdout, result.stdout
    assert "could not confirm" not in result.stdout


@pytest.mark.skipif(not SANDBOX_OK, reason="needs a user+mount namespace to stage /var/run/libvirt")
def test_sshd_check_says_so_when_ss_cannot_run(fake_bin, tmp_path):
    """...and the other half: when ss really is unreadable the line has to say
    the check did not run, in its own category, counted in the footer."""
    result = _run(fake_bin, tmp_path, state="healthy", extra_env={"FAKE_SS_BROKEN": "1"})
    assert "UNMEAS" in result.stdout, result.stdout
    assert "could not read the sshd listen address" in result.stdout
    assert "not a pass" in result.stdout
    assert "0 unmeasured" not in result.stdout
    assert "check(s) could not be measured at all" in result.stdout


@pytest.mark.skipif(not SANDBOX_OK, reason="needs a user+mount namespace to stage /var/run/libvirt")
def test_sshd_on_a_honeypot_facing_address_is_still_a_fault(fake_bin, tmp_path):
    """Splitting the stages must not weaken the finding that matters."""
    result = _run(
        fake_bin, tmp_path, state="healthy", extra_env={"FAKE_SS_22": "10.8.0.2:22"}
    )
    assert "sshd appears to be listening on a honeypot-facing address" in result.stdout
    assert result.returncode == 1, result.stdout


@pytest.mark.skipif(not SANDBOX_OK, reason="needs a user+mount namespace to stage /var/run/libvirt")
def test_no_stack_containers_is_not_reported_as_a_docker_failure(fake_bin, tmp_path):
    """`docker ps | grep -E '^(hp-|sbx-)'` exits 1 when the grep finds nothing,
    so a host with no stack containers at all was reported as 'could not
    enumerate containers (docker ps failed)' -- a claim about the tool printed
    when the truth is a claim about the deployment. Both are faults; they are
    not the same fault, and only one of them is fixable by reinstalling
    docker."""
    result = _run(fake_bin, tmp_path, state="healthy", extra_env={"FAKE_NO_STACK_CONTAINERS": "1"})
    assert "no hp-* or sbx-* container exists on this host at all" in result.stdout, result.stdout
    assert "This is not a docker failure" in result.stdout
    assert "could not enumerate containers (docker ps failed" not in result.stdout
    # ...and it is reported once, not doubled up by the capability section.
    assert result.stdout.count("no hp-* or sbx-* container exists") == 1


@pytest.mark.skipif(not SANDBOX_OK, reason="needs a user+mount namespace to stage /var/run/libvirt")
def test_docker_itself_failing_is_still_named_as_such(fake_bin, tmp_path):
    result = _run(fake_bin, tmp_path, state="healthy", extra_env={"FAKE_DOCKER_PS_FAIL": "1"})
    assert "could not enumerate containers (docker ps failed" in result.stdout, result.stdout
    assert result.returncode == 1, result.stdout


# ---------------------------------------------------------------------------
# the verdict itself is legible
# ---------------------------------------------------------------------------


def test_every_line_carries_a_category_prefix():
    """A reader has to be able to tell what kind of line they are looking at
    without counting columns, and the four labels have to stay stable, because
    the workflow's summary quotes them."""
    audit = AUDIT.read_text(encoding="utf-8")
    for label in ("'  OK      %s\\n'", "'  FAIL    %s\\n'", "'  EXPECT  %s\\n'", "'  UNMEAS  %s\\n'"):
        assert label in audit, f"the {label} label is gone -- the category vocabulary moved"


def test_verdict_prints_category_counts():
    audit = AUDIT.read_text(encoding="utf-8")
    assert "isolation-audit: categories --" in audit
    assert "VERDICT PASS" in audit and "VERDICT FAIL" in audit
    assert "could not be measured at all" in audit
    # The exit code has to follow the categories, including the fatal
    # unmeasurable ones: an unread barrier must not exit 0.
    assert 'unmeasured 1 "could not read the iptables FORWARD chain' in audit
    assert 'unmeasured 1 "iptables is not installed' in audit


def test_standdown_helper_and_audit_agree_on_the_path_and_the_window():
    audit = AUDIT.read_text(encoding="utf-8")
    helper = STANDDOWN.read_text(encoding="utf-8")
    for text in (audit, helper):
        assert "APIARY_STANDDOWN_FILE:-/etc/apiary/sandbox-standdown" in text
        assert "APIARY_STANDDOWN_MAX_DAYS:-14" in text


# ---------------------------------------------------------------------------
# the declaration tool: round trip, and the refusals
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    shutil.which("unshare") is None, reason="needs a user+mount namespace to act as root"
)
def test_declare_show_clear_round_trip(tmp_path):
    """Runs the real tool as (namespaced) root, so the file it writes is a real
    root-owned 0644 file -- the exact thing the unprivileged audit has to be
    able to read."""
    declaration = tmp_path / "sandbox-standdown"
    env = dict(os.environ, APIARY_STANDDOWN_FILE=str(declaration))
    inner = f"""
set -e
'{STANDDOWN}' declare --issue '#3135' --until '{_future(7)}' --reason 'a training leg'
stat -c '%a %U' '{declaration}'
'{STANDDOWN}' show
'{STANDDOWN}' clear
'{STANDDOWN}' show
"""
    proc = subprocess.run(
        ["unshare", "-rm", "bash", "-c", inner], env=env, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # World-readable: the audit runs as github-deploy-runner, not root.
    assert "644 root" in proc.stdout, proc.stdout
    assert "status: ACTIVE" in proc.stdout
    assert "no declaration at" in proc.stdout


def test_declare_refuses_what_the_audit_would_refuse_too_honour(tmp_path):
    """The tool and the audit must not disagree about validity -- a window the
    writer accepts but the reader ignores would be an exception that exists on
    disk and nowhere else."""
    declaration = tmp_path / "sandbox-standdown"
    env = dict(os.environ, APIARY_STANDDOWN_FILE=str(declaration))
    for args, why in (
        ("declare --until 2099-01-01 --reason r", "no issue"),
        ("declare --issue '#1' --reason r", "no until"),
        ("declare --issue '#1' --until 2099-01-01", "no reason"),
        ("declare --issue 'one' --until 2099-01-01 --reason r", "issue is not a reference"),
        ("declare --issue '#1' --until 2020-01-01 --reason r", "until is in the past"),
        ("declare --issue '#1' --until 2099-01-01 --reason r", "too far out"),
    ):
        proc = subprocess.run(
            ["unshare", "-rm", str(STANDDOWN)] + args.split(),
            env=env,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 2, f"{why}: expected a refusal, got {proc.returncode}\n{proc.stderr}"
        assert not declaration.exists(), f"{why}: a refused declaration wrote a file anyway"


# ---------------------------------------------------------------------------
# the workflow: same vocabulary, and one ledger
# ---------------------------------------------------------------------------


def test_workflow_alerts_are_categorised():
    """Every fatal condition in the workflow has to say which of the four
    things it is. #3312's whole content is that 'a red run' and 'a red run
    because the runner cannot read a root-only token' are different events,
    and only one of them is a fault in the pipeline."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    lib = LIB.read_text(encoding="utf-8")
    # No bare alert() left: every call site names a category.
    import re

    calls = re.findall(r"^\s*alert [^\n]*$", workflow, re.MULTILINE)
    assert calls, "no alert call sites found -- the workflow's shape changed"
    for call in calls:
        assert re.match(r"^\s*alert (fault|runner-config|unmeasured) ", call), (
            f"alert call site has no fatal category: {call.strip()!r}"
        )
    # ...and only categories the library defines, so a finding cannot be filed
    # under a label nothing knows how to treat.
    declared = re.search(r'DIAG_CATEGORIES="([^"]+)"', lib)
    assert declared, "scripts/diagnostics-lib.sh no longer declares DIAG_CATEGORIES"
    categories = set(declared.group(1).split())
    assert {c.split()[1] for c in calls} <= categories, lib
    # Same for note(), which carries the non-fatal ones.
    notes = re.findall(r"^\s*note [^\n]*$", workflow, re.MULTILINE)
    for call in notes:
        assert re.match(r"^\s*note (fault|runner-config|unmeasured|expected) ", call), (
            f"note call site has no category: {call.strip()!r}"
        )
    assert {c.split()[1] for c in notes} <= categories, lib
    # The categories are documented where they are defined, not only used.
    for category in ("fault", "runner-config", "expected", "unmeasured"):
        assert f"#   {category} " in lib, (
            f"{category} is defined without a line saying what it means"
        )


def test_workflow_prints_a_category_ledger():
    """One table, at the end, listing what was measured and what each finding
    was. This is what makes a red run triageable in seconds rather than by
    re-reading the body -- and it is the artefact that says 'nothing was
    unmeasured' just as loudly as it says 'this is a fault'."""
    import re

    workflow = WORKFLOW.read_text(encoding="utf-8")
    lib = LIB.read_text(encoding="utf-8")
    assert "| category | check | finding |" in lib
    assert "diag_ledger" in lib
    # The verdict line has to name the counts, not just the exit code.
    assert "unmeasured" in lib.split("diag_ledger_report() {")[1][:2000]
    # Every job that can produce a finding ends with the ledger: steps are
    # separate shells, so one job's findings cannot reach the other's table.
    assert workflow.count("- name: Category ledger (#3312)") == 2
    assert workflow.count("diag_ledger_report") == 2
    for step in re.findall(
        r"- name: Category ledger \(#3312\).*?(?=\n      - name:|\n  \w+:)", workflow, re.S
    ):
        assert "if: always()" in step, (
            "a ledger step gated on success would print nothing on exactly the "
            "runs that need it"
        )
        assert "exit 1" not in step, (
            "the ledger step is the triage view, not the verdict -- the fatal "
            "signal is each step's own exit status"
        )


def test_workflow_still_fails_on_a_real_fault_and_still_fails_when_unmeasured():
    """The two fatal categories stay fatal. This is the anti-wolf guard: the
    temptation with a job that has been red for four days is to make the thing
    that cannot be measured stop mattering, and that would leave the sensor ->
    Elasticsearch -> dashboard pipeline unmonitored while the run went green."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    for job in ("home", "vps"):
        section = workflow.split(f"  {job}:", 1)[1].split("\n  # ---", 1)[0]
        assert "schedule_failed=0" in section
        assert 'if [ "$schedule_failed" -eq 1 ]; then\n            exit 1' in section, (
            f"the {job} job no longer turns a categorised finding into a red run (#3312)"
        )


def test_workflow_runs_the_audit_from_the_triggering_ref_not_the_deployed_copy():
    """#2908: /opt/stacks/apiary is refreshed only by deploy.yml, which is
    workflow_dispatch-only, so a fix merged to isolation-audit.sh sat inert
    until a human remembered to deploy -- and for the five weeks of #3312 that
    is exactly why the red X kept naming things #3338 had already fixed. A
    check auditing the host with a stale copy of its own question cannot report
    a fix as fixed."""
    import re

    workflow = WORKFLOW.read_text(encoding="utf-8")
    for job in ("home", "vps"):
        section = workflow.split(f"  {job}:", 1)[1].split("\n  vps:", 1)[0]
        assert "- uses: actions/checkout@" in section, (
            f"the {job} job has no checkout, so the scripts it runs are whatever "
            "the last deploy left behind (#2908)"
        )
    isolation_step = workflow.split("- name: Isolation invariants", 1)[1]
    assert "$GITHUB_WORKSPACE/scripts/isolation-audit.sh" in isolation_step
    assert "/opt/stacks/apiary/scripts/isolation-audit.sh" not in isolation_step
    # ...and the deployed copy is still measured, because drift is a real
    # finding (#2908) even when the audit no longer depends on it.
    assert "diff --quiet origin/main -- scripts/" in workflow
    # Pinning is the repo's rule for every checkout (quality.yml's zizmor gate
    # blocks an unpinned one), and a workflow that reads the service token
    # through a root-owned helper must not keep a credential in the tree it
    # checked out.
    for line in re.findall(r"^\s*- uses: actions/checkout@.*$", workflow, re.MULTILINE):
        assert re.search(r"@[0-9a-f]{40} # v", line), (
            f"unpinned checkout, or a pin with no version beside it to bump: {line.strip()}"
        )
    assert workflow.count("persist-credentials: false") >= 2


def _lib_run(body: str, is_schedule: str = "true"):
    """Sources the real library in a real bash, the way a step does, and
    returns the log, the annotations and the step's exit status."""
    import re
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        env = dict(
            os.environ,
            RUNNER_TEMP=tmp,
            GITHUB_STEP_SUMMARY=f"{tmp}/summary.md",
        )
        env.pop("GITHUB_EVENT_NAME", None)
        script = f"""
set -uo pipefail
is_schedule={is_schedule}
schedule_failed=0
. '{LIB}'
{body}
diag_ledger_report
exit "$schedule_failed"
"""
        proc = subprocess.run(
            ["bash", "-c", script], env=env, capture_output=True, text=True, timeout=60
        )
        summary = pathlib.Path(f"{tmp}/summary.md").read_text(encoding="utf-8")
    # A title ends at the first "::", not at the first ":" -- the titles here
# are "<category>: <check>".
    annotations = re.findall(r"^::(error|warning) title=(.*?)::", proc.stdout, re.MULTILINE)
    return proc, summary, annotations


def test_the_library_keeps_a_runner_config_gap_distinct_and_still_fatal():
    """The load-bearing property, and the one most likely to be broken by a
    well-meaning edit: a lane that has never been able to measure anything must
    (a) not be reported as a fault in the pipeline, and (b) still fail the
    scheduled run. Dropping (b) is how a green run comes to mean "we stopped
    looking"; #3283 is what that costs."""
    proc, summary, annotations = _lib_run(
        'alert runner-config "sensor -> ES -> dashboard" "metrics unavailable: helper not installed"'
    )
    assert proc.returncode == 1, "a runner-config gap stopped being fatal"
    assert ("error", "runner-config: sensor -> ES -> dashboard") in annotations, annotations
    assert not any(title.startswith("fault:") for _, title in annotations), (
        f"the gap was filed as a pipeline fault: {annotations}"
    )
    assert "| runner-config | sensor -> ES -> dashboard | metrics unavailable: helper not installed |" in summary
    assert "1 runner-config gap(s)" in summary


def test_a_declared_absence_is_reported_and_never_fatal():
    """The case #3312 was filed about: something deliberately down must be
    legible in the summary without reddening a run that is doing its job."""
    proc, summary, annotations = _lib_run(
        'note expected "sandbox stand-down" "the sandbox stack is deliberately down until 2026-10-04"'
    )
    assert proc.returncode == 0, "a declared, expected absence reddened the run"
    assert not annotations, f"an expected absence raised an annotation: {annotations}"
    assert "| expected | sandbox stand-down |" in summary
    assert "1 expected absence(s)" in summary
    assert "Verdict: every check that could run agreed" in summary


def test_unmeasurable_is_its_own_category_and_never_a_pass():
    proc, summary, annotations = _lib_run(
        'alert unmeasured "isolation audit" "FORWARD chain could not be read at all"'
    )
    assert proc.returncode == 1, "an unread barrier stopped being fatal"
    assert ("error", "unmeasured: isolation audit") in annotations, annotations
    assert "1 unmeasured" in summary
    assert "Verdict: see the rows above" in summary


def test_a_manual_run_reports_everything_and_fails_for_nothing():
    """#2222: a workflow_dispatch run is a human reading a report. Every
    finding is still labelled and still filed, and nothing is fatal -- the two
    behaviours have to be independent, because a category that only works on
    one trigger is a category nobody can trust."""
    proc, summary, annotations = _lib_run(
        'alert fault "dashboard healthz" "unreachable"\nalert runner-config "metrics lane" "no grant"',
        is_schedule="false",
    )
    assert proc.returncode == 0, "a manual run went red on a reported finding"
    assert not annotations, f"a manual run raised annotations: {annotations}"
    assert "| fault | dashboard healthz | unreachable |" in summary
    assert "| runner-config | metrics lane | no grant |" in summary
    assert "1 fault(s), 1 runner-config gap(s)" in summary


def test_a_miscategorised_finding_cannot_turn_a_run_green():
    """`alert expected` is a call-site bug. The honest response is to say so
    loudly -- and to stay fatal anyway, because the one thing a category
    system must never do is let a mistake in it become a quiet pass."""
    proc, _summary, annotations = _lib_run(
        'alert expected "sandbox stand-down" "deliberately down"'
    )
    assert proc.returncode == 1, "a fatal call site with a non-fatal category went green"
    assert any("Wrong category" in title for _, title in annotations), annotations


def test_the_library_refuses_to_be_run():
    """Running it would exit 0 having measured nothing, which is the exact
    shape of the problem this issue is about."""
    proc = subprocess.run(["bash", str(LIB)], capture_output=True, text=True, timeout=60)
    assert proc.returncode != 0, "sourcing the library also runs it when executed"
    assert "source it, do not run it" in proc.stderr


# ---------------------------------------------------------------------------
# the isolation step, run as the step itself runs it
# ---------------------------------------------------------------------------


def _step_run_body(step_name_prefix: str, is_schedule: str = "true") -> str:
    """The literal `run:` body of a workflow step, de-indented, with the one
    ${{ }} expression these steps use already substituted.

    Text slicing rather than a YAML parse: PyYAML is not a declared dependency
    of this suite, and a test that needs one the docs job does not install is a
    test that fails in CI and passes locally.
    """
    workflow = WORKFLOW.read_text(encoding="utf-8")
    start = workflow.index(f"- name: {step_name_prefix}")
    run_at = workflow.index("        run: |\n", start)
    body = []
    for line in workflow[run_at + len("        run: |\n") :].splitlines():
        if line.strip() and not line.startswith(" " * 10):
            break
        body.append(line[10:] if line.startswith(" " * 10) else line)
    return "\n".join(body).replace(
        "${{ github.event_name == 'schedule' && 'true' || 'false' }}", is_schedule
    )


@pytest.mark.parametrize(
    "unmeasured,audit_exit,category",
    [
        (0, 1, "fault"),
        (2, 1, "unmeasured"),
    ],
)
def test_the_isolation_step_files_the_audit_verdict_under_its_own_category(
    fake_bin, tmp_path, unmeasured, audit_exit, category
):
    """The step's own half of the job, executed as the runner executes it.

    It has to do three things at once, and it is easy to break any of them
    silently: run the audit from the checkout rather than the deployed copy,
    take the audit's own counts rather than re-deriving them (one source of
    truth, so the two cannot disagree about how many faults there were), and
    file the result under a category that says whether the run failed on a
    measured violation or on a barrier nobody could read.
    """
    bindir, _rules_file = fake_bin
    # The step's #2908 freshness block shells out to git against the deployed
    # tree. A stub that fails is the same shape as an offline runner, and it
    # keeps this test from doing a real network fetch on a machine that has
    # /opt/stacks/apiary (the homeserver CI runner does).
    _stub(bindir / "git", "#!/usr/bin/env bash\nexit 1\n")

    workspace = tmp_path / "workspace"
    (workspace / "scripts").mkdir(parents=True)
    shutil.copy(LIB, workspace / "scripts" / "diagnostics-lib.sh")
    audit = workspace / "scripts" / "isolation-audit.sh"
    audit.write_text(
        "#!/usr/bin/env bash\n"
        f"echo 'isolation-audit: categories -- {unmeasured} unmeasured,"
        f" 0 expected-by-declaration, 0 triaged gap(s), {audit_exit} fault(s)'\n"
        f"exit {audit_exit}\n",
        encoding="utf-8",
    )
    audit.chmod(0o755)

    run_tmp = tmp_path / "runtmp"
    run_tmp.mkdir()
    script = tmp_path / "step.sh"
    script.write_text(_step_run_body("Isolation invariants"), encoding="utf-8")
    env = dict(os.environ)
    env.update(
        {
            "GITHUB_WORKSPACE": str(workspace),
            "RUNNER_TEMP": str(run_tmp),
            "GITHUB_STEP_SUMMARY": str(run_tmp / "summary.md"),
            "PATH": f"{bindir}:{env['PATH']}",
        }
    )
    proc = subprocess.run(
        ["bash", str(script)], env=env, capture_output=True, text=True, cwd=REPO_ROOT, timeout=120
    )
    assert proc.returncode == audit_exit, (
        f"the step exited {proc.returncode}, the audit exited {audit_exit}\n"
        f"{proc.stdout}\n{proc.stderr}"
    )
    assert f"::error title={category}: isolation audit" in proc.stdout, proc.stdout
    # ...and the row reaches the reader. Steps are separate shells, so the row
    # is a file until the ledger step renders it -- running only the first
    # step and looking for the table would pass while the ledger was broken.
    ledger = tmp_path / "ledger.sh"
    ledger.write_text(_step_run_body("Category ledger"), encoding="utf-8")
    subprocess.run(
        ["bash", str(ledger)], env=env, capture_output=True, text=True, cwd=REPO_ROOT, timeout=120
    )
    summary = (run_tmp / "summary.md").read_text(encoding="utf-8")
    assert "| category | check | finding |" in summary, summary
    assert f"| {category} | isolation audit (scripts/isolation-audit.sh) |" in summary, summary
    # The audit's own line is carried rather than reworded here: the counts in
    # the ledger are the ones the audit printed, so the two cannot disagree.
    assert f"{unmeasured} unmeasured" in summary, summary
    # ...and the deployed copy is still measured for drift, whatever its state.
    assert "could not reach origin to compare" in summary, summary


def test_a_clean_isolation_run_is_filed_as_measured_and_in_agreement(fake_bin, tmp_path):
    """The other end of the same step: a run with nothing wrong still says
    what it measured. Without this row the ledger is silent on a green run,
    and silence is the one reading a reader cannot tell apart from a lane
    that never ran."""
    bindir, _rules_file = fake_bin
    _stub(bindir / "git", "#!/usr/bin/env bash\nexit 1\n")
    workspace = tmp_path / "workspace"
    (workspace / "scripts").mkdir(parents=True)
    shutil.copy(LIB, workspace / "scripts" / "diagnostics-lib.sh")
    audit = workspace / "scripts" / "isolation-audit.sh"
    audit.write_text(
        "#!/usr/bin/env bash\n"
        "echo 'isolation-audit: categories -- 0 unmeasured, 0 expected-by-declaration,"
        " 0 triaged gap(s), 0 fault(s)'\n"
        "exit 0\n",
        encoding="utf-8",
    )
    audit.chmod(0o755)
    run_tmp = tmp_path / "runtmp"
    run_tmp.mkdir()
    script = tmp_path / "step.sh"
    script.write_text(_step_run_body("Isolation invariants"), encoding="utf-8")
    ledger = tmp_path / "ledger.sh"
    ledger.write_text(_step_run_body("Category ledger"), encoding="utf-8")
    env = dict(
        os.environ,
        GITHUB_WORKSPACE=str(workspace),
        RUNNER_TEMP=str(run_tmp),
        GITHUB_STEP_SUMMARY=str(run_tmp / "summary.md"),
        PATH=f"{bindir}:{os.environ['PATH']}",
    )
    proc = subprocess.run(
        ["bash", str(script)], env=env, capture_output=True, text=True, cwd=REPO_ROOT, timeout=120
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "::error" not in proc.stdout, proc.stdout
    subprocess.run(
        ["bash", str(ledger)], env=env, capture_output=True, text=True, cwd=REPO_ROOT, timeout=120
    )
    summary = (run_tmp / "summary.md").read_text(encoding="utf-8")
    assert "| ok | isolation audit (scripts/isolation-audit.sh) |" in summary, summary
    assert "0 unmeasured, 0 expected absence(s)" in summary, summary


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
