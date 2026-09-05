#!/usr/bin/env python3
"""Regression test for #2055: operational hardening of the rex86_* GPU-batch
drivers in ``analysis/ghidra/benchmarks/model-quant-benchmark/``.

These drivers run unattended for days on a single-GPU host. The failure modes
#2055 addressed all share a shape: the driver destroys or mislabels its own
results, and *nothing notices* -- a later run's "does the result file exist?"
check reads the wreckage as success. So the contracts worth pinning are the
ones about the result-file protocol and about serialising on the one GPU:

  item 1  A result file is never deleted before its replacement exists. The
          eval writes to ``$result.tmp``; only a successful eval promotes it
          with ``mv -f "$tmp" "$result"``. A failed launch leaves the previous
          run's result -- the safety net -- untouched.
  item 2  A failed eval leaves *no* result file: the ``.tmp`` is removed on the
          failure branch, so the next run sees a missing result and redoes the
          work instead of trusting a truncated file.
  item 3  One single-GPU guard, ``rex86_wait_for_gpu_drivers`` in the new
          ``rex86_common.sh``, matching every driver by naming convention
          rather than an enumerated list that has to be hand-maintained.
  item 4  HuggingFace snapshots are pinned to a resolved commit SHA, so
          upstream drift cannot silently swap the weights a stored result
          describes.

WHY THIS FILE WAS REWRITTEN
---------------------------
The version merged with the fix asserted substrings and passed against source
that cannot run at all. Specifically:

  * ``test_every_driver_sources_the_common_helper`` asserted
    ``"source " in text and "rex86_common.sh" in text`` -- two *independent*
    substring checks over the whole file, not one line. It is satisfied by a
    ``source`` on a line that does something else entirely (see
    ``test_driver_prologues_are_runnable`` below, which is what actually
    shipped).
  * ``test_no_driver_does_bare_rm_f_before_launch`` could not fail. It only
    matched ``rm -f`` lines that literally contain ``.corpus_eval.out``, but
    the regression it names is ``rm -f "$result"`` -- a variable. Run against
    the pre-fix blob it reports clean. (Its inner loop also had an
    unconditional ``break`` with dead code after it, so it never looked past
    the first following line.)
  * Nothing at all covered item 1/item 2 -- the tmp-promote protocol, which is
    the substance of the fix.

Every detector here is validated in the opposite direction too: the ones that
guard a regression are written so they fire against the pre-fix code at
``f03eb727^``, not merely pass against the post-fix code.
"""
import pathlib
import re
import shutil
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
REX86_DIR = REPO_ROOT / "analysis/ghidra/benchmarks/model-quant-benchmark"
COMMON = REX86_DIR / "rex86_common.sh"

# Shell that launches a model server on the single GPU. A scope containing one
# of these is a scope where destroying the previous result is unrecoverable.
GPU_LAUNCH_RE = re.compile(r"llama-server|vllm/vllm-openai|ollama\s+serve")

# A whole line that is a `source .../rex86_common.sh` statement. `args`
# captures whatever trails the sourced path -- empty in a correct prologue,
# but the eight drivers whose `set -euo pipefail` got split (#2979) left
# `pipefail` stranded there. Matching that shape rather than refusing to
# match it keeps "does this driver source the helper at all?" from
# re-reporting a defect that has its own contract below
# (test_driver_prologues_are_runnable).
SOURCE_RE = re.compile(
    r"""^\s*(?:source|\.)\s+"\$\{?(?P<var>\w+)\}?/rex86_common\.sh"(?P<args>.*)$"""
)

# A real invocation of the eval. The lookbehind is load-bearing:
# real_bench_run.sh runs a *different* script, real_corpus_eval.py, which a
# bare substring test picks up, and rex86_backfill_extra_quants.sh `mv`s the
# file around without running it.
EVAL_RE = re.compile(r"\bpython3\b.*(?<![\w])corpus_eval\.py")

# A trailing shell comment.
COMMENT_RE = re.compile(r"(?:^|\s)#.*$")

# `set -euo pipefail` / `set -uo pipefail` -- the `-o` long-option flag must
# carry its argument.
SET_RE = re.compile(r"^\s*set\s+-(?P<flags>[a-z]*o)(?P<rest>.*)$")


def _drivers():
    """Every shell script in the benchmark directory except the helper itself.

    Globbed, not enumerated: a driver added later must satisfy these contracts
    without anyone remembering to extend a list here -- the same property
    item 3 demands of the GPU guard's own pattern.
    """
    return sorted(p for p in REX86_DIR.glob("*.sh") if p.name != COMMON.name)


def _read(path):
    return path.read_text(encoding="utf-8")


def _code(line):
    """``line`` with any trailing shell comment removed.

    Load-bearing, because these drivers document the bug #2055 fixed by
    quoting the old shape verbatim -- rex86_backfill_direct.sh carries the
    comment ``the old "rm -f $result" up front destroyed the last-known-good
    result``. A line-level detector that does not strip comments reports that
    prose as the very regression it describes.
    """
    return COMMENT_RE.sub("", line)


def _logical(lines):
    """``lines`` with comments stripped and backslash-continuations joined.

    The eval invocation and the ``| tee "$tmp"`` it pipes into are written on
    two physical lines. They are one command and only mean anything when
    matched as one.
    """
    out, buf = [], ""
    for raw in lines:
        stripped = _code(raw)
        if stripped.rstrip().endswith("\\"):
            buf += stripped.rstrip()[:-1]
            continue
        out.append(buf + stripped)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _scopes(text):
    """Split a script into ``(label, lines)`` scopes: one per shell function
    plus the top level.

    Crude but sufficient here -- these drivers declare functions as
    ``name() {`` at column 0 and close with ``}`` at column 0. Scope matters
    because item 1's contract is not "never delete a result" (deleting a stale
    result immediately before re-running *that one model* is deliberate) but
    "never delete a result in the same scope that then launches a server".
    """
    lines = text.splitlines()
    scopes, top, i = [], [], 0
    while i < len(lines):
        m = re.match(r"^(\w+)\s*\(\)\s*\{\s*$", lines[i])
        if not m:
            top.append(lines[i])
            i += 1
            continue
        body, depth, i = [], 1, i + 1
        while i < len(lines) and depth:
            if re.match(r"^\}\s*$", lines[i]):
                depth -= 1
                if not depth:
                    i += 1
                    break
            body.append(lines[i])
            i += 1
        scopes.append((m.group(1) + "()", body))
    scopes.append(("<top level>", top))
    return scopes


def _result_vars(text):
    """Names of variables assigned a ``*.corpus_eval.out`` path."""
    return set(
        re.findall(
            r"^\s*(?:local\s+)?(\w+)=\"?[^\"\n]*\.corpus_eval\.out\"?", text, re.M
        )
    )


def _tmp_vars(text, result_vars):
    """Names of variables holding the staging path for a result file.

    The drivers stage through ``local tmp="${result}.tmp"``, so the tee target
    written in the source is the *variable* ``$tmp`` -- never a literal path
    ending in ``.tmp``. Resolving the assignment instead of matching how the
    token is spelled is what keeps the check below a check on the promotion
    protocol rather than a check that the variable happens to be named ``tmp``.

    The value must also derive from a result path, so an unrelated
    ``scratch="/tmp/whatever.tmp"`` cannot satisfy the protocol by accident.
    """
    names = set()
    for name, value in re.findall(
        r"^\s*(?:local\s+)?(\w+)=\"?([^\"\n]*)\"?\s*$", text, re.M
    ):
        if not value.endswith(".tmp"):
            continue
        stem = value[: -len(".tmp")]
        ref = re.fullmatch(r"\$\{?(\w+)\}?", stem)
        if ".corpus_eval.out" in stem or (ref and ref.group(1) in result_vars):
            names.add(name)
    return names


def _target(token):
    """A redirect target reduced to a comparable form.

    A target picked out of ``... | tee "$tmp"; then`` arrives as ``"$tmp";`` --
    quoted, and carrying the shell punctuation that ends the command.
    """
    return token.strip().strip(";&|").strip("\"'")


def _ref_pattern(target):
    """A regex matching ``target`` wherever it is used as a command argument.

    ``$tmp`` must also match the ``"${tmp}"`` spelling; a literal path is
    matched verbatim.
    """
    ref = re.fullmatch(r"\$\{?(\w+)\}?", target)
    return rf"\$\{{?{ref.group(1)}\}}?" if ref else re.escape(target)


def _removes_a_result(line, result_vars):
    """True if ``line`` is an ``rm`` of a final (non-``.tmp``) result file."""
    m = re.search(r"\brm\s+(?:-\w+\s+)*(?P<target>\S+)", _code(line))
    if not m:
        return False
    target = m.group("target")
    if target.endswith(".tmp") or target.endswith('.tmp"'):
        return False
    if ".corpus_eval.out" in target:
        return True
    var = re.fullmatch(r"\"?\$\{?(\w+)\}?\"?", target)
    return bool(var and var.group(1) in result_vars)


# --------------------------------------------------------------------------
# item 3 -- one shared guard, matching drivers by construction
# --------------------------------------------------------------------------


def test_common_helper_is_sourceable_and_defines_the_guard():
    """``rex86_common.sh`` must actually load in a real shell and leave both
    the pattern and the function defined. Asserting the *names appear in the
    text* would pass on a file that is syntactically broken."""
    assert COMMON.exists(), f"{COMMON} must exist as the shared driver helper"
    probe = subprocess.run(
        ["bash", "-c", f'source "{COMMON}"; echo "$REX86_DRIVER_PATTERN"; '
                       "declare -F rex86_wait_for_gpu_drivers"],
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, (
        f"sourcing {COMMON.name} failed: {probe.stderr.strip()}"
    )
    pattern, _, declared = probe.stdout.partition("\n")
    assert pattern.strip(), "REX86_DRIVER_PATTERN must be set by the helper"
    assert "rex86_wait_for_gpu_drivers" in declared, (
        "rex86_common.sh must define rex86_wait_for_gpu_drivers()"
    )


def test_guard_pattern_matches_drivers_by_convention_not_by_enumeration():
    """The pattern must match every ``rex86_*`` driver *by construction*.

    A pattern that merely alternates the current filenames would pass a naive
    "does it match today's drivers" check while regressing the whole point of
    item 3, so this also asserts a hypothetical future driver matches and that
    unrelated processes do not.
    """
    pattern = subprocess.run(
        ["bash", "-c", f'source "{COMMON}"; printf %s "$REX86_DRIVER_PATTERN"'],
        capture_output=True, text=True, check=True,
    ).stdout

    def matches(name):
        return (
            subprocess.run(
                ["grep", "-Eq", pattern], input=name, text=True
            ).returncode
            == 0
        )

    for path in _drivers():
        if path.name.startswith("rex86_"):
            assert matches(path.name), (
                f"{path.name} is a rex86_ driver but REX86_DRIVER_PATTERN "
                f"({pattern!r}) does not match it -- other drivers will not "
                f"wait for it and two model servers will contend for the GPU."
            )

    assert matches("rex86_run_something_new.sh"), (
        f"REX86_DRIVER_PATTERN ({pattern!r}) must match a rex86_*.sh driver "
        f"that does not exist yet. Item 3 is specifically about replacing an "
        f"enumerated list that has to be kept in sync by hand."
    )
    for unrelated in ("corpus_eval.py", "merge.py", "grep", "sleep"):
        assert not matches(unrelated), (
            f"REX86_DRIVER_PATTERN ({pattern!r}) matches {unrelated!r}; too "
            f"broad a guard makes every driver wait forever on unrelated "
            f"processes."
        )


def test_guard_excludes_the_calling_process():
    """The wait loop must exclude its own PID, or the first driver to call it
    blocks forever on itself -- a deadlock that looks exactly like a healthy
    'waiting for the GPU' run in the log."""
    body = subprocess.run(
        ["bash", "-c", f'source "{COMMON}"; declare -f rex86_wait_for_gpu_drivers'],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "$$" in body, (
        "rex86_wait_for_gpu_drivers must exclude its own PID (grep -vx \"$$\" "
        "or equivalent); without it the guard deadlocks against itself."
    )
    assert re.search(r"\b(while|until)\b", body), (
        "rex86_wait_for_gpu_drivers must poll in a loop, not test once."
    )


def test_every_driver_sources_the_common_helper_on_its_own_line():
    """Every driver must pick up the shared guard.

    This asserts a *whole line* that is exactly a source of the helper. The
    superseded version asserted the substrings ``"source "`` and
    ``"rex86_common.sh"`` appeared anywhere in the file, independently -- which
    a mangled line satisfies just as well as a correct one.
    """
    for path in _drivers():
        assert any(SOURCE_RE.match(ln) for ln in _read(path).splitlines()), (
            f"{path.name} has no standalone `source \"$WORK/rex86_common.sh\"` "
            f"line, so it does not get the shared GPU guard (item 3)."
        )


def test_driver_prologues_are_runnable():
    """A driver that aborts on its own second line satisfies every
    text-matching contract in this file and still runs nothing.

    Two things must hold: ``set -...o`` keeps its ``pipefail`` argument, and
    the ``source`` of the helper happens *after* the variable holding its
    directory is assigned.

    This carried a ``strict=True`` xfail from the day it was written: #2055
    inserted the ``source`` line into eight drivers by splitting their
    ``set -uo pipefail`` / ``set -euo pipefail``, stranding ``pipefail`` as an
    ignored argument to the sourced file and putting the ``source`` *above*
    the ``WORK=`` assignment it depends on. Bare ``set -o`` then printed the
    whole shell-option table into every driver log, ``pipefail`` was never
    enabled, and under ``set -u`` the source aborted the script with
    ``WORK: unbound variable`` before it reached a single line of its own
    work. All eight are repaired (#2979, alongside #2054, which could not
    otherwise be verified against a script that cannot start), so the marker
    is gone and this is now a live contract.
    """
    broken = []
    for path in _drivers():
        lines = _read(path).splitlines()

        for i, line in enumerate(lines, 1):
            m = SET_RE.match(line)
            if m and not m.group("rest").strip():
                broken.append(
                    f"{path.name}:{i}: `{line.strip()}` -- `-o` with no option "
                    f"name prints the shell-option table and leaves pipefail off"
                )

        for i, line in enumerate(lines, 1):
            m = SOURCE_RE.match(line)
            if not m:
                continue
            if m.group("args").strip():
                broken.append(
                    f"{path.name}:{i}: `{line.strip()}` -- "
                    f"{m.group('args').strip()!r} trailing the sourced path is "
                    f"the argument `set -o` lost on the line above. It is "
                    f"passed to rex86_common.sh as $1 and silently ignored, "
                    f"so pipefail is never enabled and a failing stage in the "
                    f"eval pipeline is reported as success"
                )
            var = m.group("var")
            assigned = next(
                (
                    j
                    for j, ln in enumerate(lines, 1)
                    if re.match(rf"^\s*(?:export\s+)?{var}=", ln)
                ),
                None,
            )
            if assigned is None or assigned > i:
                broken.append(
                    f"{path.name}:{i}: sources \"${var}/rex86_common.sh\" but "
                    f"${var} is "
                    + (
                        "never assigned"
                        if assigned is None
                        else f"not assigned until line {assigned}"
                    )
                    + " -- under `set -u` this aborts the driver"
                )

    assert not broken, "unrunnable driver prologues:\n  " + "\n  ".join(broken)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN GAP, still live on main as of f03eb727. vllm_tuning_run.sh was "
        "given a `source rex86_common.sh` line by #2055 -- so the fix treats "
        "it as a driver -- but it matches neither half of "
        "REX86_DRIVER_PATTERN ('rex86_*.sh' or 'real_bench_run.sh'). It "
        "starts a vllm container holding the whole GPU while no other driver "
        "waits for it, and the other drivers' free_gpu() only pkills "
        "llama-server, not vllm. Repair is either to widen the pattern or to "
        "rename the script; the source file is out of scope for this "
        "test-only change. Strict, so the repair forces this marker's removal."
    ),
)
def test_every_script_that_sources_the_helper_is_matched_by_the_guard_pattern():
    """Sourcing ``rex86_common.sh`` is the declaration "I am a GPU driver".

    The guard is only sound if that set and the set matched by
    ``REX86_DRIVER_PATTERN`` are the same: a script that waits for others but
    that others cannot see still collides with them on the single GPU.
    """
    pattern = subprocess.run(
        ["bash", "-c", f'source "{COMMON}"; printf %s "$REX86_DRIVER_PATTERN"'],
        capture_output=True, text=True, check=True,
    ).stdout
    unseen = [
        path.name
        for path in _drivers()
        if any(SOURCE_RE.match(ln) for ln in _read(path).splitlines())
        and subprocess.run(
            ["grep", "-Eq", pattern], input=path.name, text=True
        ).returncode
    ]
    assert not unseen, (
        f"these scripts source rex86_common.sh but REX86_DRIVER_PATTERN "
        f"({pattern!r}) does not match them, so no other driver waits for "
        f"them: {unseen}"
    )


# --------------------------------------------------------------------------
# items 1 and 2 -- the result-file protocol
# --------------------------------------------------------------------------


def test_no_result_is_deleted_in_a_scope_that_launches_a_server():
    """Item 1. The pre-fix shape was::

        local result=".../${name}-${tag}.corpus_eval.out"
        rm -f "$result"
        ...
        docker exec -d rex86-eval ... llama-server ...

    A launch that fails leaves neither a new result nor the old one.

    Scoped to the launching function on purpose: deleting a stale result
    immediately before re-running *that one model* (as
    rex86_backfill_answers.sh does, delegating the run to another driver) is
    deliberate and must stay legal.
    """
    offenders = []
    for path in _drivers():
        text = _read(path)
        result_vars = _result_vars(text)
        for label, body in _scopes(text):
            code = _logical(body)
            if not any(GPU_LAUNCH_RE.search(ln) for ln in code):
                continue
            offenders += [
                f"{path.name} {label}: {ln.strip()}"
                for ln in code
                if _removes_a_result(ln, result_vars)
            ]
    assert not offenders, (
        "a previous run's result is deleted in a scope that then launches a "
        "model server; a failed launch destroys the last known-good result "
        "(#2055 item 1). Write to a .tmp and promote it on success:\n  "
        + "\n  ".join(offenders)
    )


def test_eval_output_is_promoted_from_tmp_only_on_success():
    """Items 1 and 2 together, on the write side.

    Every eval invocation that owns a ``*.corpus_eval.out`` result must pipe
    into ``tee "$tmp"``, ``mv`` the tmp onto the real result only when the
    pipeline succeeded, and ``rm`` it otherwise. An unconditional
    ``tee "$result"`` leaves a truncated file that every caller's exists-check
    reads as done.

    Scoped to result-owning invocations deliberately. rex86_bench.sh runs the
    same eval three times with no result file at all -- its output goes to the
    driver log, there is nothing to clobber and nothing a later run would
    trust -- so holding it to a promotion protocol would assert a contract
    #2055 never made.
    """
    checked = 0
    for path in _drivers():
        text = _read(path)
        result_vars = _result_vars(text)
        tmp_vars = _tmp_vars(text, result_vars)
        for label, body in _scopes(text):
            code = _logical(body)
            calls = [ln for ln in code if EVAL_RE.search(ln)]
            if not calls or not any(".corpus_eval.out" in ln for ln in code):
                continue
            checked += 1
            where = f"{path.name} {label}"
            joined = "\n".join(code)
            for call in calls:
                tee_targets = [
                    _target(t) for t in re.findall(r"\|\s*tee\s+(\S+)", call)
                ]
                assert tee_targets, (
                    f"{where}: `{call.strip()}` owns a result file but its "
                    f"output is not tee'd anywhere, so a successful eval "
                    f"writes no result and the work is redone forever."
                )
                for target in tee_targets:
                    ref = re.fullmatch(r"\$\{?(\w+)\}?", target)
                    assert target.endswith(".tmp") or (
                        ref and ref.group(1) in tmp_vars
                    ), (
                        f"{where}: corpus_eval output is tee'd straight to "
                        f"{target!r}, which is not a staging file derived from "
                        f"the result path. A mid-eval failure then leaves a "
                        f"truncated result that later runs trust (#2055 "
                        f"item 2)."
                    )
                    # The staging file that was written must be the one
                    # promoted and the one cleaned up -- teeing to "$tmp" and
                    # then promoting some other path is the same regression
                    # wearing the right variable name.
                    token = _ref_pattern(target)
                    assert re.search(
                        rf"\bmv\s+(?:-\w+\s+)*\"?{token}\"?", joined
                    ), (
                        f"{where}: {target!r} is written but never `mv`'d onto "
                        f"the result, so a successful eval never replaces the "
                        f"previous result."
                    )
                    assert re.search(
                        rf"\brm\s+(?:-\w+\s+)*\"?{token}\"?", joined
                    ), (
                        f"{where}: {target!r} is never removed, so a failed "
                        f"eval leaves a partial file behind (#2055 item 2)."
                    )
    assert checked >= 5, (
        f"expected the eval-and-promote block in at least 5 result-owning "
        f"scopes, found {checked} -- the scope parser or the drivers moved; "
        f"this test would otherwise silently assert nothing."
    )


# --------------------------------------------------------------------------
# item 4 -- pinned HuggingFace snapshots
# --------------------------------------------------------------------------


def test_every_snapshot_download_pins_a_resolved_commit():
    """Item 4, across every driver that fetches from HuggingFace rather than
    just the prefetch script the superseded test happened to name.

    Both forms are acceptable: a hardcoded ``revision=<sha>``, or resolving the
    moving branch once via ``HfApi().model_info(...).sha`` and pinning the
    download to that. A bare ``snapshot_download(repo, local_dir=...)``
    defaults to ``main`` and is the regression.
    """
    fetchers = [p for p in _drivers() if "snapshot_download(" in _read(p)]
    assert fetchers, "no driver calls snapshot_download(); the fetch moved"
    for path in fetchers:
        text = _read(path)
        for call in re.findall(r"snapshot_download\(([^)]*)\)", text):
            assert "revision" in call, (
                f"{path.name}: snapshot_download({call}) has no revision=, so "
                f"it tracks the moving 'main' branch. Upstream drift then "
                f"changes the weights an already-stored result describes, "
                f"with nothing on disk recording which commit produced it "
                f"(#2055 item 4)."
            )
        assert re.search(
            r"HfApi\(\)\.model_info\([^)]+\)\.(sha|commit_sha)", text
        ) or re.search(r"revision\s*=\s*['\"][0-9a-f]{7,40}['\"]", text), (
            f"{path.name}: revision= is passed but never bound to a concrete "
            f"commit SHA (neither an HfApi()-resolved .sha nor a literal "
            f"hash), so the pin does not actually pin anything."
        )


def test_adapter_queues_pass_a_pinned_base_revision():
    """``rex86_run_one.sh`` has always accepted an optional ``[base_revision]``
    4th argument; before #2055 no caller passed one, so the pinning hook was
    dead code. Every ``run``/``retry``/``backfill`` invocation must supply a
    full 40-hex commit SHA."""
    callers = {
        "rex86_run_all.sh": "run",
        "rex86_retry_failed_adapters.sh": "retry",
        "rex86_backfill_answers.sh": "bash rex86_run_one.sh",
    }
    for filename, invocation in callers.items():
        path = REX86_DIR / filename
        assert path.exists(), f"{filename} is missing"
        calls = [
            ln
            for ln in _read(path).splitlines()
            if ln.strip().startswith(invocation) and '"' in ln
        ]
        assert calls, f"{filename}: no `{invocation}` invocations found"
        for line in calls:
            assert re.search(r"\b[0-9a-f]{40}\b", line), (
                f"{filename}: `{line.strip()}` does not pass a pinned "
                f"40-character base revision, so the adapter is merged onto "
                f"whatever 'main' points at that day (#2055 item 4)."
            )


# --------------------------------------------------------------------------
# meta -- the detectors above must fail on the pre-fix code
# --------------------------------------------------------------------------


@pytest.mark.skipif(
    shutil.which("git") is None, reason="git required to read the pre-fix blobs"
)
def test_the_regression_detectors_fire_on_the_pre_fix_code(tmp_path):
    """A regression test that also passes on the code it was written against
    guards nothing. This reconstructs the drivers as of the fix's parent
    commit and asserts the two central detectors -- item 1's pre-launch delete
    and item 2's tmp promotion -- both report the pre-fix code as broken.

    Skipped rather than failed when the commit is unreachable (shallow clone),
    since that says nothing about the drivers.
    """
    parent = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "-q", "--verify",
         "f03eb727^:analysis/ghidra/benchmarks/model-quant-benchmark"],
        capture_output=True, text=True,
    )
    if parent.returncode:
        pytest.skip("pre-fix tree f03eb727^ not available in this clone")

    listing = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-tree", "--name-only",
         "f03eb727^:analysis/ghidra/benchmarks/model-quant-benchmark"],
        capture_output=True, text=True, check=True,
    ).stdout.split()

    found_predelete = found_unconditional_tee = False
    for name in (n for n in listing if n.endswith(".sh")):
        text = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "show",
             f"f03eb727^:analysis/ghidra/benchmarks/model-quant-benchmark/{name}"],
            capture_output=True, text=True, check=True,
        ).stdout
        result_vars = _result_vars(text)
        for _label, body in _scopes(text):
            code = _logical(body)
            if not any(GPU_LAUNCH_RE.search(ln) for ln in code):
                continue
            if any(_removes_a_result(ln, result_vars) for ln in code):
                found_predelete = True
            joined = "\n".join(code)
            if "corpus_eval.py" in joined and re.search(
                r"\|\s*tee\s+\"\$\{?result\}?\"", joined
            ):
                found_unconditional_tee = True

    assert found_predelete, (
        "the item 1 detector does not fire on the pre-fix drivers, which are "
        "known to `rm -f \"$result\"` before launching llama-server -- it "
        "would not catch the regression coming back."
    )
    assert found_unconditional_tee, (
        "the item 2 detector does not fire on the pre-fix drivers, which are "
        "known to `tee \"$result\"` unconditionally."
    )


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
