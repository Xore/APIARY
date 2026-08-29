#!/usr/bin/env python3
"""Regression test for #2619: the conpot 24.04 -> 24.04.1 bump.

#2314 froze `dtagdevsec/conpot` at 24.04 because the six `*_patch.py`
scripts hard-code the base image's Python site-packages root, and the
freeze note claimed 24.04.1 had "restructured the package". It hadn't.
The only relevant difference is the Python install root: conpot moved
from 3.11 to 3.12, so

    /usr/lib/python3.11/site-packages/conpot/...

became

    /usr/lib/python3.12/site-packages/conpot/...

with the package's internal layout unchanged. #2619 bumps the pin and
retargets all six patch scripts.

What this file pins, and why it is written the way it is:

- The bump is asserted on the *parsed* `FROM` reference (repository, tag,
  digest as separate fields), not by string-searching the Dockerfile.
  A substring check for "24.04.1" passes on a Dockerfile that merely
  mentions the version in a comment while still building from 24.04, and
  it cannot see a silently dropped `@sha256:` pin -- which would let the
  mutable tag roll onto a genuinely restructured image with no file in
  this repo changing, re-creating #2314's failure mode exactly.

- The freeze-comment check bans the stale *rationale*, not the string
  "#2314". The replacement header legitimately cites #2314 to explain
  what changed and why, and it legitimately names both the 3.11 and 3.12
  paths to describe the move. Banning either would forbid documenting
  the fix. What must be gone is the claim that the pin is deliberately
  held back.

- The patch scripts are checked by parsing them with `ast` and reading
  their string literals, not by grepping. Grep cannot tell a live path
  constant from a docstring, and every one of these scripts has a long
  module docstring. An `ast` walk that skips docstrings looks at exactly
  the literals that become filesystem paths at build time.

- The repo-wide sweeps are comment-aware for the same reason. A naive
  `grep -r python3.11/site-packages/conpot` over this repo matches the
  new Dockerfile header (which documents the move), a provenance note in
  `ml-worker/tests/fixtures.py` (which records which image a JSON log
  fixture was read from) and this file's own constants -- none of which
  is a build path. The sweep below strips comments and docstrings first,
  so it reports only references that would actually resolve a path.

Ordering note: this file asserts the post-#2619 state. It is red until
that bump is on the branch, by construction -- that is what makes it a
regression test rather than a description.
"""
import ast
import pathlib
import re
import shlex
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SELF_RELPATH = "tests/docs/test_2619_fix.py"

CONPOT_DIR = "arcane/home/honeypot-conpot/conpot"
CONPOT_DOCKERFILE = f"{CONPOT_DIR}/Dockerfile"

CONPOT_REPOSITORY = "dtagdevsec/conpot"
# The bump: 24.04.1, at the manifest-list digest the retargeted patch
# scripts were verified against.
CONPOT_TAG = "24.04.1"
CONPOT_DIGEST = "sha256:ff37c322037ad8c1f4f05c2c93f7b60cc5f56b7f37a2c4cbc16901ec70bddb5b"
# What #2314 pinned, and must no longer be built from.
CONPOT_FROZEN_TAG = "24.04"
CONPOT_FROZEN_DIGEST = "sha256:717f0bdf79ad267e7402ff09fcc2f4ce413e9165843dd58c18f340acdd49ea7e"

# The regression string. 24.04.1 ships conpot under Python 3.12; any patch
# script still naming the 3.11 root FileNotFoundErrors at build time.
PY311_CONPOT_ROOT = "/usr/lib/python3.11/site-packages/conpot"
PY312_CONPOT_ROOT = "/usr/lib/python3.12/site-packages/conpot"
# Matches the site-packages root of any Python version, so a future bump
# to 3.13 that forgets a script is caught as loudly as a leftover 3.11.
CONPOT_ROOT_RE = re.compile(r"/usr/lib/python(?P<pyver>3\.\d+)/site-packages/conpot")

# The six scripts #2619 names. Spelled out rather than globbed: a seventh
# script appearing is something the suite should have an opinion about,
# not something it should silently absorb.
PATCH_SCRIPTS = [
    "persona_patch.py",
    "proxy_patch.py",
    "s7comm_patch.py",
    "modbus_patch.py",
    "guardian_ast_patch.py",
    "iec104_patch.py",
]

# Phrases that only make sense while the pin is deliberately held back.
# Matched case-insensitively against the whole Dockerfile, comments
# included -- unlike the version strings, these are wrong *as prose*.
STALE_FREEZE_PHRASES = [
    "deliberately not bumped",
    "restructured the package",
    "tracked separately",
]

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# --- helpers --------------------------------------------------------------

def _tracked_files():
    """Repo-tracked paths, relative to REPO_ROOT.

    Deliberately `git ls-files` and not `rglob`: a developer checkout
    carries untracked sibling worktrees under `.orchestrator/worktrees/`,
    each with its own copy of the conpot Dockerfile and patch scripts on
    some other branch. A filesystem walk reports every one of them as an
    offender.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
            capture_output=True, check=True, text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover
        pytest.skip(f"git ls-files unavailable: {exc}")
    return [p for p in out.split("\0") if p]


def _read(relpath):
    return (REPO_ROOT / relpath).read_text(encoding="utf-8")


def _instruction_lines(text):
    """Dockerfile instructions, comments and blanks dropped, backslash
    continuations folded into one logical line."""
    logical, buf = [], ""
    for raw in text.splitlines():
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            buf += line[:-1].strip() + " "
            continue
        logical.append((buf + line).strip())
        buf = ""
    if buf.strip():
        logical.append(buf.strip())
    return logical


def _parse_image_ref(ref):
    """Split a Docker image reference into (repository, tag, digest)."""
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    # A ':' before the last '/' is a registry port, not a tag.
    if ":" in ref and "/" not in ref.rsplit(":", 1)[1]:
        ref, tag = ref.rsplit(":", 1)
    return ref, tag, digest


def _from_refs(instructions):
    refs = []
    for line in instructions:
        m = re.match(r"^FROM\s+(?:--\S+\s+)*(\S+)", line, re.IGNORECASE)
        if m:
            refs.append(m.group(1))
    return refs


def _copy_sources(instructions):
    """Build-context-relative sources of every COPY without --from."""
    sources = []
    for line in instructions:
        if not re.match(r"^COPY\s", line, re.IGNORECASE):
            continue
        tokens = shlex.split(line)[1:]
        if any(t.startswith("--from=") for t in tokens):
            continue
        tokens = [t for t in tokens if not t.startswith("--")]
        if len(tokens) < 2:
            continue
        sources.extend(tokens[:-1])
    return sources


def _docstring_nodes(tree):
    """Every string-literal node that serves as a docstring."""
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef,
                                 ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if (isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            found.add(id(first.value))
    return found


def _code_string_literals(source):
    """String literals in `source`, excluding docstrings.

    Returns None if the file does not parse as Python, so callers can
    fall back to a raw scan rather than silently reporting "clean".
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    skip = _docstring_nodes(tree)
    return [
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in skip
    ]


def _strip_hash_comments(text):
    """Drop whole-line and trailing `#` comments.

    Trailing comments are only stripped when the `#` has no quote before
    it on the line, so a `#` inside a shell or YAML string survives.
    """
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0] if raw.lstrip().startswith("#") else raw
        if "#" in line and '"' not in line.split("#", 1)[0] and "'" not in line.split("#", 1)[0]:
            line = line.split("#", 1)[0]
        out.append(line)
    return "\n".join(out)


def _effective_text(relpath, text):
    """The part of a file that can actually resolve a filesystem path.

    Prose is excluded: documentation and docstrings describing the 3.11
    -> 3.12 move are correct and must not be flagged. Returns None for
    files that are entirely prose.
    """
    name = pathlib.PurePosixPath(relpath).name
    suffix = pathlib.PurePosixPath(relpath).suffix
    if suffix in {".md", ".txt", ".rst"}:
        return None
    if suffix == ".py":
        literals = _code_string_literals(text)
        if literals is not None:
            return "\n".join(literals)
        return text
    if name.startswith("Dockerfile") or name == "Containerfile":
        return "\n".join(_instruction_lines(text))
    return _strip_hash_comments(text)


def _sweep_conpot_roots():
    """(relpath, python-version) for every effective conpot site-packages
    path reference in the tracked repo, this file excluded."""
    hits = []
    for relpath in _tracked_files():
        if relpath == SELF_RELPATH:
            continue
        path = REPO_ROOT / relpath
        if not path.is_file() or path.is_symlink():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if "site-packages/conpot" not in text:
            continue
        effective = _effective_text(relpath, text)
        if effective is None:
            continue
        for m in CONPOT_ROOT_RE.finditer(effective):
            hits.append((relpath, m.group("pyver")))
    return hits


def _dockerfile_instructions():
    return _instruction_lines(_read(CONPOT_DOCKERFILE))


def _script_conpot_paths(script):
    """conpot site-packages paths named by a patch script's live code."""
    literals = _code_string_literals(_read(f"{CONPOT_DIR}/{script}"))
    assert literals is not None, f"{script} does not parse as Python"
    return [
        (lit, m.group("pyver"))
        for lit in literals
        for m in [CONPOT_ROOT_RE.search(lit)] if m
    ]


# --- the bump itself ------------------------------------------------------

def test_conpot_from_pins_24_04_1_at_the_expected_digest():
    """The Dockerfile must build from dtagdevsec/conpot:24.04.1 at the
    digest the retargeted patch scripts were verified against.

    Checked as parsed fields. A substring search for "24.04.1" would pass
    on a Dockerfile that only mentions the version in its header comment,
    and would not notice the `@sha256:` pin being dropped -- which is the
    more dangerous regression, since the mutable tag can then roll onto a
    different image with nothing in this repo changing.
    """
    refs = _from_refs(_dockerfile_instructions())
    assert len(refs) == 1, (
        f"{CONPOT_DOCKERFILE} should have exactly one FROM (the pinned "
        f"conpot base); found {len(refs)}: {refs}"
    )
    repository, tag, digest = _parse_image_ref(refs[0])
    assert repository == CONPOT_REPOSITORY, (
        f"{CONPOT_DOCKERFILE} builds from {repository!r}, expected "
        f"{CONPOT_REPOSITORY!r} -- #2619"
    )
    assert tag == CONPOT_TAG, (
        f"{CONPOT_DOCKERFILE} builds from tag {tag!r}, expected "
        f"{CONPOT_TAG!r}. #2619 bumped off the {CONPOT_FROZEN_TAG} freeze "
        f"once the only real difference turned out to be the Python root "
        f"({PY311_CONPOT_ROOT} -> {PY312_CONPOT_ROOT})."
    )
    assert digest is not None, (
        f"{CONPOT_DOCKERFILE} dropped the @sha256: digest pin. A bare "
        f"{CONPOT_TAG} tag is mutable and can roll onto an image with a "
        f"different Python root, breaking every patch script at build "
        f"time with no change in this repo -- exactly #2314's failure mode."
    )
    assert DIGEST_RE.match(digest), f"malformed digest pin {digest!r}"
    assert digest == CONPOT_DIGEST, (
        f"{CONPOT_DOCKERFILE} pins {CONPOT_TAG} at {digest}, expected "
        f"{CONPOT_DIGEST} -- the manifest list the patch scripts were "
        f"verified against (#2619)"
    )


def test_conpot_instructions_no_longer_reference_the_24_04_pin():
    """No instruction may still name the frozen 24.04 tag or its digest.

    Instruction lines only: the header comment explains what the pin was
    bumped *from*, and that is worth keeping.
    """
    instructions = _dockerfile_instructions()
    for banned, what in (
        (f"{CONPOT_REPOSITORY}:{CONPOT_FROZEN_TAG}@", "frozen tag"),
        (CONPOT_FROZEN_DIGEST, "frozen digest"),
    ):
        offending = [line for line in instructions if banned in line]
        assert not offending, (
            f"{CONPOT_DOCKERFILE} still references the {what} {banned!r} "
            f"in an instruction:\n  " + "\n  ".join(offending) +
            f"\n#2619 bumped this pin to {CONPOT_TAG}."
        )


def test_conpot_dockerfile_no_longer_carries_the_2314_freeze_rationale():
    """The freeze note must be gone.

    Deliberately not a ban on the string "#2314": the replacement header
    cites it to record what changed and why, which is the documentation
    this repo asks for. What must not survive is the claim that the pin
    is being held back on purpose -- that text outliving the freeze is
    how the next person re-freezes it by hand.
    """
    text = _read(CONPOT_DOCKERFILE).lower()
    stale = [p for p in STALE_FREEZE_PHRASES if p in text]
    assert not stale, (
        f"{CONPOT_DOCKERFILE} still carries #2314 freeze rationale "
        f"{stale}, but the pin was bumped to {CONPOT_TAG} in #2619. The "
        f"note now describes a state the file is not in."
    )


# --- the six patch scripts ------------------------------------------------

@pytest.mark.parametrize("script", PATCH_SCRIPTS)
def test_patch_script_exists(script):
    assert (REPO_ROOT / CONPOT_DIR / script).is_file(), (
        f"{CONPOT_DIR}/{script} is missing -- #2619 retargets all six "
        f"conpot patch scripts"
    )


@pytest.mark.parametrize("script", PATCH_SCRIPTS)
def test_patch_script_targets_the_python_3_12_root(script):
    """Every patch script's live code must name the 3.12 conpot root.

    Read via `ast`, docstrings excluded: these scripts carry long module
    docstrings, and a grep cannot tell the prose that explains the path
    from the `Path(...)` literal that opens it. Asserting at least one
    literal exists also catches a script that stops naming a path at all
    and would otherwise pass a pure "no 3.11 anywhere" check vacuously.
    """
    found = _script_conpot_paths(script)
    assert found, (
        f"{CONPOT_DIR}/{script} names no conpot site-packages path in "
        f"live code. It should target {PY312_CONPOT_ROOT}/... -- if the "
        f"script now discovers the layout at runtime instead, this "
        f"expectation needs rewriting rather than deleting (#2619)."
    )
    wrong = [(lit, ver) for lit, ver in found if ver != "3.12"]
    assert not wrong, (
        f"{CONPOT_DIR}/{script} targets a non-3.12 Python root: "
        f"{[lit for lit, _ in wrong]}. conpot 24.04.1 installs under "
        f"{PY312_CONPOT_ROOT}; anything else FileNotFoundErrors at build "
        f"time (#2619)."
    )


@pytest.mark.parametrize("script", PATCH_SCRIPTS)
def test_patch_script_does_not_reference_the_python_3_11_root(script):
    """The regression, stated directly: no 3.11 path may come back.

    Separate from the 3.12 test on purpose -- a script that gained a
    second, stale path constant alongside a correct one would satisfy
    "targets 3.12" while still breaking the build.
    """
    literals = _code_string_literals(_read(f"{CONPOT_DIR}/{script}"))
    assert literals is not None, f"{script} does not parse as Python"
    offenders = [lit for lit in literals if PY311_CONPOT_ROOT in lit]
    assert not offenders, (
        f"{CONPOT_DIR}/{script} still references {PY311_CONPOT_ROOT} in "
        f"live code: {offenders}. That is 24.04's layout; the image is "
        f"pinned at {CONPOT_TAG}, which installs conpot under Python "
        f"3.12 (#2619)."
    )


def test_dockerfile_copies_and_runs_exactly_the_six_patch_scripts():
    """The six scripts this file checks must be the six the build uses.

    Without this, adding a seventh patch script with a stale 3.11 path
    breaks the image while every parametrized test above still passes --
    they only ever look at the six names hardcoded here.
    """
    instructions = _dockerfile_instructions()
    copied = {s for s in _copy_sources(instructions) if s.endswith("_patch.py")}
    on_disk = {p.name for p in (REPO_ROOT / CONPOT_DIR).glob("*_patch.py")}
    expected = set(PATCH_SCRIPTS)
    assert copied == expected, (
        f"{CONPOT_DOCKERFILE} COPYs a different set of patch scripts than "
        f"#2619 retargeted.\nunexpected: {sorted(copied - expected)}\n"
        f"missing: {sorted(expected - copied)}"
    )
    assert on_disk == expected, (
        f"{CONPOT_DIR}/ holds a different set of patch scripts than #2619 "
        f"retargeted.\nunexpected: {sorted(on_disk - expected)}\n"
        f"missing: {sorted(expected - on_disk)}"
    )
    run_text = " ".join(
        l for l in instructions if re.match(r"^RUN\s", l, re.IGNORECASE)
    )
    never_run = [
        s for s in sorted(expected)
        if not re.search(rf"python[0-9.]*\s+\S*{re.escape(s)}(?:\s|$)", run_text)
    ]
    assert not never_run, (
        f"{CONPOT_DOCKERFILE} COPYs these patch scripts but never executes "
        f"them: {never_run}. A retargeted patch that is no longer invoked "
        f"leaves the honeypot on conpot's stock persona while the build "
        f"stays green (#2619)."
    )


# --- repo-wide sweeps -----------------------------------------------------

def test_no_effective_python_3_11_conpot_path_remains_anywhere():
    """#2619's acceptance criterion: the regression string is gone.

    Comment- and docstring-aware. A raw grep for this path also matches
    the new Dockerfile header (which documents the 3.11 -> 3.12 move) and
    `ml-worker/tests/fixtures.py`'s provenance note (recording which
    image a JSON log fixture was transcribed from). Neither resolves a
    path at build or run time, and demanding they be reworded would be
    demanding that the fix be undocumented.
    """
    offenders = sorted(
        f"{relpath}: python{ver}"
        for relpath, ver in _sweep_conpot_roots() if ver == "3.11"
    )
    assert not offenders, (
        f"{PY311_CONPOT_ROOT} still resolves a path in tracked code -- "
        f"#2619 regression:\n" + "\n".join(offenders)
    )


def test_python_3_12_conpot_paths_are_confined_to_the_six_patch_scripts():
    """The new path must appear only where it belongs.

    Guards the other direction from the sweep above: a blanket
    search-and-replace of 3.11 -> 3.12 across the repo would satisfy
    every test so far while silently rewriting unrelated files. Only the
    conpot build context runs inside that image, so only it may name the
    image's install root in live code.
    """
    expected = {f"{CONPOT_DIR}/{s}" for s in PATCH_SCRIPTS}
    actual = {relpath for relpath, ver in _sweep_conpot_roots() if ver == "3.12"}
    assert actual == expected, (
        f"{PY312_CONPOT_ROOT} appears in an unexpected set of files.\n"
        f"unexpected: {sorted(actual - expected)}\n"
        f"missing: {sorted(expected - actual)}\n"
        f"Only conpot's own patch scripts run inside the conpot image, so "
        f"only they may hard-code its install root (#2619)."
    )


def test_sweep_only_ignores_prose():
    """The sweep's own blind spot, made visible.

    `_effective_text` strips comments and docstrings, which is what makes
    the sweeps usable -- but a bug there would turn both of them into
    tests that pass on anything. This pins the three exclusions that
    matter with inputs whose correct classification is unambiguous.
    """
    assert PY311_CONPOT_ROOT not in _effective_text(
        "x/Dockerfile", f"# note: {PY311_CONPOT_ROOT}\nFROM scratch\n")
    assert PY311_CONPOT_ROOT in _effective_text(
        "x/Dockerfile", f'RUN test -d {PY311_CONPOT_ROOT}\n')
    assert PY311_CONPOT_ROOT not in _effective_text(
        "x/y.py", f'"""doc {PY311_CONPOT_ROOT}"""\nX = 1\n')
    assert PY311_CONPOT_ROOT in _effective_text(
        "x/y.py", f'"""doc"""\nX = "{PY311_CONPOT_ROOT}"\n')
    # A file that does not parse must fall back to a raw scan rather than
    # be reported clean.
    assert PY311_CONPOT_ROOT in _effective_text(
        "x/y.py", f'def (:\nX = "{PY311_CONPOT_ROOT}"\n')


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
