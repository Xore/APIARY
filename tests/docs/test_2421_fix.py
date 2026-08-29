#!/usr/bin/env python3
"""Regression test for #2421: two npm majors were writing
arcane/home/honeypot-dashboard/frontend-next/package-lock.json.
Dependabot's updater resolved with its own npm (11.x), the container
builder (node:22-alpine, npm 10.x) with another. npm 11 omits
optional-peer shadow subtrees that npm 10 materializes, so npm 10 then
hard-fails `npm ci` on an npm-11-written lock with "Missing: <pkg>@<range>
from lock file" -- twice already (lru-cache #2284, ioredis #2419).

PR #2616 added `engines.npm: "10"` to package.json. This test locks in
the contract that pin is part of.

Note on what this file deliberately does NOT assert. The test that shipped
with #2616 claimed `lockfileVersion == 3` distinguishes npm 10 from npm 11
("npm 11 introduced lockfileVersion 4"). That is not true: npm 9, 10 and
11 all write lockfileVersion 3, so that assertion is invariant across
exactly the two majors it was supposed to tell apart. It can never fire on
the skew #2421 is about, and the promise that it would ("if Dependabot's
npm is ever upgraded the lockfileVersion will tick to 4 and that test
fires") is false. The format check is kept below, but scoped honestly to
what it actually proves.

What replaces it is the invariant that genuinely breaks in this class of
incident: the lockfile's own dependency graph must close. For every
dependency edge, npm's node_modules walk-up from the depending package
must reach an entry whose version satisfies the declared range. Dropping
the `node_modules/@babel/helper-compilation-targets/node_modules/lru-cache`
shadow subtree -- the #2284 shape -- makes `lru-cache@^5.1.1` walk up to
the top-level `lru-cache@11.5.2` instead, which does not satisfy it. That
is precisely the state `npm ci` refuses to install, and it is checkable
here without a network or an npm binary.

Live verification on the homeserver is deferred to manual -- this
workstation has no wg0 interface to reach the lab.
"""
import json
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FRONTEND = REPO_ROOT / "arcane" / "home" / "honeypot-dashboard" / "frontend-next"
PACKAGE_JSON = FRONTEND / "package.json"
LOCKFILE = FRONTEND / "package-lock.json"
DOCKERFILE = FRONTEND / "Dockerfile"
QUALITY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "quality.yml"

# Which npm major each node major ships. Only the majors this repo has
# plausibly used are listed; an unlisted major skips rather than fails, so
# a future node bump asks for a deliberate update here instead of going
# red for a reason unrelated to #2421.
NODE_MAJOR_TO_NPM_MAJOR = {"18": "9", "20": "10", "22": "10", "24": "11"}


def _package_json():
    return json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))


def _lockfile():
    return json.loads(LOCKFILE.read_text(encoding="utf-8"))


def _builder_node_major():
    """The node major the Dockerfile's build stage installs under."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    majors = re.findall(r"^FROM\s+node:(\d+)-", text, flags=re.MULTILINE)
    assert majors, f"no `FROM node:<major>-...` stage found in {DOCKERFILE}"
    return majors[0]


# --------------------------------------------------------------------------
# The pin itself, and the two things that make it mean something.
# --------------------------------------------------------------------------


def test_package_json_pins_a_bare_npm_major():
    """engines.npm must name one npm major exactly.

    A bare "10" is the whole point: a range ("^10", ">=10") would admit the
    npm 11 that wrote the broken lockfiles, and the previous test's
    `startswith("10")` would have accepted "100" or "10 || 11" just as
    happily.
    """
    pin = (_package_json().get("engines") or {}).get("npm")
    assert pin is not None, (
        "package.json has no engines.npm pin; #2421 added it so the npm "
        "major is explicit at the consumer side."
    )
    assert re.fullmatch(r"\d+", str(pin)), (
        f"engines.npm must be a bare major like \"10\", got {pin!r}. A range "
        f"admits the npm 11 whose lockfile writes broke `npm ci` under the "
        f"builder image (#2284, #2419)."
    )


def test_engines_pin_matches_the_builder_image_npm_major():
    """The pin is only meaningful if it names the npm the image actually has.

    The lockfile has to install under the Dockerfile's node image. Bumping
    that image without moving engines.npm -- or the reverse -- recreates the
    two-majors-one-lockfile state #2421 closed, so the two move together or
    this fires.
    """
    node_major = _builder_node_major()
    expected = NODE_MAJOR_TO_NPM_MAJOR.get(node_major)
    if expected is None:
        pytest.skip(
            f"node:{node_major} is not in NODE_MAJOR_TO_NPM_MAJOR -- add its "
            f"bundled npm major there alongside the image bump (#2421)."
        )
    pin = str((_package_json().get("engines") or {}).get("npm"))
    assert pin == expected, (
        f"engines.npm is {pin!r} but the Dockerfile builds on node:{node_major}, "
        f"which ships npm {expected}. The pin and the builder image must name "
        f"the same npm major or the lockfile is again being written by one npm "
        f"and installed by another (#2421)."
    )


def test_ci_installs_the_lockfile_under_the_builder_image():
    """The pin warns; this CI step is what actually fails the offending PR.

    npm does not enforce engines unless engine-strict is set, so the pin
    alone only prints a warning. quality.yml's frontend-next job runs
    `npm ci` inside the same image the Dockerfile builds with (#1816), which
    is the step that turns an npm-major skew into a red PR. Deleting it
    would leave the pin decorative.
    """
    node_major = _builder_node_major()
    workflow = QUALITY_WORKFLOW.read_text(encoding="utf-8")
    assert re.search(rf"node:{node_major}-alpine\s+npm ci\b", workflow), (
        f"quality.yml no longer runs `npm ci` inside node:{node_major}-alpine. "
        f"That step is the enforcement behind engines.npm (#1816, #2421); "
        f"without it a lockfile written by the wrong npm major reaches the "
        f"container build instead of the PR that produced it."
    )


def test_lockfile_root_entry_mirrors_package_json():
    """npm rewrites packages[""] from the manifest on every install.

    So a lockfile whose root entry disagrees with package.json was not
    produced by an install of this package.json -- which is exactly the
    "Dependabot wrote it, nobody regenerated it" state. This is also
    `npm ci`'s own documented precondition ("can only install packages when
    your package.json and package-lock.json are in sync").
    """
    pkg = _package_json()
    root = _lockfile()["packages"][""]
    for field in ("engines", "dependencies", "devDependencies"):
        assert (root.get(field) or {}) == (pkg.get(field) or {}), (
            f"package-lock.json packages[\"\"].{field} does not match "
            f"package.json's {field}. Regenerate the lockfile with the pinned "
            f"npm major (#2421); `npm ci` refuses to install a lockfile that "
            f"has drifted from its manifest."
        )


# --------------------------------------------------------------------------
# The invariant the two incidents actually broke.
# --------------------------------------------------------------------------


def _resolve(packages, from_path, name):
    """npm's node_modules resolution: walk up the nesting chain."""
    base = from_path
    while True:
        candidate = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if candidate in packages:
            return candidate
        if not base:
            return None
        base = base.rsplit("/node_modules/", 1)[0] if "/node_modules/" in base else ""


def _parse_version(version):
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version or "")
    return tuple(int(part) for part in match.groups()) if match else None


def _satisfies_comparator(version, comparator):
    """One semver comparator. None means "syntax not supported here"."""
    comparator = comparator.strip()
    if comparator in ("", "*", "x", "latest"):
        return True
    caret = re.fullmatch(r"\^(\d+)(?:\.(\d+))?(?:\.(\d+))?", comparator)
    if caret:
        major = int(caret.group(1))
        minor = int(caret.group(2) or 0)
        patch = int(caret.group(3) or 0)
        if major > 0:
            upper = (major + 1, 0, 0)
        elif minor > 0:
            upper = (0, minor + 1, 0)
        else:
            upper = (0, 0, patch + 1)
        return (major, minor, patch) <= version < upper
    tilde = re.fullmatch(r"~(\d+)\.(\d+)(?:\.(\d+))?", comparator)
    if tilde:
        major, minor = int(tilde.group(1)), int(tilde.group(2))
        patch = int(tilde.group(3) or 0)
        return (major, minor, patch) <= version < (major, minor + 1, 0)
    at_least = re.fullmatch(r">=\s*(\d+)\.(\d+)\.(\d+)", comparator)
    if at_least:
        return version >= tuple(int(part) for part in at_least.groups())
    exact = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", comparator)
    if exact:
        return version == tuple(int(part) for part in exact.groups())
    return None


def _satisfies(version, spec):
    """`a || b` union. None if no disjunct was understood and none matched."""
    results = [_satisfies_comparator(version, part) for part in spec.split("||")]
    if any(result is True for result in results):
        return True
    if any(result is None for result in results):
        return None
    return False


def _edges(packages):
    """Every dependency edge npm has to satisfy at install time.

    Optional peers are excluded: npm is free to leave those unmaterialized,
    so a missing one is not a broken lockfile.
    """
    for path, meta in packages.items():
        if meta.get("link"):
            continue
        for kind in ("dependencies", "optionalDependencies", "peerDependencies"):
            optional_peers = meta.get("peerDependenciesMeta") or {}
            for name, spec in (meta.get(kind) or {}).items():
                if kind == "peerDependencies" and optional_peers.get(name, {}).get("optional"):
                    continue
                yield path, name, spec


def _classify(packages):
    """Split every edge into unresolvable / range-violating / checked / skipped.

    Prerelease versions and ranges, and `npm:` aliases, are skipped rather
    than guessed at -- a false red here would be worse than a smaller
    checked set, and test_range_coverage_is_not_degenerate keeps that set
    from quietly shrinking to nothing.
    """
    unresolved, violations, checked, skipped = [], [], 0, 0
    for path, name, spec in _edges(packages):
        target = _resolve(packages, path, name)
        if target is None:
            unresolved.append((path or "<root>", name, spec))
            continue
        resolved_version = packages[target].get("version") or ""
        if spec.startswith("npm:") or "-" in spec or "-" in resolved_version:
            skipped += 1
            continue
        parsed = _parse_version(resolved_version)
        if parsed is None:
            skipped += 1
            continue
        verdict = _satisfies(parsed, spec)
        if verdict is None:
            skipped += 1
            continue
        checked += 1
        if not verdict:
            violations.append((path or "<root>", name, spec, resolved_version, target))
    return unresolved, violations, checked, skipped


def test_every_lockfile_dependency_edge_resolves():
    """No edge may dead-end: that is `npm ci`'s "Missing: ... from lock file"."""
    unresolved, _, _, _ = _classify(_lockfile()["packages"])
    assert not unresolved, (
        "package-lock.json has dependency edges that resolve to no entry, so "
        "`npm ci` will fail with \"Missing: <pkg> from lock file\" (#2421):\n"
        + "\n".join(f"  {path} requires {name}@{spec}" for path, name, spec in unresolved[:20])
    )


def test_resolved_versions_satisfy_their_declared_ranges():
    """The #2284 / #2419 shape: a dropped shadow subtree.

    When npm 11 omits a nested copy that npm 10 materializes, the edge does
    not dead-end -- it silently walks up to the top-level copy at a version
    the range rejects. npm 10 then refuses to install it. Nothing else in
    this repo catches that from a lockfile alone.
    """
    _, violations, _, _ = _classify(_lockfile()["packages"])
    assert not violations, (
        "package-lock.json resolves dependencies to versions outside their "
        "declared ranges -- the dropped shadow-subtree shape of #2284/#2419. "
        "Regenerate with the pinned npm major (#2421):\n"
        + "\n".join(
            f"  {path} requires {name}@{spec} but resolves to {got} at {target}"
            for path, name, spec, got, target in violations[:20]
        )
    )


def test_range_coverage_is_not_degenerate():
    """Keep the two checks above from decaying into a no-op.

    They skip range syntax the comparator subset does not model. If a future
    lockfile is mostly skips, those tests would pass while proving nothing --
    so hold the checked fraction near where it is today (440 of 449 edges,
    ~98%) and fail loudly rather than silently if it collapses.
    """
    unresolved, _, checked, skipped = _classify(_lockfile()["packages"])
    total = checked + skipped + len(unresolved)
    assert total > 100, (
        f"only {total} dependency edges found in package-lock.json -- that is "
        f"too few to be this frontend's real graph; the lockfile is truncated "
        f"or the traversal broke."
    )
    assert checked / total >= 0.90, (
        f"only {checked}/{total} dependency edges could be range-checked "
        f"({skipped} skipped as unsupported syntax). The closure tests are no "
        f"longer meaningfully covering the lockfile -- extend "
        f"_satisfies_comparator to handle the new range syntax."
    )


def test_lockfile_is_the_v3_format_npm_10_writes():
    """Format floor only -- explicitly NOT an npm-major discriminator.

    npm 9, 10 and 11 all write lockfileVersion 3, so this cannot detect the
    #2421 skew (the shipped #2616 test claimed it could; see the module
    docstring). It still catches a genuine regression: a v1/v2 lockfile from
    npm 6-or-older tooling, or a future format bump landing without the
    engines pin and the builder image moving with it.
    """
    version = _lockfile().get("lockfileVersion")
    assert version == 3, (
        f"package-lock.json lockfileVersion is {version!r}, expected 3 -- the "
        f"format npm 9 through 11 write. A different value means the lockfile "
        f"came from tooling outside the range engines.npm pins (#2421)."
    )


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
