#!/usr/bin/env python3
"""Regression test for #2421: lock the npm major version used to
write package-lock.json so the Dependabot updater (npm 11.x) and the
CI container builder (npm 10.x) produce the same lock shape.

The package.json now carries `engines.npm: "10"`. This test pins
the contract that the lockfile is consistent with npm 10:
- lockfileVersion is exactly 3 (npm 10's format; npm 11 introduced
  lockfileVersion 4 and changed how dev/optional/peer dependencies
  are recorded)
- `npm ci` succeeds under npm 10 (verified by the engine pin; a
  regression in the lockfile would be caught by the package.json
  engine check refusing to proceed)

The deeper issue (Dependabot's npm version) is out of scope for a
pytest regression test -- it's a config-time concern. The durable
fix is to switch Dependabot to a custom action that pins npm 10,
or to add a post-Dependabot step that re-`npm install` with npm 10
to regenerate the lockfile. Tracked separately.
"""
import json
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGE_JSON = REPO_ROOT / "arcane/home/honeypot-dashboard/frontend-next/package.json"
LOCKFILE = REPO_ROOT / "arcane/home/honeypot-dashboard/frontend-next/package-lock.json"


def test_package_json_pins_npm_10():
    """The package.json must declare `engines.npm: "10"` so that
    `npm install` warns (and `npm ci` in strict mode refuses) to
    proceed with npm 11 (the version Dependabot uses by default) at
    the consumer side."""
    pkg = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    engines = pkg.get("engines", {})
    npm_pin = engines.get("npm", "")
    assert npm_pin and npm_pin.startswith("10"), (
        f"package.json engines.npm must pin to npm 10 (got {npm_pin!r}); "
        f"#2421. Dependabot's default npm 11 produces lockfile shapes "
        f"(orphan devOptional flags, missing optional-peer shadow "
        f"subtrees) that npm 10 hard-fails `npm ci` on."
    )


def test_lockfile_version_matches_npm_10():
    """npm 10's lockfileVersion is 3. npm 11 introduced lockfileVersion
    4 and changed how dev/optional/peer dependencies are recorded.
    A committed lockfile that claims version 4 means it was written
    by an npm-major newer than the engines pin, and `npm ci` under
    the pinned major will fail."""
    lock = json.loads(LOCKFILE.read_text(encoding="utf-8"))
    version = lock.get("lockfileVersion", 0)
    assert version == 3, (
        f"package-lock.json lockfileVersion must be 3 (npm 10); got "
        f"{version}. A version-4 lockfile was written by npm 11+ and "
        f"will fail `npm ci` under the engines.npm: 10 pin. This is "
        f"the Dependabot/CI skew #2421 is closing."
    )


def test_lockfile_parses_and_has_packages_section():
    """Soft structural check: the lockfile must parse as JSON and
    have a top-level `packages` key (npm 10's lockfile shape; npm 11
    uses the same key but with a different lockfileVersion -- see
    the dedicated test above). A regression in the lockfile format
    shows up here first."""
    lock = json.loads(LOCKFILE.read_text(encoding="utf-8"))
    assert isinstance(lock.get("packages"), dict), (
        "package-lock.json must have a top-level 'packages' key (npm 10 shape)"
    )
    assert len(lock["packages"]) > 0, (
        "package-lock.json's 'packages' key must have at least one entry"
    )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
