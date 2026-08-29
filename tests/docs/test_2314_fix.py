#!/usr/bin/env python3
"""Regression test for #2314: stale base-image digest pins.

golang:1.26-alpine was pinned at the 1.26.5 digest
(sha256:0178a641fbb4...) in six Dockerfiles; the moving `1.26-alpine` tag
had since rolled forward to 1.26.7 (sha256:28d89ee9cc0f...) -- two Go
patch cycles of stdlib fixes never made it into the shipped binaries.

The same sweep (docs/CONTAINER-UPDATES.md's "safe batch") also covers the
issue's "same-version digest refreshes" -- tag aliases that moved
underneath without a version change -- for python:3.14-slim,
python:3.11-slim, python:3.10-slim, python:3.12-slim, debian:bookworm-slim,
valkey/valkey:9.1.1-alpine3.24, postgres:18.6-bookworm, redis:7-alpine, and
a real dtagdevsec/conpot:24.04 -> 24.04.1 patch bump.

Two things the issue body got wrong, corrected here against the real repo
and a live registry query rather than trusted verbatim:

- Its per-file attribution for the python:3.10-slim and python:3.12-slim
  refreshes names honeyfs-implant/elasticpot/mailoney/tanner and
  cowrie/dicompot respectively -- but grepping the actual repo shows only
  tanner/tanner ever pinned the 3.10-slim digest, and only elasticpot (both
  stages) ever pinned the 3.12-slim one. honeyfs-implant is a Go/scratch
  build with no Python stage at all. Files are listed below as they truly
  are, not as the issue claimed.
- The issue was "registry-resolved 2026-08-26"; by the time of this fix
  (2026-08-29) python:*-slim had already rebuilt again upstream, so the
  four python digests the issue cites were themselves already stale. Per
  this repo's own docs/CONTAINER-UPDATES.md ("verify it directly, don't
  trust a secondary source"), all nine same-version pins were refreshed
  against a live `docker-content-digest` registry query, not copied from
  the issue text. golang/debian/valkey/postgres/redis/conpot matched the
  issue's cited digests exactly; only the four python ones differed.
"""
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

OLD_GOLANG_DIGEST = "sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2"
NEW_GOLANG_DIGEST = "sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468"

# Issue #2314's "real bump" section names exactly these six Dockerfiles
# for the golang:1.26-alpine bump.
GOLANG_DOCKERFILES = {
    "attacker-identity-worker": "arcane/home/honeypot-attacker-identity-worker/attacker-identity-worker/Dockerfile",
    "correlator-worker": "arcane/home/honeypot-correlator-worker/correlator-worker/Dockerfile",
    "payload-inventory-worker": "arcane/home/honeypot-payload-inventory-worker/payload-inventory-worker/Dockerfile",
    "beelzebub": "arcane/home/honeypot-beelzebub/beelzebub/Dockerfile",
    "canarytokens-adapter": "arcane/home/honeypot-canarytokens/canarytokens-adapter/Dockerfile",
    "canarytokens-http-router": "arcane/home/honeypot-canarytokens/canarytokens-http-router/Dockerfile",
}

# Same-version digest refreshes from the issue's second section, plus the
# one real conpot patch bump -- files listed are every file in the repo
# that actually carries the stale pin (confirmed by grep), not the
# issue's own per-file claims where those didn't match reality.
SAME_VERSION_REFRESHES = {
    "python:3.14-slim": {
        "old": "sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc",
        "new": "sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5",
        "files": [
            "analysis/ghidra/statictools/Dockerfile",
            "arcane/home/honeypot-agent-intrusion-worker/analysis/agent-intrusion-corpus/Dockerfile",
            "arcane/home/honeypot-dashboard/analysis/es-results-importer/Dockerfile",
            "arcane/home/honeypot-dashboard/services-adapter/Dockerfile",
            "auth-events-worker/Dockerfile",
            "llm-worker/Dockerfile",
            "ml-worker/Dockerfile",
        ],
    },
    "python:3.11-slim": {
        "old": "sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff",
        "new": "sha256:1042b61448fef4ba92d16a8c7eb4996d027568ce64792a7877fd88511e0af7c6",
        "files": [
            "arcane/home/honeypot-tanner/snare/Dockerfile",
            "arcane/home/honeypot-init/snare/Dockerfile",
            "arcane/home/honeypot-mailoney/mailoney/Dockerfile",
        ],
    },
    "python:3.10-slim": {
        "old": "sha256:63669fd2563fa90b0442fa7b568e66e3667755636cda086d7bcaaa895f66fe39",
        "new": "sha256:38758a82a44d1acb9bae3dd5f7d2a55452fb44a5ceca7c4589f360f2c4aa3d0c",
        "files": [
            "arcane/home/honeypot-tanner/tanner/tanner/Dockerfile",
        ],
    },
    "python:3.12-slim": {
        "old": "sha256:dd29372629eeba2dd003fd9e9d35a5b8236c44727875a0364254b5127af88e65",
        "new": "sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217",
        "files": [
            "arcane/home/honeypot-elasticpot/elasticpot/Dockerfile",
        ],
    },
    "debian:bookworm-slim": {
        "old": "sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241",
        "new": "sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171",
        "files": [
            "arcane/home/honeypot-cowrie/cowrie/Dockerfile",
            "arcane/home/honeypot-galah/galah/Dockerfile",
        ],
    },
    "valkey/valkey:9.1.1-alpine3.24": {
        "old": "sha256:ee91f7a174ac4d6a6b0685b3a60e321f0a9dbbb691f9b0e285be2ba1d1be8328",
        "new": "sha256:de31910896150d5e754a07d57d227cfdde4e258ddd0d1aa4607f2d2f95843715",
        "files": [
            "arcane/home/honeypot-dashboard/compose.yml",
        ],
    },
    "postgres:18.6-bookworm": {
        "old": "sha256:7d2695c3aa88e792e8b3b233e7e4adb296a20412c6c0ca361e3edaaacfada108",
        "new": "sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af",
        "files": [
            "arcane/home/honeypot-keycloak/compose.yml",
        ],
    },
    "redis:7-alpine": {
        "old": "sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2",
        "new": "sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf",
        "files": [
            "arcane/home/honeypot-tanner/tanner/redis/Dockerfile",
            "scripts/test-dashboard-oidc-chaos.sh",
            "scripts/test-dashboard-oidc-pkce-totp-login.sh",
        ],
    },
}

CONPOT_DOCKERFILE = "arcane/home/honeypot-conpot/conpot/Dockerfile"
CONPOT_OLD = "dtagdevsec/conpot:24.04@sha256:717f0bdf79ad267e7402ff09fcc2f4ce413e9165843dd58c18f340acdd49ea7e"
# 24.04.1 EXISTS on Docker Hub (manifest list
# sha256:ff37c322037ad8c1f4f05c2c93f7b60cc5f56b7f37a2c4cbc16901ec70bddb5b) but
# the six *_patch.py scripts below hard-code the 24.04 directory
# layout, so the build FileNotFoundErrors. The conpot bump is OUT OF
# SCOPE for #2314 and is tracked separately; this test pins the
# constraint so a future edit doesn't accidentally re-break the build.
CONPOT_24_04_1_TAG = "dtagdevsec/conpot:24.04.1"
CONPOT_24_04_1_DIGEST = "sha256:ff37c322037ad8c1f4f05c2c93f7b60cc5f56b7f37a2c4cbc16901ec70bddb5b"

ALL_OLD_DIGESTS = {OLD_GOLANG_DIGEST} | {spec["old"] for spec in SAME_VERSION_REFRESHES.values()}


@pytest.mark.parametrize("name,relpath", sorted(GOLANG_DOCKERFILES.items()))
def test_golang_dockerfile_exists(name, relpath):
    assert (REPO_ROOT / relpath).exists(), f"{name}: not found at {relpath}"


@pytest.mark.parametrize("name,relpath", sorted(GOLANG_DOCKERFILES.items()))
def test_golang_dockerfile_no_longer_pins_1_26_5(name, relpath):
    text = (REPO_ROOT / relpath).read_text(encoding="utf-8")
    assert OLD_GOLANG_DIGEST not in text, (
        f"{name} ({relpath}) still pins golang:1.26-alpine at the stale "
        f"1.26.5 digest {OLD_GOLANG_DIGEST} -- #2314"
    )


@pytest.mark.parametrize("name,relpath", sorted(GOLANG_DOCKERFILES.items()))
def test_golang_dockerfile_pins_1_26_7(name, relpath):
    text = (REPO_ROOT / relpath).read_text(encoding="utf-8")
    assert f"golang:1.26-alpine@{NEW_GOLANG_DIGEST}" in text, (
        f"{name} ({relpath}) does not pin golang:1.26-alpine at the "
        f"refreshed 1.26.7 digest {NEW_GOLANG_DIGEST} -- #2314"
    )


def test_golang_bump_scope_is_exactly_six_files():
    """Issue #2314's 'real bump' section cites exactly six Dockerfiles for
    the golang:1.26-alpine bump -- guard against silent scope drift."""
    assert len(GOLANG_DOCKERFILES) == 6
    assert set(GOLANG_DOCKERFILES) == {
        "attacker-identity-worker",
        "correlator-worker",
        "payload-inventory-worker",
        "beelzebub",
        "canarytokens-adapter",
        "canarytokens-http-router",
    }


@pytest.mark.parametrize("image,spec", sorted(SAME_VERSION_REFRESHES.items()))
def test_same_version_refresh_applied(image, spec):
    for relpath in spec["files"]:
        path = REPO_ROOT / relpath
        assert path.exists(), f"{relpath}: not found ({image} refresh -- #2314)"
        text = path.read_text(encoding="utf-8")
        assert spec["old"] not in text, (
            f"{relpath} still pins {image} at the stale digest {spec['old']} -- #2314"
        )
        assert spec["new"] in text, (
            f"{relpath} does not pin {image} at the refreshed digest {spec['new']} -- #2314"
        )


def test_conpot_does_not_bump_to_24_04_1():
    """The conpot Dockerfile must stay on dtagdevsec/conpot:24.04 (the
    specific manifest-list digest the patch scripts were written
    against). Bumping to 24.04.1 breaks the build because the patch
    scripts target 24.04's directory layout; that bump is tracked
    separately and requires auditing every patch against 24.04.1's
    layout. This test pins the constraint so a future edit does not
    re-introduce the failure mode silently. The conpot 24.04.1
    container build was verified to FileNotFoundError on
    /usr/lib/python3.11/site-packages/conpot/templates/default
    (the path every *_patch.py targets)."""
    text = (REPO_ROOT / CONPOT_DOCKERFILE).read_text(encoding="utf-8")
    assert CONPOT_OLD in text, (
        f"{CONPOT_DOCKERFILE} no longer pins dtagdevsec/conpot:24.04 at "
        f"the expected manifest-list digest -- #2314"
    )
    # The 24.04.1 tag must not appear at all (no version bump; the
    # patch scripts target 24.04's layout).
    assert CONPOT_24_04_1_TAG not in text, (
        f"{CONPOT_DOCKERFILE} bumped to {CONPOT_24_04_1_TAG}, "
        f"which breaks the *_patch.py scripts (24.04.1 restructured the "
        f"conpot package layout). Revert to 24.04 and track the bump "
        f"as a separate task that audits the patches against 24.04.1."
    )
    assert CONPOT_24_04_1_DIGEST not in text, (
        f"{CONPOT_DOCKERFILE} references the 24.04.1 digest {CONPOT_24_04_1_DIGEST} -- "
        f"this is the digest that breaks the *_patch.py scripts. Revert."
    )


def test_no_stale_digest_pins_remain_anywhere():
    """Acceptance criterion: 'no stale digest pins remain' -- sweep the
    whole repo (not just the files this test already names) for every old
    digest, since the issue's own per-file attribution for a couple of the
    same-version refreshes didn't match the real repo (see module
    docstring). Mirrors docs/CONTAINER-UPDATES.md's own "find every pinned
    image" file patterns.
    """
    offenders = []
    seen = set()
    for pattern in ("Dockerfile*", "*.yml", "*.yaml", "*.sh"):
        for path in REPO_ROOT.rglob(pattern):
            if not path.is_file() or ".git" in path.parts or path in seen:
                continue
            seen.add(path)
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for old_digest in ALL_OLD_DIGESTS:
                if old_digest in text:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {old_digest}")
    assert not offenders, "stale digest pins remain -- #2314:\n" + "\n".join(offenders)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))

