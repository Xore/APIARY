#!/usr/bin/env python3
"""List every external base image this repo pulls -- from Dockerfiles and
from compose files -- for #2316's scheduled trivy scan
(image-security-scan.yml).

Dependabot's docker updater only proposes an update when the *tag* in a
FROM line changes -- confirmed against this repo's own PR history (every
digest-pinned docker-ecosystem Dependabot PR examined paired a digest change
with a tag/version-string change; none was a same-tag digest-only refresh).
A base image that gets rebuilt under the same tag (a security patch to
`alpine:3.24`, say) is invisible to it forever. Trivy scanning the resolved
image directly closes that gap regardless of whether a newer tag exists, and
regardless of whether the directory is in dependabot.yml's `directories:` at
all -- this walks the whole tree itself, so it also closes the 22-directory
coverage gap #2316 found in dependabot's docker section as a side effect.

Multi-stage builds are handled: a `FROM <name>` that refers to an `AS <name>`
declared earlier in the *same file* is a build-stage reference, not an
external image, and is excluded.

The virtual `scratch` base (and any `FROM ${ARG}` still carrying an
unexpanded build-arg) is excluded too: neither resolves to a pullable image,
and trivy FATALs the whole scan when handed one.

#2763: the walk above covers Dockerfiles only, so every image a compose
service *pulls* rather than builds went unscanned -- traefik and
oauth2-proxy among them, both internet-facing. compose_pulled_images()
walks every tracked compose file the same way, repo-wide off `git ls-tree`
rather than a fixed path list, and includes a service's `image:` only when
that service has no `build:` of its own and no `pull_policy: never`/`build`
-- a locally-built service's `image:` is just the tag its own build
produces, not something to pull and scan externally. Parsed with PyYAML,
not a regex: a regex over compose (anchors, multi-line values) would rot
the same way the coverage gap it closes did.

One directory is excluded from the compose walk: `**/honeyfs/**`. That is
cowrie's fake filesystem, served to attackers as bait -- its
`docker-compose.yml` under
`arcane/home/honeypot-cowrie/cowrie/honeyfs/opt/nexusai-inference/` names a
fictional internal registry (`registry.nexusai.local`) that was never meant
to resolve, on purpose. Nothing else in the repo is excluded by path:
vendored upstream compose/Dockerfiles (e.g. sandbox/ghosts/vendor/ghosts-src/)
are deliberately included, matching this workflow's own stated design for
the Dockerfile walk of scanning whatever a vendored file currently resolves
to rather than special-casing it out.

Separately from that path exclusion, an individual reference can be withheld
because no scanner can resolve it at all -- see UNSCANNABLE below, which
carries a written reason per entry. Those are reported on stderr so they
stay visible rather than silently vanishing.

#3501: ACCEPTED_CVES below carries the base-image CVE exemptions the
scheduled scan defers to, and allow_cve_findings() is the only thing that
consults it. Its contract, in one line: a key matches a printed reference
when the reference is the key or the key plus an `@sha256:` digest. That is
the whole matching rule, and the reason it is that narrow is in the comment
on the dict itself.

Usage: python3 scripts/list-docker-base-images.py
Prints one deduplicated, scannable image reference per line, sorted, on
stdout; notes any withheld unscannable reference on stderr.
"""
import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$",
    re.IGNORECASE,
)

# Virtual/non-pullable bases that have no registry image to scan. `scratch`
# is Docker's reserved empty base; trivy aborts on it with a FATAL
# "unable to find the specified image \"scratch\"" that fails the whole scan
# job. It carries nothing to have a CVE, so dropping it is correct, not a
# coverage gap.
VIRTUAL_BASES = {"scratch"}

# Bait content served to attackers, not real infrastructure -- see module
# docstring. Matched against the git-relative path with forward slashes.
EXCLUDED_PATH_RE = re.compile(r"(^|/)honeyfs/")

# References that genuinely exist in the tree but that no scanner can ever
# resolve. Withheld from stdout and reported on stderr instead.
#
# Withholding one is not the same as excluding its file: the vendored tree
# stays in the walk (see module docstring), so any *other* image a vendored
# file names is still scanned. This is a per-reference list with a written
# reason precisely so a new unscannable reference has to be argued for here
# rather than quietly disappearing behind a path glob.
#
# It matters because the scan cannot distinguish "this image does not exist"
# from "this image has CRITICAL CVEs" -- both are a non-zero trivy exit. One
# unresolvable reference otherwise sits in the report permanently, labelled
# as a vulnerability finding, which trains the reader to ignore the report.
UNSCANNABLE: dict[str, str] = {
    "dustinupdyke/ghosts-client-universal": (
        "never published: the Docker Hub v2 API returns 404 for this "
        "repository (the same query for dustinupdyke/ghosts returns 200, so "
        "this is the image's absence, not an API failure). The vendored "
        "upstream compose names it, but nothing pulls it -- this repo builds "
        "that image itself from "
        "sandbox/ghosts/vendor/ghosts-src/Dockerfile-client-universal"
    ),
}


def is_scannable(ref: str) -> bool:
    """A base is scannable only if it resolves to a real pullable image.

    Excludes the virtual `scratch` base and any `FROM ${ARG}` whose ref still
    carries an unexpanded build-arg substitution -- trivy can pull neither,
    and both would FATAL the scan.
    """
    return ref.lower() not in VIRTUAL_BASES and "$" not in ref


# ------------------------------------------------------------------------
# #3501: base-image CVE exemptions.
#
# The gate this feeds (image-security-scan.yml) fails the build on an image
# with fixable CRITICAL/HIGH findings. It is armed now, which means this dict
# has to be a real instrument rather than a wish list, and three rules follow
# from that. All three exist because an earlier attempt at arming this gate was
# reverted for breaking them.
#
# 1. Every entry needs a reason this repo can verify *against a scan*, never
#    "no patched build is published" asserted from memory. trivy reporting a
#    `FixedVersion` for an image is upstream saying a patch exists; the fix
#    for such an image is to bump the pin, not to write an exemption. So each
#    reason below states the constraint that makes the image immovable
#    *despite* a published fix -- a build stage that does not ship, an
#    on-disk format, a vendor with no rebuild -- rather than claiming the
#    finding is unfixable.
#
# 2. A key is a reference list-docker-base-images.py actually prints, matched
#    exactly. The earlier attempt spelled 30 of its 40 keys as bare tags
#    while main() emits digest-pinned refs for 58 of its 67 images, so those
#    keys matched nothing at all: each read as an exemption somebody had
#    argued for while covering no image. Pinning every key to the digest that
#    was measured is what makes rule 3 work at all.
#
# 3. Exact matching is also what makes the exemption expire. The reason
#    written against these counts describes these digests, so when a
#    Dependabot bump moves the digest the key stops matching and the gate
#    re-applies to whatever now sits at that tag -- nobody has to remember
#    to revisit this file, and a stale operator's judgement cannot ride
#    along onto an artifact nobody measured. A bare-tag key would survive
#    every bump forever, which is the opposite of what an exemption should
#    do.
#
# Prose reasons do not retire a stale entry and no test can check them, so
# the count that accompanied each reason is recorded here next to it: it is
# trivy 0.74.0's own `--severity CRITICAL,HIGH --ignore-unfixed` tally for
# that ref on 2026-10-04, read out of the run logged in REPORT.md. An image
# whose scan did not complete is UNVERIFIED and stays failing on purpose --
# an unmeasured image is a coverage gap, not a finding, and must not be
# quietly written off.
ACCEPTED_CVES: dict[str, tuple[str | None, str]] = {
    # --- build stages that never reach a running image -------------------
    # Verified by resolving every tracked Dockerfile's stage graph: for each
    # ref below, no file names it outside a stage the final image does not
    # inherit, so the CVEs live in a compiler/toolchain layer that is
    # compiled against and then discarded. Trivy scans the *base* image, so
    # it reports them regardless; nothing this repo builds carries them.
    #
    # Keyed tag -> (digest, reason); the digest is the one the scan measured,
    # and None where main() emits the tag unpinned. Kept as two fields rather
    # than one joined `tag@digest` string so this file never spells a pin in
    # the form #2314's repo-wide consistency check reads
    # (tests/docs/test_2314_fix.py counts the files carrying the 1.26-alpine
    # pin and requires exactly the six it names; an exemption table is not a
    # seventh pin -- it names an artifact without controlling it).
    "node:22": (
        "sha256:363e1587494626837fa7f9a23bdb453d13b0ff3c67c705c2805cfc69c2d2fad7",
        "build stage only -- canarytokens names it `AS frontend-builder` and "
        "the final image does not inherit it; measured 28 fixable "
        "CRITICAL/HIGH, all in the discarded build layer. The pin was moved "
        "to the tag's current digest, which took this from 160 to 28; the "
        "remainder is not reachable in any running image, and the key is "
        "digest-keyed so the next pin move retires it."
    ),
    "rust:1-bookworm": (
        "sha256:59037199c44290f2befcdd58dcc540164763fc296950255aaefeef096a1866b0",
        "build stage only -- vps/huginn-sidecar names it `AS build` and ships "
        "a separate debian:bookworm-slim final image; measured 18 fixable "
        "CRITICAL/HIGH after the pin moved to the tag's current digest, down "
        "from 147"
    ),
    "rust:1-slim-bookworm": (
        "sha256:452176c0cefca88c0b3184ce85a4eb03e3d4fa05d2afb5366abcba853221019e",
        "build stage only -- backend-service names it `AS build` and ships a "
        "debian:bookworm-slim final image; measured 1 fixable CRITICAL/HIGH "
        "after the pin moved to the tag's current digest, down from 74"
    ),
    "mcr.microsoft.com/dotnet/sdk:10.0.101": (
        None,
        "build stage only -- the vendored ghosts Dockerfile-client-universal "
        "names it `AS dev`; measured 64 fixable CRITICAL/HIGH, all in the SDK "
        "layer the final image does not inherit. No `FROM` in the tree "
        "digest-pins this tag, so main() emits it bare and the digest field "
        "is None."
    ),
    "golang:1.27-bookworm": (
        "sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195",
        "build stage only -- galah names it `AS build` and ships a separate "
        "debian:bookworm-slim final image; measured 7 fixable CRITICAL/HIGH, "
        "all debian 12.15 libexpat1 and libpcre2-8-0 that upstream has not "
        "rebuilt into this tag (1.26, 1.27 and tip-bookworm each measure the "
        "same 7). It cannot move to alpine: galah builds CGO_ENABLED=1 "
        "against mattn/go-sqlite3, which has no pure-Go fallback, and runs "
        "that glibc binary in the bookworm-slim final stage, so the "
        "toolchain has to be glibc."
    ),
    # The other golang toolchain tags are deliberately absent. The stale
    # 1.23-bookworm and bare 1.23 pins are gone -- their three Dockerfiles
    # moved to golang:1.27-alpine, which measures 0 fixable CRITICAL/HIGH,
    # so the fix there was the bump rather than an exemption.
    # golang:1.27-alpine needs no entry for the same reason: measured clean.
    # The entry above is the one that had to be argued rather than bumped.
}


def accepted_ref(tag: str) -> str:
    """The exact reference an ACCEPTED_CVES entry stands for."""
    digest, _ = ACCEPTED_CVES[tag]
    return tag if digest is None else f"{tag}@{digest}"


def allow_cve_findings(ref: str) -> bool:
    """Is `ref` exempt from the base-image CVE gate (#3501)?

    True only when `ref` is exactly the reference some ACCEPTED_CVES entry
    was written against. Deliberately an exact match, not a prefix or a
    bare-tag lookup -- see rules 2 and 3 on the dict: a key has to be a
    reference this script really emits, and it has to stop matching the
    moment the digest under it moves, or the exemption outlives the
    measurement it was written for.
    """
    return ref in {accepted_ref(tag) for tag in ACCEPTED_CVES}


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "HEAD"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    return out.splitlines()


def tracked_dockerfiles(paths: list[str]) -> list[str]:
    return [
        p for p in paths
        if re.search(r"(^|/)(Dockerfile|Containerfile)[^/]*$", p)
        and not EXCLUDED_PATH_RE.search(p)
    ]


def tracked_compose_files(paths: list[str]) -> list[str]:
    return [
        p for p in paths
        if re.search(r"(^|/)(docker-)?compose[^/]*\.ya?ml$", p, re.IGNORECASE)
        and not EXCLUDED_PATH_RE.search(p)
    ]


def images_in(path: Path) -> set[str]:
    stage_names: set[str] = set()
    images: set[str] = set()
    for raw_line in path.read_text().splitlines():
        m = FROM_RE.match(raw_line)
        if not m:
            continue
        ref, alias = m.group(1), m.group(2)
        if ref not in stage_names and is_scannable(ref):
            images.add(ref)
        if alias:
            stage_names.add(alias)
    return images


def compose_pulled_images(path: Path) -> set[str]:
    """Images a compose file *pulls*, i.e. excluding services it builds.

    Malformed or non-compose-shaped YAML is skipped rather than crashing the
    listing -- the walk is repo-wide and will meet files whose name matches
    the compose pattern without being compose documents.
    """
    try:
        doc = yaml.safe_load(path.read_text())
    except (yaml.YAMLError, UnicodeDecodeError, OSError):
        return set()
    if not isinstance(doc, dict):
        return set()
    services = doc.get("services")
    if not isinstance(services, dict):
        return set()

    images: set[str] = set()
    for service in services.values():
        if not isinstance(service, dict):
            continue
        if "build" in service:
            continue
        if service.get("pull_policy") in ("never", "build"):
            continue
        image = service.get("image")
        if isinstance(image, str) and image.strip() and is_scannable(image.strip()):
            images.add(image.strip())
    return images


def main() -> int:
    paths = tracked_files()
    all_images: set[str] = set()
    for rel in tracked_dockerfiles(paths):
        all_images |= images_in(REPO_ROOT / rel)
    for rel in tracked_compose_files(paths):
        all_images |= compose_pulled_images(REPO_ROOT / rel)

    for image in sorted(all_images & UNSCANNABLE.keys()):
        print(f"not scannable: {image} -- {UNSCANNABLE[image]}", file=sys.stderr)

    for image in sorted(all_images - UNSCANNABLE.keys()):
        print(image)
    return 0


if __name__ == "__main__":
    sys.exit(main())
