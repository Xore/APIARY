#!/usr/bin/env python3
"""List every external base image a Dockerfile/Containerfile in this repo
pulls, for #2316's scheduled trivy scan (image-security-scan.yml).

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

Usage: python3 scripts/list-docker-base-images.py
Prints one deduplicated image reference per line, sorted.
"""
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$",
    re.IGNORECASE,
)


def tracked_dockerfiles() -> list[str]:
    out = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "HEAD"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    return [
        line for line in out.splitlines()
        if re.search(r"(^|/)(Dockerfile|Containerfile)[^/]*$", line)
    ]


def images_in(path: Path) -> set[str]:
    stage_names: set[str] = set()
    images: set[str] = set()
    for raw_line in path.read_text().splitlines():
        m = FROM_RE.match(raw_line)
        if not m:
            continue
        ref, alias = m.group(1), m.group(2)
        if ref not in stage_names:
            images.add(ref)
        if alias:
            stage_names.add(alias)
    return images


def main() -> int:
    all_images: set[str] = set()
    for rel in tracked_dockerfiles():
        all_images |= images_in(REPO_ROOT / rel)
    for image in sorted(all_images):
        print(image)
    return 0


if __name__ == "__main__":
    sys.exit(main())
