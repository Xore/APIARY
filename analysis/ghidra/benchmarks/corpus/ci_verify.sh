#!/usr/bin/env bash
# Rebuilds the reverse-engineering benchmark corpus from source inside the
# exact build environment the corpus's own provenance claims (README.md),
# and fails if the rebuild does not reproduce manifest.json byte-for-byte --
# the corpus's disassembly text and hashes are the actual evaluation
# artifact, so a stale or hand-edited manifest.json is exactly the kind of
# drift #159's "CI verifies ... reproducible generation" exists to catch.
#
# Also runs the fast structural/safety checks (validate_manifest.py) and the
# executable semantic checks (verify_semantics.py) against the freshly
# rebuilt corpus, so all three of #159's CI requirements -- provenance,
# fixture safety, and reproducible generation -- run from one entry point.
#
# Must run inside debian:trixie-slim (or be given the packages the
# "Rebuilding" section of README.md lists) as root -- the toolchain versions
# are part of the recorded provenance, and package installation needs root.
#
# Usage: from a debian:trixie-slim container with the repo checked out,
#   analysis/ghidra/benchmarks/corpus/ci_verify.sh
set -euo pipefail

corpus_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "::group::install toolchains"
apt-get -o APT::Sandbox::User=root update -qq
apt-get -o APT::Sandbox::User=root install -y -qq --no-install-recommends \
  gcc clang binutils python3 qemu-user \
  gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
  gcc-multilib-i686-linux-gnu \
  gcc-mipsel-linux-gnu libc6-dev-mipsel-cross \
  gcc-arm-linux-gnueabihf libc6-dev-armhf-cross
echo "::endgroup::"

echo "::group::structural and safety validation"
python3 "$corpus_dir/validate_manifest.py"
echo "::endgroup::"

# Fixed paths, not mktemp: this always runs in a fresh, disposable CI
# container, so there is nothing to collide with and nothing worth cleaning
# up afterward.
rm -rf /src /harness /work
mkdir -p /src /harness /work/corpus
cp "$corpus_dir"/src/*.c /src/
cp "$corpus_dir"/harness/*.c /harness/
cp "$corpus_dir/build_corpus.py" /work/build_corpus.py
cp "$corpus_dir/verify_semantics.py" /work/verify_semantics.py

echo "::group::rebuild corpus and diff against the committed manifest"
python3 /work/build_corpus.py
if ! diff -q "$corpus_dir/manifest.json" /work/corpus/manifest.json > /dev/null; then
  echo "FAIL: a fresh rebuild does not reproduce the committed manifest.json byte-for-byte." >&2
  echo "Either the source/toolchain changed without regenerating manifest.json, or a build is not reproducible." >&2
  diff "$corpus_dir/manifest.json" /work/corpus/manifest.json | head -50 >&2
  exit 1
fi
echo "rebuild matches the committed manifest.json exactly"
echo "::endgroup::"

echo "::group::executable semantic checks"
python3 /work/verify_semantics.py
echo "::endgroup::"
