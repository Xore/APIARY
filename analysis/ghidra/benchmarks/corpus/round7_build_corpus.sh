#!/usr/bin/env bash
# build_corpus_round7.sh -- rebuild the 17-case benchmark corpus from source
# inside the exact provenance container ci_verify.sh documents
# (debian:trixie-slim + the pinned cross toolchains), verified byte-for-byte
# against the committed manifest, then copied out to a NEW directory. The
# 14-case corpus at /mnt-1/benchmarks/corpus is left untouched.
# Operational copy: /mnt-1/benchmarks/round7_build_corpus.sh
set -euo pipefail
REPO=${REPO:-/mnt-1/benchmarks/APIARY-round7}
OUT=${OUT:-/mnt-1/benchmarks/corpus-round7}
NAME=corpus-round7-build
docker rm -f "$NAME" >/dev/null 2>&1 || true
# no --rm: the built corpus is copied out of the stopped container afterwards,
# which keeps ci_verify.sh byte-identical (it rm -rf's /work itself, so /work
# cannot be a bind mount).
#
# DNS pinned to the LAN resolvers (#2974/#3031) -- container DNS is what
# killed four models in four minutes on the a99e765 sweep. The addresses are
# read from the host's own /etc/resolv.conf rather than written here: the
# homeserver's resolver list IS the pair of LAN nodes (install-homeserver.sh
# asserts the first entry is one of them), and the second of them is a
# deployment address scripts/check-public-leaks.py bans from this repo.
# Override with RESOLVERS="ip ip" on a host whose resolv.conf is a local stub.
RESOLVERS=${RESOLVERS:-$(awk '/^nameserver /{print $2}' /etc/resolv.conf | grep -v '^127\.' || true)}
[ -n "${RESOLVERS//[[:space:]]/}" ] || { echo "ABORT: no non-loopback nameserver in /etc/resolv.conf -- set RESOLVERS=\"ip ip\""; exit 1; }
DNS_FLAGS=()
for ns in $RESOLVERS; do DNS_FLAGS+=(--dns "$ns"); done
echo "container DNS: $RESOLVERS"
docker run --name "$NAME" "${DNS_FLAGS[@]}" \
  -v "$REPO":/repo:ro -e PYTHONDONTWRITEBYTECODE=1 debian:trixie-slim \
  bash -c 'cd /repo && bash analysis/ghidra/benchmarks/corpus/ci_verify.sh' 2>&1 | tail -25
rm -rf "$OUT"
docker cp "$NAME":/work/corpus "$OUT"
docker rm "$NAME" >/dev/null
echo "files: $(ls "$OUT" | wc -l)"
echo "new-case files: $(ls "$OUT" | grep -c 'strcpy_note\|process_witness')"
diff -q "$OUT/manifest.json" "$REPO/analysis/ghidra/benchmarks/corpus/manifest.json" && echo "manifest identical to the pinned repo copy"
