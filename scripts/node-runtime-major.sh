#!/usr/bin/env bash
# #3331: print the node major the given Dockerfile builds and runs on, and
# export it as step outputs so CI never hardcodes it a second time.
#
# Why this exists. frontend-next's Dockerfile pins node:22-alpine, while
# every frontend job in quality.yml ran setup-node with node-version "24".
# The only Node 22 coverage anywhere was the #1816/#2741 lockfile-install
# step, so the unit tests, the production build and both Playwright suites
# never once executed on the node that actually ships the artifact. That is
# the entire class of bug the frontend gates exist to catch, and the gate was
# blind to the runtime.
#
# The fix that does not rot: read the version out of the Dockerfile's own FROM
# line, so bumping the image moves CI with it automatically. A second copy of
# the number is a second thing to forget, which is what created the drift.
#
# Outputs (when GITHUB_OUTPUT is set, i.e. inside Actions):
#   node-version=<major>   for setup-node's node-version
#   node-image=<ref>       the first node stage's image, digest stripped, for
#                          `docker run` steps that must use the image's npm
#
# Usage: scripts/node-runtime-major.sh [path-to-Dockerfile]
#   defaults to arcane/home/honeypot-dashboard/frontend-next/Dockerfile
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="${1:-$root/arcane/home/honeypot-dashboard/frontend-next/Dockerfile}"

[ -f "$dockerfile" ] || { echo "no such Dockerfile: $dockerfile" >&2; exit 1; }

# Every `FROM node:<tag>` stage, in file order, digest included for now.
# Leading whitespace is tolerated; a commented-out #FROM is not (sed anchors
# on FROM after optional blanks, so a `#` simply does not match).
refs=()
while IFS= read -r ref; do
  [ -n "$ref" ] && refs+=("$ref")
done < <(sed -n -E 's/^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]+(node:[^[:space:]]+).*$/\1/p' "$dockerfile")

if [ "${#refs[@]}" -eq 0 ]; then
  echo "$dockerfile declares no 'FROM node:<tag>' stage, so there is no node" >&2
  echo "version to derive. If the base image moved to another runtime, teach" >&2
  echo "this script that runtime rather than deleting the check." >&2
  exit 1
fi

majors=()
images=()
for ref in "${refs[@]}"; do
  # node:22-alpine@sha256:... -> 22-alpine. The digest is deliberately dropped:
  # `npm ci` must resolve the same tag the Dockerfile builds, and leaving the
  # digest off keeps the emitted image a plain `node:<tag>` reference.
  tag="${ref#node:}"
  tag="${tag%@sha256:*}"
  # The whole tag is validated, not just the part this script parses out of
  # it: it is written to GITHUB_OUTPUT and interpolated into a docker command
  # line further down.
  case "$tag" in
    '' | *[!a-z0-9._-]*)
      echo "$dockerfile: '$ref' is not a node:<tag> reference this script can" >&2
      echo "read a version from" >&2
      exit 1
      ;;
  esac
  # Leading digits, stopping at the first separator: 22-alpine -> 22,
  # 24.1-alpine -> 24, 20 -> 20. setup-node wants the major, and a
  # major.minor tag must not read as a major of "24.1".
  major="${tag%%[.-]*}"
  case "$major" in
    '' | *[!0-9]*)
      echo "$dockerfile: could not read a node major out of '$ref'" >&2
      exit 1
      ;;
  esac
  majors+=("$major")
  images+=("node:$tag")
done

# A build stage and a runtime stage on different node majors is a legitimate
# thing to write and a genuine drift hazard: the artifact would be produced by
# one node and served by another, and neither is what these jobs test. Refuse
# rather than pick a winner -- if that split is ever deliberate, encode it here
# explicitly instead of letting a FROM edit decide it by accident.
major="${majors[0]}"
for other in "${majors[@]}"; do
  if [ "$other" != "$major" ]; then
    echo "$dockerfile: node stages disagree on the major -- ${majors[*]}" >&2
    echo "The build stage and the runtime stage must be on the same node major," >&2
    echo "or the artifact is built by one node and served by another." >&2
    exit 1
  fi
done

# The first node stage wins for the image reference: a Dockerfile's build stage
# comes first by convention, and `npm ci` must run under the image that builds.
image="${images[0]}"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'node-version=%s\n' "$major" >>"$GITHUB_OUTPUT"
  printf 'node-image=%s\n' "$image" >>"$GITHUB_OUTPUT"
fi

echo "node $major ($image), derived from ${dockerfile#"$root"/}"
