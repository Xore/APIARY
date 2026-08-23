#!/usr/bin/env bash
# Build the lab image. ICSNPP compiles Spicy/C++ plugins, so this takes ~10
# minutes the first time and is cached thereafter.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-apiary-sensing-lab:zeek8}"
ENGINE="${ENGINE:-podman}"

"$ENGINE" build -t "$IMAGE" -f "${here}/Containerfile" "$here"

echo
echo "sensing-lab: loaded Zeek plugins in ${IMAGE}:"
"$ENGINE" run --rm --entrypoint /bin/bash "$IMAGE" \
    -lc 'cat /usr/local/share/zeek-lab/loaded-plugins.txt'
