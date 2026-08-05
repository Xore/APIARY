#!/usr/bin/env bash
# provision-golden-image.sh — inject the GHOSTS Windows client into the
# dedicated GHOSTS golden image (#326).
#
# Deliberately a SEPARATE golden image from win11-analysis.qcow2, not a
# provisioner step added to that build. win11-analysis.qcow2 stays exactly
# what win11-analysis.pkr.hcl produces -- win11-sandbox's fully air-gapped
# pipeline (#294/#298/etc.) never gains a GHOSTS-related file, registry key,
# or running process it didn't ask for, and this file never touches that
# image. The two golden images are independent from this point on: no
# backing-file relationship, no shared writes, ever.
#
# Client: Ghosts.Client.Universal (cross-platform, .NET, ships win-x64 as a
# supported RuntimeIdentifier) rather than the legacy .NET-Framework-4.6.1
# Ghosts.Client.Windows #326 originally described -- that project no longer
# exists in the v9.0.0 tag this repo's GHOSTS host stack (#324) is pinned
# to; CMU SEI replaced it with Universal. Built self-contained (see
# Dockerfile.client-win for why NOT PublishSingleFile) so the golden image
# needs no .NET runtime installed for it.
#
# Not wired to autostart. Per #326's own gating question ("client installed
# in every image, but only started/enrolled for guests on virbr-ghosts" vs.
# a build-time fork) -- since this is already a separate image from
# win11-analysis.qcow2, a second fork isn't needed, but autostart still
# isn't baked in here: #327/#328 own deciding when this guest's client
# actually runs (their worker, not a golden-image Run key). This script
# only proves the client CAN enroll -- see verify-client-enrollment.sh.
#
# Usage:
#   sudo provision-golden-image.sh [/path/to/win11-ghosts.qcow2]
#     Defaults to /var/dockge/sandbox/golden-images/win11-ghosts.qcow2.

set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOLDEN_IMAGE="${1:-/var/dockge/sandbox/golden-images/win11-ghosts.qcow2}"
GHOSTS_TAG=v9.0.0
BUILD_TAG=ghosts-client-win-build

[[ -f "$GOLDEN_IMAGE" ]] || { echo "error: $GOLDEN_IMAGE not found" >&2; exit 1; }
case "$GOLDEN_IMAGE" in
  *win11-analysis.qcow2) echo "error: refusing to provision win11-analysis.qcow2 -- see this script's header" >&2; exit 1 ;;
esac
if pgrep -af qemu-system | grep -qF -- "$GOLDEN_IMAGE"; then
  echo "error: refusing to touch $GOLDEN_IMAGE -- a qemu-system process has it open right now" >&2
  exit 1
fi

echo "== building Ghosts.Client.Universal (win-x64, self-contained) from cmu-sei/GHOSTS@$GHOSTS_TAG"
docker build -q \
  -f "$here/Dockerfile.client-win" \
  -t "$BUILD_TAG" --target build \
  "https://github.com/cmu-sei/GHOSTS.git#$GHOSTS_TAG:src"

work="$(mktemp -d)"
trap 'rm -rf -- "$work"; docker rm -f ghosts-client-win-extract >/dev/null 2>&1 || true' EXIT

echo "== extracting the published output"
docker create --name ghosts-client-win-extract "$BUILD_TAG" >/dev/null
docker cp ghosts-client-win-extract:/app/dist "$work/ghosts-client"
docker rm ghosts-client-win-extract >/dev/null

echo "== overlaying this repo's application.json/timeline.json"
install -m 0644 "$here/config/application.json" "$work/ghosts-client/config/application.json"
install -m 0644 "$here/config/timeline.json" "$work/ghosts-client/config/timeline.json"

echo "== injecting into $GOLDEN_IMAGE at C:\\Program Files\\Contoso\\EndpointAgent"
# #462: install path and binary name deliberately don't say "ghosts"
# anywhere -- C:\ghosts\Ghosts.Client.Universal.exe is a dead giveaway to
# anyone who reaches the desktop. Blends in under Program Files with the
# same "Contoso" cover identity Dockerfile.client-win bakes into the
# binary's own PE version resource (Company/Product strings), so a
# right-click -> Properties and a directory listing tell the same
# consistent, plausible story.
#
# virt-copy-in lands a copy of the source directory, named after its own
# basename, inside the given remote directory -- it can't rename on the
# way in, and --run-command can't help either (host is Linux, guest is
# Windows; virt-customize refuses to run guest commands cross-platform,
# only --firstboot scripts, which need an actual boot). Renaming the local
# directory before copying, and pre-creating the Contoso parent under
# Program Files, lands it at exactly the target path without needing a
# boot just to move a directory.
mv "$work/ghosts-client" "$work/EndpointAgent"
mkdir -p "$work/pf/Contoso"
mv "$work/EndpointAgent" "$work/pf/Contoso/EndpointAgent"
# Idempotent re-run: virt-copy-in errors if the destination already exists,
# so a re-provision (picking up a Dockerfile.client-win fix, a config
# change) needs the old copy gone first.
virt-rm -a "$GOLDEN_IMAGE" -rf "/Program Files/Contoso/EndpointAgent" 2>/dev/null || true
virt-mkdir -a "$GOLDEN_IMAGE" -p "/Program Files/Contoso" 2>/dev/null || true
virt-copy-in -a "$GOLDEN_IMAGE" "$work/pf/Contoso/EndpointAgent" "/Program Files/Contoso/"

echo "== done"
echo "C:\\Program Files\\Contoso\\EndpointAgent\\EndpointAgent.exe is now in $GOLDEN_IMAGE, not autostarted."
echo "Verify enrollment with: sandbox/ghosts/verify-client-enrollment.sh"
