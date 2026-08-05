#!/usr/bin/env bash
# resolve-sample.sh <hash> — print the absolute path to a captured payload,
# or exit 1 with nothing printed if no root holds it.
#
# <hash> is 32-64 hex, matching dashboard's own hashName -- not 64-only.
# Dionaea's binaries/ is keyed by MD5, not SHA256 (dionaea's own convention,
# predating this feature), and the dashboard's payload rows for Dionaea
# captures carry that MD5 as their id. A strict 64-hex requirement here would
# silently refuse every Dionaea-sourced submission.
#
# Same three roots sandbox/submit-capture.sh already searches, resolved the
# same way (docker volume inspect for the two Docker-volume-backed roots, a
# plain host path for Cowrie's bind mount), with the same two-pass lookup:
# a direct filename match first, then -- for a 64-char request, since only
# SHA256 needs this -- a full-content hash scan of the Dionaea root, because
# a SHA256 naturally never matches an MD5-named file by filename alone.
# Keep both scripts' root list in sync by hand if the volume names change.
set -euo pipefail

hash=${1:?usage: resolve-sample.sh <hash>}
hash=${hash,,}
[[ $hash =~ ^[0-9a-f]{32,64}$ ]] || { echo "invalid hash" >&2; exit 2; }

roots=("${COWRIE_DOWNLOADS_DIR:-/opt/stacks/honeypot-stack/logs/cowrie/downloads}")
dionaea_root="$(docker volume inspect dionaea-lib --format '{{.Mountpoint}}' 2>/dev/null || true)/binaries"
scripts_root="$(docker volume inspect dashboard-state --format '{{.Mountpoint}}' 2>/dev/null || true)/script-payloads"
[[ $dionaea_root == /* && -d $dionaea_root ]] && roots+=("$dionaea_root")
[[ $scripts_root == /* && -d $scripts_root ]] && roots+=("$scripts_root")

for root in "${roots[@]}"; do
  found=$(find "$root" -xdev -type f -iname "$hash" -print -quit 2>/dev/null || true)
  if [[ -n $found ]]; then
    printf '%s\n' "$found"
    exit 0
  fi
done

if [[ ${#hash} -eq 64 && -n ${dionaea_root:-} && -d $dionaea_root ]]; then
  while IFS= read -r -d '' path; do
    if [[ $(sha256sum "$path" | cut -d' ' -f1) == "$hash" ]]; then
      printf '%s\n' "$path"
      exit 0
    fi
  done < <(find "$dionaea_root" -xdev -type f -print0 2>/dev/null)
fi
exit 1
