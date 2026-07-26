#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
hash=${1:-}
hash=${hash,,}
[[ $hash =~ ^[0-9a-f]{32,64}$ ]] || { echo "Usage: $0 <captured MD5/SHA-1/SHA-256 filename or SHA-256>" >&2; exit 2; }

root_dir=/var/lib/honeypot-sandbox
queue="$root_dir/inbox/queued"
samples="$root_dir/inbox/samples"
mkdir -p "$queue" "$samples" "$root_dir/inbox/completed" "$root_dir/inbox/failed" "$root_dir/export"
chmod 0700 "$root_dir/inbox" "$queue" "$samples" "$root_dir/inbox/completed" "$root_dir/inbox/failed" "$root_dir/export"

roots=(/opt/stacks/honeypot-stack/logs/cowrie/downloads)
labels=(cowrie)
dionaea_root="$(docker volume inspect honeypot-stack_dionaea-lib --format '{{.Mountpoint}}' 2>/dev/null || true)/binaries"
scripts_root="$(docker volume inspect honeypot-stack_dashboard-state --format '{{.Mountpoint}}' 2>/dev/null || true)/script-payloads"
[[ $dionaea_root == /* && -d $dionaea_root ]] && { roots+=("$dionaea_root"); labels+=(dionaea); }
[[ $scripts_root == /* && -d $scripts_root ]] && { roots+=("$scripts_root"); labels+=(scripts); }

candidate=
source_name=
for index in "${!roots[@]}"; do
  root=${roots[$index]}
  found=$(find "$root" -xdev -type f -name "$hash" -print -quit 2>/dev/null || true)
  if [[ -n $found ]]; then candidate=$found; source_name=${labels[$index]}; break; fi
done
if [[ -z $candidate && ${#hash} -eq 64 ]]; then
  for index in "${!roots[@]}"; do
    root=${roots[$index]}
    while IFS= read -r -d '' path; do
      [[ $(sha256sum "$path" | awk '{print $1}') == "$hash" ]] || continue
      candidate=$path; source_name=${labels[$index]}; break 2
    done < <(find "$root" -xdev -type f -regextype posix-extended -regex '.*/[0-9a-fA-F]{32,64}' -print0 2>/dev/null)
  done
fi
[[ -n $candidate ]] || { echo "No captured payload resolves to $hash" >&2; exit 1; }

sha256=$(sha256sum "$candidate" | awk '{print $1}')
if [[ -e $root_dir/inbox/completed/$sha256.json || -e $queue/$sha256.json ]]; then
  echo "Capture already queued or analyzed: $sha256"
  exit 0
fi
install -m 0400 -o root -g root "$candidate" "$samples/$sha256.new"
mv -f "$samples/$sha256.new" "$samples/$sha256"
request="$queue/$sha256.json"
jq -n --arg sha256 "$sha256" --arg requested_at "$(date -u +%FT%TZ)" \
  --arg source "$source_name" --arg capture_name "$(basename "$candidate")" \
  '{version:1,sha256:$sha256,requested_at:$requested_at,source:$source,capture_name:$capture_name}' \
  >"$request.new"
mv -f "$request.new" "$request"
/usr/local/libexec/honeypot-sandbox/status-export.py --worker-state idle 2>/dev/null || true
systemctl start --no-block honeypot-sandbox-worker.service
echo "Queued isolated Linux analysis: $sha256"
