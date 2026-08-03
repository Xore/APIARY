#!/usr/bin/env bash
# Install the Windows sandbox worker: scripts, systemd units, host
# directories, and the environment file. Mirrors sandbox/install-worker.sh
# (the Linux equivalent) in layout and conventions -- same
# /usr/local/libexec/honeypot-sandbox base, same requests/{pending,rejected}
# + export directory shape, and now the same two-stage chain: a single path
# unit watches the request spool and triggers the hash-resolution/
# submission-handoff service, which then explicitly starts the detonation
# worker once the sample bytes actually exist (see
# honeypot-windows-sandbox-worker.path's own comment for why this has to be
# one linear chain, not two independent path units racing each other).
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
target=/usr/local/libexec/honeypot-sandbox/windows

install -d -m 0755 -o root -g root "$target" "$target/orchestrate"
install -m 0755 -o root -g root "$script_dir/run_pending.sh" "$target/run_pending.sh"
install -m 0755 -o root -g root "$script_dir/process-windows-web-requests.sh" "$target/process-windows-web-requests.sh"
for file in "$script_dir"/orchestrate/*.py; do
  install -m 0755 -o root -g root "$file" "$target/orchestrate/$(basename "$file")"
done

for unit in honeypot-windows-sandbox-worker.service honeypot-windows-sandbox-worker.path honeypot-windows-sandbox-web-requests.service; do
  install -m 0644 -o root -g root "$script_dir/$unit" "/etc/systemd/system/$unit"
done

if [[ ! -e /etc/default/honeypot-windows-sandbox ]]; then
  install -m 0600 -o root -g root \
    "$script_dir/honeypot-windows-sandbox.default.example" \
    /etc/default/honeypot-windows-sandbox
  echo "Wrote /etc/default/honeypot-windows-sandbox from the example -- edit VM_PASS" \
    "(and anything else) before real detonations run." >&2
fi

install -d -m 0700 -o root -g root /var/lib/honeypot-windows-sandbox/requests/{pending,rejected}
install -d -m 0750 -o root -g xore /var/lib/honeypot-windows-sandbox/export

systemctl daemon-reload
systemctl reset-failed honeypot-windows-sandbox-worker.service honeypot-windows-sandbox-web-requests.service 2>/dev/null || true
systemctl enable --now honeypot-windows-sandbox-worker.path

echo "Windows sandbox worker installed. The .path unit is enabled and watching"
echo "/var/lib/honeypot-windows-sandbox/requests/pending, and now triggers the"
echo "hash-resolution/submission-handoff service before the detonation worker --"
echo "a request the dashboard writes will have its sample bytes resolved from"
echo "the capture roots and copied to \$WINDOWS_SANDBOX_SAMPLES_DIR automatically."
systemctl --no-pager --plain is-active honeypot-windows-sandbox-worker.path
