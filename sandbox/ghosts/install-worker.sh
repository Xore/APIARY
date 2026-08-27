#!/usr/bin/env bash
# Install the GHOSTS sandbox worker (#328): scripts, systemd units, host
# directories, and the environment file. Mirrors sandbox/windows/install-worker.sh
# exactly -- same /usr/local/libexec/honeypot-sandbox base, same
# requests/{pending,rejected} + export directory shape, and the same
# two-stage chain (a path unit triggers hash-resolution, which then
# explicitly starts the detonation worker once sample bytes actually exist).
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
target=/usr/local/libexec/honeypot-sandbox/ghosts

python3 -m pip install --break-system-packages pywinrm

# orchestrate/run_sample.py shells out to smbclient to push the sample into
# the guest and pull results back out (SAMPLE_SHARE/LOGS_SHARE) -- found
# missing live (#498): the worker started, the guest booted fine, and the
# detonation still failed outright with "[Errno 2] No such file or
# directory: 'smbclient'" because nothing here ever installed it.
if ! command -v smbclient >/dev/null 2>&1; then
  apt-get update && apt-get install -y smbclient
fi

install -d -m 0755 -o root -g root "$target" "$target/orchestrate"
install -m 0755 -o root -g root "$script_dir/run_pending.sh" "$target/run_pending.sh"
install -m 0755 -o root -g root "$script_dir/process-ghosts-web-requests.sh" "$target/process-ghosts-web-requests.sh"
for file in "$script_dir"/orchestrate/*.py; do
  install -m 0755 -o root -g root "$file" "$target/orchestrate/$(basename "$file")"
done

for unit in honeypot-ghosts-sandbox-worker.service honeypot-ghosts-sandbox-worker.path honeypot-ghosts-sandbox-web-requests.service; do
  install -m 0644 -o root -g root "$script_dir/$unit" "/etc/systemd/system/$unit"
done

if [[ ! -e /etc/default/honeypot-ghosts-sandbox ]]; then
  install -m 0600 -o root -g root \
    "$script_dir/honeypot-ghosts-sandbox.default.example" \
    /etc/default/honeypot-ghosts-sandbox
  echo "Wrote /etc/default/honeypot-ghosts-sandbox from the example -- edit VM_PASS" \
    "before real detonations run (VM_HOST already matches network.xml's DHCP pin)." >&2
fi

install -d -m 0700 -o root -g root /var/lib/honeypot-ghosts-sandbox/requests/{pending,rejected}
install -d -m 0750 -o root -g xore /var/lib/honeypot-ghosts-sandbox/export

systemctl daemon-reload
systemctl reset-failed honeypot-ghosts-sandbox-worker.service honeypot-ghosts-sandbox-web-requests.service 2>/dev/null || true
systemctl enable --now honeypot-ghosts-sandbox-worker.path

echo "GHOSTS sandbox worker installed. Edit /etc/default/honeypot-ghosts-sandbox, then:"
echo "  systemctl status honeypot-ghosts-sandbox-worker.path"
