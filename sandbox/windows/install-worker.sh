#!/usr/bin/env bash
# Install the Windows sandbox worker: scripts, systemd units, host
# directories, and the environment file. Mirrors sandbox/install-worker.sh
# (the Linux equivalent) in layout and conventions -- same
# /usr/local/libexec/honeypot-sandbox base, same requests/{pending,rejected}
# + export directory shape, same "only the .path unit is enabled" pattern.
#
# What this does NOT install: a hash-resolution/submission handoff
# equivalent to Linux's honeypot-sandbox-web-requests.service +
# honeypot-sandbox-submit. That layer resolves a bare SHA-256 against the
# approved capture roots (Cowrie/Dionaea/inline-script stores), recomputes
# the hash, and copies the sample into the worker's samples directory under
# root ownership -- a real, security-relevant piece of its own that doesn't
# exist for Windows yet. Until it does, run_pending.sh will accept a
# {sha256}.request but drop it ("sample $sha is not in $samples_dir") unless
# something else already placed the sample bytes at
# $WINDOWS_SANDBOX_SAMPLES_DIR/$sha first.
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
target=/usr/local/libexec/honeypot-sandbox/windows

# #438: run_sample.py's own docstring has always said "pip install pywinrm
# paramiko python-evtx", but nothing ever actually ran that for the user
# the systemd units execute as (root) -- so a `pip install` done by hand as
# a regular user (site-packages under that user's own home) was invisible
# to the worker, and every WinRM attempt failed with "pywinrm not
# installed" from inside wait_for_winrm()'s own except-and-retry loop.
# Confirmed live: that exact failure produced no useful symptom on its own
# -- wait_for_winrm() silently swallowed it and reported a generic
# "WinRM not responsive after boot" timeout, which reads exactly like a
# slow-boot problem instead of a missing-dependency one. (Also fixed
# there, separately: that loop now logs the real per-attempt error instead
# of discarding it.) Installing here, for root, as part of the same setup
# step that installs everything else this worker needs, closes the gap at
# its source instead of relying on whoever deploys this noticing a vague
# timeout and guessing why.
python3 -m pip install --break-system-packages pywinrm paramiko python-evtx

install -d -m 0755 -o root -g root "$target" "$target/orchestrate"
install -m 0755 -o root -g root "$script_dir/run_pending.sh" "$target/run_pending.sh"
for file in "$script_dir"/orchestrate/*.py; do
  install -m 0755 -o root -g root "$file" "$target/orchestrate/$(basename "$file")"
done

for unit in honeypot-windows-sandbox-worker.service honeypot-windows-sandbox-worker.path; do
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
systemctl reset-failed honeypot-windows-sandbox-worker.service 2>/dev/null || true
systemctl enable --now honeypot-windows-sandbox-worker.path

echo "Windows sandbox worker installed. The .path unit is enabled and watching"
echo "/var/lib/honeypot-windows-sandbox/requests/pending."
echo "NOT yet installed: the hash-resolution/submission handoff -- see this"
echo "script's own header comment. A request written directly to that"
echo "directory will be dropped unless the sample is already at"
echo "\$WINDOWS_SANDBOX_SAMPLES_DIR/\$sha256."
systemctl --no-pager --plain is-active honeypot-windows-sandbox-worker.path
