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

install -d -m 0755 -o root -g root "$target" "$target/orchestrate" "$target/packer" "$target/vnc-bridge" "$target/analysis"
install -m 0755 -o root -g root "$script_dir/run_pending.sh" "$target/run_pending.sh"
install -m 0755 -o root -g root "$script_dir/process-windows-web-requests.sh" "$target/process-windows-web-requests.sh"
install -m 0755 -o root -g root "$script_dir/golden-image-status.sh" "$target/golden-image-status.sh"
for file in "$script_dir"/orchestrate/*.py; do
  install -m 0755 -o root -g root "$file" "$target/orchestrate/$(basename "$file")"
done
# run_sample.py's KVM_XML_TEMPLATE resolves win11-kvm.xml relative to its own
# installed location ($target/packer/win11-kvm.xml) -- this was never copied
# here, so regenerate_registry_baseline() (used by
# diff_registry_against_baseline(), called after every detonation) has been
# silently failing with FileNotFoundError on every real run on this host,
# caught and logged but never actually producing a registry baseline diff.
# Confirmed live 2026-08-05 during #47/#53's end-to-end verification.
install -m 0644 -o root -g root "$script_dir/packer/win11-kvm.xml" "$target/packer/win11-kvm.xml"

# #805: read-only viewer bridge for the live detonation VM's own VNC console
# (already enabled in win11-kvm.xml above -- this just exposes it to the
# dashboard). stdlib-only, same reasoning as every other host-side script
# here: it holds libvirt access, so it does not get a pip dependency tree.
install -m 0755 -o root -g root "$script_dir/vnc-bridge/server.py" "$target/vnc-bridge/server.py"

# #528: row-aware CDC dedup store for procmon.csv, and the timer-triggered
# job that archives old diagnostics.zip files into it. Both stdlib-only
# (sqlite3, zipfile, hashlib) -- no pip dependency tree, same reasoning as
# everything else installed here. Lives in analysis/ (shared with the
# containerized payload-dedupe/yara-scanner stack) rather than
# sandbox/windows/orchestrate/ since it's not part of the detonation
# pipeline itself, but this worker's own libexec tree is where it actually
# needs to run from -- diagnostics.zip only ever exists on this host, not
# in any container that mounts it.
install -m 0644 -o root -g root "$script_dir/../../analysis/procmon_cdc_store.py" "$target/analysis/procmon_cdc_store.py"
install -m 0644 -o root -g root "$script_dir/../../analysis/archive_diagnostics.py" "$target/analysis/archive_diagnostics.py"
install -m 0755 -o root -g root "$script_dir/archive-diagnostics.sh" "$target/archive-diagnostics.sh"

for unit in honeypot-windows-sandbox-worker.service honeypot-windows-sandbox-worker.path honeypot-windows-sandbox-web-requests.service \
    honeypot-windows-golden-image-status.service honeypot-windows-golden-image-status.timer \
    archive-diagnostics.service archive-diagnostics.timer; do
  install -m 0644 -o root -g root "$script_dir/$unit" "/etc/systemd/system/$unit"
done
install -m 0644 -o root -g root "$script_dir/vnc-bridge/honeypot-windows-vnc-bridge.service" \
  "/etc/systemd/system/honeypot-windows-vnc-bridge.service"

if [[ ! -e /etc/default/honeypot-windows-sandbox ]]; then
  install -m 0600 -o root -g root \
    "$script_dir/honeypot-windows-sandbox.default.example" \
    /etc/default/honeypot-windows-sandbox
  echo "Wrote /etc/default/honeypot-windows-sandbox from the example -- edit VM_PASS" \
    "(and anything else) before real detonations run." >&2
fi

install -d -m 0700 -o root -g root /var/lib/honeypot-windows-sandbox/requests/{pending,rejected}
install -d -m 0750 -o root -g xore /var/lib/honeypot-windows-sandbox/export
# #528: root-owned like export/ above -- archive-diagnostics.service (root,
# no User= override) is the only writer, same posture as the requests dirs.
install -d -m 0750 -o root -g xore /var/lib/honeypot-windows-sandbox/procmon-cdc-store

systemctl daemon-reload
systemctl reset-failed honeypot-windows-sandbox-worker.service honeypot-windows-sandbox-web-requests.service 2>/dev/null || true
systemctl enable --now honeypot-windows-sandbox-worker.path
systemctl enable --now honeypot-windows-golden-image-status.timer
systemctl start honeypot-windows-golden-image-status.service || true
systemctl enable --now honeypot-windows-vnc-bridge.service
systemctl enable --now archive-diagnostics.timer

echo "Windows sandbox worker installed. The .path unit is enabled and watching"
echo "/var/lib/honeypot-windows-sandbox/requests/pending, and now triggers the"
echo "hash-resolution/submission-handoff service before the detonation worker --"
echo "a request the dashboard writes will have its sample bytes resolved from"
echo "the capture roots and copied to \$WINDOWS_SANDBOX_SAMPLES_DIR automatically."
systemctl --no-pager --plain is-active honeypot-windows-sandbox-worker.path
