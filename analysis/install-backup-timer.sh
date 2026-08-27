#!/usr/bin/env bash
# install-backup-timer.sh — enable the daily stack-config backup
# (#1413; since that removal story the script backs up config, secrets,
# the Keycloak dump and small volumes only -- no Elasticsearch snapshot).
# Modelled on sandbox/install-worker.sh and
# analysis/github/install-github-publisher.sh's own unit-install shape.
#
# Unlike those two, backup-honeypot.sh itself is not copied out to
# /usr/local/libexec -- it's tightly coupled to the live checkout it backs
# up (STACK_DIR defaults to /opt/stacks/apiary, and it tars up that
# checkout's own analysis/dashboard/personas/state directories relative to
# itself), so a stale copied-out version would silently drift from what it's
# actually backing up. The systemd unit runs it in place instead, same
# posture docs/RECOVERY.md already documents for factory-reset.sh.
#
# Failure posture, kept deliberately (#2348): both units are Type=oneshot
# with no Restart= and no OnFailure= hook -- a failed run waits until the
# next day's timer (+30m jitter). Persistent=true covers missed STARTS
# while the box was off, not failed runs. Two facts make that acceptable
# rather than accidental: retention running FIRST (#2025) removed the one
# failure mode that used to self-perpetuate past a manual fix (a full disk
# aborting every run before pruning could free anything), and this fleet
# has no operator alert channel OnFailure= could notify even if we wanted
# one. Revisit if either fact changes.
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

for unit in backup-honeypot.service backup-honeypot.timer; do
  install -m 0644 -o root -g root "$script_dir/$unit" "/etc/systemd/system/$unit"
done

install -d -m 0700 -o root -g root /opt/backups/honeypot

systemctl daemon-reload
systemctl reset-failed backup-honeypot.service 2>/dev/null || true
systemctl enable --now backup-honeypot.timer

echo "backup-honeypot.timer installed and enabled -- daily, +/-30m random delay."
