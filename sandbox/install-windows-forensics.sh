#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root: sudo bash $0" >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if systemctl is-active --quiet honeypot-sandbox-worker.service; then
  echo "The sandbox worker is active. Wait for the current analysis to finish, then rerun." >&2
  exit 1
fi

# Do not let existing queued work start against a partially rebuilt image.
systemctl stop honeypot-sandbox-worker.path 2>/dev/null || true
# Only restart the queue automatically once verification (steps 4-5) has
# actually passed -- verified is set right after verify-windows-sandbox.sh
# succeeds, so it stays 0 if any earlier step (including a rebuilt-but-
# unverified image) fails and set -e aborts the script before reaching it.
verified=0
restore_worker_path() {
  if [[ $verified -eq 1 ]]; then
    systemctl start honeypot-sandbox-worker.path 2>/dev/null || true
  else
    echo "Sandbox rebuild did not complete verification -- honeypot-sandbox-worker.path stays stopped. Investigate, fix, and rerun before the queue processes samples again." >&2
  fi
}
trap restore_worker_path EXIT

echo "[1/6] Rebuilding the verified golden guest with Wine and PE tooling"
bash "$script_dir/prepare-linux-base.sh"

echo "[2/6] Restoring narrow libvirt image permissions"
bash "$script_dir/repair-permissions.sh"

echo "[3/6] Installing controlled real-DNS and allowlisted retrieval services"
bash "$script_dir/install-forensic-egress.sh"

echo "[4/6] Verifying a fresh Linux guest lifecycle"
bash "$script_dir/verify-linux-sandbox.sh"

echo "[5/6] Verifying PE analysis, Wine, DNS/PCAP, and overlay destruction"
bash "$script_dir/verify-windows-sandbox.sh"
verified=1

echo "[6/6] Installing and starting the serial hash-only queue"
bash "$script_dir/install-worker.sh"
trap - EXIT

echo "Windows forensic sandbox installed and verified."
echo "Every payload receives a new transient KVM domain and disposable qcow2 overlay."
