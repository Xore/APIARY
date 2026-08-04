#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
command -v tcpdump >/dev/null || { echo "tcpdump is required; rerun sandbox/install-host.sh" >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bash "$script_dir/extract-linux-boot.sh"
target=/usr/local/libexec/honeypot-sandbox
install -d -m 0755 -o root -g root "$target"
for file in run-linux-sample.sh guest-runner.sh guest-pe-forensics.py guest-payload-classifier.py guest-clean-strings.py linux-runner.service worker.sh process-web-requests.sh export-result.py status-export.py cleanup.sh; do
  install -m 0755 -o root -g root "$script_dir/$file" "$target/$file"
done
bash "$script_dir/apply-network-filter.sh"
install -m 0755 -o root -g root "$script_dir/submit-capture.sh" /usr/local/sbin/honeypot-sandbox-submit
if [[ ! -e /etc/default/honeypot-sandbox ]]; then
  install -m 0644 -o root -g root "$script_dir/sandbox.env.example" /etc/default/honeypot-sandbox
fi
for unit in honeypot-sandbox-worker.service honeypot-sandbox-worker.path honeypot-sandbox-web-requests.service honeypot-sandbox-web-requests.path honeypot-sandbox-cleanup.service honeypot-sandbox-cleanup.timer; do
  install -m 0644 -o root -g root "$script_dir/$unit" "/etc/systemd/system/$unit"
done
install -d -m 0700 -o root -g root /var/lib/honeypot-sandbox/inbox/{queued,running,completed,failed,samples}
install -d -m 0700 -o root -g root /var/lib/honeypot-sandbox/requests/{pending,rejected}
install -d -m 0750 -o root -g xore /var/lib/honeypot-sandbox/export
# Backfill bounded captures for retained reports so older investigations gain
# the same administrator-only Wireshark downloads as new worker results.
shopt -s nullglob
for report in /var/lib/honeypot-sandbox/export/{linux,windows}-*.json; do
  job=$(basename "$report" .json)
  result="/var/lib/honeypot-sandbox/results/$job"
  [[ -d $result ]] || continue
  for capture in network.pcap guest-network.pcap; do
    [[ -f $result/$capture && ! -L $result/$capture ]] || continue
    size=$(stat -c %s "$result/$capture")
    (( size <= 67108864 )) || continue
    suffix=host
    [[ $capture == guest-network.pcap ]] && suffix=guest
    install -m 0640 -o root -g xore "$result/$capture" \
      "/var/lib/honeypot-sandbox/export/$job.$suffix.pcap"
  done
done
systemctl daemon-reload
systemctl reset-failed honeypot-sandbox-worker.service honeypot-sandbox-web-requests.service 2>/dev/null || true
systemctl enable --now honeypot-sandbox-worker.path honeypot-sandbox-web-requests.path honeypot-sandbox-cleanup.timer
/usr/local/libexec/honeypot-sandbox/status-export.py --worker-state idle
systemctl start --no-block honeypot-sandbox-web-requests.service honeypot-sandbox-worker.service
echo "Sandbox queues installed. Dashboard requests and direct hash submissions are enabled."
echo "Submit from the CLI only by hash: sudo honeypot-sandbox-submit <hash>"
systemctl --no-pager --plain is-active honeypot-sandbox-worker.path honeypot-sandbox-web-requests.path honeypot-sandbox-cleanup.timer
