#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

xml=$(virsh net-dumpxml honeypot-sandbox)
grep -q '<forward' <<<"$xml" && { echo "isolated network unexpectedly forwards traffic" >&2; exit 1; }
grep -q '<ip ' <<<"$xml" && { echo "isolated network unexpectedly has a host IP" >&2; exit 1; }
if virsh net-info default >/dev/null 2>&1 && virsh net-info default | grep -q '^Active:.*yes'; then
  echo "default libvirt NAT network is active" >&2
  exit 1
fi
filter_xml=$(virsh nwfilter-dumpxml honeypot-sandbox-strict)
grep -q "filterref filter='no-mac-spoofing'" <<<"$filter_xml"
grep -q "filterref filter='no-other-l2-traffic'" <<<"$filter_xml"

log=$(mktemp)
request=
trap 'rm -f -- "$log" ${request:+"$request"}' EXIT
bash "$script_dir/run-linux-sample.sh" \
  --i-understand-this-executes-untrusted-code "$script_dir/benign-smoke.sh" | tee "$log"
result=$(sed -n 's/^RESULT_DIR=//p' "$log" | tail -n 1)
[[ -n $result && -f $result/report.json && -f $result/sample.sha256 ]]
[[ $(jq -r .exit_status "$result/report.json") == 0 ]]
grep -q honeypot-smoke-created "$result/files-created-or-changed.tsv"
compgen -G "$result/trace/strace.*" >/dev/null
[[ -s $result/network.pcap ]]
tcpdump -nn -c 1 -r "$result/network.pcap" >/dev/null 2>&1 || [[ $(stat -c %s "$result/network.pcap") -ge 24 ]]
[[ ! -e /var/lib/honeypot-sandbox/overlays/"$(basename "$result")".qcow2 ]]

request=$(mktemp)
jq -n --arg sha256 "$(cut -d' ' -f1 "$result/submitted.sha256")" \
  --arg requested_at "$(cat "$result/host-started-at.txt")" \
  '{version:1,sha256:$sha256,requested_at:$requested_at,source:"smoke-test",capture_name:"benign-smoke.sh"}' >"$request"
python3 "$script_dir/export-result.py" --request "$request" --result "$result" \
  --output "/var/lib/honeypot-sandbox/export/$(basename "$result").json"
rm -f -- "$request"
echo "Linux sandbox smoke test passed: $result"
