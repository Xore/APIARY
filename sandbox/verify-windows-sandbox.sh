#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
base=${SANDBOX_LINUX_BASE:-/var/lib/honeypot-sandbox/base/ubuntu-noble.qcow2}
work=$(mktemp -d /var/lib/honeypot-sandbox/base/.windows-smoke.XXXXXX)
request=
trap 'rm -rf -- "$work"; rm -f -- ${request:+"$request"}' EXIT

virt-copy-out -a "$base" /home/sandbox/.wine/drive_c/windows/system32/notepad.exe "$work"
sample="$work/notepad.exe"
[[ -f $sample ]] || {
  echo "Wine fixture missing; rebuild the golden image with prepare-linux-base.sh" >&2
  exit 1
}
file "$sample" | grep -q 'PE32'

log="$work/run.log"
bash "$script_dir/run-linux-sample.sh" \
  --i-understand-this-executes-untrusted-code "$sample" | tee "$log"
result=$(sed -n 's/^RESULT_DIR=//p' "$log" | tail -n 1)
[[ -n $result && -f $result/report.json && -s $result/pe-forensics.json ]]
[[ $(jq -r .detected "$result/pe-forensics.json") == true ]]
[[ $(cat "$result/execution-mode.txt") == wine ]]
[[ -s $result/network.pcap && -s $result/guest-network.pcap ]]
[[ ! -e /var/lib/honeypot-sandbox/overlays/"$(basename "$result")".qcow2 ]]

request=$(mktemp)
jq -n --arg sha256 "$(cut -d' ' -f1 "$result/submitted.sha256")" \
  --arg requested_at "$(cat "$result/host-started-at.txt")" \
  '{version:1,sha256:$sha256,requested_at:$requested_at,source:"smoke-test",capture_name:"wine-notepad.exe"}' >"$request"
exported="/var/lib/honeypot-sandbox/export/$(basename "$result").json"
python3 "$script_dir/export-result.py" --request "$request" --result "$result" --output "$exported"
jq -e '.windows_forensics.detected == true and .windows_forensics.execution_mode == "wine"' "$exported" >/dev/null

echo "Windows/Wine sandbox smoke test passed: $result"
