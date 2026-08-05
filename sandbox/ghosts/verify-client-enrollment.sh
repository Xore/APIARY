#!/usr/bin/env bash
# verify-client-enrollment.sh — boot a throwaway clone of win11-ghosts.qcow2
# and confirm the GHOSTS client enrolls against Ghosts.Api (#326).
#
# Requires sandbox/ghosts/win11-ghosts-kvm.xml (#327) to already be defined
# -- this script doesn't own the domain's hardware profile (SMBIOS/firmware/
# TPM have to match exactly what win11-analysis.pkr.hcl built the shared
# base install with, see that file's own header) and duplicating it here
# would just be a second copy to drift out of sync.
#
# Re-run this after any change to config/application.json, Dockerfile.client-win,
# or a re-provision of the golden image -- same "verify, don't just assert"
# standard the rest of sandbox/ghosts/ holds itself to.
#
# Usage: sudo verify-client-enrollment.sh

set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOLDEN_IMAGE=/var/dockge/sandbox/golden-images/win11-ghosts.qcow2
DOMAIN_XML_TEMPLATE="$here/win11-ghosts-kvm.xml"
GHOSTS_API_ADDR=10.20.30.1:5000
WINRM_USER=analyst
WINRM_PASS=malware123!

# #651: this throwaway verification VM used to be named win11-ghosts, the
# exact same domain name and disk path as the real, persistent production
# GHOSTS VM (#327/#641). The cleanup trap below unconditionally virsh
# destroy/undefine's that name and rm -f's that disk on *every* exit path,
# including the pre-flight failure that fires precisely when the real
# domain already exists -- so running this script while the real VM is up
# (the normal state, now that #641 is fixed) would silently destroy it.
# Give this run its own PID-suffixed name/disk/nvram/MAC instead, matching
# verify-network-isolation.sh's own $$-suffixed throwaway-domain pattern
# in this same directory -- independent of whatever the production domain
# is currently named, so this script can never touch it.
vm="win11-ghosts-enrollment-check-$$"
VM_DISK="/var/dockge/sandbox/vms/${vm}.qcow2"
NVRAM_PATH="/var/lib/libvirt/qemu/nvram/${vm}_VARS.qcow2"
mac="52:54:00:ee:$(printf '%02x' $((RANDOM % 256))):$(printf '%02x' $((RANDOM % 256)))"
work="$(mktemp -d)"
DOMAIN_XML="$work/domain.xml"

[[ -f "$GOLDEN_IMAGE" ]] || { echo "error: $GOLDEN_IMAGE not found -- run provision-golden-image.sh first" >&2; exit 1; }
[[ -f "$DOMAIN_XML_TEMPLATE" ]] || { echo "error: $DOMAIN_XML_TEMPLATE not found -- #327 hasn't landed yet, nothing to boot this image with" >&2; exit 1; }
command -v python3 >/dev/null && python3 -c 'import winrm' 2>/dev/null || {
  echo "error: python3's winrm module is required (pip install pywinrm)" >&2; exit 1;
}
virsh net-info ghosts >/dev/null 2>&1 || { echo "error: the 'ghosts' libvirt network doesn't exist -- run install-network.sh net-setup first" >&2; exit 1; }
curl -sf -m5 "http://$GHOSTS_API_ADDR/" >/dev/null || { echo "error: $GHOSTS_API_ADDR (Ghosts.Api, #324) is not answering" >&2; exit 1; }

# This script doesn't own the domain's hardware profile (SMBIOS/firmware/
# TPM have to match exactly what win11-analysis.pkr.hcl built the shared
# base install with, see that file's own header) -- so rather than
# duplicating win11-ghosts-kvm.xml's content here (a second copy to drift
# out of sync), take the real template and substitute only the identity
# fields that must be unique to this throwaway run.
sed \
  -e "s#<name>win11-ghosts</name>#<name>${vm}</name>#" \
  -e "s#/var/dockge/sandbox/vms/win11-ghosts\.qcow2#${VM_DISK}#" \
  -e "s#/var/lib/libvirt/qemu/nvram/win11-ghosts_VARS\.qcow2#${NVRAM_PATH}#" \
  -e "s#00:1a:a0:3c:4d:6f#${mac}#" \
  "$DOMAIN_XML_TEMPLATE" > "$DOMAIN_XML"

cleanup() {
  virsh destroy "$vm" >/dev/null 2>&1 || true
  virsh undefine "$vm" --nvram >/dev/null 2>&1 || true
  rm -f -- "$VM_DISK"
  rm -rf -- "$work"
}
trap cleanup EXIT

echo "== baseline machine count"
before="$(curl -sf "http://$GHOSTS_API_ADDR/api/machines/list" | grep -o '"id"' | wc -l)"
echo "  $before"

echo "== creating throwaway overlay + defining the domain ($vm)"
[[ -e "$VM_DISK" ]] && { echo "error: $VM_DISK already exists -- remove it deliberately first" >&2; exit 1; }
qemu-img create -q -f qcow2 -F qcow2 -b "$GOLDEN_IMAGE" "$VM_DISK"
chown libvirt-qemu:kvm "$VM_DISK"
virsh define "$DOMAIN_XML" >/dev/null
# `virsh start` on a domain whose nvram doesn't exist yet is supposed to
# create it from <nvram template=...> automatically -- on this host that
# auto-conversion fails ("conversion of the nvram template to another
# target format is not supported"), verified live (#326). Pre-create it by
# hand with the same raw->qcow2 conversion libvirt would otherwise do. This
# path is always fresh now (PID-suffixed, never pre-existing), but the
# existence check is cheap insurance against a leftover from a killed run.
if [[ ! -e $NVRAM_PATH ]]; then
  qemu-img convert -q -f raw -O qcow2 /usr/share/OVMF/OVMF_VARS_4M.ms.fd "$NVRAM_PATH"
  chown libvirt-qemu:libvirt-qemu "$NVRAM_PATH"
fi
virsh start "$vm" >/dev/null

echo "== waiting for WinRM"
guest_ip=""
tries=60
while [ "$tries" -gt 0 ]; do
  # Fields: Date Time MAC Protocol IP Hostname ClientID -- date+time are two
  # separate space-separated fields, so the IP is $5, not $4 (caught live,
  # #326: this originally printed "ipv4" and the wait loop spun until
  # timeout since it was checking connectivity to an empty/garbage host).
  guest_ip="$(virsh net-dhcp-leases ghosts 2>/dev/null | awk -v mac="$mac" '$3 == mac {print $5}' | cut -d/ -f1)"
  if [ -n "$guest_ip" ] && (exec 3<>"/dev/tcp/$guest_ip/5985") 2>/dev/null; then
    exec 3<&- 3>&-
    break
  fi
  guest_ip=""
  tries=$((tries - 1))
  sleep 5
done
[ -n "$guest_ip" ] || { echo "error: WinRM never came up on $vm" >&2; exit 1; }
echo "  guest is at $guest_ip"

echo "== launching the client (WMI Create, not Start-Process: verified live (#326) that"
echo "   Start-Process -RedirectStandardOutput hangs indefinitely over this WinRM path)"
python3 - "$guest_ip" "$WINRM_USER" "$WINRM_PASS" <<'PYEOF'
import sys, winrm
ip, user, pw = sys.argv[1:4]
s = winrm.Session(ip, auth=(user, pw), transport='ntlm', operation_timeout_sec=25, read_timeout_sec=30)
ps = r'''
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
  CommandLine = "C:\ghosts\Ghosts.Client.Universal.exe"
  CurrentDirectory = "C:\ghosts"
}
if ($r.ReturnValue -ne 0) { throw "Win32_Process.Create failed: $($r.ReturnValue)" }
$r.ProcessId
'''
r = s.run_ps(ps)
if r.status_code != 0:
    print(r.std_err.decode(errors="replace"), file=sys.stderr)
    sys.exit(1)
print(r.std_out.decode().strip())
PYEOF

echo "== polling for a fresh check-in from this guest (can take several"
echo "   minutes -- the client's first registration handshake is not instant)"
# NOT a machine-count check: the golden image bakes in a fixed hostname
# (the persona's, e.g. acp-fin0142), and the API's ApplicationSettings
# MatchMachinesBy: "name" updates that existing record on every re-run
# instead of creating a new one -- verified live (#326) after two
# count-based runs both reported FAIL while the machine's own
# lastReportedUtc had in fact just advanced. A fresh timestamp on the named
# machine is the real signal; a rising count only ever fires once.
started="$(date -u +%s)"
reported_epoch=0
tries=60
while [ "$tries" -gt 0 ]; do
  reported_epoch="$(curl -sf "http://$GHOSTS_API_ADDR/api/machines?q=" 2>/dev/null | \
    python3 -c "
import json, sys, datetime
try:
    d = json.load(sys.stdin)
    m = next((x for x in d if x.get('hostIp') == '$guest_ip'), None)
    if not m:
        print(0)
    else:
        ts = m['lastReportedUtc'].split('.')[0]
        print(int(datetime.datetime.fromisoformat(ts).replace(tzinfo=datetime.timezone.utc).timestamp()))
except Exception:
    print(0)
" 2>/dev/null || echo 0)"
  [ "${reported_epoch:-0}" -ge "$started" ] && break
  tries=$((tries - 1))
  sleep 10
done

if [ "${reported_epoch:-0}" -lt "$started" ]; then
  echo "RESULT: FAIL -- no check-in from $guest_ip newer than script start seen" >&2
  exit 1
fi
# $after, not just $before: caught live while fixing #651 -- referencing
# an unset $after here under `set -u` would abort the script on every
# success, right after the real check above already passed.
after="$(curl -sf "http://$GHOSTS_API_ADDR/api/machines/list" | grep -o '"id"' | wc -l)"
echo "RESULT: PASS -- $before -> $after machines. Last registered:"
curl -sf "http://$GHOSTS_API_ADDR/api/machines/list" | python3 -c 'import json,sys; print(json.load(sys.stdin)[-1])'
