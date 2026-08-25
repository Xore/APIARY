#!/usr/bin/env bash
# Write the capture NIC's real name into the VPS .env, before Docker starts.
#
# Suricata, Zeek and huginn-sidecar all sniff a named interface. The name was
# hardcoded to `ens6` -- correct for this VPS until it was rebooted on
# 2026-08-25 and came back as `eth0`. Zeek and huginn died on
# "Could not find network interface: ens6"; Suricata stayed *up*, sniffing an
# interface that no longer existed, which is the worse of the two failures
# because nothing in `docker ps` says anything is wrong (#1929).
#
# The name is not ours to predict -- it depends on the provider's virtual NIC,
# the kernel, and udev's naming policy, any of which can change under a
# reboot or a rebuild. So this asks the running system instead of guessing:
# the interface carrying the default route is the one the honeypot's traffic
# arrives on, and that is a fact Linux can answer at boot.
#
# Runs as a systemd oneshot ordered before docker.service, so every boot
# re-derives it and a rename corrects itself.
set -euo pipefail

ENV_FILE="${1:-/root/vps/.env}"

iface="$(ip route show default 2>/dev/null | awk '{ for (i=1; i<NF; i++) if ($i == "dev") { print $(i+1); exit } }')"

if [[ -z "$iface" ]]; then
  echo "detect-capture-interface: no default route, cannot determine the capture NIC" >&2
  exit 1
fi

# Belt and braces: the route table can name an interface that has since gone.
if ! ip link show "$iface" >/dev/null 2>&1; then
  echo "detect-capture-interface: default route names '$iface', which does not exist" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "detect-capture-interface: $ENV_FILE does not exist yet, nothing to update" >&2
  exit 0
fi

current="$(sed -n 's/^CAPTURE_INTERFACE=//p' "$ENV_FILE" | tail -1)"
if [[ "$current" == "$iface" ]]; then
  echo "detect-capture-interface: CAPTURE_INTERFACE already $iface"
  exit 0
fi

# Rewrite in place, preserving everything else. A temp file in the same
# directory keeps the replacement atomic and the permissions intact.
tmp="$(mktemp "${ENV_FILE}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
if grep -q '^CAPTURE_INTERFACE=' "$ENV_FILE"; then
  sed "s|^CAPTURE_INTERFACE=.*|CAPTURE_INTERFACE=${iface}|" "$ENV_FILE" > "$tmp"
else
  cat "$ENV_FILE" > "$tmp"
  printf '\n# Written by detect-capture-interface.service at boot (#1929).\nCAPTURE_INTERFACE=%s\n' "$iface" >> "$tmp"
fi
chmod --reference="$ENV_FILE" "$tmp"
mv "$tmp" "$ENV_FILE"
trap - EXIT

echo "detect-capture-interface: CAPTURE_INTERFACE=${iface} (was '${current:-unset}')"
