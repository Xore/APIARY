#!/usr/bin/env bash
set -euo pipefail

# Make the 10 GbE homeserver uplink the boot-critical interface without
# hard-coding its DHCP address. Run with --apply from a local console or a
# session connected through that interface.

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root: sudo ./setup-home-network.sh [--apply]" >&2
  exit 1
fi

required_interface=${REQUIRED_INTERFACE:-ens9f0}
secondary_interface=${SECONDARY_INTERFACE:-eno2}
unused_interface=${UNUSED_INTERFACE:-eno1}
apply=false

if [[ ${1:-} == "--apply" ]]; then
  apply=true
elif [[ $# -gt 0 ]]; then
  echo "Usage: sudo ./setup-home-network.sh [--apply]" >&2
  exit 2
fi

for interface in \
  "$required_interface" \
  "$secondary_interface" \
  "$unused_interface"; do
  [[ -e "/sys/class/net/$interface" ]] || {
    echo "Network interface not found: $interface" >&2
    exit 1
  }
done

install -d -m 0755 /etc/netplan
cat >/etc/netplan/90-honeypot-uplink.yaml <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${required_interface}:
      dhcp4: true
      optional: false
      dhcp4-overrides:
        route-metric: 50
    ${secondary_interface}:
      optional: true
      dhcp4-overrides:
        route-metric: 200
    ${unused_interface}:
      optional: true
EOF
chmod 0600 /etc/netplan/90-honeypot-uplink.yaml

# Netplan can emit more than one wait-online ExecStart when configurations are
# merged. Pin boot readiness to the actual required uplink and do not require
# the local DNS service to be running before Docker starts it.
install -d -m 0755 \
  /etc/systemd/system/systemd-networkd-wait-online.service.d
cat \
  >/etc/systemd/system/systemd-networkd-wait-online.service.d/90-honeypot-uplink.conf <<EOF
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --interface=${required_interface}:routable --timeout=60
EOF

netplan generate
systemctl daemon-reload

if [[ "$apply" == true ]]; then
  netplan apply
  networkctl status "$required_interface" --no-pager
else
  echo "Configuration generated but not applied."
  echo "Review /etc/netplan/90-honeypot-uplink.yaml, then run:"
  echo "  sudo netplan try"
fi
