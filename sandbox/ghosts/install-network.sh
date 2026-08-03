#!/usr/bin/env bash
# install-network.sh — libvirt network + iptables policy lifecycle for the
# GHOSTS guest network (#325). Same shape as sandbox/windows/setup's
# kvm_manage.sh net-setup/net-teardown, plus the iptables half that network
# has never needed (it has no <forward> to police).
#
# Usage:
#   sudo install-network.sh net-setup     # define+start virbr-ghosts, install
#                                          # + enable the filter service, verify
#   sudo install-network.sh net-teardown  # reverse of the above
#   sudo install-network.sh verify        # re-run the iptables + in-guest checks

set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NET_NAME=ghosts
NET_XML="$here/network.xml"
LIBEXEC=/usr/local/libexec/honeypot-ghosts

log() { echo "[$(date '+%H:%M:%S')] $*"; }

install_filter() {
  install -d -m 0755 -o root -g root "$LIBEXEC"
  install -m 0750 -o root -g root "$here/network-filter.sh" "$LIBEXEC/network-filter.sh"
  install -m 0644 -o root -g root "$here/ghosts-network-filter.service" \
    /etc/systemd/system/ghosts-network-filter.service
  systemctl daemon-reload
  systemctl enable ghosts-network-filter.service
  # restart, not `enable --now`: a RemainAfterExit=yes oneshot that's already
  # active treats "start" as a no-op, so a re-run after editing
  # network-filter.sh would leave the old rules in place instead of applying
  # the new ones -- verified live (#325) after adding the INPUT/DOCKER-USER
  # rules and finding "verify" still failing against the stale first-run
  # rule set.
  systemctl restart ghosts-network-filter.service
}

net_setup() {
  log "(re)defining libvirt network: $NET_NAME"
  # Always destroy+undefine first, not just define-if-missing: `virsh
  # net-define` on an already-active network updates the persistent XML but
  # not the live dnsmasq config, so an edit to network.xml (the DHCP range,
  # say) would silently keep running under the old config until a manual
  # destroy -- verified live (#325) after widening the DHCP range and
  # finding dnsmasq still handing out the old, smaller pool.
  virsh net-destroy "$NET_NAME" >/dev/null 2>&1 || true
  virsh net-undefine "$NET_NAME" >/dev/null 2>&1 || true
  virsh net-define "$NET_XML"
  virsh net-start "$NET_NAME"
  virsh net-autostart "$NET_NAME"
  log "installing and starting the iptables filter service"
  install_filter
  log "verifying"
  "$LIBEXEC/network-filter.sh" verify
  log "done. Run verify-network-isolation.sh for the in-guest check before any real detonation."
}

net_teardown() {
  log "stopping the filter service"
  systemctl disable --now ghosts-network-filter.service 2>/dev/null || true
  log "removing libvirt network: $NET_NAME"
  virsh net-destroy "$NET_NAME" 2>/dev/null || true
  virsh net-undefine "$NET_NAME" 2>/dev/null || true
  log "done"
}

CMD="${1:-}"
case "$CMD" in
  net-setup)    net_setup ;;
  net-teardown) net_teardown ;;
  verify)       "$LIBEXEC/network-filter.sh" verify && "$here/verify-network-isolation.sh" ;;
  *) echo "Usage: $0 <net-setup|net-teardown|verify>" >&2; exit 2 ;;
esac
