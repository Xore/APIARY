#!/bin/sh
# vps-hub-peer.sh: add or remove one spoke peer on the VPS hub wg0 (#3589).
#
# Strictly additive. It never runs wg syncconf, wg-quick down/up or a
# wg0 restart, so the existing VPS <-> homeserver peer (live sensor
# forwarding) keeps its session and its roamed endpoint. Run as root on the VPS.
#
#   vps-hub-peer.sh add    PUBKEY_FILE PSK_FILE ADDR NAME   # live peer + wg0.conf block
#   vps-hub-peer.sh arm    PUBKEY_FILE [10min]              # dead-man: remove peer, restore wg0.conf
#   vps-hub-peer.sh disarm
#   vps-hub-peer.sh remove PUBKEY_FILE CONF_BACKUP          # what the dead-man runs
#
# Keys are read from root-only files and never appear on a command line.
set -eu
conf=/etc/wireguard/wg0.conf
unit=vps-hub-peer-rollback-3589
backup_root=/var/lib/apiary-swarm

case "${1:-}" in
  add)
    [ "$#" -eq 5 ] || { echo 'usage: add PUBKEY_FILE PSK_FILE ADDR NAME' >&2; exit 2; }
    pub=$(cat "$2")
    wg set wg0 peer "$pub" preshared-key "$3" allowed-ips "$4/32" persistent-keepalive 25
    if ! grep -qxF "PublicKey = $pub" "$conf"; then
      umask 077
      { printf '\n[Peer]\n# %s\nPublicKey = %s\nPresharedKey = ' "$5" "$pub"
        cat "$3"
        printf 'AllowedIPs = %s/32\nPersistentKeepalive = 25\n' "$4"; } >>"$conf"
    fi
    ;;
  arm)
    [ "$#" -ge 2 ] || { echo 'usage: arm PUBKEY_FILE [10min]' >&2; exit 2; }
    systemctl is-active --quiet "$unit.timer" && { echo 'rollback already armed' >&2; exit 1; }
    install -d -m 0700 "$backup_root"
    saved="$backup_root/wg0.conf.$(date -u +%Y%m%dT%H%M%SZ)"
    install -m 0600 "$conf" "$saved"
    install -m 0700 "$0" "$backup_root/vps-hub-peer.sh"
    systemctl reset-failed "$unit.service" 2>/dev/null || true
    systemd-run --on-active="${3:-10min}" --unit="$unit" \
      /bin/sh "$backup_root/vps-hub-peer.sh" remove "$2" "$saved"
    echo "$saved"
    ;;
  disarm) systemctl stop "$unit.timer" ;;
  remove)
    [ "$#" -eq 3 ] || { echo 'usage: remove PUBKEY_FILE CONF_BACKUP' >&2; exit 2; }
    wg set wg0 peer "$(cat "$2")" remove
    install -m 0600 "$3" "$conf"
    ;;
  *) sed -n '2,13p' "$0" >&2; exit 2 ;;
esac
