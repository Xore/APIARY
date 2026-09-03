#!/bin/sh
# Idempotently expose the raw OT/IoT and FTP/SSH/Telnet/SMTP honeypot ports
# handled by portbridge (vps/docker-compose.yml's RULES env var). #152: 21
# (dionaea FTP), 22/23 (cowrie SSH/Telnet), and 25 (multipot SMTP) are live
# portbridge listeners too but were missing here -- confirmed via live ufw
# state and external reachability tests that they were already open by hand
# at some point, so this was firewall-policy drift (script fell behind
# RULES), not a deliberate "keep these closed" choice. Real admin SSH lives
# on 2222 (opened by hand per docs/CGNAT-DEPLOYMENT.md, not by this script)
# and is unaffected -- portbridge's 22 is a separate host listener bound
# only after 2222 takes over the real SSH port.
#
# #1509: the exact same drift happened again, silently, and much further --
# this script is documented as needing a manual re-run
# (check-firewall-portbridge-sync.sh) "after editing either file", not
# wired into CI, and nobody re-ran it as sensors were added over time.
# Confirmed live via `ufw status numbered` on the VPS that beelzebub
# (389/2200/8000/8880), hellpot (8080), elasticpot (9201), galah (8889), and
# sentrypeer (5070 tcp+udp) all had a live portbridge RULES entry but no
# firewall rule -- fully unreachable from the internet despite every other
# piece (dashboard visibility, ip-enrichment-worker joins) being wired.
# wordpot (8082) and endlessh (2022) are newly added in this same commit;
# wordpot's 8082 went again when its stack retired (#2381).
# check-firewall-portbridge-sync.sh now passes clean against this file.
#
# vps/check-firewall-portbridge-sync.sh statically compares this list
# against RULES so this can't silently fall behind again -- run it after
# editing either file.
set -eu

# --backend apt (ufw, the Ubuntu/original path) | dnf (firewalld, Rocky).
# Defaults to ufw so existing invocations behave exactly as before. The port
# lists below are the single source of truth either way -- only the firewall
# backend differs.
BACKEND=ufw
if [ "${1:-}" = "--backend" ]; then
    BACKEND="$2"
    shift 2
fi

TCP_PORTS="21 22 23 25 102 110 135 143 389 445 502 1025 1080 1102 1433 1502 1723 1883 2022 2102 2200 2375 2404 2502 2575 3306 3389 4443 5060 5070 5432 5555 5900 6379 8000 8080 8081 8443 8880 8888 8889 9100 9200 9201 10001 11112 11211 20000 27017 44818 50100"
UDP_PORTS="53 69 161 500 623 1900 5060 5070 47808"

case "$BACKEND" in
apt|ufw)
    for port in $TCP_PORTS; do
        ufw allow "${port}/tcp" comment honeypot
    done
    for port in $UDP_PORTS; do
        ufw allow "${port}/udp" comment honeypot
    done
    ;;
dnf|firewalld)
    # firewalld: idempotent adds into the public zone. --permanent + reload,
    # same two-phase pattern the installer's own base step uses.
    for port in $TCP_PORTS; do
        firewall-cmd --permanent --zone=public --add-port="${port}/tcp"
    done
    for port in $UDP_PORTS; do
        firewall-cmd --permanent --zone=public --add-port="${port}/udp"
    done
    firewall-cmd --reload
    ;;
*)
    echo "unknown backend: $BACKEND (use apt|ufw or dnf|firewalld)" >&2
    exit 1
    ;;
esac
