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
# vps/check-firewall-portbridge-sync.sh statically compares this list
# against RULES so this can't silently fall behind again.
set -eu

for port in 21 22 23 25 102 110 135 143 445 502 1025 1080 1102 1433 1502 1723 1883 2102 2375 2404 2502 2575 3306 3389 4443 5060 5432 5555 5900 6379 8081 8443 8888 9100 9200 10001 11112 11211 20000 27017 44818 50100; do
    ufw allow "${port}/tcp" comment honeypot
done

for port in 53 69 161 500 623 1900 5060 47808; do
    ufw allow "${port}/udp" comment honeypot
done
