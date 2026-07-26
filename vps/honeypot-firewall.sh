#!/bin/sh
# Idempotently expose the raw OT honeypot ports handled by portbridge.
set -eu

for port in 102 135 445 502 1025 1102 1433 1502 1723 1883 2102 2375 2404 2502 3306 5060 5432 5900 6379 8081 8888 9100 9200 10001 11211 20000 27017 44818 50100; do
    ufw allow "${port}/tcp" comment honeypot
done

for port in 69 161 623 1900 5060 47808; do
    ufw allow "${port}/udp" comment honeypot
done
