#!/bin/bash
# Join a Linux host to the NEXUSAI.LOCAL domain
# Usage: sudo ./domain-join-linux.sh <hostname> <admin-user>
# Tested on: Ubuntu 22.04 LTS
# Owner: NEXUSAI\devops   Version: 2.1   Last: 2026-04-11

set -euo pipefail

HOSTNAME_NEW="${1:-$(hostname)}"
ADMIN_USER="${2:-administrator}"
DOMAIN="nexusai.local"
REALM="NEXUSAI.LOCAL"
AD_SERVER="ad.nexusai.local"

echo "[+] Updating hostname to ${HOSTNAME_NEW}"
hostnamectl set-hostname "${HOSTNAME_NEW}.${DOMAIN}"

echo "[+] Installing packages"
apt-get update -qq
apt-get install -y -qq sssd sssd-ad sssd-tools realmd adcli samba-common-bin \
    krb5-user packagekit oddjob oddjob-mkhomedir

echo "[+] Joining domain ${DOMAIN}"
realm join --user="${ADMIN_USER}" --computer-ou="OU=GPU Nodes,OU=Servers,DC=nexusai,DC=local" \
    "${DOMAIN}"

echo "[+] Configuring PAM homedir creation"
pam-auth-update --enable mkhomedir

echo "[+] Restricting SSH login to mlops and devops groups"
realm permit -g 'NEXUSAI\mlops' 'NEXUSAI\devops' 'NEXUSAI\domain admins'

echo "[+] Done. Reboot recommended."
