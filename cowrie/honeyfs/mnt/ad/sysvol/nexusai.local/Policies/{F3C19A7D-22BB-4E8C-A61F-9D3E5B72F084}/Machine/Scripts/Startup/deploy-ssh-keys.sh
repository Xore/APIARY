#!/bin/bash
# Distribute authorised SSH public keys for MLOps service accounts
# GPO: MLOps Service Accounts - SSH Key Distribution
# Runs at machine startup on Linux domain members via winbind/adcli
# Owner: devops@nexusai.local   Rev: 7   Last: 2026-06-30

set -euo pipefail

KEY_SOURCE="/mnt/ad/sysvol/nexusai.local/Policies/{F3C19A7D-22BB-4E8C-A61F-9D3E5B72F084}/Machine/Scripts/keys"
AUTHORIZED_USERS=(svc-gpu01 svc-jenkins svc-mlflow deploy)

for user in "${AUTHORIZED_USERS[@]}"; do
    home=$(getent passwd "${user}" | cut -d: -f6) || continue
    mkdir -p "${home}/.ssh"
    chmod 700 "${home}/.ssh"
    cp -f "${KEY_SOURCE}/${user}.pub" "${home}/.ssh/authorized_keys" 2>/dev/null || true
    chmod 600 "${home}/.ssh/authorized_keys"
    chown -R "${user}:domain users" "${home}/.ssh"
done
