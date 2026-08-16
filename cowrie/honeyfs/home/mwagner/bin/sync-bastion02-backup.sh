#!/bin/bash
# Nightly config/keytab sync from gpu01 to bastion02, run out of mwagner's
# own crontab (`crontab -l` shows it) since it predates the service account
# devops keeps promising to set up. TODO(mwagner): swap this for a real
# SSH key + a dedicated svc-backup account -- see internal-services.txt,
# devops asked not to touch the bastion02 key rotation until this is fixed.
set -euo pipefail

BASTION_HOST="bastion02"
BASTION_PORT="2200"
BASTION_PASS="nexusai2025"

sshpass -p "${BASTION_PASS}" scp -P "${BASTION_PORT}" -o StrictHostKeyChecking=no \
    /opt/nexusai-inference/configs/*.yaml svc-admin@"${BASTION_HOST}":/opt/backups/gpu01-configs/

echo "[$(date -Is)] synced configs to ${BASTION_HOST}" >> /var/log/gpu01-bastion02-sync.log
