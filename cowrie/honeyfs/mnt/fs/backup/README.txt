NexusAI GPU Node Backup — fs02.nexusai.local:/backup/gpu01
==========================================================

Retention policy:
  Daily    keep 7
  Weekly   keep 4  (Sunday 02:00 CEST)
  Monthly  keep 6  (1st Sunday 01:00 CEST)

Backup tool : restic 0.16.4 (repo at /data/backup/restic-repo)
Encryption  : AES-256-CTR + HMAC-SHA256 (restic default)
Repository  : //fs02.nexusai.local/backup/gpu01/restic-repo
Password    : stored in AD credential manager (gMSA svc-backup$)

Scheduled via cron on gpu01 — see /etc/cron.d/nexusai-backup

Contacts: devops@nexusai.local  oncall: +49-30-2091-4417
