# Backup and recovery

For a *deliberate* full reset on the same hosts (not disaster recovery), see
[`docs/STACK-REBUILD.md`](../STACK-REBUILD.md) instead — this doc is
about restoring a backup archive onto a replacement host after data loss.

Run `sudo analysis/backup-honeypot.sh` from the deployed stack. It creates a
timestamped, mode-0700 directory beneath `/opt/backups/honeypot`, requests a
consistent Elasticsearch snapshot, archives configuration/runtime state, and
exports non-Elasticsearch named volumes. Validate it with
`analysis/verify-backup.sh <directory>` and copy the result to encrypted storage
outside the homeserver.

Recovery is intentionally not automatic because overwriting live volumes is
destructive. On a replacement host:

1. Verify `SHA256SUMS`, unpack `stack-config-state.tar.gz` into a new empty stack
   directory, and inspect `.env` permissions and values.
2. Create the named volumes with `docker compose -f compose.yml create`, keep all
   services stopped, and restore each matching volume archive using a temporary
   networkless BusyBox container.
3. Start Elasticsearch alone, register the `honeypot-fs` repository, list
   snapshots, and use Elasticsearch `_snapshot/.../_restore` with
   `include_global_state=false`.
4. Start setup jobs and sensors, then run `analysis/verify-stack.py`.

Never restore a volume archive into a running container. Captured malware must
remain encrypted at rest outside the analysis host and must not be unpacked on a
workstation.
