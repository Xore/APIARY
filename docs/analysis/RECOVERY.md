# Backup and recovery

For a *deliberate* full reset on the same hosts (not disaster recovery), see
[`docs/STACK-REBUILD.md`](../STACK-REBUILD.md) instead — this doc is
about restoring a backup archive onto a replacement host after data loss.

Two backups cover the homeserver stack, with the same exclusions. **Scope
differs**, which matters here because the two produce different filenames:

- [`scripts/backup-essentials.sh`](../../scripts/backup-essentials.sh) runs on
  the workstation and fans an encrypted archive out to three locations. This
  is the one that survives the homeserver dying, and the broader of the two —
  it additionally carries the VPS config, WireGuard, Technitium, the
  installer's answers file and the repo's runbooks. Full restore procedure:
  [`docs/BACKUP-ESSENTIALS.md`](../BACKUP-ESSENTIALS.md).
- `sudo analysis/backup-honeypot.sh` runs on the homeserver itself, into a
  timestamped mode-0700 directory beneath `/opt/backups/honeypot`. Faster to
  reach, useless if the box is gone. Validate with
  `analysis/verify-backup.sh <directory>`.

Both capture configuration, secrets, the Keycloak identity database and small
config-bearing volumes. Neither captures Elasticsearch data, captured payloads,
PCAP or sandbox images — a restored stack comes back configured and
authenticated with an empty event history. See
[`docs/BACKUP-ESSENTIALS.md`](../BACKUP-ESSENTIALS.md) for the full in/out list
and the sizes behind it.

Recovery is intentionally not automatic because overwriting live volumes is
destructive. On a replacement host:

1. Unpack the archive's `env/` and `secrets/` trees back under
   `/var/dockge/stacks/<stack>/` and inspect `.env` permissions and values.
   Note the filename first: `SHA256SUMS` and `stack-config-state.tar.gz` are
   the **on-host** copy's only — `analysis/backup-honeypot.sh` writes them and
   `analysis/verify-backup.sh` checks them. A `scripts/backup-essentials.sh`
   archive contains neither; verify that one with
   `sha256sum -c apiary-essentials-<stamp>.tar.gz.gpg.sha256`.
2. Restore the Keycloak database from `keycloak.sql.gz` with `hp-keycloak-postgres`
   up and `hp-keycloak` still stopped — this is what preserves the OIDC client
   secrets that the VPS's own `secrets/oidc/` copies have to match.
3. Keep all services stopped, then `docker volume create <name>` for each
   `homeserver/volumes/<name>.tar.gz` and restore each archive into it through a
   temporary networkless BusyBox container. Use the **full real volume name** —
   four of the five carry their Arcane project prefix and live in four
   different stacks, so one `docker compose -f compose.yml create` cannot cover
   them.
4. Start stacks in [`docs/STACK-REBUILD.md`](../STACK-REBUILD.md)'s order —
   `honeypot-elk` healthy before `honeypot-init`, everything else after — then
   run `analysis/verify-stack.py` — with
   `DASHBOARD_SERVICE_TOKEN` from the restored stack's `.env` exported; it
   reads source-health through dashboard-next's `/bff` passthrough and exits
   nonzero on any failure.

Never restore a volume archive into a running container. Captured malware must
remain encrypted at rest outside the analysis host and must not be unpacked on a
workstation.
