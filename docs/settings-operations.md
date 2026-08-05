# Settings Operations Runbook

Operational companion to `settings-user-configuration-roadmap.md` (Milestone
G). Covers the settings stores owned by the dashboard:

| File (inside the `dashboard-state` volume) | Contents |
| --- | --- |
| `dashboard-config.json` | administrator dashboard configuration |
| `dashboard-users.json` | user projections + per-user preferences |
| `dashboard-audit.jsonl` | settings audit log (rotates at its size cap) |
| `dashboard-config-history.jsonl` | configuration revision history for rollback |

Paths are overridable through `DASHBOARD_CONFIG_FILE`,
`DASHBOARD_USERS_FILE`, `DASHBOARD_AUDIT_FILE`, and
`DASHBOARD_CONFIG_HISTORY_FILE`; the defaults above apply to the compose
deployment.

## Metrics

`/metrics` exposes the settings subsystem alongside the existing honeypot
gauges:

- `honeypot_settings_config_revision` — current configuration revision;
  increments on every accepted admin write or rollback.
- `honeypot_settings_store_readonly{store="config|users"}` — 1 when a store
  refuses writes (persistence failure, degraded file). **Alert on 1.**
- `honeypot_settings_store_degraded{store=...}` — 1 when the store file was
  unreadable at startup and compiled defaults are being served. **Alert on
  1.**
- `honeypot_settings_store_recovered{store=...}` — 1 when startup recovered
  from the `.bak` generation; investigate why the primary was lost.
- `honeypot_settings_projected_users` — users with stored preferences.
- `honeypot_settings_audit_events` — audit events in the current log
  generation (capped at 500 per scrape read).
- `honeypot_settings_save_failures_total{kind="preferences|config"}` —
  rejected writes. A sustained climb means clients are sending invalid or
  stale payloads, or a store went read-only.
- `honeypot_settings_retention_removed_total` — orphaned projections removed
  by the retention sweep.

## Backup

`scripts/backup-state.sh` archives the whole `dashboard-state` volume —
settings files plus the sandbox payload scripts that share it:

```sh
scripts/backup-state.sh                       # default volume + backup dir
BACKUP_DIR=/mnt/backups KEEP=30 scripts/backup-state.sh
scripts/backup-state.sh <other-volume-name>   # non-default project name
```

Archives land as `dashboard-state-<utc-timestamp>.tar.gz` next to the other
host-level state backups; the newest 14 (configurable via `KEEP`) are
retained. Wire it into the same schedule as the existing host state copies
(e.g. a nightly cron entry).

## Restore

1. Stop the dashboard: `docker compose stop dashboard`.
2. Untar the chosen archive into the volume:
   `docker run --rm -v dashboard-state:/state -v <backup-dir>:/backup alpine:3 tar xzf /backup/dashboard-state-<ts>.tar.gz -C /state`
3. Start the dashboard: `docker compose start dashboard`.

Every settings store validates its file on load: a well-formed file loads
normally; a corrupt primary falls back to the `.bak` generation; if both are
unusable the store serves compiled defaults **read-only** and the
`degraded`/`readonly` metrics flip to 1. A partial or wrong restore therefore
degrades safely instead of crashing the dashboard.

## Rollback (no restore needed)

For configuration mistakes rather than file loss, use the built-in history:
the settings modal's history pane lists retained revisions, and
`POST /api/settings/config/rollback` restores one. Rollback entries are
themselves audited and become a new revision, so rollback-of-rollback works.

## Break-glass disabling

If the settings subsystem itself misbehaves:

- **Configuration:** stop the dashboard, move `dashboard-config.json*` out of
  the volume, start the dashboard. It serves compiled defaults read-only
  (`degraded` metric = 1) until a valid file returns.
- **Per-user preferences:** same procedure with `dashboard-users.json*`.
- **Admin configuration API:** revoke the admin role in auth-backend; the
  admin panes and endpoints are gated server-side on live introspection, so
  access ends on the next request.
- **Orphan retention:** `DASHBOARD_USER_RETENTION_DAYS` (default 90) controls
  the sweep; it cannot fully disable live-introspection revocation, which is
  always immediate.

## Staged rollout sequence

1. **Observe-only.** Deploy the build. Stores start, metrics appear, the
   settings UI reads. No admin writes yet; per-user preference writes are the
   only mutations and are strictly isolated per subject.
2. **Per-user writes.** Let users save preferences; watch
   `save_failures_total{kind="preferences"}` and the store health gauges.
3. **Admin configuration.** Grant admin role to operators and exercise the
   configuration pane; watch `config_revision`,
   `save_failures_total{kind="config"}`, and the audit pane.
4. **Soak.** Run 72 hours multi-user (roadmap §8 exit criteria) before
   calling the migration complete.
