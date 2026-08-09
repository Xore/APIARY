# Settings Operations Runbook

Operational companion to `settings-user-configuration-roadmap.md` (Milestone
G). Covers the settings stores owned by the dashboard:

| Store | Location | Contents |
| --- | --- | --- |
| config | Elasticsearch index `dashboard-config-v1`, doc id `config` | administrator dashboard configuration |
| users | Elasticsearch index `dashboard-users-v1`, doc id `users` | user projections + per-user preferences |
| audit | local file `dashboard-audit.jsonl` (`dashboard-state` volume) | settings audit log (rotates at its size cap) |
| history | local file `dashboard-config-history.jsonl` (+ `.1` rotation) | configuration revision history for rollback |

**#787:** config/users used to be local files on the shared `dashboard-state`
volume. With two dashboard replicas, each replica cached its file in memory
once at startup and never reloaded it — a setting changed via one replica's
admin UI was invisible on the other until it was restarted. Moved to
Elasticsearch, the one backend both replicas already treat as shared source
of truth (`dashboard/settings_store_es.go`); each replica now polls its
document every few seconds (`settingsPollInterval`, currently 3s), so a
change made via one replica is visible on the other within that window, no
restart needed.

audit/history were never affected by that bug (both do a fresh disk read on
every request against the same shared volume, so cross-replica visibility
already worked) and stay local files. Their paths are overridable through
`DASHBOARD_AUDIT_FILE` and `DASHBOARD_CONFIG_HISTORY_FILE`; the defaults
above apply to the compose deployment. config/users have no path override
any more — they always live in Elasticsearch at the index/doc-id pair above.

## Metrics

`/metrics` exposes the settings subsystem alongside the existing honeypot
gauges:

- `honeypot_settings_config_revision` — current configuration revision;
  increments on every accepted admin write or rollback.
- `honeypot_settings_store_readonly{store="config|users"}` — 1 when a store's
  most recent attempt to reach Elasticsearch failed. **Self-heals** on the
  next successful poll; a sustained 1 means Elasticsearch is unreachable, not
  that a file needs fixing. **Alert on a sustained 1**, not a brief blip.
- `honeypot_settings_store_degraded{store=...}` — 1 when the store has never
  yet loaded real state from Elasticsearch this process lifetime and is
  serving compiled defaults. **Self-heals** the first time a poll succeeds
  (including a legitimate "no document yet" result on a genuinely fresh
  install). **Alert on a sustained 1.**
- `honeypot_settings_store_recovered{store=...}` — always 0 since #787;
  Elasticsearch has no local backup-generation concept to recover from. Kept
  for metric-name stability, not meaningful any more.
- `honeypot_settings_projected_users` — users with stored preferences.
- `honeypot_settings_audit_events` — audit events in the current log
  generation (capped at 500 per scrape read).
- `honeypot_settings_save_failures_total{kind="preferences|config"}` —
  rejected writes. A sustained climb means clients are sending invalid or
  stale payloads, or a store went read-only.
- `honeypot_settings_retention_removed_total` — orphaned projections removed
  by the retention sweep.

## Backup

Config and users (Elasticsearch-backed since #787) are covered by whatever
snapshot/backup policy this cluster's other Elasticsearch-owned dashboard
data already has (`analysis/elasticsearch-setup.sh`) — not
`scripts/backup-state.sh`, which now only covers what's still on the
`dashboard-state` volume.

`scripts/backup-state.sh` archives the whole `dashboard-state` volume —
audit/history plus the sandbox payload scripts that share it:

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

**Audit/history (local files):**

1. Stop the dashboard: `docker compose stop dashboard`.
2. Untar the chosen archive into the volume:
   `docker run --rm -v dashboard-state:/state -v <backup-dir>:/backup alpine:3 tar xzf /backup/dashboard-state-<ts>.tar.gz -C /state`
3. Start the dashboard: `docker compose start dashboard`.

**Config/users (Elasticsearch):** restore via whatever mechanism recovers the
`dashboard-config-v1`/`dashboard-users-v1` indices (snapshot repository
restore, or `keycloak/restore.sh`-style tooling if one exists for these
indices) — there is no per-dashboard-replica file to move.

Every store fails safe on a load problem: config/users serve compiled
defaults **read-only** when Elasticsearch is unreachable or the document is
corrupt (the `degraded`/`readonly` metrics flip to 1, self-healing once
Elasticsearch is reachable again); audit/history tolerate a corrupt line by
skipping it. A partial or wrong restore therefore degrades safely instead of
crashing the dashboard.

## Rollback (no restore needed)

For configuration mistakes rather than data loss, use the built-in history:
the settings modal's history pane lists retained revisions, and
`POST /api/settings/config/rollback` restores one. Rollback entries are
themselves audited and become a new revision, so rollback-of-rollback works.

## Break-glass disabling

If the settings subsystem itself misbehaves:

- **Configuration:** the store already fails open to compiled defaults,
  read-only, whenever Elasticsearch is unreachable — no manual action needed
  to force this state; if you need a deliberate outage, block network access
  from the dashboard to Elasticsearch instead of touching a file.
- **Per-user preferences:** same posture as configuration above.
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
