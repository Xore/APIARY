# User Settings and Dashboard Configuration Roadmap

> **Status (2026-07-31):** built. Gate A's dashboard and proxy work is in the
> tree — live introspection in `dashboard/authorization.go`, the
> `strip-auth-identity` middleware on every authenticated router in
> `vps/traefik/dynamic.yml`, and tests that forge `X-Auth-Role` and assert it
> grants nothing. Milestones B through G have shipped: typed stores with
> revisions and audit log, `/api/settings/me`, the settings dialog, admin
> configuration with rollback, retention, and `honeypot_settings_*` metrics.
> What remains is not code — deployment verification of the shared
> introspection token and the 72-hour multi-user soak, tracked in
> [#81](https://github.com/Xore/apiary/issues/81). Earlier revisions of
> this header said "stores and UI remain proposed" long after both existed.
>
> **Identity authority:** [`Xore/auth-backend`](https://github.com/Xore/auth-backend)
>
> **UI reference:** [`Xore/theme`](https://github.com/Xore/theme)
>
> **Gate A review baseline:** `theme@efcc979`, `auth-backend@adaec4e`,
> `APIARY@bca2d3e`

This roadmap adds a full-viewport settings surface to the honeypot dashboard,
using the shared Xore theme and the user system already provided by
`auth-backend`. It also introduces persisted per-user preferences and safe,
administrator-managed page configuration.

## 1. Architectural decision

Do **not** build a second login, password, passkey, TOTP, session, recovery, or
role database in APIARY.

`auth-backend` remains authoritative for:

- identity and immutable user ID;
- username, display name, email, and account status;
- password, passkeys, TOTP, backup codes, and recovery;
- active sessions and trusted devices;
- role and allowed-host authorization;
- login and security audit events.

The dashboard owns:

- a local projection of authenticated users;
- dashboard-only per-user preferences;
- global dashboard presentation and behavior configuration;
- configuration revisions and dashboard audit events.

This boundary avoids contradictory roles, stale passwords, duplicate account
deletion semantics, and a second high-value credential store.

## 2. Identity contract with auth-backend

`X-Auth-Role` is not an adequate authorization credential by itself. It is
plain request metadata and can be forged whenever a caller reaches the
dashboard without traversing the exact Traefik middleware chain. Encrypting
the header would conceal a non-secret value without proving freshness,
session validity, revocation state, or account status.

The authoritative contract is live service-to-service introspection:

```text
browser -> Traefik forward-auth -> dashboard
                                  |
                                  +-> POST auth-backend /_auth/introspect
                                      bearer service token + session cookie
```

The dashboard forwards only the configured auth session cookie, never all
browser cookies. Auth-backend revalidates the PASETO session, session
revocation, idle timeout, disabled state, user generation, current role, and
allowed target host on every introspection request. The endpoint returns:

```json
{
  "subject": "opaque-uuid",
  "username": "analyst",
  "display_name": "Analyst",
  "role": "user",
  "generation": 3
}
```

The service bearer token is a separate random secret, at least 32 bytes, stored
only in protected deployment configuration. It is not a user credential and
is never returned to the browser. Introspection is HTTPS-only outside
loopback tests, bounded to 4 KiB requests and 8 KiB responses, rejects
redirects, and fails closed.

Traefik strips all client-supplied `X-Auth-*` identity headers before
forward-auth. `X-Auth-User` may still be copied as a non-authoritative display
hint for legacy upstreams, but the dashboard ignores all such headers for
identity and authorization. There is no username-hash compatibility identity:
preference and administrator writes require a successful introspection result
with an immutable subject.

The dashboard's `/api/whoami` response becomes:

```json
{
  "subject": "opaque-uuid",
  "username": "analyst",
  "display_name": "Analyst",
  "role": "user",
  "capabilities": ["preferences:write", "evidence:read"],
  "auth_account_url": "https://auth.example.com/auth/app?pane=account"
}
```

Capabilities are computed server-side from the trusted role and dashboard
policy. Client code never derives permission from a badge or hidden control.

## 3. User projection and preferences

Create a small dashboard-owned user record on first authenticated request:

```json
{
  "subject": "opaque-uuid",
  "last_username": "analyst",
  "last_display_name": "Analyst",
  "role_snapshot": "user",
  "first_seen_at": "2026-07-29T18:00:00Z",
  "last_seen_at": "2026-07-29T18:30:00Z",
  "preferences_version": 1,
  "preferences": {}
}
```

The projection is not authorization state. Privileged requests use a current
auth-backend introspection result; the stored role is diagnostic only.

### Useful per-user preferences

| Category | Settings | Initial defaults |
|---|---|---|
| Appearance | theme (`system`, `dark`, `light`), density, reduced motion | system, comfortable, system preference |
| Navigation | collapsed sidebar, default landing page, remember last investigation filters | expanded, overview, off |
| Tables | rows per page, wrap long values, visible optional columns | 50, off, product defaults |
| Time | timezone (`browser`, `UTC`, IANA zone), 12/24-hour clock, relative/absolute timestamps | browser, 24-hour, relative |
| Live data | auto-refresh, refresh interval from bounded choices, live-update toasts | on, 30 seconds, on |
| Map | preferred basemap from admin allowlist, clustering, animation | system default, on, on |
| Accessibility | high contrast, reduced motion override, larger monospace evidence text | off, system, off |
| Notifications | in-app severity floor, sound, desktop notifications | high, off, off |
| Investigation | default event window, preserve filters, open details in new tab | 24 hours, off, off |

Browser-only preferences may remain in `localStorage` before the server store
exists. After migration, server values win when signed in, and a one-time
client migration uploads recognized values such as `hp-theme` and sidebar
state. Never store auth tokens or sensitive evidence in preferences.

## 4. Global configuration model

Global settings are typed, schema-versioned, and divided into independently
authorized namespaces. They are not arbitrary key/value HTML.

### Presentation and editable text

Useful administrator-adjustable text:

- application name and short product label;
- dashboard title and subtitle;
- organization/site display name;
- welcome/overview introduction;
- sidebar section labels;
- empty-state titles and help text;
- investigation help/contact link and label;
- maintenance or incident banner text, severity, start, and expiry;
- footer text;
- AI-generated analysis disclaimer;
- evidence-handling/privacy notice;
- source-health explanatory text.

Text is stored as plain text, length-bounded, and escaped on output. Markdown
and raw HTML are out of scope for v1. Links are separate URL fields validated
against an `https` allowlist.

### Safe runtime behavior

- default landing page and time window;
- allowed rows-per-page values and maximum export rows;
- bounded refresh interval choices;
- source stale/warning thresholds;
- default map provider chosen from a deployment allowlist;
- alert display severity floor and acknowledgement labels;
- whether experimental ML/LLM panels are visible;
- dashboard maintenance/read-only mode;
- enabled navigation destinations and external-tool links.

### Keep outside the UI

The settings API must not edit:

- passwords, cookie/PASETO keys, SMTP or webhook credentials;
- Elasticsearch credentials or endpoints;
- Docker socket, bind addresses, volume paths, or network configuration;
- arbitrary commands, Compose YAML, environment variables, templates, CSS,
  JavaScript, HTML, or filesystem paths;
- sensor behavior, firewall rules, malware execution controls, or deployment
  secrets.

Those stay in protected environment/configuration files and deployment review.

## 5. Persistence and concurrency

Use two atomic JSON stores on the existing `/state` volume for the first
release:

```text
/state/dashboard-users.json
/state/dashboard-config.json
/state/dashboard-audit.jsonl
```

This matches the current single-instance deployment and existing atomic
write/rename patterns. Each store has:

- a schema version;
- strict decode with unknown-field rejection;
- size and record-count limits;
- file mode `0600` and directory mode `0750`;
- write-to-temporary-file, `fsync`, atomic rename, and a retained backup;
- an in-process read/write lock;
- monotonically increasing revision and ETag;
- optimistic concurrency through `If-Match`;
- startup validation and last-known-good recovery.

If dashboard replicas are introduced, migrate these stores to SQLite or a
transactional service before scaling. Do not pretend a shared JSON volume is a
multi-writer database.

Configuration layers resolve in this order:

```text
compiled safe defaults
  < deployment environment overrides
  < persisted administrator configuration
  < per-user preferences
  < request query parameters for the current view only
```

Environment values marked immutable or secret cannot be overridden by the UI.
The effective-config API reports each value's source without returning secrets.

## 6. API and authorization

### Self-service API

```text
GET   /api/settings/me
PATCH /api/settings/me/preferences
POST  /api/settings/me/preferences/reset
```

Users may update only their own allowlisted preference fields. PATCH uses a
typed request, byte limit, `Content-Type: application/json`, CSRF protection,
ETag/`If-Match`, and per-subject rate limiting.

Account-security actions are links into auth-backend:

- profile and recovery email;
- password and passkeys;
- TOTP and backup codes;
- sessions/trusted devices;
- log out everywhere.

Do not proxy credentials through the dashboard.

### Administrator API

```text
GET   /api/settings/config
PATCH /api/settings/config
POST  /api/settings/config/validate
POST  /api/settings/config/rollback
GET   /api/settings/config/history
GET   /api/settings/users
GET   /api/settings/audit
```

All administrator mutations require the same trusted admin check as other
evidence-changing operations, plus CSRF protection. Validation returns a
preview and impact classification before save:

- `live`: effective immediately;
- `new-request`: visible on subsequent requests;
- `restart-required`: informational in v1, never triggers a restart;
- `rejected`: secret, immutable, invalid, or unsafe.

Every mutation records actor subject/username, request ID, time, client IP
after trusted-proxy handling, changed field names, old/new value hashes, result,
and configuration revision. Sensitive values are never logged.

## 7. Settings page design

Implement `/settings` as the Xore theme's permanent full-viewport settings
dialog. It owns scrolling and cannot close on Escape. Nested confirmations are
descendants of the permanent dialog, following the theme modal contract.

Suggested panes:

### Personal

1. **Account** — current identity, role, capabilities, and links to
   auth-backend security pages.
2. **Appearance** — theme, density, motion, contrast, evidence font size.
3. **Navigation and tables** — landing page, sidebar, page size, columns.
4. **Time and live data** — timezone, clock, refresh, notifications.
5. **Map and investigation** — basemap, clustering, default windows/filters.

### Administration

6. **Branding and text** — product labels, help, notices, footer.
7. **Dashboard behavior** — safe bounded defaults and feature visibility.
8. **Users** — read-only projected dashboard activity with links to the
   authoritative auth-backend admin user pane.
9. **Configuration history** — revision diff, actor, validation, rollback.
10. **Audit log** — preference/config changes with filtering.

Search filters panes and fields but does not search secret values. Each pane has
dirty-state tracking, Reset, Save, visible success/error status, and protection
against accidental navigation with unsaved changes.

## 8. Implementation milestones

### Gate A — Cross-repository contracts

1. Pin the reviewed `theme` and `auth-backend` commits.
2. Add immutable subjects and the authenticated introspection endpoint to
   auth-backend.
3. Configure Traefik spoofed-header stripping and remove authoritative role
   propagation.
4. Make dashboard administrator checks and `/api/whoami` use live
   introspection.
5. Add integration tests proving direct client headers cannot impersonate
   another subject or role and auth outages fail closed.

**Exit:** the dashboard receives a stable subject and current role from
auth-backend in production and tests; unsigned identity headers grant no
capabilities.

#### Gate A rollout and rollback

Roll out in dependency order:

1. Generate one `openssl rand -hex 32` value and install it as
   `AUTH_INTROSPECTION_TOKEN` in auth-backend and the dashboard. Restrict both
   `.env` files to mode `0600`.
2. Deploy auth-backend first and verify that unauthenticated, wrong-token, and
   invalid-session introspection calls are rejected.
3. Deploy the Traefik header-strip middleware and dashboard together.
4. Verify `/api/whoami`, one user denial, one administrator action, direct
   forged `X-Auth-Role`, auth-backend outage behavior, and role/disable
   changes.

For rollback, restore the previous dashboard and Traefik configuration first.
The unused introspection endpoint can remain enabled during rollback; remove or
rotate its token only after no deployed consumer uses it. Never deploy the new
dashboard before auth-backend and the shared token are ready, because
privileged actions intentionally fail closed.

### Milestone B — Settings domain and stores

1. Define typed preference/config schemas, defaults, validation, and migration.
2. Implement atomic stores, revisions, ETags, backup recovery, and audit log.
3. Add identity middleware and server-side capabilities.
4. Add pure unit tests and corruption/concurrency fixtures.

**Exit:** restart persistence, corrupt-file recovery, conflicting writes,
unknown fields, oversized input, and migrations pass.

### Milestone C — Self-service preferences

1. Add `/api/settings/me` endpoints.
2. Wire theme, sidebar, density, time display, tables, and refresh behavior to
   effective preferences.
3. Migrate existing recognized localStorage preferences once.
4. Add reset-to-default and multi-browser consistency.

**Exit:** two users cannot read or modify each other's preferences; logged-out
or missing-subject writes fail closed; existing theme behavior remains stable.

### Milestone D — Settings UI

1. Add the permanent `/settings` dialog and personal panes.
2. Add sidebar profile navigation to Settings.
3. Implement search, responsive layout, focus management, dirty-state
   protection, and nested confirmation behavior.
4. Test system/dark/light, reduced motion, keyboard-only, screen-reader labels,
   desktop, tablet, and mobile.

**Exit:** all modal invariants from `Xore/theme` pass automated browser tests.

### Milestone E — Administrator configuration

1. Add typed admin APIs and preview/validation.
2. Add branding/text and safe behavior panes.
3. Replace selected hard-coded page copy with effective configuration.
4. Add revision history, audit view, and rollback.

**Exit:** text is escaped, links are validated, stale ETags conflict safely,
rollback restores a prior revision, and no setting can introduce executable
content or reveal/edit secrets.

### Milestone F — Auth account integration

1. Add stable deep links from dashboard panes to auth-backend account/admin
   panes.
2. Extend the authenticated introspection response only when additional
   read-only profile metadata is required.
3. Keep credential mutation entirely within auth-backend's origin and CSRF
   boundary.
4. Define account deletion behavior for orphaned dashboard preferences.

**Exit:** password/passkey/session actions never traverse dashboard APIs; a
disabled/deleted auth account immediately loses dashboard access; orphan
preferences expire through retention.

### Milestone G — Operations and rollout

1. Add configuration health, revision, save failures, and audit metrics.
2. Back up settings files with the existing state backup process.
3. Run migration in observe-only mode, then enable per-user writes, then admin
   configuration.
4. Document restore, rollback, and break-glass disabling.

**Exit:** a 72-hour multi-user soak passes with no identity crossover, lost
writes, XSS, privilege escalation, or settings-induced dashboard outage.

**Status: shipped.** Metrics for store health, revision, save failures,
projections, audit volume, and retention removals are exposed on `/metrics`
(`honeypot_settings_*`); `scripts/backup-state.sh` archives the
`dashboard-state` volume (which holds every settings file) with pruning; and
`docs/settings-operations.md` documents restore, rollback, break-glass
disabling, and the staged rollout sequence. The 72-hour soak is an
operational follow-up run on the deployed stack, not a code artifact.

## 9. Test matrix

- forged identity/role headers at the public proxy;
- absent subject, renamed username, changed role, disabled/deleted user;
- cross-user GET/PATCH attempts;
- CSRF, wrong content type, oversized body, unknown fields, invalid enum/URL;
- concurrent saves with the same and different ETags;
- crash during write and corrupt primary with valid backup;
- stored/reflected XSS strings in every editable text field;
- preference migration across two browser profiles;
- admin vs user pane/API visibility and direct endpoint access;
- nested dialog focus, Escape, Enter, double-submit, cancel, and mobile layout;
- configuration rollback and audit completeness;
- auth-backend outage: existing protected requests fail closed;
- settings-store outage: dashboard serves safe defaults and becomes read-only.

## 10. Deliberate exclusions for v1

- locally managed dashboard passwords or sessions;
- arbitrary custom CSS/HTML/JavaScript;
- user-created roles or fine-grained policy editor;
- secret/integration credential editing;
- live Docker/Compose/environment mutation;
- arbitrary map tile URLs;
- automatic service restarts after saving;
- multi-replica JSON persistence.

These exclusions keep the first release useful without turning a presentation
settings page into a remote administration or code-execution surface.
## 11. AI agent implementation prompt

Copy the prompt below into an AI coding agent with access to both
`Xore/apiary` and `Xore/auth-backend`:

```text
Implement the user settings and dashboard configuration system described in
docs/settings-user-configuration-roadmap.md.

Repositories and authorities:
- Xore/auth-backend is the sole authority for identity, passwords, passkeys,
  TOTP, recovery, sessions, trusted devices, roles, and account administration.
- Xore/apiary owns only the dashboard user projection, per-user
  dashboard preferences, global dashboard configuration, revision history,
  and dashboard audit events.
- Xore/theme is the UI and modal-behavior reference. Follow its permanent
  settings dialog, nested confirmation, accessibility, and responsive rules.

Before editing:
1. Read docs/settings-user-configuration-roadmap.md completely.
2. Inspect the current auth-backend forward-auth header contract, Traefik
   forwarding configuration, dashboard authorization, /api/whoami,
   persistence patterns, page rendering, hp-app.js, and existing tests.
3. Check git status in every repository. Preserve unrelated user changes.
4. Record the exact auth-backend and theme commits used as references.
5. Produce a short implementation plan mapped to Gates/Milestones A-G. Do not
   collapse the work into one unreviewable change.

Required architecture:
- Do not create dashboard passwords, login cookies, sessions, roles, passkeys,
  TOTP, recovery, or another credential database.
- Add a stable opaque subject and authenticated session-introspection contract
  in auth-backend. Strip spoofed client identity headers at the trust boundary.
- Authorize privileged requests from current introspection results, never from
  caller-supplied headers. Stored role snapshots are diagnostic only.
- Refuse preference writes without a trusted immutable subject.
- Keep credential and account-security mutations on the auth-backend origin;
  the dashboard exposes links, not credential-proxy APIs.
- Store only typed, allowlisted preferences and configuration. Never accept
  arbitrary HTML, Markdown, CSS, JavaScript, commands, templates, environment
  variables, Compose content, filesystem paths, secrets, or arbitrary URLs.
- Escape every configurable text value on render. Validate link fields against
  the documented HTTPS allowlist.
- Use CSRF protection, request-size limits, JSON content-type enforcement,
  ETags/If-Match, optimistic concurrency, per-actor rate limits, and audit
  records for mutations.
- Use atomic state persistence with schema versions, migrations, fsync,
  rename, backup recovery, locks, permissions, and last-known-good fallback.
- The settings store failing must leave the dashboard on safe defaults and
  read-only; it must not take down investigations.

Delivery order:
A. Implement and test the immutable identity/introspection trust contract
   across auth-backend, Traefik, and dashboard.
B. Implement typed settings domains, identity middleware, atomic stores,
   revisions, validation, migration, ETags, and audit logging.
C. Implement self-service preference APIs and migrate recognized localStorage
   values such as hp-theme once.
D. Build /settings using the Xore/theme permanent dialog, personal panes,
   search, responsive behavior, focus rules, dirty-state protection, and
   nested confirmations.
E. Add administrator configuration APIs and panes for bounded branding/text,
   safe behavior defaults, configuration history, audit, and rollback.
F. Add auth-backend account/admin deep links without moving credentials across
   origins.
G. Add operational metrics, backup/restore documentation, feature flags,
   staged rollout, and rollback.

Start with Gate A and Milestone B. Stop at a reviewable boundary if work spans
multiple repositories or pull requests. Do not enable administrator
configuration writes until identity spoofing and cross-user isolation tests
pass.

Minimum tests:
- forged, absent, renamed, disabled, and deleted identities;
- user/admin authorization and direct endpoint access;
- cross-user preference reads and writes;
- CSRF, wrong content type, unknown fields, oversized bodies, invalid enums
  and URLs;
- concurrent writes with stale and current ETags;
- crash/corruption recovery and migrations;
- stored/reflected XSS through every configurable field;
- localStorage migration and multi-browser preference consistency;
- keyboard, focus, Escape, Enter, cancel, double-submit, screen-reader labels,
  reduced motion, dark/light/system, desktop, tablet, and mobile;
- configuration revision, audit completeness, rollback, and safe-default
  behavior during store failure;
- auth-backend outage remains fail-closed.

Verification:
- run repository unit, integration, browser/e2e, formatting, static analysis,
  public-repository safety, and Compose validation checks relevant to changed
  files;
- inspect the final diff for real IPs, domains, credentials, captured data, and
  unrelated changes;
- report changed files, schema/API decisions, migration/rollback behavior,
  tests run, results, and any remaining deployment steps.

Do not deploy, merge, change production auth configuration, create users, or
rotate credentials unless separately and explicitly authorized.
```

## 12. Addendum — honeypot system configuration tiers (2026-07-29)

This addendum extends the global configuration model (§4) and the
administrator panes (§7) with operational settings for the honeypot stack
itself. It changes no authority boundaries: everything below lives in the
dashboard-owned configuration store, never in auth-backend's Administration →
Configuration pane and never in deployment secrets.

### Placement decision

Honeypot system settings do **not** belong in the auth-backend settings app
that the dashboard's settings popup embeds. Putting them there would couple
the repositories, mix operational state into the credential store, and weaken
the rule that credential mutation never crosses origins. The settings surface
presented to the operator is dashboard-owned; its account pane deep-links or
embeds auth-backend, and the panes below carry honeypot configuration.

### Tier 1 — live-safe, dashboard-consumed (impact class `live`/`new-request`)

Apply immediately; no service restart:

- alert display severity floor and acknowledgement labels;
- default event time window, allowed rows-per-page values, maximum export rows;
- bounded refresh interval choices and live-toast toggles;
- map basemap chosen from a deployment allowlist (never an arbitrary URL);
- feature visibility (experimental ML/LLM panels), maintenance banner,
  dashboard read-only mode.

These are the fields already enumerated in §4 and are delivered through
Milestones B–E unchanged.

### Tier 2 — staged operational thresholds (impact class `restart-required`)

Currently environment-only and consumed at container start:

- `HONEYPOT_ALERT_COOLDOWN` and `HONEYPOT_ALERT_CAMPAIGN_SCORE`;
- `SANDBOX_ALERT_RISK_SCORE`;
- `YARA_SCAN_INTERVAL` and `YARA_MAX_BYTES`;
- `PAYLOAD_DEDUPE_INTERVAL`.

v1 model: the UI accepts typed, range-bounded values, shows the validation
preview with impact `restart-required`, and persists them into a **staging
area** of the configuration store. Saving never restarts anything. The pane
renders a staged-vs-active diff plus the exact apply command for the operator
(for example `docker compose -f compose.yml up -d dashboard yara-scanner`).
A later iteration may teach individual services to read a shared read-only
`/state/honeypot-config.json` (mtime-watched) instead of their environment,
with the environment kept as an immutable override — converting a Tier 2
setting into Tier 1 one service at a time. Automatic restarts after saving
remain excluded (§10).

### Tier 3 — never editable through the UI

- webhook URLs/tokens, `AUTH_INTROSPECTION_TOKEN`, Arkime/Kibana secrets;
- `HP_BIND`, Docker socket, network, Compose, environment, or filesystem
  mutation;
- arbitrary map tile URLs, sensor behavior, anything influencing malware
  execution.

The settings API enforces this with a server-side denylist and a regression
test proving no future schema field can mark a Tier 3 value as editable.

### Schema and API additions

- New `honeypot` configuration namespace beside `presentation`/`behavior`.
  Every field declares: type and bounds, impact class, target service, and
  whether a deployment environment value pins it (env-pinned fields are
  reported but rejected on write).
- `GET /api/settings/config` reports each value's **source** (compiled
  default / environment / persisted / staged), so the pane can display
  `active: 6h (environment), staged: 2h — applies on restart` instead of a
  silent lie. Staged values are covered by the same revision, ETag, audit,
  and rollback machinery as every other setting.

### UI pane

Add one administrator pane to §7:

11. **Honeypot operations** — Tier 1 fields save live; Tier 2 fields save
    into the staging area with a staged-vs-active diff view and a copyable
    apply command; rollback restores a prior revision. The pane is hidden for
    non-administrators via server-side capabilities, never by hiding client
    controls alone.

### Delivery sequence

1. Milestones B–E with Tier 1 fields only.
2. Read-only effective-config viewer exposing every current environment knob
   and its source (zero mutation risk, immediately useful).
3. Tier 2 staging with manual, operator-run apply.
4. Optional per-service config-file consumers enabling hot reload.

### Additional tests (extends §9)

- staged-vs-active consistency across dashboard restarts;
- env-pinned fields rejected on write but still reported with source
  `environment`;
- Tier 3 denylist regression: schema fields cannot mark excluded values
  editable;
- staged values participate in revision history, ETag conflicts, and
  rollback;
- store outage still yields safe defaults and read-only behavior for the new
  namespace.
