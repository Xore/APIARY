# Operating the stack

[← back to README](../README.md)

Personas, the seeded cowrie filesystem, GeoIP enrichment, and how to actually
read the data once it's flowing.

## Persona inventory

Every sensor belongs to a stable fictional organization/site/asset identity in
[personas/personas.json](../personas/personas.json). Native sensors include these
fields in JSON; Filebeat enriches upstream logs that cannot. The dashboard makes
persona, site, and asset labels clickable so investigations can span protocols
without confusing defender-side identity with the attacker's ASN organization.
See [personas/README.md](personas/README.md) for the complete matrix and validator.

## Seeded filesystem (cowrie)

The fake shell is a believable in-use NexusAI GPU inference node, not an empty
box — realistic `/etc/passwd`, inference services, a credential-laden `.env`,
`.bash_history`, nginx/cron configs and logs (all fictional). Baked at build time; details in
[cowrie/README-fs.md](../arcane/home/honeypot-cowrie/cowrie/README-fs.md).

## GeoIP

The custom dashboard, Arkime, and Elasticsearch all share the same local
MaxMind GeoLite2 MMDB files under `analysis/geoip/`, kept current by the
`hp-geoipupdate` container (`docker compose -f compose.yml --profile
geoip-update up -d geoipupdate`, needs `MAXMIND_ACCOUNT_ID` /
`MAXMIND_LICENSE_KEY` in the honeypot-init stack's `.env`, managed by
Arcane). Dashboard lookups happen after
portbridge real-IP correlation, support IPv4/IPv6, and add country, city,
coordinates, accuracy radius, ASN, organization, and cloud/hosting/scanner
classification without sending attacker IPs to an external lookup API.

Two independent geo integrations, same source files:

- **Arkime** reads `analysis/geoip/GeoLite2-{Country,ASN}.mmdb`, mounted
  read-only into both capture and viewer at `/opt/arkime/geo` and configured
  via `geoLite2Country`/`geoLite2ASN` in
  [arkime/config.ini](../arcane/home/honeypot-elk/arkime/config.ini). Sessions
  get country + ASN. (#2713: this used to point at a separate,
  never-automated `arkime/geo/` directory populated by hand from db-ip.com —
  retired in favor of the same files everything else already uses.)
- **Elasticsearch** enriches every `suricata-*` and `honeypot-v2-*` event (and
  the portbridge, zeek, extracted-files, huginn and traefik families) through
  the `geoip-honeypot` ingest pipeline (set as `index.default_pipeline` on 8 of
  the init stack's 33 index templates), writing ECS `source.geo` / `source.as` / `destination.geo`
  with city-level lat/lon — this is what powers Kibana maps
  (`source.geo.location` is mapped as `geo_point`), from
  `GeoLite2-City.mmdb` mounted at
  `analysis/geoip/ → /usr/share/elasticsearch/config/ingest-geoip`, with
  `ingest.geoip.downloader.enabled=false` (ES's own auto-downloader needs
  egress the home server doesn't have).

The `.mmdb` files themselves are not in git; `hp-geoipupdate` refreshes them
on `GEOIPUPDATE_FREQUENCY` (hours) automatically once credentials are set —
no manual download/copy step.

> **Elasticsearch field limits:** Suricata's EVE output creates so many
> dynamic fields that the default 1000-field index cap breaks ingest — every
> event is 400-rejected and filebeat silently drops it (this bit us on
> 2026-07-19: Kibana "froze" while eve.json was fine). The `suricata-*`
> template raises the limit to 5000; stats live in their own event-type index.
> Honeypot source objects use a bounded `flattened` mapping.

## Analyse the data

The one-shot `honeypot-kibana-setup` job installs normalized honeypot,
Suricata, and dead-letter data views plus the **XORE Honeypot — enriched
investigation** dashboard. Panels cover recent attacks, OT personas,
commands/credentials, payloads, enriched IDS alerts, and ingest failures.

- **Dashboard** (built in) → `https://honeypot.<domain>`, authenticated via
  its own native OIDC session against Keycloak directly (no gateway hop,
  unlike the investigation UIs below -- #1026). Live
  KPIs, feed-freshness states, per-sensor/protocol counts, top IPs/creds/commands,
  payload downloads, attack chains, and 7-day `/24`/`/64` campaign correlation
  scored across sensors, credentials, ports, IDS alerts, and payload hashes.
  The interface is organized as an operations console rather than a shortcut
  collection: task-based navigation separates monitoring, investigation, and the
  Elasticsearch archive. Four top-level overview tabs group live operations,
  the threat landscape, attacker behavior, and evidence/campaigns so only one
  workflow is visible at a time; the selected tab survives live refreshes.
  Every KPI and ranked value pivots directly into the relevant
  investigation, while explanatory labels make states and metrics usable
  without a separate legend. The responsive navigation becomes an accessible
  menu on narrow displays, and light, dark, and automatic themes remain
  available.
  The frontend follows the shared [**Xore/theme**](https://github.com/Xore/theme)
  design system (migration guide:
  [MIGRATE-HONEYPOT-STACK.md](https://github.com/Xore/theme/blob/main/docs/MIGRATE-HONEYPOT-STACK.md)):
  a semantic, server-rendered application shell (toolbar, sidebar, main
  canvas, command bar) styled only by the byte-identical vendored `theme.css`.
  APIARY does not carry a custom dashboard stylesheet; new selectors are
  implemented in `Xore/theme` and re-vendored. The theme and Leaflet are
  served from the dashboard binary rather than a JavaScript CDN.
  The fixed desktop sidebar becomes a compact rail and then an off-canvas
  navigation panel on narrow screens, while the 32px application toolbar keeps
  activity, health, and theme controls (dark, light, system) available across
  every investigation page.
  The command bar also routes IP addresses, payload hashes, session IDs, ASNs,
  HTTP paths, and free-text input directly to the appropriate investigation.
  Event results use server-side pagination (25 rows by default; `per_page`
  accepts 25–500).
  Every longer table and API-fed list initially displays 25 entries, then
  reveals the next 25 near the end of the page or through an accessible
  **Load 25 more** control. This also covers payloads, alerts, sandbox results,
  commands, source lists, and Elasticsearch dead letters. Payload, event, and
  attack-source rows are fetched from the server in 25-row chunks, avoiding
  large initial HTML responses even when an inventory contains thousands of
  records.
  Attacker profiles combine network enrichment, behavior aggregates, and a
  chronological progression view. `/sessions/<id>` provides an oldest-to-newest
  session replay, and both views add conservative MITRE ATT&CK Enterprise/ICS
  behavior mappings with links and explicit evidence (behavior context, never
  actor attribution). `/clusters` finds fingerprints, payloads, ASNs, and
  provider classes shared by multiple source IPs. Campaign rows now explain
  exactly which cross-sensor, credential, payload, alert, or fingerprint factors
  produced their correlation score. The navbar alert badge shows unacknowledged
  alert state, while source health uses neutral metric tiles for feeds,
  Elasticsearch, Filebeat, and dead letters.
  `/api/v1/campaigns` exposes the same correlation data. A balanced recent feed
  prevents one noisy sensor from hiding lower-volume sensors. The
  portbridge connection log is used only to recover real source IPs; it is not
  counted as a sensor or displayed as an event.
  The overview attack map uses the vendored Leaflet 1.9.4 client with a
  hardcoded OpenStreetMap raster basemap and GeoLite2 City/ASN coordinates
  from `/api/map-points`. Attack origins are geographic circles whose physical
  radius is weighted by event count, so their displayed size changes naturally
  with zoom. Hover shows IP/city/ASN/provider details and selecting a circle
  opens every event for that attacker. Live refreshes retain the Leaflet map DOM
  and update only its GeoJSON layer, preserving pan and zoom. If the map library
  or tiles fail, the current OpenStreetMap container remains visible with an
  availability message; there is no local basemap fallback.
  #2425: `HONEYPOT_MAP_TILE_URL` / `HONEYPOT_MAP_ATTRIBUTION` are gone --
  they fed the retired Go dashboard's server-side template; the Leaflet layer
  hardcodes both values outright (`frontend-next/src/components/
  OverviewPanels.tsx`), so there is no basemap env surface to set anymore.
  The hourly activity chart also exposes exact counts on hover/focus. The 24-hour
  KPI compares activity with the preceding 24 hours and labels large changes;
  source health reports dashboard process uptime and memory (RSS + virtual)
  as the runtime card on `/api/v1/source-health` — the Go heap/goroutine
  figures that card used to show have no Rust equivalent and are gone.
  Event metadata is directly pivotable: sessions, HASSH/JA3/JA4/User-Agent
  fingerprints, exact commands and credentials, HTTP paths, IDS signatures and
  categories, payload hashes, ASNs, organizations, and provider classes all
  open their related events. Source-health tail counts open normalized events;
  Elasticsearch source totals open a pre-populated historical query.
  Management-ready A4 PDF reports are available from the overview, alert
  center, campaign view, attacker profiles, sessions, and every filtered Event
  Explorer result. `/export/report.pdf` applies the same filters as Event
  Explorer, including source IP/CIDR, ASN, organization/provider, country,
  sensor, signature/category, payload, session, protocol/port, HTTP path,
  fingerprint, and time window. Reports contain an executive risk summary,
  ranked sources and indicators, operational alert state, recommendations, and
  a bounded representative-evidence appendix. Report downloads require the
  dashboard's own Keycloak-derived `admin` role because they contain hostile-source telemetry.
  The overview also ranks fingerprints, ASNs, and provider classes with the
  same one-click pivots.
  ASN/provider pivots,
  `/commands` session-aware command analysis, and `/payload-analysis/<hash>`
  with bounded hashes, entropy, hex, strings, PE/ELF and script classification,
  behavior indicators, packing likelihood, extracted URL/domain/IP indicators,
  real YARA rule matches from a networkless, read-only scanner, risk scoring, and
  Base64/hex/URL/PowerShell UTF-16 decoding. Payload inventory scans run in the
  background and refresh every two minutes, so walking large capture volumes
  cannot block `/payloads`; source filters and duplicate provenance are
  preserved. Download event rows link directly to the matching static report. `/history` adds
  Elasticsearch search/export; `/source-health` shows Filebeat/Elasticsearch
  diagnostics. Alerts have persistent cooldown/acknowledgment, live refresh uses
  SSE, and events pivot directly to Kibana, EveBox, Arkime, and VirusTotal.
  Event tables support keyboard-accessible sorting, selectable columns, and an
  expandable normalized-row JSON view; live events on investigation pages raise
  a transient notification. Browser API contracts live in
  `arcane/home/honeypot-dashboard/frontend-next`
  as strict TypeScript and compile to the committed, dependency-free production
  bundle, so Node.js is only a development tool and never part of the container.
- **Operational APIs** — `/metrics` exposes Prometheus text metrics for event,
  sensor, ingestion, Filebeat, runtime, dead-letter, and YARA health.
  `/dead-letters` investigates rejected Elasticsearch documents, and
  durable campaign/cluster snapshots in `dashboard-intelligence-archive-v1`
  are readable through the generic index-store route
  `/api/v1/store/intelligence` (there is no dedicated intelligence route
  in the Rust router).
  Alert acknowledgements and captured-malware downloads require the
  dashboard's own Keycloak-derived `admin` role.
- **Safe payload triage** — `yara-scanner` inventories all mounted Dionaea,
  Cowrie, and script captures without network access or execution. Its results
  enrich `/payloads`, static-analysis reports, risk scores, alerts, and health.
- **Backups** — run `sudo analysis/backup-honeypot.sh`; Elasticsearch uses its
  snapshot API and other named volumes are archived separately. Test and restore
  procedures are in [`docs/analysis/RECOVERY.md`](analysis/RECOVERY.md).
- **Kibana saved objects** (dashboards, visualizations, data views you build
  by hand) live only in Elasticsearch's Kibana saved-objects index — on this
  stack's Kibana 9.5.3 that is `.kibana_<n>`, not a bare `.kibana` — so an ES
  reset, migration, or upgrade loses them with no recovery path unless you've
  exported first. Run `analysis/kibana-export.sh` before any ES-affecting
  change (matching `KIBANA_URL` to how you reach Kibana — defaults to
  `http://kibana:5601`, the in-cluster address); restore with
  `analysis/kibana-import.sh`. **Export first, the same way you'd back up
  anything else you'd be upset to lose** — `backup-honeypot.sh` above
  doesn't cover these, only the raw Elasticsearch data.
- **Hard-isolated sandbox** — the optional [`sandbox/`](../sandbox/) host setup
  installs KVM/libvirt beside Docker, defines a non-forwarding network, disables
  libvirt's default NAT network, and uses disposable qcow2 overlays. It never
  mounts the Docker socket, host folders, or payloads into a running guest.
  The root-only hash resolver and serial systemd queue accept existing captures,
  deduplicate them by SHA-256, enforce guest/host deadlines, and export only
  bounded escaped JSON summaries to the dashboard's `/sandbox` investigation
  page. The view includes queue health, search, risk, timeout/duration, static
  versus dynamic evidence, ATT&CK behavior, Windows PE forensics, DNS
  query/response evidence, host and guest packet summaries, and sanitized JSON
  export. Content-based routing distinguishes PE executables, DLLs, VBS,
  JScript, batch, PowerShell, shell, Python, PHP, Node.js, ELF, documents,
  archives, and unknown data before selecting a static-only or type-specific
  detonation path. Optional headless Wine execution and allowlisted real-DNS/HTTP(S)
  forensic retrieval remain inside a freshly recreated VM and a host-enforced
  proxy boundary. Authenticated administrators can queue an existing
  captured hash with the payload **Analyze** button through a narrow host-owned
  request spool. Bounded host/guest PCAPs can be downloaded by administrators
  for Wireshark; complete traces, oversize captures, and direct queue control
  remain outside Docker. A libvirt NIC filter prevents MAC spoofing and
  unwanted L2 traffic.
- **analyze.py** — summarize the bind-mounted logs directly on the home server:
  ```bash
  python3 analysis/analyze.py /opt/stacks/apiary/logs --top 20
  ```
- **Kibana** → `https://kibana.<domain>` (Keycloak via the oauth2-proxy gateway). Data views already exist:
  `honeypot-v2-*` and `suricata-*` (time field `@timestamp`) plus
  `dead-letter-honeypot*`, alongside **Arkime
  Sessions** (`arkime_sessions3-*`, time field `lastPacket`). All suricata and
  honeypot events carry `source.geo` / `source.as` — build maps on
  `source.geo.location`. Arkime sessions have country + ASN only (GeoLite2
  Country has no coordinates).
- **Arkime** → `http://<HP_BIND>:19080` — full-packet session search over
  everything Suricata captured on the VPS.
- **TANNER dashboard** → `https://tanner.<domain>` (Keycloak via the oauth2-proxy gateway) — web-attack analysis.
- Dionaea/Conpot write their own JSON into the shared volume for jq/ELK; the
  live dashboard ingests them alongside Cowrie, multipot, HTTP, and Suricata.

## Service health contract (backend-service)

`apiary-backend` (the Rust tier behind every `/api/v1` route) answers two
different questions on two different endpoints. They used to be one endpoint
with a constant answer: `/healthz` returned `{"ok": true, "es": <bool>}`,
where `ok` was literally hardcoded to `true`, so a backend that could not
reach Elasticsearch at all still told its own healthcheck, and anything else
that probed it, that it was healthy. The `#3283` ingest outage would not have
appeared there. Split into:

| Endpoint | Question | Touches Elasticsearch | Non-200 |
|---|---|---|---|
| `/livez` | Is the process up and serving? | **No** | never |
| `/healthz` | Same handler as `/livez`, historical name | **No** | never |
| `/readyz` | Can it actually do its job? | Yes (2 probes) | 503 + `reason` |

```console
$ curl -s http://backend-service:8081/livez
{"live":true,"built":"2026-09-27T01:46:34+00:00","revision":"3dca4457f1b2c0d4e5a69788796a5b4c3d2e1f0ab"}

$ curl -s http://backend-service:8081/readyz
{"ready":true,"cluster":"green","write_blocked":[]}

$ curl -s -o /dev/null -w '%{http_code}\n' http://backend-service:8081/readyz   # during an ES outage
503
```

`/readyz` deliberately carries **no** `revision`: readiness is about whether
this process can do its job, which is a property of the running container and
not of a build, and the two questions have different answers during a rollback.
The revision belongs to the liveness body, which is the one every probe and
every ops script already reads.

**`/livez` is what the container `HEALTHCHECK` curls, and it must stay that
way.** A probe that can block on Elasticsearch converts that dependency's
outage into a restart loop of a container that was never the problem. The
image's own comment on the `HEALTHCHECK` line says this too. `/healthz` is
kept as an alias because the port-test harness
(`arcane/home/honeypot-dashboard/port-tests/lib.sh`) and the ops scripts
already use that name; it is a rename-with-a-twist, not a rename.

### What `/readyz` actually checks

1. **Reachable** — `GET /_cluster/health` answers. This is the check the old
   `es: <bool>` field gestured at; the difference is that failing it now
   produces a 503.
2. **Not red** — red means unassigned primaries, against which reads and
   writes both fail. **Yellow stays ready**: it means unassigned *replicas*,
   which is the ordinary shape of a replicated cluster during a rolling
   restart, and gating on it would mark the backend not-ready on every deploy.
3. **Writable** — no `index.blocks.write` set on any of the index families
   this tier writes to (the list is `es::WRITE_TARGET_FAMILIES` in
   `backend-service/src/es.rs`, `dashboard-*` plus the bundled worker loops'
   own families). This is what catches the flood-stage disk watermark, which
   sets the block on every index at once, and an operator's
   `PUT /<index>/_block/write`.

The response names the blocked indices rather than counting them, and the
`reason` string points at `_cat/allocation` because the endpoint **cannot
tell those two causes apart** — an honest limit, stated rather than papered
over. A *missing* index is not a block: every dashboard-owned index is created
lazily on its first write, so a fresh cluster correctly reads ready.

Both probes run concurrently under a 5s deadline
(`READINESS_TIMEOUT`), shorter than the shared client's 30s, because a probe
that blocks for 30s is indistinguishable from the outage it exists to report.

### What to point at what

- **Docker/compose healthcheck, Traefik, uptime pings** → `/livez` (or
  `/healthz`). Never `/readyz`; see above.
- **Deploy verification, diagnostics, "is ingest actually working?"** →
  `/readyz`, and treat 503 as a real answer, not a transport error. This is
  the endpoint that would have shown `#3283`.
- **"Why is the dashboard empty?"** → `/api/v1/source-health` (the
  per-sensor freshness page). `/readyz` says the backend cannot write; only
  source-health says whether events are arriving.
- **"Which commit is actually deployed?"** → `revision` on `/livez`, plus
  the image label. See below.

### Which revision is deployed (#3315)

The failure this exists for is the one `docs/ARCANE-GIT-SYNC.md` names
directly: a content-change redeploy leaves the dashboard **"green, healthy,
running the old code."** A fresh container id, a passing healthcheck and a
recent image build all say the machinery ran — none of them say this code is
what is running. So both dashboard images carry the git revision they were
built from, and `scripts/verify-deploy.sh` compares it against what you
expect.

**The contract, in one table.** Four surfaces, one value:

| Surface | Where | Read it with |
|---|---|---|
| Backend health body | `{"live":…,"built":…,"revision":…}` on `/livez` and `/healthz` | `curl -s …/healthz` |
| Backend boot log | `revision=…` on the `apiary-backend listening` line | `docker logs … \| grep listening` |
| Frontend static file | `/build.json` → `{"built":…,"revision":…,"source":…}` | `curl -s …/build.json` |
| Both images | `org.opencontainers.image.revision` (with `.source`, `.created`) | `docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' apiary-backend:latest` |

The health body and `build.json` are small enough to read unfiltered, so
there is nothing to parse here and nothing that needs `jq` — which is
deliberately absent from these hosts (`verify-deploy.sh` uses `python3` for
the same reason).

**Where the value comes from, and what `"unknown"` means.** `GIT_SHA` is a
Docker **build arg**, declared in both Dockerfiles and passed by the stacks'
compose files as `build.args.GIT_SHA: ${GIT_SHA:-}`. The backend compiles it
in (`build.rs` re-exports `GIT_SHA` as `APIARY_GIT_SHA`); the frontend writes
it into `public/build.json` before `npm run build`. Unset is normal and not
an error — you get the literal string `unknown`, never a fabricated revision,
because a plausible-looking wrong answer is worse than no answer. Both tiers
normalize to a bare lowercase hex object name (optional `sha256:` prefix
stripped, 7–64 hex chars) or `unknown`, and both are held to one shared table,
`backend-service/src/revision-corpus.json`, so the two normalizers — different
languages, different CI lanes — cannot drift.

`build.rs` also emits `cargo:rerun-if-env-changed=GIT_SHA`. That line is
load-bearing, not hygiene: cargo caches a build script's output by its inputs
and an environment variable is not one of them unless declared, so without it
the *second* build of an identical tree silently reports the *first* build's
revision — the exact failure this section exists to end, reproduced by the
stamp itself.

**Turning it on.** Nothing repo-tracked writes `GIT_SHA`; the stacks' `.env`
files are root-owned and provisioned outside this repository, and there is no
`.git` on the host to ask (`deploy.yml` rsyncs with `--exclude .git/`). So
the first run after this landed correctly reports **not stamped**. From a
clone you are deploying, one line per stack:

```console
echo "GIT_SHA=$(git rev-parse HEAD)" >> /var/dockge/stacks/honeypot-dashboard-backend/.env
echo "GIT_SHA=$(git rev-parse HEAD)" >> /var/dockge/stacks/honeypot-dashboard/.env
```

followed by the `POST /projects/{id}/build` that a content-change sync does
*not* do. CI (`.github/workflows/containers.yml`) passes `github.sha` for the
two Dockerfiles that declare the arg.

**Running the check.** `scripts/verify-deploy.sh` compares the live revision,
the image label, and an expected revision — which it takes from `origin/main`
in a real clone, or from an argument:

```console
# On a host with a clone of apiary, the full check:
scripts/verify-deploy.sh --healthz-exec \
  'docker exec hp-apiary-backend curl -sf http://127.0.0.1:8081/healthz' \
  --image apiary-backend:latest

# Without one, name the expected revision yourself:
scripts/verify-deploy.sh --behind-days 0 "$(git rev-parse origin/main)" \
  --healthz-exec 'docker exec hp-apiary-backend curl -sf http://127.0.0.1:8081/healthz'

# The frontend's form:
scripts/verify-deploy.sh --healthz-url http://host:19090/build.json
```

Exit codes are the point, and are deliberately three-valued: **0** the
deployed revision matches; **1** a finding (missing, unstamped, malformed, or
stale past `--behind-days`); **2** *could not tell* — an unreadable body or an
image that is not on this host. An unreadable answer must never read as a
stale deploy, which is why 2 is not 1. Add `--image` to check a label against
the running container, which catches the commoner variant where a
`compose up` recreated from an older image than the one whose label you just
read. The lag check measures the age of the *commit*, not of the container, so
it survives a container that has been up since before the merge it is missing
— but it needs a clone to measure against, hence `--behind-days 0` for the
clone-less form.

`diagnostics.yml` runs it in `--warn-only` mode in its own "Deployed
revision" section, against `$GITHUB_SHA`: the home runner has no clone to
measure against, so the section degrades to "is the running revision the
current tip of `main`" and says so in the report. Its exit 2 is still
reported as **could not tell**, not as a pass.

## Disk space monitoring

`hp-disk-space-monitor` (`arcane/home/honeypot-utilities/analysis/disk-space-check.sh`)
polls `df` on the bind-mounted host paths in `DISK_CHECK_PATHS` (default:
`honeypot-logs=/logs:honeypot-state=/state:dionaea-payloads=/dionaea-lib`)
plus Elasticsearch's own data volume over HTTP (`_cat/allocation`), and
writes a warning line to `/logs/diagnostics/disk-space.json` whenever a
checked filesystem's free space drops below `DISK_WARN_PERCENT_FREE`
(default 15%). Filebeat ships those lines under
`event.module:disk-space-check`.

**#2707: alerts are grouped by physical filesystem, not by bind-mounted
path.** `honeypot-logs` (`/logs`) and `honeypot-state` (`/state`) are both
bind-mounts of the same host directory tree
(`/opt/stacks/apiary` on the home server), so a low-free-space condition on
that one filesystem used to fire one near-identical WARNING line per bind
mount. The monitor now reads the backing device from `df -Pk`'s first
column, groups every checked path that shares a device into a single
alert, and names the largest of the grouped paths (by `du`) as
`top_contributor` so a real spike points straight at a directory instead
of leaving an operator to compare N identical percentages by hand. Shape:

```json
{
  "@timestamp": "2026-08-30T12:00:00Z",
  "event": {"module": "disk-space-check", "category": "host"},
  "disk": {
    "source": "/dev/sda1",
    "labels": "honeypot-logs,honeypot-state",
    "percent_free": 8,
    "available_kb": 1234567,
    "total_kb": 20000000,
    "top_contributor": {"label": "honeypot-logs", "path": "/logs", "used_kb": 15000000}
  },
  "level": "warning"
}
```

`elasticsearch-data` alerts (from `_cat/allocation`, since `es-data` is a
stack-private volume never bind-mounted cross-stack) are unaffected --
there is only ever one of them per check.
