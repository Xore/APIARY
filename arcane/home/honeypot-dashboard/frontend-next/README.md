# frontend-next

TanStack Start frontend/BFF tier of the honeypot dashboard modernization
port ([#1608](https://github.com/Xore/APIARY/issues/1608)) — the
replacement for the Go `dashboard`'s HTML/template UI, paired with the
Rust `backend-service`/`backend-worker` tier
(`../backend-service`) it proxies every `/api/v1/*` call to. See
[`../../../../docs/DASHBOARD-CUTOVER.md`](../../../../docs/DASHBOARD-CUTOVER.md)
for the cutover status (still `next`-profile-gated, not live) and
[#1628](https://github.com/Xore/APIARY/issues/1628) for the tracking
issue. Routes live under `src/routes/`, BFF-only server logic in
`*.server.ts` files (TanStack Start's `import-protection` plugin blocks
these from being statically imported by anything bundled for the client —
`createServerFn().handler()` bodies dynamically `import()` them instead;
see `src/lib/backend.server.ts` for the tier-split (SERVE_MODE) seam these
files sit behind), shared components in `src/components/`.

## Local development

Needs a reachable Elasticsearch (`../port-tests/README.md`'s
"Prerequisites" section documents the devbox tunnel — default
`http://127.0.0.1:19200`) and a running `backend-service` (`cd
../backend-service && cargo run`, defaults to `127.0.0.1:8081`). With both
up:

```bash
npm install
npm run dev
```

Both tiers refuse to boot without auth configured (#2183): an unset
`SERVICE_TOKEN` used to silently disable the Rust tier's `/api/v1` check
*and* this tier's `/bff/*` proxy check; now both fail at startup with
`[E-SERVICE-TOKEN]`. So run `SERVICE_TOKEN=dev-secret cargo run` /
`SERVICE_TOKEN=dev-secret npm run dev` (any non-empty value both tiers
agree on), or set `APIARY_ALLOW_UNAUTH_DEV=1` to state explicitly that an
unauthenticated dev instance is what you want — exactly "1", nothing else.

`OIDC_DISABLED=1` skips the Keycloak login flow entirely (treats every
request as an authenticated admin) — the mode `port-tests/` and most local
iteration use, since standing up a real Keycloak realm locally is rarely
worth it just to click around the UI. Without it, set `OIDC_ISSUER_URL`/
`OIDC_CLIENT_ID`/`OIDC_CLIENT_SECRET_FILE`/`OIDC_EXTERNAL_URL` to point at
a real Keycloak instance.

Add route files under `src/routes/`; TanStack Router regenerates
`src/routeTree.gen.ts` for you (`npm run generate-routes` to force it
without a dev-server rebuild). The TanStack packages are pinned at exact
versions (no carets, no tags) because that generation runs from them on a
fresh install: bumping one is a deliberate act done for the family together,
with route-tree behaviour verified before landing (#2180).

## Build and run

```bash
npm run build
OIDC_DISABLED=1 BACKEND_URL=http://127.0.0.1:8081 PORT=3000 node .output/server/index.mjs
```

The real deployment target is the `dashboard-next` service in
`../compose.yml` (Docker, built from this directory, gated behind the
`next` Compose profile) — not a generic Nitro preset (Vercel/Netlify/AWS
Lambda/etc.); this app assumes it's always reached through the BFF's own
env-var-configured `backend-service`/`BACKEND_MOUNTED_URL`/session-Redis
wiring, not a serverless request/response model. See
[`../../../../docs/ARCANE-GIT-SYNC.md`](../../../../docs/ARCANE-GIT-SYNC.md)
for how a commit actually reaches the live host.

## Verification

`../port-tests/` is the live-ES smoke suite for this tier and
`backend-service` together (`frontend-ssr.sh`, `auth-flow.sh`,
`backend-api.sh`, `bff-load.sh`) — see `../port-tests/README.md`. Run
against a real build, not `npm run dev`'s HMR server.

## Scaling (#1616)

The Dockerfile runs `server/cluster.mjs`, not `.output/server/index.mjs`
directly — it forks `WEB_CONCURRENCY` copies of the built server (default
`min(4, host cpus)`) sharing one listen port, so one slow/blocking request
only stalls its own worker's event loop. Set `WEB_CONCURRENCY=1` (or run
`.output/server/index.mjs` directly, as `port-tests/lib.sh` does) for a
single process.

Fan-out to the Rust service tier and the byte-streaming proxy routes
(`/api/live`, report/artifact/canarytoken downloads) are each behind a
bounded-queue admission gate (`src/lib/backpressure.server.ts`) that sheds
with `503` past capacity instead of queuing without bound. Tuning env
vars, all optional with in-code defaults: `BACKEND_MAX_INFLIGHT`,
`BACKEND_MAX_QUEUE`, `BACKEND_HTTP_MAX_SOCKETS`, `LIVE_MAX_STREAMS`,
`REPORT_PDF_MAX_CONCURRENT`, `ARTIFACT_MAX_CONCURRENT`,
`CANARYTOKEN_MAX_CONCURRENT`, `BFF_EVENT_LOOP_SHED_MS`. See
`../port-tests/bff-load.sh` for the load-test gate that exercises both.
