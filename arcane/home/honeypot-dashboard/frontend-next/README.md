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
a real Keycloak instance. The process refuses to boot with `OIDC_DISABLED=1`
unless `NODE_ENV=development` or `APIARY_ALLOW_UNAUTH_DEV=1` is also set
(#3112), so local harnesses need one of those two alongside it.

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

### Unit tests, coverage and the ratchet (#3318)

`npm test` is the unit suite and stays uninstrumented — no coverage, no
report tree — so it stays the cheap command that `deploy.yml`, this README
and your own loop all reach for. The coverage number lives in its own
command:

```bash
npm run test:coverage     # vitest + v8 coverage for src/, into coverage/ (gitignored)
npm run coverage:ratchet  # compare that measurement to the committed baseline; non-zero on a drop
npm run test:discovery    # fail if a *.test.ts / *.spec.ts exists that no runner collects
```

`coverage-baseline.json` at this directory's root is the committed
non-regression floor: **806/7359 lines (10.95%) and 346/7250 branches
(4.77%)** across 127 files of `src/`, measured on the `node:22` image the
tier ships. It is a measurement, not a target, and the low number is the
real one — the tier's tests concentrate on `src/lib` server logic, and most
of `src/routes` and `src/components` is covered by the Playwright matrix
instead, which the v8 provider does not see. Do not hand-edit it, and do
not regenerate it to turn a red run green.

To move it on purpose, having first established the drop is intended
rather than a lost test:

```bash
npm run test:coverage && npm run coverage:baseline   # commit both, together
```

The ratchet has two independent gates. `tolerance.coveredCount` is 0: no
covered line or branch may stop being covered, which is what catches a
change that deletes tested behaviour, and which no shrinking-denominator
trick can satisfy. `tolerance.pctPoints` is 1.0: the overall percentage may
not fall more than that, which catches a change that adds a lot of untested
source. At a ~11% baseline the second is the coarse one — it needs several
hundred new uncovered lines to move — which is the honest shape of a
low-coverage ratchet and the reason the first one carries the weight.
`scripts/tests/test_3318_coverage_ratchet.py` in the repository root pins
both, so neither can be loosened without that test going red.

## New-page review checklist (capped-truth discipline, #2179)

When authoring or reviewing a page, check the ways a number can quietly lie.
Every bounded fetch must either reach reality or disclose its bound, bound
to the same state that applies the cap:

- **Counts over partial loads** — any KPI/badge/chip computed from fetched
  rows while more exist in the store either paginates to completion or says
  "X of Y" next to itself. In-repo exemplars: the ips route's
  `{rows.length} of {total} entries`, payloads' verdict-badge note.
- **Filters over loaded pages** — a client-side filter whose table shows
  fewer than the header chips' store-wide total must say what it filtered
  within (see `FilterScopeNote` in payload-workbench.results).
- **Backend scans** — no unsorted size-bounded scan; sort freshest-first,
  warn on cap hit (worker.rs alert loops, per #2179), and surface ES's
  `sum_other_doc_count` where a terms agg is the bound (search.rs,
  stores.rs source census).

The sibling census (#2178) covers the same pages for error-surface
null-collapse; check both when adding a new list page.

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
