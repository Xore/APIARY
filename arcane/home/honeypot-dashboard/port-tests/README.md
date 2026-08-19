# Port smoke suite (#1608 / #1610 / #1616)

Live-data smoke tests for the modernization port: the Rust service tier
(`backend-service/`), the TanStack Start SSR/BFF tier (`frontend-next/`),
and the worker loops. Every check runs against the **real** Elasticsearch,
so results reflect actual parity, not fixtures.

## Prerequisites

- Elasticsearch reachable (default `http://127.0.0.1:19200`). On the
  devbox that's a tunnel: `ssh -N -L 19200:172.16.1.12:9200 xore@$HOMESERVER_HOST &`
  (it dies occasionally — restart it before blaming a failure on code).
- Rust toolchain (`cargo`) and Node 22+ / `npm ci` done in `frontend-next/`.

## Scripts

| script | covers | writes to live ES? |
| --- | --- | --- |
| `backend-api.sh` | every `/api/v1` endpoint: KPIs, dashboard aggregation, events + filters + q, stores, charts, session/ip/payload/replay details, artifacts, SSE, report PDF | ip-block round trip on the TEST-NET-3 address `203.0.113.99` (restored) |
| `frontend-ssr.sh` | every route SSRs 200 under `OIDC_DISABLED=1`, 404 page, chart/SSE proxies, unauthenticated blackhole export | no |
| `auth-flow.sh` | auth guard: SSR redirect to `/auth/login`, 401 API proxies, blackhole export stays open (tunnel trust) | no |
| `worker-notifier.sh` | `WORKER_LOOPS=alert-notifier` baseline pass | yes — upserts `dashboard-alert-state-v1` on the same key/shape contract as the Go alertManager (safe alongside it) |
| `worker-reports-scheduler.sh` | `WORKER_LOOPS=reports-scheduler` scheduled-tick parity against the old Go `reportScheduleLoop`'s own test contract (success path + #1340 no-hot-loop failure path) | yes — two throwaway definitions in `dashboard-reports-definitions-v1` + one generated doc in `dashboard-generated-reports-v1`, all deleted at the end |
| `bff-load.sh` | #1616 load-test gate: cluster.mjs actually forks WEB_CONCURRENCY workers; SSE fan-out + burst navigation run concurrently against artificially tight caps and the BFF sheds (503) instead of hanging/500ing/crashing | no |

Run one: `bash port-tests/backend-api.sh`
Run all: `for s in port-tests/{backend-api,frontend-ssr,auth-flow,worker-notifier,worker-reports-scheduler}.sh; do bash "$s" || exit 1; done`

`bff-load.sh` is slower and noisier (concurrent bursts, not single checks) than
the rest of the sweep, so it's not in the "run all" loop above — run it on
its own when touching `lib/backend.server.ts`, `lib/backpressure.server.ts`,
`server/cluster.mjs`, or any of the byte-streaming `api/*` proxy routes.

Env knobs: `ES_URL`, `BE_PORT` (18081), `FE_PORT` (14173),
`SKIP_FE_BUILD=1` to reuse the last vite build.

## Conventions for new tests

- Source `lib.sh`; use `check` / `check_http` / `check_json` + `summary`
  so scripts exit non-zero on any failure.
- Discover test keys (session ids, hashes, report ids) from live data —
  never hardcode ids that rot.
- Anything that writes must use reserved/test values (TEST-NET-3 IPs) and
  restore state before exiting.
- Never pipe a test command through `| tail` without capturing the exit
  code — that pattern has silently hidden failures before.
