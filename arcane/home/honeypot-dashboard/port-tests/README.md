# Port smoke suite (#1608 / #1610)

Live-data smoke tests for the modernization port: the Rust service tier
(`backend-service/`), the TanStack Start SSR/BFF tier (`frontend-next/`),
and the worker loops. Every check runs against the **real** Elasticsearch,
so results reflect actual parity, not fixtures.

## Prerequisites

- Elasticsearch reachable (default `http://127.0.0.1:19200`). On the
  devbox that's a tunnel: `ssh -N -L 19200:172.16.1.12:9200 xore@192.168.42.250 &`
  (it dies occasionally — restart it before blaming a failure on code).
- Rust toolchain (`cargo`) and Node 22+ / `npm ci` done in `frontend-next/`.

## Scripts

| script | covers | writes to live ES? |
| --- | --- | --- |
| `backend-api.sh` | every `/api/v1` endpoint: KPIs, dashboard aggregation, events + filters + q, stores, charts, session/ip/payload/replay details, artifacts, SSE, report PDF | ip-block round trip on the TEST-NET-3 address `203.0.113.99` (restored) |
| `frontend-ssr.sh` | every route SSRs 200 under `OIDC_DISABLED=1`, 404 page, chart/SSE proxies, unauthenticated blackhole export | no |
| `auth-flow.sh` | auth guard: SSR redirect to `/auth/login`, 401 API proxies, blackhole export stays open (tunnel trust) | no |
| `worker-notifier.sh` | `WORKER_LOOPS=alert-notifier` baseline pass | yes — upserts `dashboard-alert-state-v1` on the same key/shape contract as the Go alertManager (safe alongside it) |

Run one: `bash port-tests/backend-api.sh`
Run all: `for s in port-tests/{backend-api,frontend-ssr,auth-flow,worker-notifier}.sh; do bash "$s" || exit 1; done`

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
