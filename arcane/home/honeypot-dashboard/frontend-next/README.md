# frontend-next

A minimal TanStack Start app with one route and plain CSS.

```bash
npm install
npm run dev
```

Edit `src/routes/index.tsx` to get started. Add route files under
`src/routes`; TanStack Router updates `src/routeTree.gen.ts` for you.

Build the production app with:

```bash
npm run build
```

## Deploy with Nitro

This project uses Nitro as a generic server adapter, so it can run on any Node-compatible host.

```bash
npm run build
node dist/server/index.mjs
```

The build output is a self-contained Node server. To deploy, push the `dist/` directory to your host (Render, Fly.io, your own VPS, etc.) and run the server command above.

For host-specific presets (Vercel, Netlify, Cloudflare, AWS Lambda, etc.) and tuning, see https://v3.nitro.build/deploy.

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
`port-tests/bff-load.sh` for the load-test gate that exercises both.


