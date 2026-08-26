// #1616: cluster-mode entrypoint for the built Nitro server
// (.output/server/index.mjs). A single Node process has one event loop —
// under this tier's hard "never get overwhelmed" backpressure requirement,
// one slow synchronous stretch (a big JSON.stringify, a GC pause) would
// stall every in-flight request on that replica, not just the one that
// caused it. Forking WEB_CONCURRENCY worker processes,
// each running the same built server and sharing the listen port (Node's
// cluster module round-robins accepted connections across them on Linux),
// keeps that blast radius to one worker's share of the traffic instead of
// the whole replica.
//
// This wraps the build output rather than living in src/ so it's never
// part of the Vite/Nitro build graph — it's a plain Node script the
// Dockerfile execs directly, same as `node .output/server/index.mjs` was
// before. Set WEB_CONCURRENCY=1 (or run index.mjs directly, as
// port-tests/lib.sh's smoke suite does) to opt back into a single process,
// e.g. for local debugging where per-worker stdout interleaving is noise.
import cluster from 'node:cluster'
import os from 'node:os'

// #2183: checked here as well as inside the server bundle (server/plugins/
// service-token-gate.ts -> src/lib/serviceToken.server.ts) because the
// primary does not evaluate that bundle itself — without this, a tokenless
// boot would not refuse but crashloop-respawn every worker it forks, which
// is loud but reads as breakage, not as the deliberate refusal it is. Keep
// this truth table identical to serviceTokenPolicy() there and to
// backend-service/src/main.rs's resolve_service_token: one contract,
// rendered where each runtime can act on it.
const tokenIsSet = typeof process.env.SERVICE_TOKEN === 'string' && process.env.SERVICE_TOKEN.length > 0
if (!tokenIsSet && process.env.APIARY_ALLOW_UNAUTH_DEV !== '1') {
  console.error(
    '[E-SERVICE-TOKEN] refusing to start: SERVICE_TOKEN is unset or empty, which would leave ' +
      'every /bff/* proxy route open to unauthenticated requests. Set SERVICE_TOKEN to the ' +
      'shared secret the Rust tier also carries — see docs/DASHBOARD-CUTOVER.md step 2 — or, ' +
      'for local development only, set APIARY_ALLOW_UNAUTH_DEV=1 explicitly (#2183).',
  )
  process.exit(1)
}

const workerCount = Math.max(1, Number(process.env.WEB_CONCURRENCY) || Math.min(4, os.cpus().length))

if (workerCount === 1 || !cluster.isPrimary) {
  await import('../.output/server/index.mjs')
} else {
  console.log(`[cluster] primary ${process.pid} starting ${workerCount} workers`)

  for (let i = 0; i < workerCount; i++) cluster.fork()

  // Respawn a worker that dies unexpectedly (not from the shutdown below)
  // so one crashing worker degrades capacity instead of compounding into
  // the whole replica losing workers one at a time under sustained load.
  // During shutdown the same 'exit' event instead drives the primary's
  // own exit — cluster.disconnect()'s callback fires once IPC disconnects,
  // which in testing fired before a worker's process had actually
  // terminated, so the primary would exit while a worker was still
  // alive; counting real 'exit' events is the ground truth disconnect()
  // couldn't reliably promise. `docker stop`/compose restarts send
  // SIGTERM and wait, not kill -9, so exiting has to be self-driven and
  // bounded: the force-kill timer below SIGKILLs any worker wedged on an
  // in-flight request rather than hanging the container's shutdown.
  let shuttingDown = false
  let pendingExits = 0
  cluster.on('exit', (worker, code, signal) => {
    if (!shuttingDown) {
      console.error(`[cluster] worker ${worker.process.pid} exited (code=${code} signal=${signal}), respawning`)
      cluster.fork()
      return
    }
    pendingExits--
    if (pendingExits <= 0) process.exit(0)
  })

  const shutdown = (signal) => {
    if (shuttingDown) return
    shuttingDown = true
    // Captured once, up front: cluster.workers drops an entry as soon as
    // its IPC channel disconnects, which can happen before the OS process
    // it backs has actually exited — the force-kill loop below needs its
    // own handle on every worker, not a live read of a map that may have
    // already emptied out from under it by the time the timer fires.
    const workers = Object.values(cluster.workers)
    pendingExits = workers.length
    console.log(`[cluster] primary ${process.pid} received ${signal}, stopping ${pendingExits} workers`)
    if (pendingExits === 0) process.exit(0)
    // Shorter than Docker/compose's own default 10s stop_grace_period —
    // this has to win that race and actually run, not get pre-empted by
    // the platform's own SIGKILL of the whole container before it fires.
    const forceKill = setTimeout(() => {
      console.error('[cluster] workers did not exit in time, forcing')
      for (const worker of workers) worker.process.kill('SIGKILL')
      process.exit(1)
    }, 5_000)
    forceKill.unref()
    for (const worker of workers) worker.disconnect()
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'))
  process.on('SIGINT', () => shutdown('SIGINT'))
}
